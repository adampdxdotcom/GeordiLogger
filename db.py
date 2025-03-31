# db.py
import sqlite3
import datetime
from datetime import timezone # Import timezone directly
import logging
import os
import json # For storing lists/dicts like ignored containers or colors

DATABASE_DIR = '/app/data' # Container path where data is mounted
DATABASE = os.path.join(DATABASE_DIR, 'monitoring_data.db')

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(), format='%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s')

# --- Default Settings ---
DEFAULT_SETTINGS = {
    "ollama_model": os.environ.get("OLLAMA_MODEL", "phi3"),
    "ollama_api_url": os.environ.get("OLLAMA_API_URL", "http://localhost:11434"), # Base URL default
    "analysis_prompt": """Analyze the following Docker container logs STRICTLY for CRITICAL errors, application crashes, fatal exceptions, stack traces indicating failure, severe performance degradation (like persistent high resource usage warnings), OOM (Out Of Memory) errors, or potential security breaches (like repeated auth failures).

FOCUS ONLY on issues that indicate service failure, instability, or require immediate attention.

MUST IGNORE:
- Routine operational messages, startup sequences, successful connections, periodic status updates.
- Lines starting with 'INFO:' unless they ALSO contain critical keywords like 'error', 'fail', 'crash', 'fatal', 'exception', 'denied', 'unauthorized'. For example, ignore lines like 'INFO Challenge not detected!' or 'INFO Response in X.XXX s' or 'INFO XXX.XXX.XXX.XXX POST ... 200 OK'.
- Expected transient warnings (e.g., temporary network issues that recover).
- Non-critical warnings (e.g., deprecation warnings, minor config mismatches if app runs).
- Verbose DEBUG output unless it clearly shows a critical failure loop or error.
- Successful health checks or HTTP 2xx status codes.

RESPONSE FORMAT:
1. If ONLY ignored message types are present, respond ONLY with the single word 'NORMAL'. Do not explain. Do not add any other text.
2. If critical abnormalities ARE found:
   a. Respond ONLY with a line starting EXACTLY with "ERROR: " followed by a VERY SHORT (1 sentence max) description of the specific critical issue identified.
   b. After the "ERROR: " line, on a NEW line, quote the MOST RELEVANT log line(s) (max 3-4 lines) supporting the finding, prefixed exactly with 'Relevant Log(s):'.
   c. Do NOT include introductory phrases like "Here is the analysis", "Based on the logs", etc.

--- LOGS ---
{logs}
--- END LOGS ---

Analysis Result:""",
    "color_healthy": "#28a745",
    "color_unhealthy": "#dc3545",
    "color_error": "#fd7e14",          # Default general error color
    "color_error_fetching_logs": "#e67e22", # More specific error colors...
    "color_error_analysis": "#e74c3c",
    "color_error_db_log": "#8e44ad",
    "color_error_db_lookup": "#95a5a6",
    "color_pending": "#ffc107",
    "color_awaiting_scan": "#6f42c1",
    "color_ignored": "#17a2b8",
    "color_resolved": "#007bff",
    "ignored_containers": "[]", # Store as JSON list string
    "scan_interval_minutes": str(os.environ.get("SCAN_INTERVAL_MINUTES", "180")),
    "summary_interval_hours": str(os.environ.get("SUMMARY_INTERVAL_HOURS", "12")),
    "log_lines_to_fetch": str(os.environ.get("LOG_LINES_TO_FETCH", "100")),
    "api_key": "" # API Key Setting (default empty = disabled)
}

# --- Helper Functions ---
def _parse_iso_datetime(iso_string):
    """Helper function to safely parse ISO datetime strings."""
    if not iso_string: return None
    try:
        # Handle various ISO formats, ensuring timezone info is considered or added if missing
        # Attempt direct parsing first
        if 'Z' in iso_string:
             dt = datetime.datetime.fromisoformat(iso_string.replace('Z', '+00:00'))
        elif '+' in iso_string or '-' in iso_string[10:]: # Check for timezone offset
             dt = datetime.datetime.fromisoformat(iso_string)
        else:
             # Assume UTC if no timezone info
             dt = datetime.datetime.fromisoformat(iso_string).replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc) # Ensure it's always UTC
    except (ValueError, TypeError) as e:
        logging.warning(f"Could not parse ISO timestamp '{iso_string}': {e}. Returning as string.")
        # Fallback or return original string? Returning original might be safer for display
        return iso_string

def get_db():
    """Connects to the specific database, ensuring parent directory exists."""
    # Ensure the directory exists just before connecting
    # This helps if the bind mount wasn't created beforehand
    try:
        os.makedirs(DATABASE_DIR, exist_ok=True)
    except OSError as e:
        # Log an error if directory creation fails, but proceed anyway
        # SQLite might still work if path is valid relative to current dir
        logging.error(f"Could not create database directory {DATABASE_DIR}: {e}")

    conn = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row
    return conn

def _row_to_dict_with_parsed_dates(row):
    """Converts a sqlite3.Row to a dict and parses stored ISO date strings."""
    if not row: return None
    item = dict(row)
    # Use the updated _parse_iso_datetime helper
    item['first_detected_timestamp'] = _parse_iso_datetime(item.get('first_detected_timestamp'))
    item['last_detected_timestamp'] = _parse_iso_datetime(item.get('last_detected_timestamp'))
    # Add parsing for summary_history timestamp if key exists
    item['timestamp'] = _parse_iso_datetime(item.get('timestamp'))
    return item

# --- Database Initialization (with extra logging) ---
def init_db():
    """Initializes the database schema if it doesn't exist. With extra logging."""
    conn = None
    logging.info("Attempting database initialization...")
    try:
        # Ensure the directory exists before trying to connect/create the file
        os.makedirs(DATABASE_DIR, exist_ok=True)
        logging.info(f"Ensured directory {DATABASE_DIR} exists.")
    except OSError as e:
        logging.error(f"Failed to ensure database directory {DATABASE_DIR} exists: {e}")
        # Decide if we should exit or proceed cautiously
        # For now, proceed, SQLite might handle relative paths okay or fail later

    try:
        conn = get_db()
        cursor = conn.cursor()
        logging.info(f"Connected to DB for init ({DATABASE}).")

        # Abnormalities Table
        logging.info("Executing CREATE TABLE IF NOT EXISTS abnormalities...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS abnormalities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                container_name TEXT NOT NULL,
                container_id TEXT NOT NULL,
                log_snippet TEXT NOT NULL,
                ollama_analysis TEXT,
                first_detected_timestamp TEXT, /* Store as ISO 8601 String */
                last_detected_timestamp TEXT, /* Store as ISO 8601 String */
                status TEXT DEFAULT 'unresolved', /* unresolved, resolved, ignored */
                resolution_notes TEXT,
                UNIQUE(container_id, log_snippet)
            )
        ''')
        logging.info("Executing CREATE INDEX for abnormalities...")
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_abnormalities_container_status ON abnormalities (container_id, status);')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_abnormalities_last_detected ON abnormalities (last_detected_timestamp);')

        # Settings Table
        logging.info("Executing CREATE TABLE IF NOT EXISTS settings...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')

        # --- START: Add Summary History Table ---
        logging.info("Executing CREATE TABLE IF NOT EXISTS summary_history...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS summary_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,      -- ISO 8601 timestamp when generated
                summary_text TEXT,            -- The AI-generated summary (can be NULL if error)
                error_text TEXT,              -- Error message if generation failed (can be NULL if success)
                status TEXT NOT NULL          -- 'success', 'error', 'skipped'
                -- notes TEXT                -- Optional: Add later for user notes
            )
        ''')
        logging.info("Executing CREATE INDEX for summary_history...")
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_summary_history_timestamp ON summary_history (timestamp DESC);')
        # --- END: Add Summary History Table ---

        logging.info("Finished CREATE TABLE statements.")

        conn.commit() # Commit schema changes first
        logging.info(f"Database schema initialization committed successfully.")

        # Populate default settings if table is empty
        logging.info("Checking if settings table needs population...")
        cursor.execute("SELECT COUNT(*) FROM settings")
        count = cursor.fetchone()[0]
        logging.info(f"Settings table count: {count}")
        if count == 0:
            logging.info("Settings table is empty, populating with defaults...")
            try:
                default_data = [(k, v) for k, v in DEFAULT_SETTINGS.items()]
                cursor.executemany("INSERT INTO settings (key, value) VALUES (?, ?)", default_data)
                conn.commit() # Commit defaults insertion
                logging.info(f"Inserted {len(default_data)} default settings.")
            except sqlite3.Error as e_insert:
                logging.error(f"Failed to insert default settings: {e_insert}")
                conn.rollback() # Rollback only the insert if it fails
        else:
             logging.info("Settings table already populated.")
             # Check for missing default keys and add them if necessary
             cursor.execute("SELECT key FROM settings")
             existing_keys = {row['key'] for row in cursor.fetchall()}
             missing_keys = DEFAULT_SETTINGS.keys() - existing_keys
             if missing_keys:
                 logging.info(f"Found missing default setting keys: {', '.join(missing_keys)}. Adding them...")
                 try:
                     missing_data = [(k, DEFAULT_SETTINGS[k]) for k in missing_keys]
                     cursor.executemany("INSERT INTO settings (key, value) VALUES (?, ?)", missing_data)
                     conn.commit()
                     logging.info(f"Inserted {len(missing_data)} missing default settings.")
                 except sqlite3.Error as e_insert_missing:
                     logging.error(f"Failed to insert missing default settings: {e_insert_missing}")
                     conn.rollback()


    except sqlite3.Error as e:
        logging.error(f"Database initialization SQLite error: {e}", exc_info=True) # Log full traceback for DB errors
        if conn: conn.rollback()
    except OSError as e: # Catch potential OS errors like permission denied if directory failed earlier
         logging.error(f"Database initialization OS error (check permissions for {DATABASE_DIR}?): {e}", exc_info=True)
         if conn: conn.rollback()
    except Exception as e_generic:
         logging.error(f"Generic error during database initialization: {e_generic}", exc_info=True)
         if conn: conn.rollback()
    finally:
        if conn:
            logging.info("Closing DB connection after init.")
            conn.close()


# --- Settings Functions (with added logging) ---
def get_setting(key, default=None):
    """Retrieves a setting value by key."""
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
        result = cursor.fetchone(); value = result['value'] if result else None
        # If value not found in DB, try the hardcoded defaults, then the function default
        final_value = value if value is not None else DEFAULT_SETTINGS.get(key, default)
        logging.debug(f"Retrieved setting '{key}': {'(Using Default)' if value is None else ''}{str(final_value)[:50]}{'...' if final_value and len(str(final_value))>50 else ''}")
        return final_value
    except sqlite3.Error as e:
        logging.error(f"Error fetching setting '{key}': {e}")
        # Fallback to defaults on error
        return DEFAULT_SETTINGS.get(key, default)
    finally:
        if conn: conn.close()

def set_setting(key, value):
    """Inserts or updates a setting value. Includes logging."""
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
        conn.commit()
        if cursor.rowcount > 0:
             logging.info(f"Setting '{key}' saved/updated successfully in DB ({cursor.rowcount} row(s) affected).")
        else:
             logging.info(f"Setting '{key}' processed in DB (value likely unchanged, 0 rows affected).")
        return True
    except sqlite3.Error as e:
        logging.error(f"Error saving setting '{key}' to DB: {e}")
        conn.rollback()
        return False
    finally:
        if conn: conn.close()

def get_all_settings():
    """Retrieves all settings as a dictionary."""
    conn = get_db()
    cursor = conn.cursor()
    settings_dict = DEFAULT_SETTINGS.copy() # Start with defaults
    try:
        cursor.execute("SELECT key, value FROM settings")
        rows = cursor.fetchall()
        fetched_count = 0
        for row in rows:
            settings_dict[row['key']] = row['value'] # Override with DB values
            fetched_count += 1
        logging.info(f"Fetched {fetched_count} settings from DB, merged with defaults.")
        return settings_dict
    except sqlite3.Error as e:
        logging.error(f"Error fetching all settings: {e}")
        return settings_dict # Return defaults on error
    finally:
        if conn: conn.close()

# --- Abnormality Functions ---

def add_or_update_abnormality(container_name, container_id, log_snippet, ollama_analysis):
    """Adds a new abnormality or updates the last_detected timestamp if an unresolved one exists. Returns the ID of the record."""
    conn = get_db()
    cursor = conn.cursor()
    record_id = None # <<< Initialize ID variable
    try:
        # Check if an 'unresolved' record with the same snippet already exists
        cursor.execute("""
            SELECT id, last_detected_timestamp FROM abnormalities
            WHERE container_id = ? AND log_snippet = ? AND status = 'unresolved'
            ORDER BY last_detected_timestamp DESC LIMIT 1
        """, (container_id, log_snippet))
        existing = cursor.fetchone()

        # Use timezone-aware datetime
        now = datetime.datetime.now(timezone.utc)
        now_iso = now.isoformat() # Store as ISO string

        if existing:
            # Update last_detected_timestamp and potentially analysis for the existing unresolved record
            record_id = existing['id'] # <<< Get the ID of the existing record
            # Always update timestamp and analysis
            cursor.execute("""
                UPDATE abnormalities
                SET last_detected_timestamp = ?, ollama_analysis = ?
                WHERE id = ?
            """, (now_iso, ollama_analysis, record_id))
            conn.commit()
            logging.info(f"Existing 'unresolved' abnormality updated for {container_name[:12]} (ID: {record_id})")
        else:
            # Insert a new 'unresolved' record
            cursor.execute("""
                INSERT INTO abnormalities
                (container_id, container_name, log_snippet, ollama_analysis, status, first_detected_timestamp, last_detected_timestamp)
                VALUES (?, ?, ?, ?, 'unresolved', ?, ?)
            """, (container_id, container_name, log_snippet, ollama_analysis, now_iso, now_iso))
            record_id = cursor.lastrowid # <<< Get the ID of the newly inserted record
            conn.commit()
            # Use the newly obtained ID in the log message
            logging.info(f"New abnormality logged for {container_name[:12]} ID {record_id}")

    except sqlite3.Error as e:
        logging.error(f"DB Error adding/updating abnormality for {container_id[:12]}: {e}")
        conn.rollback() # Rollback on error
        record_id = None # Ensure ID is None on error
    except Exception as e:
         logging.exception(f"Unexpected error in add_or_update_abnormality for {container_id[:12]}:")
         conn.rollback()
         record_id = None
    finally:
        if conn:
            conn.close()

    return record_id # <<< RETURN THE ID (or None if error)


def get_abnormality_status(container_id, log_snippet):
    """Retrieves the status of the latest abnormality matching container_id and snippet."""
    conn = get_db(); cursor = conn.cursor(); status = None
    try:
        cursor.execute("""
            SELECT status FROM abnormalities
            WHERE container_id = ? AND log_snippet = ?
            ORDER BY last_detected_timestamp DESC LIMIT 1
        """, (container_id, log_snippet))
        result = cursor.fetchone(); status = result['status'] if result else None
    except sqlite3.Error as e: logging.error(f"DB Error checking status for {container_id[:12]}: {e}")
    finally: conn.close()
    return status

def get_latest_unresolved_abnormality_id(container_id, log_snippet=None):
    """Gets the ID of the latest 'unresolved' abnormality for a container, optionally matching a snippet."""
    conn = get_db(); cursor = conn.cursor(); db_id = None
    try:
        if log_snippet:
             cursor.execute("""
                SELECT id FROM abnormalities
                WHERE container_id = ? AND log_snippet = ? AND status = 'unresolved'
                ORDER BY last_detected_timestamp DESC LIMIT 1
            """, (container_id, log_snippet))
             result = cursor.fetchone(); db_id = result['id'] if result else None
        # If no specific snippet match, find the latest unresolved for the container
        if not db_id:
            cursor.execute("""
                SELECT id FROM abnormalities
                WHERE container_id = ? AND status = 'unresolved'
                ORDER BY last_detected_timestamp DESC LIMIT 1
            """, (container_id,))
            result = cursor.fetchone(); db_id = result['id'] if result else None
    except sqlite3.Error as e: logging.error(f"Error fetching latest unresolved ID for {container_id[:12]}: {e}"); return None
    finally: conn.close()
    return db_id

def get_abnormality_by_id(abnormality_id):
    """Fetches a single abnormality by its primary key ID."""
    conn = get_db(); cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM abnormalities WHERE id = ?", (abnormality_id,));
        row = cursor.fetchone();
        return _row_to_dict_with_parsed_dates(row)
    except sqlite3.Error as e: logging.error(f"Error fetching abnormality by ID {abnormality_id}: {e}"); return None
    finally: conn.close()

def update_abnormality_status(abnormality_id, status, notes=None):
    """Updates the status and optionally notes for a specific abnormality ID."""
    conn = get_db(); cursor = conn.cursor()
    if status not in ['unresolved', 'resolved', 'ignored']:
        logging.warning(f"Invalid status '{status}' provided for update_abnormality_status.")
        return False
    try:
        if notes is not None:
            cursor.execute("UPDATE abnormalities SET status = ?, resolution_notes = ? WHERE id = ?", (status, notes, abnormality_id))
        else:
            cursor.execute("UPDATE abnormalities SET status = ? WHERE id = ?", (status, abnormality_id))
        conn.commit(); success = cursor.rowcount > 0
        if success: logging.info(f"Updated status for abnormality ID {abnormality_id} to '{status}'")
        else: logging.warning(f"No abnormality found with ID {abnormality_id} to update status.")
        return success
    except sqlite3.Error as e:
        logging.error(f"Error updating status for ID {abnormality_id}: {e}");
        conn.rollback();
        return False
    finally:
        conn.close()

def get_recent_abnormalities(hours=24):
    """Fetches abnormalities detected or updated within the last N hours."""
    conn = get_db(); cursor = conn.cursor(); results = []
    try:
        cutoff_time = datetime.datetime.now(timezone.utc) - datetime.timedelta(hours=hours)
        cutoff_iso = cutoff_time.isoformat()
        cursor.execute("SELECT * FROM abnormalities WHERE last_detected_timestamp >= ? ORDER BY last_detected_timestamp DESC", (cutoff_iso,))
        rows = cursor.fetchall()
        for row in rows: results.append(_row_to_dict_with_parsed_dates(row))
        logging.debug(f"Fetched {len(results)} abnormalities from last {hours} hours.")
    except sqlite3.Error as e: logging.error(f"Error fetching recent abnormalities: {e}")
    finally: conn.close()
    return results

def get_abnormalities_by_container(container_id, limit=50):
    """Fetches abnormalities for a specific container_id, most recent first."""
    conn = get_db(); cursor = conn.cursor(); results = []
    try:
        cursor.execute("SELECT * FROM abnormalities WHERE container_id = ? ORDER BY last_detected_timestamp DESC LIMIT ?", (container_id, limit))
        rows = cursor.fetchall()
        for row in rows: results.append(_row_to_dict_with_parsed_dates(row))
        logging.debug(f"Fetched {len(results)} abnormalities for container {container_id[:12]} (limit {limit}).")
    except sqlite3.Error as e: logging.error(f"Error fetching abnormalities for container {container_id[:12]}: {e}")
    finally: conn.close()
    return results

def get_abnormalities_by_status(status='unresolved', limit=100):
    """Fetches abnormalities by status ('unresolved', 'resolved', 'ignored', 'all'), most recent first."""
    if status not in ['unresolved', 'resolved', 'ignored', 'all']: status = 'unresolved'
    conn = get_db(); cursor = conn.cursor(); results = []
    try:
        if status == 'all':
            cursor.execute("SELECT * FROM abnormalities ORDER BY last_detected_timestamp DESC LIMIT ?", (limit,))
        else:
            cursor.execute("SELECT * FROM abnormalities WHERE status = ? ORDER BY last_detected_timestamp DESC LIMIT ?", (status, limit))
        rows = cursor.fetchall()
        for row in rows:
            dict_row = _row_to_dict_with_parsed_dates(row)
            if dict_row: # Convert datetimes back to strings for JSON safety
                 if isinstance(dict_row.get('first_detected_timestamp'), datetime.datetime):
                     dict_row['first_detected_timestamp'] = dict_row['first_detected_timestamp'].isoformat() + "Z" # Add Z for UTC indication
                 if isinstance(dict_row.get('last_detected_timestamp'), datetime.datetime):
                     dict_row['last_detected_timestamp'] = dict_row['last_detected_timestamp'].isoformat() + "Z"
                 results.append(dict_row)
        logging.debug(f"Fetched {len(results)} abnormalities with status '{status}' (limit {limit}).")
    except sqlite3.Error as e: logging.error(f"Error fetching abnormalities by status {status}: {e}")
    finally: conn.close()
    return results

def get_last_known_status(container_id):
    """
    Checks the database for the most recent record of a container_id
    and returns its status and abnormality ID.
    Returns ('no_history', None) if no record found.
    Returns ('db_error', None) on database error.
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, status FROM abnormalities
            WHERE container_id = ?
            ORDER BY last_detected_timestamp DESC
            LIMIT 1
        """, (container_id,))
        result = cursor.fetchone()
        if result:
            abnormality_id, status = result['id'], result['status']
            # Always return the ID, regardless of status, for potential linking
            return status, abnormality_id # e.g., ('unresolved', 123), ('resolved', 124)
        else:
            return 'no_history', None
    except sqlite3.Error as e:
        logging.error(f"Database error in get_last_known_status for {container_id[:12]}: {e}")
        return 'db_error', None
    finally:
        if conn:
            conn.close()

# --- START: New Summary History Functions ---

def add_summary_history(timestamp, summary_text=None, error_text=None):
    """Adds a record to the AI summary history table."""
    conn = get_db()
    cursor = conn.cursor()
    record_id = None
    status = 'unknown'

    # Determine status based on inputs
    if error_text:
        status = 'error'
        summary_text = None # Ensure summary is null if there's an error
    elif summary_text and "Skipped" in summary_text: # Check if summary indicates skipped
        status = 'skipped'
        error_text = summary_text # Store the reason for skipping if available
        summary_text = None # Ensure summary is null if skipped
    elif summary_text:
        status = 'success'
        error_text = None # Ensure error is null if success
    else:
        # Should not happen if called correctly, but handle it
        status = 'error'
        error_text = "Internal error: Neither summary nor error text provided."
        summary_text = None

    try:
        # Use timezone-aware datetime object for timestamp
        if not isinstance(timestamp, datetime.datetime):
            # Attempt to parse if a string was passed, default to now if fails
            parsed_ts = _parse_iso_datetime(str(timestamp))
            timestamp_obj = parsed_ts if parsed_ts else datetime.datetime.now(timezone.utc)
        else:
            timestamp_obj = timestamp.astimezone(timezone.utc) # Ensure UTC

        timestamp_iso = timestamp_obj.isoformat() # Convert to ISO string for storage

        cursor.execute("""
            INSERT INTO summary_history
            (timestamp, summary_text, error_text, status)
            VALUES (?, ?, ?, ?)
        """, (timestamp_iso, summary_text, error_text, status))
        record_id = cursor.lastrowid
        conn.commit()
        logging.info(f"Added summary history record ID {record_id} with status '{status}'.")

    except sqlite3.Error as e:
        logging.error(f"DB Error adding summary history: {e}")
        conn.rollback()
        record_id = None
    except Exception as e:
        logging.exception("Unexpected error adding summary history:")
        conn.rollback()
        record_id = None
    finally:
        if conn:
            conn.close()
    return record_id


def get_summary_history(limit=50):
    """Fetches the most recent AI summary history records."""
    conn = get_db()
    cursor = conn.cursor()
    results = []
    try:
        cursor.execute("""
            SELECT id, timestamp, summary_text, error_text, status
            FROM summary_history
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        for row in rows:
            # Use the helper that also parses the 'timestamp' field
            parsed_row = _row_to_dict_with_parsed_dates(row)
            if parsed_row:
                 results.append(parsed_row)
        logging.debug(f"Fetched {len(results)} summary history records (limit {limit}).")
    except sqlite3.Error as e:
        logging.error(f"Error fetching summary history: {e}")
    except Exception as e:
        logging.exception("Unexpected error fetching summary history:")
    finally:
        if conn:
            conn.close()
    return results

# --- END: New Summary History Functions ---


# Initialize the database when this module is first imported
# This function is now more robust with logging
# init_db() # Call moved to app.py startup to ensure logging is fully configured first
