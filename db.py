# db.py
import sqlite3
import datetime
import logging
import os

DATABASE_DIR = '/app/data' # Suggest putting DB in a sub-directory if using bind mount for /app
DATABASE = os.path.join(DATABASE_DIR, 'monitoring_data.db')

# Ensure the data directory exists
os.makedirs(DATABASE_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_db():
    """Connects to the specific database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row # Return rows as dictionary-like objects
    return conn

def init_db():
    """Initializes the database schema if it doesn't exist."""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS abnormalities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                container_name TEXT NOT NULL,
                container_id TEXT NOT NULL,
                log_snippet TEXT NOT NULL,
                ollama_analysis TEXT,
                first_detected_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_detected_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'unresolved', -- 'unresolved', 'resolved', 'ignored'
                resolution_notes TEXT,
                UNIQUE(container_id, log_snippet) -- Basic duplicate prevention based on exact snippet match
            )
        ''')
        # Optional: Add index for faster lookups if needed later
        # cursor.execute('''
        #     CREATE INDEX IF NOT EXISTS idx_abnormalities_container_status
        #     ON abnormalities (container_id, status);
        # ''')
        conn.commit()
        logging.info(f"Database initialized successfully at {DATABASE}")
    except sqlite3.Error as e:
        logging.error(f"Database initialization error: {e}")
    finally:
        if conn:
            conn.close()

def add_or_update_abnormality(container_name, container_id, log_snippet, ollama_analysis):
    """
    Adds a new abnormality record if it doesn't exist (based on container_id and log_snippet).
    If it exists and is 'unresolved', updates the last_detected_timestamp and analysis.
    """
    conn = get_db()
    cursor = conn.cursor()
    # Use ISO format for consistent datetime storage as strings
    now_iso = datetime.datetime.now().isoformat()
    try:
        # Attempt to insert. If UNIQUE constraint fails, it means this specific issue exists.
        cursor.execute('''
            INSERT OR IGNORE INTO abnormalities
            (container_name, container_id, log_snippet, ollama_analysis, first_detected_timestamp, last_detected_timestamp, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (container_name, container_id, log_snippet, ollama_analysis, now_iso, now_iso, 'unresolved'))

        rows_inserted = cursor.rowcount

        # If the insert was ignored (rowcount is 0), it means the record exists.
        # Update the last_detected_timestamp and analysis only if it's currently 'unresolved'.
        if rows_inserted == 0:
             cursor.execute('''
                UPDATE abnormalities
                SET last_detected_timestamp = ?, ollama_analysis = ?
                WHERE container_id = ? AND log_snippet = ? AND status = 'unresolved'
            ''', (now_iso, ollama_analysis, container_id, log_snippet))

        conn.commit()
        if rows_inserted > 0:
            logging.info(f"New abnormality logged for container {container_name} ({container_id[:12]})")
        else:
            logging.info(f"Existing abnormality updated for container {container_name} ({container_id[:12]})")

    except sqlite3.Error as e:
        logging.error(f"Error adding/updating abnormality: {e}")
    finally:
        if conn:
            conn.close()

def get_latest_unresolved_abnormality_id(container_id, log_snippet=None):
    """
    Finds the ID of the most recent 'unresolved' abnormality for a container.
    Tries to match the log snippet for specificity if provided.
    """
    conn = get_db()
    cursor = conn.cursor()
    try:
        # Prioritize matching snippet if provided for accuracy
        if log_snippet:
             cursor.execute("""
                SELECT id FROM abnormalities
                WHERE container_id = ? AND log_snippet = ? AND status = 'unresolved'
                ORDER BY last_detected_timestamp DESC
                LIMIT 1
             """, (container_id, log_snippet))
             result = cursor.fetchone()
             if result:
                 return result['id']
        # Fallback: If no snippet provided or no exact match found, get the latest unresolved for the container
        # This handles cases where the snippet might slightly change but the container is still flagged
        cursor.execute("""
            SELECT id FROM abnormalities
            WHERE container_id = ? AND status = 'unresolved'
            ORDER BY last_detected_timestamp DESC
            LIMIT 1
        """, (container_id,))
        result = cursor.fetchone()
        return result['id'] if result else None
    except sqlite3.Error as e:
        logging.error(f"Error fetching latest unresolved abnormality ID for {container_id[:12]}: {e}")
        return None
    finally:
        conn.close()

def get_abnormality_by_id(abnormality_id):
    """Fetches a single abnormality record by its primary key ID."""
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM abnormalities WHERE id = ?", (abnormality_id,))
        abnormality = cursor.fetchone()
        # Convert Row to dict and parse datetime string back to object
        if abnormality:
            item = dict(abnormality)
            try:
                # Parse ISO format string back to datetime object
                item['first_detected_timestamp'] = datetime.datetime.fromisoformat(item['first_detected_timestamp'])
                item['last_detected_timestamp'] = datetime.datetime.fromisoformat(item['last_detected_timestamp'])
            except (ValueError, TypeError, KeyError) as dt_error: # Handle potential parsing or missing key errors
                 logging.warning(f"Could not parse timestamp for abnormality ID {item.get('id')}: {dt_error}")
                 # Assign epoch/None if parsing fails to avoid breaking the template
                 item['first_detected_timestamp'] = None # Or datetime.datetime.fromtimestamp(0)
                 item['last_detected_timestamp'] = None # Or datetime.datetime.fromtimestamp(0)
            return item
        else:
            return None
    except sqlite3.Error as e:
        logging.error(f"Error fetching abnormality by ID {abnormality_id}: {e}")
        return None
    finally:
        conn.close()

def get_abnormalities(status_filter='unresolved'):
    """
    Fetches all abnormalities, optionally filtered by status.
    This is less used by the dashboard view but can be useful for other purposes.
    """
    conn = get_db()
    cursor = conn.cursor()
    results = []
    try:
        if status_filter == 'all':
             cursor.execute("SELECT * FROM abnormalities ORDER BY last_detected_timestamp DESC")
        else:
            cursor.execute("SELECT * FROM abnormalities WHERE status = ? ORDER BY last_detected_timestamp DESC", (status_filter,))
        abnormalities_raw = cursor.fetchall()

        # Convert Row objects to dictionaries and parse datetime
        for row in abnormalities_raw:
            item = dict(row)
            try:
                 item['first_detected_timestamp'] = datetime.datetime.fromisoformat(item['first_detected_timestamp'])
                 item['last_detected_timestamp'] = datetime.datetime.fromisoformat(item['last_detected_timestamp'])
            except (ValueError, TypeError, KeyError) as dt_error:
                 logging.warning(f"Could not parse timestamp for abnormality ID {item.get('id')} in list view: {dt_error}")
                 item['first_detected_timestamp'] = None
                 item['last_detected_timestamp'] = None
            results.append(item)
        return results
    except sqlite3.Error as e:
        logging.error(f"Error fetching abnormalities list: {e}")
        return []
    finally:
        conn.close()


def update_abnormality_status(abnormality_id, status, notes=None):
    """Updates the status and optionally the notes for a given abnormality ID."""
    conn = get_db()
    cursor = conn.cursor()
    if status not in ['unresolved', 'resolved', 'ignored']:
        logging.error(f"Invalid status '{status}' provided for update.")
        return False

    try:
        if notes is not None: # Allow empty string for notes, but handle None separately
            cursor.execute("UPDATE abnormalities SET status = ?, resolution_notes = ? WHERE id = ?", (status, notes, abnormality_id))
        else:
             # If notes are None, only update the status (don't overwrite existing notes)
             cursor.execute("UPDATE abnormalities SET status = ? WHERE id = ?", (status, abnormality_id))
        conn.commit()

        if cursor.rowcount == 0:
             logging.warning(f"No abnormality found with ID {abnormality_id} to update status.")
             return False
        else:
             logging.info(f"Updated status for abnormality ID {abnormality_id} to {status}")
             return True
    except sqlite3.Error as e:
        logging.error(f"Error updating abnormality status for ID {abnormality_id}: {e}")
        return False
    finally:
        conn.close()

# Initialize the database when this module is first imported
# Ensures the table exists before any other operations try to use it.
init_db()
