# app.py
import os
import logging
from datetime import datetime, timedelta, timezone
import threading
from threading import Lock
import json
# Removed secrets and functools as they were for the removed decorator
# <<< Import current_app >>>
from flask import Flask, render_template, redirect, url_for, flash, current_app
# <<< Import nl2br supporting functions >>>
from markupsafe import Markup, escape # Used by Flask internally, nl2br needs Markup potentially
# We will add nl2br manually below

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.jobstores.base import JobLookupError
import pytz
import docker
# --- Import Blueprints ---
from routes.ui_routes import ui_bp
from routes.api_routes import api_bp # <<< ADD THIS IMPORT
from utils import get_display_timezone
from routes.scheduler_routes import scheduler_bp

# --- Logging Setup ---
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format='%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s'
)

# --- Local Imports ---
try: import db; import analyzer
except ImportError as e: logging.critical(f"Import Error: {e}"); exit(1)

# --- Configuration ---

# --- Flask App Initialization ---
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change_this_in_production_please")
if app.secret_key == "change_this_in_production_please": logging.warning("FLASK_SECRET_KEY is default.")

# --- START: Manually add nl2br filter ---
# Jinja2/MarkupSafe's nl2br converts newlines to <br> and escapes HTML unless wrapped in Markup
def nl2br_filter(s):
    if s:
        # Escape the input string first to prevent XSS
        s_escaped = escape(s)
        # Replace newlines with <br> and mark the whole thing as safe HTML
        return Markup(s_escaped.replace('\n', '<br>\n'))
    return ''

app.jinja_env.filters['nl2br'] = nl2br_filter
logging.info("Added nl2br filter to Jinja environment.")
# --- END: Manually add nl2br filter ---


# --- Register Blueprints ---
app.register_blueprint(ui_bp)
logging.info("Registered UI Blueprint")
app.register_blueprint(api_bp) # <<< REGISTER THE API BLUEPRINT
logging.info("Registered API Blueprint")
app.register_blueprint(scheduler_bp) # <<< REGISTER THE SCHEDULER BLUEPRINT
logging.info("Registered Scheduler Blueprint")

# --- Global State Variables ---
container_statuses = {}; container_statuses_lock = Lock()
scan_status = {"last_run_time": None, "last_run_status": "Not run yet", "next_run_time": None, "running": False}
available_ollama_models = []; models_lock = Lock()
ai_health_summary = {"summary": "Summary generation pending...", "last_updated": None, "error": None}; ai_summary_lock = Lock()
app_settings = {}; settings_lock = Lock() # Populated by load_settings
stop_scan_event = threading.Event()
scheduler = BackgroundScheduler(daemon=True)

def fetch_initial_ollama_models():
    """Fetches the list of models from Ollama at startup."""
    logging.info("Fetching initial Ollama model list...")
    try:
        # Ensure analyzer URL is set from initial settings load if needed
        # Might need to load settings *before* this if URL isn't default
        # analyzer.OLLAMA_API_URL = app_settings.get('ollama_api_url') # If run after load_settings

        fetched_models = analyzer.get_ollama_models() # Call the function
        if fetched_models is not None: # Check if fetch was successful
            with models_lock: # Use the global lock
                global available_ollama_models # Declare modification of global
                available_ollama_models[:] = fetched_models # Update the list content
            logging.info(f"Successfully fetched {len(fetched_models)} models at startup.")
        else:
             logging.warning("Fetching initial models returned None. Check Ollama connection/logs.")

    except Exception as e:
        logging.exception("Error fetching initial Ollama models:")
        # Keep available_ollama_models empty or with its current state

# --- Settings Loader ---
def load_settings():
    global app_settings
    logging.info("Loading application settings from database...")
    with settings_lock:
        app_settings = db.get_all_settings()
        # Convert types and parse JSON lists
        try: app_settings['scan_interval_minutes'] = int(app_settings.get('scan_interval_minutes', 180))
        except: app_settings['scan_interval_minutes'] = 180
        try: app_settings['summary_interval_hours'] = int(app_settings.get('summary_interval_hours', 12))
        except: app_settings['summary_interval_hours'] = 12
        try:
            # Ensure ignored_containers exists before loading, default to '[]' string
            ignored_json = app_settings.get('ignored_containers', '[]')
            app_settings['ignored_containers_list'] = json.loads(ignored_json)
            if not isinstance(app_settings['ignored_containers_list'], list):
                logging.warning(f"Invalid format for 'ignored_containers' in DB: {ignored_json}. Resetting to [].")
                app_settings['ignored_containers_list'] = []
                # Optionally, update the DB setting here if desired
                # db.set_setting('ignored_containers', '[]')
        except json.JSONDecodeError:
            logging.error(f"Failed to parse 'ignored_containers' JSON: {app_settings.get('ignored_containers')}. Resetting to [].")
            app_settings['ignored_containers_list'] = []
            # Optionally, update the DB setting here if desired
            # db.set_setting('ignored_containers', '[]')
        except Exception as e:
            logging.error(f"Error processing ignored_containers setting: {e}. Defaulting to [].")
            app_settings['ignored_containers_list'] = []

        # Update analyzer config directly
        #analyzer.OLLAMA_API_URL = app_settings.get('ollama_api_url')
        #analyzer.LOG_LINES_TO_FETCH = app_settings.get('log_lines_to_fetch')
        #analyzer.DEFAULT_OLLAMA_MODEL = app_settings.get('ollama_model')
        #logging.info(f"Settings loaded. API Key configured: {'Yes' if app_settings.get('api_key') else 'No'}")


# --- REMOVE API Key Authentication Decorator ---
# def require_api_key(f): # <<< THIS FUNCTION IS REMOVED
#    ...


# --- Background Tasks ---

def populate_initial_statuses():
    """
    Connects to Docker, lists running containers, checks their last known
    status from the DB, and populates the initial container_statuses dict.
    Runs once at startup.
    """
    logging.info("Populating initial container statuses...")
    initial_statuses = {}
    client = None

    try:
        # Need ignored list from settings - ensure settings are loaded first
        with settings_lock:
            # Make sure list exists, default to empty list if not loaded yet or invalid
            ignored_list = app_settings.get('ignored_containers_list', [])
            if not isinstance(ignored_list, list):
                 logging.warning("ignored_containers_list was not a list during initial population, using [].")
                 ignored_list = []


        client = analyzer.get_docker_client()
        if not client:
            logging.error("Initial population failed: Cannot connect to Docker.")
            # Optionally set a global error flag here if needed for UI
            return # Exit if no Docker connection

        running_containers = client.containers.list()
        logging.info(f"Found {len(running_containers)} running containers for initial population.")

        for container in running_containers:
            container_id = container.id
            container_name = container.name

            if container_name in ignored_list:
                logging.debug(f"Skipping ignored container {container_name} during initial population.")
                continue

            # Check DB for last known status (Assuming db.get_last_known_status exists)
            last_status, db_id = 'pending', None # Default before DB lookup
            try:
                # Check if the function exists before calling
                if hasattr(db, 'get_last_known_status'):
                    # <<< MODIFIED: Expect tuple return (status, db_id) >>>
                    result_tuple = db.get_last_known_status(container_id)
                    if isinstance(result_tuple, tuple) and len(result_tuple) == 2:
                        last_status, db_id = result_tuple
                    else:
                        logging.error(f"Unexpected return type/length from db.get_last_known_status for {container_name[:12]}: {result_tuple}. Expected (status, db_id).")
                        last_status, db_id = 'db_error', None
                else:
                    logging.error("CRITICAL: db.py does not have the required 'get_last_known_status' function. Cannot perform initial status population.")
                    last_status, db_id = 'error_db_lookup', None # Mark as error if function missing
            except ValueError as unpack_err:
                 # Handle the specific "too many values to unpack" error or similar issues if the signature changes unexpectedly
                 logging.error(f"Error unpacking DB status return for {container_name[:12]}: {unpack_err}. Check db.get_last_known_status return signature.")
                 last_status = 'db_error' # Use status directly
                 db_id = None
            except Exception as db_lookup_err:
                logging.error(f"Error calling db.get_last_known_status for {container_name[:12]}: {db_lookup_err}")
                last_status, db_id = 'db_error', None


            current_app_status = 'pending' # Default, will be updated based on DB lookup

            if last_status == 'unresolved':
                current_app_status = 'unhealthy'
                logging.info(f"Initial status for {container_name[:12]}: Unhealthy (based on DB ID {db_id})")
                # Keep the db_id from get_last_known_status
            elif last_status in ['resolved', 'ignored']:
                current_app_status = 'awaiting_scan' # Needs scan to confirm current health
                db_id = None # Don't link to resolved/ignored issue on dashboard initially
                logging.info(f"Initial status for {container_name[:12]}: Awaiting Scan (based on DB history)")
            elif last_status == 'no_history':
                current_app_status = 'healthy' # Assume healthy if no history
                db_id = None
                logging.info(f"Initial status for {container_name[:12]}: Healthy (no DB history)")
            elif last_status == 'db_error' or last_status == 'error_db_lookup':
                current_app_status = 'error_db_lookup' # Indicate DB issue during lookup
                db_id = None
                logging.warning(f"Initial status for {container_name[:12]}: DB Error during lookup")
            else: # Fallback for 'pending' or unexpected status
                 current_app_status = 'pending'
                 db_id = None
                 logging.warning(f"Initial status for {container_name[:12]}: Pending (DB status '{last_status}')")


            initial_statuses[container_id] = {
                'name': container_name,
                'id': container_id,
                'status': current_app_status,
                'details': None, # No scan details yet
                'db_id': db_id # Store ID only if status is unhealthy (or pending resolution check)
            }

        # Update global state safely
        with container_statuses_lock:
            global container_statuses
            # Overwrite existing dict with newly populated one
            container_statuses = dict(sorted(initial_statuses.items(), key=lambda item: item[1]['name'].lower()))
            logging.info(f"Initial container_statuses populated with {len(container_statuses)} entries.")

    except docker.errors.DockerException as docker_err:
        logging.error(f"Docker error during initial population: {docker_err}")
    except Exception as e:
        logging.exception("Unhandled error during initial container status population:")
    finally:
        if client:
            try:
                client.close()
            except Exception as ce:
                logging.warning(f"Error closing Docker client after initial population: {ce}")


def scan_docker_logs():
    global container_statuses, available_ollama_models, scan_status # Added scan_status
    if scan_status["running"]: logging.warning("Scan skipped: previous active."); return
    try:
        # NOTE: If running outside Flask request context (e.g., APScheduler directly),
        # accessing `app` or `current_app` might require `app.app_context().push()`.
        # However, these background tasks currently access global variables with locks,
        # which avoids the direct need for Flask's app context here.
        # If they needed flask functions like url_for, context would be necessary.
        with settings_lock: current_settings = app_settings.copy()
        log_lines = int(current_settings.get('log_lines_to_fetch', 100))
        analysis_prompt = current_settings.get('analysis_prompt', db.DEFAULT_SETTINGS['analysis_prompt'])
        ignored_list = current_settings.get('ignored_containers_list', []); model_to_use = current_settings.get('ollama_model')
        # Validate Ollama URL before proceeding
        ollama_url = current_settings.get('ollama_api_url')
        if not ollama_url:
            logging.warning("Scan skipped: Ollama API URL is not configured in settings.")
            scan_status["last_run_status"] = f"Skipped @ {datetime.now(get_display_timezone()).strftime('%H:%M:%S %Z')}: Ollama URL missing."
            scan_status["running"] = False # Ensure not marked as running
            return
    except Exception as e:
         logging.error(f"Scan settings error: {e}"); log_lines=100; analysis_prompt=db.DEFAULT_SETTINGS['analysis_prompt']; ignored_list=[]; model_to_use=db.DEFAULT_SETTINGS['ollama_model']
         ollama_url = None # Ensure ollama_url is defined for the check below
         if not ollama_url: # Check again in case of error during loading
             logging.warning("Scan skipped due to settings error and missing Ollama URL.")
             scan_status["last_run_status"] = f"Skipped @ {datetime.now(get_display_timezone()).strftime('%H:%M:%S %Z')}: Settings Error/Ollama URL missing."
             scan_status["running"] = False
             return


    scan_status["running"] = True; stop_scan_event.clear(); logging.info("Starting Docker log scan...")
    start_time = datetime.now(); scan_status["last_run_time"] = start_time
    current_scan_results = {}; found_issues_this_scan = 0; containers_scanned_count = 0
    scan_timezone = get_display_timezone()

    try: # Fetch models (only if URL is set)
        if ollama_url:
            fetched_models = analyzer.get_ollama_models();
            with models_lock: available_ollama_models = fetched_models
        else:
             with models_lock: available_ollama_models = [] # Clear models if no URL
    except Exception as e: logging.error(f"Model fetch error: {e}")

    client = analyzer.get_docker_client()
    if not client: scan_status["last_run_status"]=f"Docker connect fail"; scan_status["running"]=False; logging.error("Docker connect fail"); return

    scan_cancelled = False
    try:
        running_containers = client.containers.list(); containers_scanned_count = len(running_containers)
        logging.info(f"Found {containers_scanned_count} containers.")
        active_container_ids = {c.id for c in running_containers}

        # Get current statuses to update, preserving initial state for containers not yet scanned
        with container_statuses_lock:
            current_global_statuses = container_statuses.copy()

        for container in running_containers:
            if stop_scan_event.is_set(): scan_cancelled = True; logging.warning("Scan cancelled by event."); break
            container_id = container.id; container_name = container.name
            if container_name in ignored_list: logging.info(f"Skipping ignored: {container_name}"); continue

            logging.debug(f"Scanning: {container_name[:12]}");
            # Initialize result from current global state if exists, else default
            current_scan_results[container_id] = current_global_statuses.get(container_id,
                {'name': container_name, 'id': container_id, 'status': 'pending', 'details': None, 'db_id': None})

            logs = analyzer.fetch_container_logs(container, num_lines=log_lines) # Pass log_lines setting
            if logs is None: current_scan_results[container_id].update({'status': 'error_fetching_logs', 'details': {'analysis': 'Failed logs', 'snippet': ''}}); continue

            # --- Analysis Block ---
            analysis_result = "NORMAL" # Default if no analysis performed
            log_snippet = "" # Initialize snippet

            if ollama_url:
                try:
                    # Assuming analyze_logs_with_ollama returns "NORMAL", "ERROR: <details>", or raises an Exception on true API failure
                    logging.debug(f"Sending logs for {container_name[:12]} to Ollama model {model_to_use}...")
                    analysis_result = analyzer.analyze_logs_with_ollama(logs, model_to_use, custom_prompt=analysis_prompt)
                    logging.info(f"Ollama analysis result for {container_name[:12]}: {analysis_result[:150]}...") # Log the result received

                    # Extract snippet regardless of result for potential logging/DB storage
                    if analysis_result != "NORMAL":
                         # Use the content after "ERROR:" as the snippet, or the whole result if prefix missing
                         potential_snippet = analysis_result[len("ERROR:"):].strip() if analysis_result.startswith("ERROR:") else analysis_result
                         log_snippet = analyzer.extract_log_snippet(potential_snippet, logs) # Refine snippet using context

                except Exception as analysis_exception:
                    logging.exception(f"Exception during Ollama analysis for {container_name[:12]}:")
                    analysis_result = f"ANALYSIS_FAILED: {analysis_exception}" # Special internal status for true failure
            else:
                logging.debug(f"Skipping Ollama analysis for {container_name[:12]} - URL not configured.")
                analysis_result = "SKIPPED" # Indicate analysis was skipped due to config

            # --- Result Processing Block ---
            if analysis_result.startswith("ERROR:"):
                # --- SUCCESSFUL ABNORMALITY DETECTION ---
                found_issues_this_scan += 1
                logging.warning(f"Abnormality detected by AI in {container_name[:12]}: {log_snippet}") # Use extracted snippet

                # Check DB status for this specific abnormality
                # Ensure function exists before calling
                db_id = None # Initialize db_id for cases where we don't find a specific record
                existing_status = 'unknown' # Default status if DB check fails or no record found

                if hasattr(db, 'get_abnormality_status'):
                    try:
                        # Call the function - it returns only the status string or None
                        status_from_db = db.get_abnormality_status(container_id, log_snippet)

                        if status_from_db is not None:
                             existing_status = status_from_db # Use the status found in the DB
                             # Since the function only returns status, we need another way
                             # to get the ID if the status is resolved/ignored.
                             if existing_status in ['resolved', 'ignored']:
                                  # Add a quick query to get the ID for linking purposes
                                  # Note: This adds another DB call, modifying the function is better
                                  temp_conn = None # Initialize outside try
                                  try:
                                       temp_conn = db.get_db()
                                       cursor = temp_conn.cursor()
                                       cursor.execute("SELECT id FROM abnormalities WHERE container_id = ? AND log_snippet = ? AND status = ? ORDER BY last_detected_timestamp DESC LIMIT 1",
                                                      (container_id, log_snippet, existing_status))
                                       id_result = cursor.fetchone()
                                       if id_result:
                                           db_id = id_result['id']
                                           logging.debug(f"Found matching '{existing_status}' record ID {db_id} for {container_name[:12]} snippet.")
                                  except Exception as id_lookup_err:
                                        logging.error(f"Error looking up ID for existing '{existing_status}' status: {id_lookup_err}")
                                        # If ID lookup fails, db_id remains None, which is acceptable
                                  finally:
                                       if temp_conn: temp_conn.close()
                        else:
                             # If status_from_db is None, it means no matching record found for this specific snippet
                             existing_status = 'no_history' # Or keep 'unknown'? Let's use 'no_history'
                             logging.debug(f"No specific DB record found for {container_name[:12]} and snippet.")

                    except Exception as db_lookup_err:
                        logging.error(f"Error calling/processing DB status function for {container_name[:12]} snippet: {db_lookup_err}")
                        existing_status = 'db_error' # Indicate a failure during the DB check
                else:
                    logging.error("DB function 'get_abnormality_status' missing.")
                    existing_status = 'db_error' # Mark as DB error if the function doesn't exist


                # --- Now use existing_status and db_id ---

                if existing_status in ['resolved', 'ignored']:
                    # Abnormality found, but already handled in DB. Treat as healthy for dashboard.
                    current_scan_results[container_id].update({
                        'status': 'healthy',
                        'details': None, # Clear details
                        'db_id': db_id # Link to the existing record using the ID we looked up (or None if lookup failed)
                    })
                    logging.info(f"Detected abnormality for {container_name[:12]} matches a previously '{existing_status}' issue (ID: {db_id}). Treating as Healthy.")
                elif existing_status == 'db_error':
                     # Failed to check DB (either function missing or error during call/processing)
                     current_scan_results[container_id].update({
                          'status': 'error_db_lookup', # Specific status for DB check failure
                          'details': {'analysis': analysis_result, 'snippet': log_snippet, 'timestamp': datetime.now(scan_timezone)},
                          'db_id': None
                     })
                # --- START: Updated 'else' Block for New/Unresolved Issues ---
                else: # Handles 'unresolved', 'no_history', 'unknown' -> Treat as needing logging/update
                    # Log to DB and set status to unhealthy
                    new_db_id = None # Initialize
                    try:
                        if hasattr(db, 'add_or_update_abnormality'):
                            # <<< CAPTURE THE RETURNED ID HERE >>>
                            new_db_id = db.add_or_update_abnormality(
                                container_name=container_name,
                                container_id=container_id,
                                log_snippet=log_snippet,
                                ollama_analysis=analysis_result # Store the full AI response
                            )
                            # <<< REMOVE REDUNDANT LOGGING HERE (it's now done inside db.py) >>>
                            # logging.info(f"Logged new/updated abnormality for {container_name[:12]} ID {new_db_id if new_db_id else 'N/A'}")
                            if new_db_id is None:
                                 # If db function returned None, it indicates a DB error during save
                                 existing_status = 'db_error' # Set status to reflect save failure
                        else:
                             logging.error("DB function 'add_or_update_abnormality' missing.")
                             existing_status = 'db_error' # Mark as DB error if function missing

                    except Exception as db_err:
                         # Catch potential errors calling the function itself
                         logging.error(f"Error calling add_or_update_abnormality for {container_name[:12]}: {db_err}")
                         existing_status = 'db_error' # Mark as DB error

                    # --- Set status based on DB outcome ---
                    if existing_status == 'db_error':
                         # If DB save failed (either function missing, exception, or returned None)
                         current_scan_results[container_id].update({
                             'status': 'error_db_log',
                             'details': {'analysis': analysis_result, 'snippet': log_snippet, 'timestamp': datetime.now(scan_timezone)},
                             'db_id': None # No valid DB ID if save failed
                         })
                    else:
                         # DB Save was successful, set status to unhealthy
                         current_scan_results[container_id].update({
                             'status': 'unhealthy',
                             'details': {'analysis': analysis_result, 'snippet': log_snippet, 'timestamp': datetime.now(scan_timezone)},
                             'db_id': new_db_id # <<< USE THE CAPTURED ID >>>
                         })
                # --- END: Updated 'else' Block ---


            elif analysis_result == "NORMAL" or analysis_result == "SKIPPED":
                 # --- NORMAL or SKIPPED Analysis ---
                 if current_scan_results[container_id]['status'] != 'healthy':
                     logging.info(f"{container_name[:12]} status changing to 'healthy' (Result: {analysis_result}).")
                 current_scan_results[container_id]['status'] = 'healthy'
                 current_scan_results[container_id]['db_id'] = None # Ensure no stale DB ID if now healthy
                 current_scan_results[container_id]['details'] = None # Clear old details if healthy
                 logging.debug(f"{container_name[:12]} OK (Result: {analysis_result}).")

            elif analysis_result.startswith("ANALYSIS_FAILED:"):
                 # --- OLLAMA ANALYSIS FAILED ---
                 logging.error(f"Analysis failed for {container_name[:12]}: {analysis_result}")
                 current_scan_results[container_id].update({
                     'status': 'error_analysis',
                     'details': {'analysis': analysis_result, 'snippet': '(Analysis Failed)', 'timestamp': datetime.now(scan_timezone)},
                     'db_id': None
                 })
            else:
                 # --- UNEXPECTED AI RESPONSE FORMAT ---
                 # AI responded, but not with "NORMAL" or "ERROR:" prefix
                 logging.warning(f"Unexpected analysis format for {container_name[:12]}: {analysis_result[:150]}...")
                 # Treat as potential abnormality but maybe use a different status or log differently?
                 # For now, let's treat it like an abnormality was detected but format is off.
                 # Reuse abnormality logic but maybe log a warning about format.
                 log_snippet = analyzer.extract_log_snippet(analysis_result, logs) # Try to get snippet anyway
                 # You could copy/adapt the 'ERROR:' handling block here, perhaps setting a specific status like 'unhealthy_format'
                 # For simplicity now, let's log it and mark 'error_analysis'
                 current_scan_results[container_id].update({
                     'status': 'error_analysis', # Or a custom status?
                     'details': {'analysis': f"Unexpected Format: {analysis_result}", 'snippet': log_snippet, 'timestamp': datetime.now(scan_timezone)},
                     'db_id': None
                 })
            # --- END: Result Processing Block ---


        if not scan_cancelled: # Update global state
             with container_statuses_lock:
                 # Merge scan results back into the potentially pre-populated global state
                 for c_id, data in current_scan_results.items():
                     container_statuses[c_id] = data
                 # Remove containers that are no longer running
                 ids_to_remove = set(container_statuses.keys()) - active_container_ids
                 for c_id in ids_to_remove:
                     if c_id in container_statuses: logging.info(f"Removing stopped container: {container_statuses[c_id]['name'][:12]}"); del container_statuses[c_id]
                 # Sort the final dict
                 container_statuses = dict(sorted(container_statuses.items(), key=lambda item: item[1]['name'].lower()))
                 logging.info(f"Global state updated. {len(container_statuses)} active containers tracked.")
        else: logging.warning("Global state NOT updated due to cancellation.")

        if scan_cancelled: scan_status["last_run_status"] = f"Scan cancelled @ {datetime.now(scan_timezone).strftime('%H:%M:%S %Z')}"
        else: scan_status["last_run_status"] = f"Completed @ {datetime.now(scan_timezone).strftime('%H:%M:%S %Z')}. Scanned {containers_scanned_count} ({len(ignored_list)} ignored). {found_issues_this_scan} new/active issues."
        logging.info(scan_status["last_run_status"])

    except docker.errors.DockerException as docker_err: logging.error(f"Docker error during scan: {docker_err}"); scan_status["last_run_status"] = f"Docker error: {docker_err}"
    except Exception as e: logging.exception("Unhandled scan error:"); scan_status["last_run_status"] = f"Critical error: {e}"
    finally:
        if client:
            try: client.close()
            except Exception as ce: logging.warning(f"Error closing Docker client: {ce}")
        scan_status["running"] = False; stop_scan_event.clear()
        try:
            # Update next run time based on the scheduler job ONLY if the scheduler is running
            if scheduler.running:
                job = scheduler.get_job('docker_log_scan_job')
                scan_status["next_run_time"] = job.next_run_time if job else None
            else:
                # If scheduler isn't running, there is no next run time
                scan_status["next_run_time"] = None
        except Exception as e: logging.error(f"Next run time update error: {e}"); scan_status["next_run_time"] = None

# <<< START REPLACEMENT: update_ai_health_summary FUNCTION (Optimized + History Save) >>>
def update_ai_health_summary():
    summary_start_time = datetime.now(timezone.utc)
    final_summary = "Summary generation failed." # Default error summary
    final_error = "An unknown error occurred." # Default error message

    # --- Configuration for Summary Optimization ---
    MAX_SUMMARY_ISSUES = 30  # Max number of unresolved issues to include
    ANALYSIS_TRUNCATE_LENGTH = 150 # Max characters of analysis text per issue
    # --- End Configuration ---

    # Need to ensure we have the app context when running in background thread
    with app.app_context(): # Push context for current_app access
        try:
            # Safely get settings
            settings_local = getattr(current_app, 'app_settings', {})
            with current_app.settings_lock:
                # Use .get with defaults for safety
                summary_hours = settings_local.get('summary_interval_hours', 12)
                model_to_use = settings_local.get('ollama_model')
                ollama_url = settings_local.get('ollama_api_url')

            # Convert summary_hours to int safely after retrieving
            try: summary_hours = int(summary_hours)
            except (ValueError, TypeError): summary_hours = 12 # Default if conversion fails


            # Check prerequisite: Ollama URL
            if not ollama_url:
                logging.warning("AI Health Summary skipped: Ollama API URL is not configured.")
                final_summary = "Skipped" # Specific value to indicate skipping
                final_error = "Ollama API URL not configured in settings."
            else:
                # Check prerequisite: DB function
                if not hasattr(db, 'get_recent_abnormalities'):
                    logging.error("DB function 'get_recent_abnormalities' missing. Cannot generate summary.")
                    final_summary = "Failed"
                    final_error = "Internal error (Database function missing)."
                else:
                    try:
                        # --- Step 1: Fetch ALL recent data ---
                        logging.debug(f"Fetching ALL recent abnormalities (last {summary_hours} hours) for summary.")
                        all_recent_abnormalities = db.get_recent_abnormalities(hours=summary_hours)
                        logging.info(f"Fetched {len(all_recent_abnormalities)} total abnormalities from DB.")

                        # --- Step 2: Filter for 'unresolved' status ---
                        unresolved_issues = [
                            record for record in all_recent_abnormalities
                            if isinstance(record, dict) and record.get('status') == 'unresolved'
                        ]
                        logging.info(f"Filtered down to {len(unresolved_issues)} unresolved issues.")

                        # --- Step 3: Sort by most recent timestamp ---
                        def get_sort_key(item):
                           ts = item.get('last_detected_timestamp')
                           return ts if isinstance(ts, datetime) else datetime.min.replace(tzinfo=timezone.utc)
                        unresolved_issues.sort(key=get_sort_key, reverse=True)

                        # --- Step 4: Limit the count ---
                        limited_issues = unresolved_issues[:MAX_SUMMARY_ISSUES]
                        if len(unresolved_issues) > MAX_SUMMARY_ISSUES:
                             logging.info(f"Limiting summary input to the latest {MAX_SUMMARY_ISSUES} unresolved issues (out of {len(unresolved_issues)}).")
                        else:
                             logging.info(f"Using all {len(limited_issues)} unresolved issues for summary input.")

                        # --- Step 5: Format Reduced Data ---
                        formatted_issue_summaries = []
                        if not limited_issues:
                            summary_input_data = "No unresolved issues detected recently."
                            logging.info("No unresolved issues to summarize.")
                        else:
                            for issue in limited_issues:
                                container_name = issue.get('container_name', 'UnknownContainer')
                                analysis_text = issue.get('ollama_analysis', 'Analysis missing')
                                if analysis_text.startswith("ERROR:"): analysis_text = analysis_text[len("ERROR:"):].strip()
                                truncated_analysis = analysis_text[:ANALYSIS_TRUNCATE_LENGTH]
                                if len(analysis_text) > ANALYSIS_TRUNCATE_LENGTH: truncated_analysis += "..."
                                formatted_issue_summaries.append(f"- Container: {container_name}, Issue: {truncated_analysis}")
                            summary_input_data = "\n".join(formatted_issue_summaries)

                        # --- Step 6: Prepare the Prompt for Ollama ---
                        summary_prompt = f"""Analyze the following list of recent unresolved container issues.
Provide a concise (2-4 sentences) health summary identifying the most significant types of active problems.
**Crucially, for each significant problem type mentioned, list the primary container name(s) experiencing it.**
If the list is empty or says 'No unresolved issues detected', state that the system appears healthy. Avoid generic descriptions; focus on specific issues and their locations.

Recent Unresolved Issues:
{summary_input_data}

---
Health Summary (mentioning affected containers):"""

                        # --- Step 7: Call Analyzer ---
                        logging.info(f"Generating health summary using Ollama model {model_to_use} with concise input.")
                        summary_or_error = analyzer.summarize_recent_abnormalities(
                            abnormalities_data=None,
                            api_url=ollama_url,
                            model_name=model_to_use,
                            prompt_template=summary_prompt
                        )

                        # --- Step 8: Process result from analyzer ---
                        # Updated check based on analyzer.py returning specific error strings
                        if isinstance(summary_or_error, str) and summary_or_error.startswith("Error:"): # Analyzer signals error
                             logging.warning(f"AI Summary generation failed: {summary_or_error}")
                             final_summary = "Failed"
                             final_error = summary_or_error # Use the error message from analyzer
                        elif summary_or_error is None: # Handle explicit None return as failure
                             logging.warning("AI Summary generation failed: Analyzer returned None.")
                             final_summary = "Failed"
                             final_error = "Summary generation failed (analyzer returned None)."
                        else: # Success
                             logging.info("AI Health Summary updated successfully.")
                             final_summary = summary_or_error
                             final_error = None # No error

                    except Exception as db_err: # Catch errors during DB fetch or processing
                         logging.exception("Error fetching/processing abnormalities for summary:")
                         final_summary = "Failed"
                         final_error = f"Error processing data for summary: {db_err}"

        except AttributeError as e: # Error accessing app attributes
             logging.error(f"Error accessing app state in update_ai_health_summary: {e}")
             final_summary = "Failed"
             final_error = "Internal error accessing application state."
        except Exception as e: # Catch any other unexpected errors
            logging.exception("Unhandled error during AI health summary task:")
            final_summary = "Failed"
            final_error = f"An unexpected internal error occurred: {e}"
        finally:
            # --- Step 9: Update global state (always do this) ---
            try:
                with current_app.ai_summary_lock:
                     # Update main summary text based on whether there was an error or not
                     if final_error is None and final_summary != "Skipped":
                         current_app.ai_health_summary["summary"] = final_summary
                     elif final_summary == "Skipped":
                         current_app.ai_health_summary["summary"] = "Summary skipped (Ollama URL not configured)."
                     else: # An error occurred
                         current_app.ai_health_summary["summary"] = "Error generating summary (see details)."

                     current_app.ai_health_summary["error"] = final_error # Update error field
                     current_app.ai_health_summary["last_updated"] = summary_start_time
            except AttributeError:
                 logging.error("Failed to update global ai_health_summary state (AttributeError).")
            except Exception as update_err:
                 logging.exception("Error updating AI summary state:")

            # --- Step 10: Save result to history DB (always attempt this) ---
            try:
                if hasattr(db, 'add_summary_history'):
                    # Pass the timestamp object, the final summary (None if error/skipped), and the final error (None if success)
                    # Store the actual summary text only if generation was successful and not skipped
                    summary_to_store = final_summary if final_error is None and final_summary != "Skipped" else None
                    db.add_summary_history(
                        timestamp=summary_start_time,
                        summary_text=summary_to_store,
                        error_text=final_error # Save error text if applicable
                    )
                    logging.debug(f"Attempted to save summary history. Summary: '{'Yes' if summary_to_store else 'No'}', Error: '{final_error if final_error else 'None'}'")
                else:
                    logging.error("Cannot save summary history: db.add_summary_history function not found.")
            except Exception as history_save_err:
                 # Log error but don't crash the main task if history save fails
                 logging.exception(f"Failed to save summary result to history database: {history_save_err}")

            # Context is automatically popped by 'with app.app_context()'
# <<< END REPLACEMENT: update_ai_health_summary FUNCTION (Optimized + History Save) >>>


# --- Scheduler Setup ---
def setup_scheduler():
    global scheduler, scan_status # Added scan_status to modify
    display_timezone = get_display_timezone()
    logging.info(f"Configuring scheduler with TZ: {display_timezone}")
    try: scheduler.configure(timezone=display_timezone)
    except Exception as e: logging.error(f"Scheduler TZ config error: {e}")

    with settings_lock:
        scan_interval = app_settings.get('scan_interval_minutes', 180);
        summary_interval = app_settings.get('summary_interval_hours', 12)

    try: # Add Scan Job
        # Schedule first run after the full interval to allow initial state to settle
        first_scan_delay = timedelta(minutes=scan_interval)
        first_scan_time = datetime.now(display_timezone) + first_scan_delay
        logging.info(f"Scheduling first log scan to run around: {first_scan_time.strftime('%Y-%m-%d %H:%M:%S %Z')}")

        scheduler.add_job(
            scan_docker_logs, # The job references the function directly
            trigger=IntervalTrigger(minutes=scan_interval, timezone=display_timezone), # Explicitly set trigger TZ
            id='docker_log_scan_job',
            name='Log Scan',
            replace_existing=True,
            next_run_time=first_scan_time,
            misfire_grace_time=300 # Allow 5 minutes for misfire
        )
        # Update global status immediately to reflect the scheduled time
        scan_status["next_run_time"] = first_scan_time
        scan_status["last_run_status"] = "Scheduled, awaiting first run." # Update initial message
        logging.info(f"Scan job added: runs every {scan_interval}m.")
    except Exception as e: logging.critical(f"Failed scan job add: {e}")

    try: # Add Summary Job
        # Schedule first summary shortly after startup
        first_summary_time = datetime.now(display_timezone) + timedelta(minutes=2) # Small delay
        scheduler.add_job(
            update_ai_health_summary, # The job references the function directly
            trigger=IntervalTrigger(hours=summary_interval, timezone=display_timezone), # Explicitly set trigger TZ
            id='ai_summary_job',
            name='AI Summary',
            replace_existing=True,
            next_run_time=first_summary_time,
            misfire_grace_time=600 # Allow 10 minutes for misfire
        )
        logging.info(f"Summary job added: runs every {summary_interval}h.")
    except Exception as e: logging.error(f"Failed summary job add: {e}")

    if not scheduler.running:
        try: scheduler.start(); logging.info("Scheduler started.")
        except Exception as e: logging.critical(f"Scheduler start failed: {e}")
    else: logging.info("Scheduler already running.")

# --- Main Execution ---
if __name__ == '__main__':
    logging.info("Starting Docker Log Monitor application...")
    try:
        # Ensure DB exists and is initialized *before* loading settings or populating
        if hasattr(db, 'init_db'):
            db.init_db()
            logging.info("Database initialized.")
        else:
             logging.warning("Database module does not have 'init_db' function. Skipping initialization.")

        load_settings() # Load settings from DB
        fetch_initial_ollama_models()
        populate_initial_statuses() # <-- Call added here
        setup_scheduler() # Setup and start background jobs

        # --- Attach shared state/objects directly to the app instance ---
        # This makes them accessible within blueprints via current_app
        app.app_settings = app_settings
        app.settings_lock = settings_lock
        app.container_statuses = container_statuses
        app.container_statuses_lock = container_statuses_lock
        app.scan_status = scan_status
        app.stop_scan_event = stop_scan_event # Attach event object
        app.ai_health_summary = ai_health_summary
        app.ai_summary_lock = ai_summary_lock
        app.available_ollama_models = available_ollama_models
        app.models_lock = models_lock
        app.scheduler = scheduler # Attach scheduler instance
        app.analyzer = analyzer
        app.db = db # Make DB module accessible if needed in blueprints

        # <<< ADD THESE LINES TO ATTACH FUNCTION REFERENCES >>>
        app.scan_docker_logs_func = scan_docker_logs
        app.update_ai_health_summary_func = update_ai_health_summary
        # <<< END ADD >>>

        logging.info("Attached shared state and task functions to Flask app object.") # Updated log message

    except Exception as startup_err:
         logging.critical(f"Critical error during application startup: {startup_err}", exc_info=True)
         # Depending on the severity, you might want to exit
         # exit(1)

    try:
        port = int(os.environ.get("PORT", "5001"))
        if not 1 <= port <= 65535: raise ValueError("Port must be 1-65535")
    except ValueError as e:
         logging.warning(f"Invalid PORT environment variable: {e}. Defaulting to 5001."); port = 5001

    logging.info(f"Flask app starting - preparing to listen on port {port}")
    use_waitress = os.environ.get("USE_WAITRESS", "true").lower() == "true"

    if use_waitress:
        try:
            from waitress import serve
            logging.info(f"Starting server with Waitress on http://0.0.0.0:{port}")
            # Adjust threads as needed, default is 4
            serve(app, host='0.0.0.0', port=port, threads=8)
        except ImportError:
            logging.warning("Waitress not found. Falling back to Flask development server (recommended for development only).")
            # Disable reloader for stability with background scheduler
            app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
        except Exception as serve_err:
             logging.critical(f"Failed to start waitress server: {serve_err}")
             logging.info("Attempting fallback to Flask development server.")
             # Disable reloader for stability with background scheduler
             app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
    else:
        logging.info(f"Starting with Flask's development server on http://0.0.0.0:{port} (recommended for development only).")
        # Disable reloader for stability with background scheduler
        app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

    logging.info("Docker Log Monitor application shut down.")
