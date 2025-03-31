# app.py
import os
import logging
from datetime import datetime, timedelta, timezone
import threading
from threading import Lock
import json
from flask import Flask, render_template, redirect, url_for, flash, current_app
from markupsafe import Markup, escape
# <<< ADD re module for regex replacement >>>
import re # Added import re
import sys
import signal
import time
import secrets # For default API key generation if needed
import pytz # For timezone handling

# Background scheduler
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.jobstores.base import JobLookupError

# Local module imports
import db
import analyzer
from routes.ui_routes import ui_bp # Import blueprint
from routes.api_routes import api_bp # Import blueprint
from routes.scheduler_routes import scheduler_bp # Import blueprint
from utils import get_display_timezone # Import utility

# --- Logging Setup ---
log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
# Allow basicConfig to run first if Flask/Werkzeug hasn't configured root logger
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s'
)
# Fine-tune specific loggers if needed
logging.getLogger("apscheduler.scheduler").setLevel(logging.WARNING)
logging.getLogger("apscheduler.executors.default").setLevel(logging.WARNING)
logging.getLogger("werkzeug").setLevel(logging.WARNING) # Reduce Flask's built-in server noise
logging.getLogger("urllib3.connectionpool").setLevel(logging.INFO) # Can be noisy

logger = logging.getLogger(__name__)
logger.info(f"Geordi log level set to: {log_level}")


# --- Configuration ---
PORT = int(os.environ.get("PORT", 5001))
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not FLASK_SECRET_KEY:
    logger.warning("FLASK_SECRET_KEY not set in environment! Using a temporary, insecure key. SET THIS IN PRODUCTION.")
    FLASK_SECRET_KEY = secrets.token_hex(16) # Generate a temporary one

# --- Flask App Initialization ---
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
logger.info("Flask app initialized.")

# --- START: REVISED nl2br filter ---
# Use regex to replace one or more consecutive newlines with a single <br>
newline_re = re.compile(r'\n+')

def nl2br_filter(s):
    """
    Converts newlines in a string to HTML <br> tags, ensuring safety.
    First escapes the string, then replaces consecutive newlines with a single <br>.
    """
    if s:
        # Escape the input string first to prevent XSS
        s_escaped = escape(s)
        # Replace sequences of one or more newlines with a single <br>
        result = newline_re.sub('<br>\n', s_escaped)
        # Mark the whole thing as safe HTML
        return Markup(result)
    return ''

app.jinja_env.filters['nl2br'] = nl2br_filter
logging.info("Added improved nl2br filter to Jinja environment.")
# --- END: REVISED nl2br filter ---


# --- Global State Variables ---
# These hold the current state of monitored containers and settings.
# Locks are crucial for thread safety between web requests and the background scanner.
container_statuses = {} # Key: container_id, Value: dict {'name': str, 'status': str, 'last_checked': datetime, 'error_detail': str, 'db_id': int}
container_statuses_lock = Lock()

app_settings = {} # Cache of settings from the database
settings_lock = Lock()

ai_health_summary = {"summary": "No summary generated yet.", "last_updated": None, "error": None}
ai_summary_lock = Lock()

# Available Ollama models discovered at startup
available_ollama_models = []
models_lock = Lock()

# Status of the background scanning job
scan_status = {"last_run_status": "Not run yet", "running": False, "next_run_time": None}
scan_status_lock = Lock()

# --- Attach State and Functions Directly to App Context ---
# This allows blueprints to access them via current_app
# Note: Mutating these dicts requires acquiring the corresponding lock first!
app.container_statuses = container_statuses
app.container_statuses_lock = container_statuses_lock
app.app_settings = app_settings
app.settings_lock = settings_lock
app.ai_health_summary = ai_health_summary
app.ai_summary_lock = ai_summary_lock
app.available_ollama_models = available_ollama_models
app.models_lock = models_lock
app.scan_status = scan_status
app.scan_status_lock = scan_status_lock
# We'll attach scheduler and task functions later after they are defined

# --- Initial Data Loading Functions ---

# <<< START: CORRECTED fetch_initial_ollama_models function >>>
def fetch_initial_ollama_models():
    """Fetches the list of models from Ollama at startup."""
    # <<< FIX: Declare global at the top of the function scope >>>
    global available_ollama_models

    logging.info("Fetching initial Ollama model list...")
    # Retrieve URL from app_settings (must be loaded before this is called)
    ollama_api_url = None # Initialize
    try:
        with settings_lock:
            # Get URL safely, fallback to default from db module if needed
            ollama_api_url = app_settings.get("ollama_api_url", db.DEFAULT_SETTINGS.get("ollama_api_url"))
            if ollama_api_url:
                # Update analyzer's URL based on settings at startup
                analyzer.OLLAMA_API_URL = ollama_api_url
                logger.info(f"Using Ollama API URL: {ollama_api_url}")
            else:
                logger.warning("Ollama API URL not found in settings or defaults. Cannot fetch models.")
                # Set analyzer URL to None if not found
                analyzer.OLLAMA_API_URL = None

        # Proceed only if URL is set
        if not ollama_api_url:
             raise ValueError("Ollama API URL is not configured.")

        # analyzer.get_ollama_models now returns only the list (or empty list on error)
        fetched_models = analyzer.get_ollama_models() # <<< FIX: Expect only one return value

        # Check if the return value is a list (it should be, even if empty)
        if isinstance(fetched_models, list):
            with models_lock: # Use the global lock
                # No 'global' declaration needed here anymore
                # Use list slicing [:] to update in-place
                available_ollama_models[:] = fetched_models
            logging.info(f"Successfully fetched {len(fetched_models)} models at startup.")
            if not fetched_models:
                 logging.warning("Ollama returned an empty model list. Check Ollama server status or logs.")
        else:
            # This case shouldn't happen with the current analyzer code, but good to handle
            logging.error(f"Fetching initial models returned an unexpected type: {type(fetched_models)}. Expected list.")
            with models_lock:
                # No 'global' declaration needed here anymore
                available_ollama_models[:] = [] # Ensure it's an empty list

    except ValueError as ve: # Catch specific error if URL is missing
        logging.error(f"Cannot fetch Ollama models: {ve}")
        with models_lock:
            # No 'global' declaration needed here anymore
            available_ollama_models[:] = [] # Reset to empty on error
    except Exception as e:
        # Catch any other unexpected error during the call
        logging.exception("Error calling or processing fetch_initial_ollama_models:")
        with models_lock:
            # No 'global' declaration needed here anymore
            available_ollama_models[:] = [] # Reset to empty on error
# <<< END: CORRECTED fetch_initial_ollama_models function >>>


def load_settings():
    """Loads all settings from DB into the global cache."""
    global app_settings # Ensure we modify the global dict
    logger.info("Loading settings from database...")
    try:
        db_settings = db.get_all_settings()
        with settings_lock:
            app_settings.clear() # Start fresh
            app_settings.update(db_settings) # Update with values from DB/defaults

            # --- Post-process settings ---
            # Convert numeric settings from string to int
            int_keys = ['scan_interval_minutes', 'summary_interval_hours', 'log_lines_to_fetch']
            for key in int_keys:
                try:
                    app_settings[key] = int(app_settings[key])
                except (ValueError, TypeError, KeyError) as e:
                    logger.warning(f"Could not convert setting '{key}' to int (value: {app_settings.get(key)}, error: {e}). Using default.")
                    try:
                        app_settings[key] = int(db.DEFAULT_SETTINGS[key])
                    except (ValueError, KeyError):
                        logger.error(f"Default for '{key}' is also invalid. Setting to fallback 1.")
                        app_settings[key] = 1 # Fallback

            # Parse ignored containers JSON string into a list
            try:
                ignored_json = app_settings.get('ignored_containers', '[]')
                app_settings['ignored_containers_list'] = json.loads(ignored_json)
                if not isinstance(app_settings['ignored_containers_list'], list):
                     raise TypeError("Parsed JSON is not a list.")
                # For settings page display consistency if textarea is used
                app_settings['ignored_containers_textarea'] = "\n".join(app_settings['ignored_containers_list'])
            except (json.JSONDecodeError, TypeError) as e:
                 logger.error(f"Failed to parse ignored_containers JSON '{ignored_json}': {e}. Using empty list.")
                 app_settings['ignored_containers'] = "[]" # Store valid JSON back
                 app_settings['ignored_containers_list'] = []
                 app_settings['ignored_containers_textarea'] = ""

            # Ensure API key is loaded (might be empty)
            if 'api_key' not in app_settings:
                 app_settings['api_key'] = db.DEFAULT_SETTINGS['api_key']

            # Make sure essential Ollama settings are present
            if 'ollama_api_url' not in app_settings:
                app_settings['ollama_api_url'] = db.DEFAULT_SETTINGS['ollama_api_url']
            if 'ollama_model' not in app_settings:
                app_settings['ollama_model'] = db.DEFAULT_SETTINGS['ollama_model']

            # Propagate key settings to the analyzer module's global scope after loading
            analyzer.OLLAMA_API_URL = app_settings['ollama_api_url']
            analyzer.DEFAULT_OLLAMA_MODEL = app_settings['ollama_model']
            # Note: LOG_LINES_TO_FETCH is passed per function call in analyzer now, not set globally there.

            logger.info("Settings loaded and processed successfully.")
            logger.debug(f"Loaded settings cache: { {k: (v if k != 'analysis_prompt' else v[:30]+'...') for k,v in app_settings.items()} }") # Avoid logging long prompt

    except Exception as e:
        logger.exception("CRITICAL: Failed to load settings from database! Application might not function correctly.")
        # Consider falling back to defaults entirely or exiting if settings are critical
        with settings_lock:
             app_settings.clear()
             app_settings.update(db.DEFAULT_SETTINGS) # Fallback to hardcoded defaults
             # Process fallbacks too
             try:
                 app_settings['scan_interval_minutes'] = int(app_settings['scan_interval_minutes'])
                 app_settings['summary_interval_hours'] = int(app_settings['summary_interval_hours'])
                 app_settings['log_lines_to_fetch'] = int(app_settings['log_lines_to_fetch'])
                 app_settings['ignored_containers_list'] = []
                 app_settings['ignored_containers_textarea'] = ""
                 analyzer.OLLAMA_API_URL = app_settings['ollama_api_url']
                 analyzer.DEFAULT_OLLAMA_MODEL = app_settings['ollama_model']
             except Exception as fallback_e:
                  logger.error(f"Error processing fallback default settings: {fallback_e}")


# <<< START: CORRECTED populate_initial_statuses function >>>
def populate_initial_statuses():
    """Gets initial list of running containers and sets status based on DB history."""
    logger.info("Populating initial container statuses...")
    global container_statuses # Ensure modification of global dict
    containers = []
    docker_client = None # Initialize to None

    # --- Get Ignored List ---
    ignored_list = []
    try:
        with settings_lock:
             ignored_list = app_settings.get('ignored_containers_list', [])
             if not isinstance(ignored_list, list): ignored_list = []
    except Exception as e:
        logger.error(f"Error reading ignored list during initial population: {e}")
        ignored_list = [] # Use empty on error

    # --- Get Docker Containers ---
    try:
        docker_client = analyzer.get_docker_client()
        if not docker_client:
             raise ConnectionError("Failed to get Docker client for initial population.")
        # Remove sparse=True to potentially ensure .name is always populated, accept slightly slower list
        containers = docker_client.containers.list(sparse=False)
        logger.info(f"Found {len(containers)} running containers.")
    except Exception as e:
        logger.error(f"Failed to list running Docker containers on startup: {e}")
        containers = [] # Proceed with empty list if Docker fails initially
    finally:
        # Close the client if it was obtained
        if docker_client:
            try:
                docker_client.close()
            except Exception as ce:
                 logging.warning(f"Could not close docker client after initial population: {ce}")

    # --- Populate Statuses ---
    initial_statuses_temp = {} # Build temporary dict
    for container in containers:
        try:
            container_id = container.id # Use full ID for internal key
            container_name = container.name # Should be populated now

            # Extra check just in case name is still None or empty
            if not container_name:
                 logger.warning(f"Container with ID {container_id[:12]} has no name. Skipping initial status population for this container.")
                 continue # Skip this container

            if container_name in ignored_list:
                logger.debug(f"Skipping ignored container {container_name} ({container_id[:12]}) during initial population.")
                continue

            # Get last known status from DB before setting initial state
            last_status, last_db_id = db.get_last_known_status(container_id) # Pass full ID
            initial_status = 'pending' # Default if no history
            db_id_to_set = None

            if last_status in ['resolved', 'ignored']:
                initial_status = 'awaiting_scan'
                logger.debug(f"Container {container_name} ({container_id[:12]}): Found last status '{last_status}'. Setting initial to 'awaiting_scan'.")
            elif last_status == 'unhealthy':
                initial_status = 'unhealthy'
                db_id_to_set = last_db_id # Keep link to the unresolved issue
                logger.debug(f"Container {container_name} ({container_id[:12]}): Found last status 'unhealthy' (ID: {last_db_id}). Setting initial to 'unhealthy'.")
            elif last_status == 'no_history':
                 logger.debug(f"Container {container_name} ({container_id[:12]}): No history found. Setting initial to 'pending'.")
                 initial_status = 'pending'
            elif last_status == 'db_error':
                 logger.warning(f"Container {container_name} ({container_id[:12]}): DB error looking up status. Setting initial to 'pending'.")
                 initial_status = 'pending'
            else:
                 logger.warning(f"Container {container_name} ({container_id[:12]}): Unexpected last status '{last_status}'. Setting initial to 'pending'.")
                 initial_status = 'pending'

            initial_statuses_temp[container_id] = {
                'name': container_name, # Name should be valid here
                'status': initial_status,
                'last_checked': None,
                'error_detail': None,
                'db_id': db_id_to_set
            }
        except AttributeError as ae:
             # Catch cases where container object might be missing expected attributes
             logger.error(f"Attribute error processing container {getattr(container, 'id', 'UNKNOWN_ID')} during initial population: {ae}. Skipping.")
        except Exception as cont_err:
            logger.error(f"Error processing container {getattr(container, 'name', 'UNKNOWN')} during initial population: {cont_err}")

    # Update global state safely
    with container_statuses_lock:
        container_statuses.clear() # Clear any old state
        # --- FIX: Use .get() in lambda for safe sorting ---
        sorted_items = sorted(initial_statuses_temp.items(), key=lambda item: item[1].get('name', '').lower())
        container_statuses.update(dict(sorted_items))
        logger.info(f"Initial statuses set for {len(container_statuses)} containers.")
# <<< END: CORRECTED populate_initial_statuses function >>>


# --- Background Tasks ---

def scan_docker_logs():
    """Background task to fetch logs, analyze, and update statuses."""
    current_thread = threading.current_thread()
    logger.info(f"Starting scheduled log scan... (Thread: {current_thread.name})")
    global scan_status, container_statuses, app_settings # Access global state

    # --- Set scan running status ---
    with scan_status_lock:
        # Prevent concurrent scans if one is already marked as running
        if scan_status.get('running', False):
            logger.warning("Scan job triggered, but previous scan appears to be active. Skipping.")
            return
        scan_status['running'] = True
        scan_status['last_run_status'] = "Running scan..."

    containers_to_scan_ids = []
    ignored_containers_list = [] # Default to empty list
    settings_for_scan = {}
    docker_client = None # Initialize

    # --- Get settings and current container list safely ---
    try:
        with settings_lock:
            # Copy settings needed for this run to avoid holding lock during long operations
            settings_for_scan = {
                'ollama_model': app_settings.get('ollama_model'),
                'ollama_api_url': app_settings.get('ollama_api_url'),
                'analysis_prompt': app_settings.get('analysis_prompt'),
                'log_lines_to_fetch': app_settings.get('log_lines_to_fetch', 100), # Default if missing
                'ignored_containers_list': app_settings.get('ignored_containers_list', []) # Get parsed list
            }
        ignored_containers_list = settings_for_scan['ignored_containers_list']

        # Get Docker client here to list *currently* running containers
        docker_client = analyzer.get_docker_client()
        if not docker_client:
            raise ConnectionError("Failed to get Docker client for listing containers in scan.")

        running_containers_now = docker_client.containers.list(sparse=False) # Use sparse=False
        running_container_ids_now = {c.id for c in running_containers_now}
        logger.info(f"Scan found {len(running_containers_now)} containers currently running.")

        # Get a consistent snapshot of the cache to work with
        with container_statuses_lock:
            current_cache_state = container_statuses.copy()

        # Determine which containers need scanning
        containers_to_scan_ids = []
        containers_to_add = {}
        for container in running_containers_now:
             # Ensure container has a valid name before proceeding
            container_name = getattr(container, 'name', None)
            if not container_name:
                logger.warning(f"Skipping container with ID {container.id[:12]} because it has no name.")
                continue

            if container_name in ignored_containers_list:
                continue # Skip ignored

            if container.id not in current_cache_state:
                # Container is running but not in our cache - add it as pending
                logger.info(f"Found new running container: {container_name} ({container.id[:12]}). Adding as 'pending'.")
                containers_to_add[container.id] = {
                    'name': container_name, 'status': 'pending', 'last_checked': None, 'error_detail': None, 'db_id': None
                }
                # Add to scan list as well
                containers_to_scan_ids.append(container.id)
            elif container.id in current_cache_state:
                # Already tracking, add to scan list
                containers_to_scan_ids.append(container.id)

        # Add newly discovered containers to the main cache
        if containers_to_add:
            with container_statuses_lock:
                 container_statuses.update(containers_to_add)
                 # Re-sort after adding
                 sorted_items = sorted(container_statuses.items(), key=lambda item: item[1].get('name', '').lower()) # Safe sort
                 container_statuses.clear()
                 container_statuses.update(dict(sorted_items))

        logger.info(f"Scan will check {len(containers_to_scan_ids)} non-ignored containers.")
        logger.debug(f"Ignored containers: {ignored_containers_list}")
        logger.debug(f"Containers to scan: {[cid[:12] for cid in containers_to_scan_ids]}")

    except Exception as e:
        logger.exception("Error preparing for log scan (listing containers/accessing state/settings):")
        with scan_status_lock:
            scan_status['running'] = False
            scan_status['last_run_status'] = f"Error preparing scan: {e}"
        # Close client if obtained
        if docker_client: docker_client.close() # Use existing variable name
        return # Abort scan if initial setup fails

    # --- Iterate and process each container ---
    # Note: docker_client is already obtained above if preparation was successful
    analysis_errors_occurred = 0
    db_errors_occurred = 0
    fetch_errors_occurred = 0
    containers_processed = 0
    scan_results_temp = {} # Store results temporarily

    try:
        for container_id in containers_to_scan_ids:
            containers_processed += 1
            container_name = "Unknown" # Default
            current_status_in_cache = 'unknown'
            db_id_in_cache = None
            result_data = {} # Temp storage for this container's scan result

            # Get current name/status safely from main cache
            with container_statuses_lock:
                if container_id in container_statuses:
                    container_name = container_statuses[container_id].get('name', 'NAME_MISSING') # Safe get
                    current_status_in_cache = container_statuses[container_id]['status']
                    db_id_in_cache = container_statuses[container_id].get('db_id')
                    # Initialize result data with current cache state
                    result_data = container_statuses[container_id].copy()
                else:
                    logger.warning(f"Container {container_id[:12]} was in scan list but disappeared from cache. Skipping.")
                    continue # Skip if container vanished

            logger.debug(f"Processing container: {container_name} ({container_id[:12]}) - Cache status: {current_status_in_cache}")

            try:
                # Get container object - might fail if stopped between list and get
                container = docker_client.containers.get(container_id)

                # Fetch logs using the analyzer function
                log_lines_count = settings_for_scan.get('log_lines_to_fetch', 100)
                # --- ADDED LOGGING ---
                logger.debug(f"Calling analyzer.fetch_container_logs for {container_name} with num_lines={log_lines_count}")
                logs = analyzer.fetch_container_logs(container, log_lines_count)

                if logs is None: # fetch_container_logs returns None on internal error
                    raise ConnectionError(f"Log fetching failed via analyzer for {container_name}")

                # Analyze logs if fetched successfully
                analysis_result = None
                analysis_error = None
                # Check if Ollama URL is actually configured before attempting analysis
                ollama_api_url_for_scan = settings_for_scan.get('ollama_api_url')
                if not ollama_api_url_for_scan:
                    logger.warning(f"Skipping analysis for {container_name}: Ollama API URL not configured.")
                    analysis_result = "NORMAL" # Treat as normal if URL is missing
                elif logs: # Don't analyze empty logs string
                    logger.debug(f"Sending {len(logs.splitlines())} lines from {container_name} for analysis.")
                    try:
                        # Use settings copied earlier for the analyzer call
                        analysis_result = analyzer.analyze_logs_with_ollama(
                            logs=logs, # Pass logs keyword argument
                            model_to_use=settings_for_scan['ollama_model'], # Pass model keyword argument
                            custom_prompt=settings_for_scan['analysis_prompt'] # Pass prompt keyword argument
                        )
                        logger.debug(f"Analysis result for {container_name}: '{analysis_result[:100]}{'...' if analysis_result and len(analysis_result) > 100 else ''}'")
                        if analysis_result is None: # Handle case where analysis returns None unexpectedly
                            analysis_error = "AI analysis returned None unexpectedly."
                            logger.error(analysis_error)
                        elif not isinstance(analysis_result, str):
                            analysis_error = f"AI analysis returned unexpected type: {type(analysis_result)}."
                            logger.error(analysis_error)
                        # Check for internal analyzer errors returned in the string
                        elif analysis_result.startswith("ERROR: "):
                             # Check if it's an internal error reported by the analyzer function
                             if "Ollama model not configured" in analysis_result or \
                                "Invalid analysis prompt configuration" in analysis_result or \
                                "Ollama API URL is not set" in analysis_result or \
                                "Ollama model" in analysis_result and "not found on the server" in analysis_result or \
                                "Ollama endpoint not found" in analysis_result or \
                                "Ollama request timed out" in analysis_result or \
                                "Could not connect to Ollama API" in analysis_result or \
                                "Ollama API request failed" in analysis_result or \
                                "Ollama communication failed" in analysis_result or \
                                "Invalid JSON response from Ollama" in analysis_result or \
                                "Unexpected analysis failure" in analysis_result:
                                 analysis_error = analysis_result # It's an internal processing error
                                 logger.error(f"Analysis process error for {container_name}: {analysis_error}")
                                 analysis_errors_occurred += 1
                                 analysis_result = None # Clear analysis result as it's an error


                    except Exception as analysis_exc:
                         analysis_error = f"Ollama analysis call failed: {analysis_exc}"
                         logger.error(f"Error during Ollama analysis for {container_name}: {analysis_exc}")
                         analysis_errors_occurred += 1
                         analysis_result = None # Clear analysis result on exception
                else:
                    logger.info(f"No new logs fetched for {container_name}. Treating as NORMAL.")
                    analysis_result = "NORMAL" # Treat empty logs as normal for status update logic

                # --- Update Status Based on Analysis ---
                new_status = 'error_analysis' if analysis_error else None
                error_detail = analysis_error
                abnormality_db_id = None # ID from adding/updating abnormality

                if not new_status: # Only proceed if analysis itself didn't error
                    # Check if the (valid string) analysis_result indicates an abnormality
                    if analysis_result is not None and not analysis_result.strip().upper().startswith("NORMAL"):
                        # Assume any non-NORMAL, non-error string is an abnormality description
                        new_status = 'unhealthy'
                        error_detail = analysis_result.strip() # Store the AI's finding
                        log_snippet = analyzer.extract_log_snippet(error_detail, logs) # Get snippet for DB
                        logger.info(f"Abnormality detected by AI for {container_name}: {error_detail.splitlines()[0]}")

                        # Check DB status for this specific abnormality to avoid noise
                        existing_db_status = db.get_abnormality_status(container_id, log_snippet)

                        if existing_db_status in ['resolved', 'ignored']:
                            # AI found it, but we already handled this *exact* issue. Treat as healthy for now.
                            new_status = 'healthy'
                            error_detail = None # Clear error detail
                            abnormality_db_id = None # Clear DB link
                            logger.info(f"Detected abnormality for {container_name} matches previously '{existing_db_status}' issue. Status set to 'healthy'.")
                        elif existing_db_status == 'db_error':
                             new_status = 'error_db_lookup'
                             error_detail = "Failed to check DB for existing abnormality"
                             db_errors_occurred += 1
                             logger.error(f"{error_detail} for {container_name}")
                             abnormality_db_id = db_id_in_cache # Keep existing link on DB error
                        else: # Includes 'unresolved' or 'no_history' -> Log/Update
                             try:
                                 abnormality_db_id = db.add_or_update_abnormality(
                                     container_name, container_id, log_snippet, analysis_result
                                 )
                                 if abnormality_db_id is None:
                                     # If DB interaction failed, reflect this
                                     new_status = 'error_db_log'
                                     error_detail = "Failed to log abnormality to DB"
                                     db_errors_occurred += 1
                                     logger.error(f"{error_detail} for {container_name}")
                                 else:
                                     logger.info(f"Logged/Updated abnormality ID {abnormality_db_id} for {container_name}")
                                     # Status remains 'unhealthy'
                             except Exception as db_exc:
                                 logger.exception(f"Unexpected DB error logging abnormality for {container_name}:")
                                 new_status = 'error_db_log'
                                 error_detail = f"Unexpected DB error: {db_exc}"
                                 db_errors_occurred += 1
                                 abnormality_db_id = None # Ensure None on error

                    # Explicitly check for NORMAL (including after empty logs or skipped analysis)
                    elif analysis_result is not None and analysis_result.strip().upper().startswith("NORMAL"):
                        # AI explicitly said NORMAL or was treated as NORMAL
                        new_status = 'healthy'
                        error_detail = None
                        abnormality_db_id = None # Clear DB link when healthy
                        # Log change only if it was unhealthy/awaiting
                        if current_status_in_cache in ['unhealthy', 'awaiting_scan', 'error_db_log', 'error_db_lookup', 'error_analysis', 'error_fetching_logs']:
                            logger.info(f"Container {container_name} status changed from '{current_status_in_cache}' to 'healthy'.")
                        else:
                            logger.debug(f"Container {container_name} confirmed 'healthy'.")
                    else:
                         # Should not be reached if analysis_error is None and analysis_result is not None
                         # But handle just in case
                         new_status = 'error_analysis' # Fallback status
                         error_detail = f"Inconsistent internal state after analysis (Result: {analysis_result}, Error: {analysis_error})"
                         logger.error(f"Container {container_name}: {error_detail}")
                         analysis_errors_occurred += 1
                         abnormality_db_id = db_id_in_cache # Keep existing link

                # --- Store result for bulk update ---
                result_data['status'] = new_status
                result_data['last_checked'] = datetime.now(timezone.utc)
                result_data['error_detail'] = error_detail
                # Update DB ID only if a new/updated one was obtained, or if explicitly cleared (healthy)
                if abnormality_db_id is not None or new_status == 'healthy':
                     result_data['db_id'] = abnormality_db_id
                # Else: keep the existing db_id from the start of the loop iteration
                scan_results_temp[container_id] = result_data


            except docker.errors.NotFound:
                logger.warning(f"Container {container_name} ({container_id[:12]}) not found during scan get(). Marked for removal.")
                # Mark for removal instead of deleting immediately to avoid modifying dict while iterating potentially
                scan_results_temp[container_id] = {'status': 'stopped', 'remove': True} # Special flag
            except (docker.errors.APIError, ConnectionError) as e:
                logger.error(f"Docker API/Connection error processing container {container_name} ({container_id[:12]}): {e}")
                fetch_errors_occurred += 1
                scan_results_temp[container_id] = {
                     **result_data, # Keep existing data
                     'status': 'error_fetching_logs',
                     'last_checked': datetime.now(timezone.utc),
                     'error_detail': str(e)
                     # Keep existing db_id link on fetch error
                }
            except Exception as e:
                logger.exception(f"Unexpected error processing container {container_name} ({container_id[:12]}):")
                fetch_errors_occurred += 1
                scan_results_temp[container_id] = {
                     **result_data, # Keep existing data
                     'status': 'error_fetching_logs', # Generic error status
                     'last_checked': datetime.now(timezone.utc),
                     'error_detail': f"Unexpected error: {e}"
                     # Keep existing db_id link on generic error
                }

        # --- Bulk Update Cache After Loop ---
        ids_to_remove = set()
        with container_statuses_lock:
            for cid, data in scan_results_temp.items():
                if data.get('remove'):
                    ids_to_remove.add(cid)
                elif cid in container_statuses: # Check if still exists
                    container_statuses[cid].update(data)

            # Remove containers marked as stopped/not found
            for cid in ids_to_remove:
                if cid in container_statuses:
                    logger.info(f"Removing stopped container {container_statuses[cid]['name']} ({cid[:12]}) from cache.")
                    del container_statuses[cid]

            # Also remove any containers that are in the cache but weren't seen running now
            cached_ids = set(container_statuses.keys())
            stopped_ids = cached_ids - running_container_ids_now # Use IDs from start of scan
            for cid in stopped_ids:
                 if cid not in ids_to_remove: # Avoid double logging if already marked
                    # Ensure the container still exists in the dict before trying to access name
                    if cid in container_statuses:
                        logger.info(f"Removing stopped container {container_statuses[cid].get('name','UNKNOWN')} ({cid[:12]}) from cache (not seen running).")
                        del container_statuses[cid]
                    else:
                        logger.warning(f"Attempted to remove stopped container {cid[:12]} but it was already gone from cache.")


            # Re-sort the dictionary after updates/removals
            sorted_items = sorted(container_statuses.items(), key=lambda item: item[1].get('name', '').lower()) # Safe sort
            container_statuses.clear()
            container_statuses.update(dict(sorted_items))
            logger.debug(f"Container status cache updated after scan. Size: {len(container_statuses)}")


    except ConnectionError as e: # Handle failure to get Docker client initially
        logger.error(f"Log scan aborted: {e}")
        with scan_status_lock:
            scan_status['running'] = False
            scan_status['last_run_status'] = f"Scan failed: Could not connect to Docker ({e})"
        return # Don't proceed if Docker client failed
    except Exception as e:
        logger.exception("Unexpected error during the main scan loop:")
        with scan_status_lock:
            scan_status['last_run_status'] = f"Scan failed: Unexpected error ({e})"
            # Ensure running is set to False even if loop errors out
            scan_status['running'] = False
        # Ensure client is closed if obtained
        if docker_client: docker_client.close() # Use existing variable name
        return # Abort on major loop error

    finally:
        # Close Docker client if it was opened
        if docker_client: # Use existing variable name
            try:
                docker_client.close()
                logger.debug("Docker client closed after log scan.")
            except Exception as ce:
                 logging.warning(f"Error closing Docker client after scan: {ce}")

        # --- Final Scan Status Update ---
        final_status_msg = f"Scan finished @ {datetime.now(get_display_timezone()).strftime('%H:%M:%S')}. Processed: {containers_processed}."
        error_counts = []
        if fetch_errors_occurred: error_counts.append(f"Fetch: {fetch_errors_occurred}")
        if analysis_errors_occurred: error_counts.append(f"Analysis: {analysis_errors_occurred}")
        if db_errors_occurred: error_counts.append(f"DB: {db_errors_occurred}")
        if error_counts:
             final_status_msg += f" Errors - {', '.join(error_counts)}."

        with scan_status_lock:
            scan_status['running'] = False # Ensure running is false
            scan_status['last_run_status'] = final_status_msg
            # Update next run time from scheduler (safer here)
            try:
                # Access scheduler attached to app context if available
                scheduler_instance = getattr(app, 'scheduler', None)
                job = scheduler_instance.get_job('docker_log_scan_job') if scheduler_instance else None
                if job and job.next_run_time:
                    scan_status['next_run_time'] = job.next_run_time
                else:
                    scan_status['next_run_time'] = None # Handle job not found or paused/stopped
            except Exception as e:
                logger.error(f"Could not update next run time in scan status: {e}")
                scan_status['next_run_time'] = None

        logger.info(final_status_msg)


# <<< START REPLACEMENT: update_ai_health_summary FUNCTION (Optimized + History Save) >>>
def update_ai_health_summary():
    """Background task to generate AI health summary based on recent abnormalities."""
    current_thread = threading.current_thread()
    logger.info(f"Starting scheduled AI health summary update... (Thread: {current_thread.name})")
    summary_start_time = datetime.now(timezone.utc)
    final_summary = None # Default success summary
    final_error = None # Default error message
    status_for_db = 'unknown' # Status for the history record

    # --- Configuration for Summary Optimization ---
    MAX_SUMMARY_ISSUES = 30  # Max number of unresolved issues to include
    ANALYSIS_TRUNCATE_LENGTH = 150 # Max characters of analysis text per issue
    # --- End Configuration ---

    try:
        # --- Get Settings ---
        settings_local = {}
        with settings_lock:
            # Copy required settings
            settings_local = {
                'summary_interval_hours': app_settings.get('summary_interval_hours', 12),
                'ollama_model': app_settings.get('ollama_model'),
                'ollama_api_url': app_settings.get('ollama_api_url')
            }

        summary_hours = settings_local['summary_interval_hours']
        model_to_use = settings_local['ollama_model']
        ollama_url = settings_local['ollama_api_url']

        # Check prerequisites
        if not ollama_url:
            raise ValueError("Ollama API URL is not configured.")
        if not hasattr(db, 'get_recent_abnormalities'):
            raise RuntimeError("DB function 'get_recent_abnormalities' missing.")
        if not hasattr(analyzer, 'summarize_recent_abnormalities'):
            raise RuntimeError("Analyzer function 'summarize_recent_abnormalities' missing.")

        # --- Data Fetching and Preparation ---
        logger.debug(f"Fetching abnormalities from last {summary_hours} hours for summary.")
        all_recent_abnormalities = db.get_recent_abnormalities(hours=summary_hours)
        logger.info(f"Fetched {len(all_recent_abnormalities)} total abnormalities from DB for summary.")

        unresolved_issues = [r for r in all_recent_abnormalities if isinstance(r, dict) and r.get('status') == 'unresolved']
        logger.info(f"Filtered down to {len(unresolved_issues)} unresolved issues for summary.")

        def get_sort_key(item):
           ts = item.get('last_detected_timestamp')
           # Ensure comparison works even if timestamp is None or not datetime
           return ts if isinstance(ts, datetime) else datetime.min.replace(tzinfo=timezone.utc)
        unresolved_issues.sort(key=get_sort_key, reverse=True)

        limited_issues = unresolved_issues[:MAX_SUMMARY_ISSUES]
        if len(unresolved_issues) > MAX_SUMMARY_ISSUES:
             logging.info(f"Limiting summary input to the latest {MAX_SUMMARY_ISSUES} unresolved issues.")

        # --- Format Input for AI ---
        if not limited_issues:
            summary_input_data = "No unresolved issues detected recently."
            # Set final_summary directly, don't call AI if nothing to summarize
            final_summary = f"No unresolved issues detected in the last {summary_hours} hours. System appears stable."
            status_for_db = 'success' # Treat as success, just nothing to report
            logger.info("No unresolved issues; using standard 'stable' summary.")
            analysis_error_msg = None # Ensure no error msg in this case
        else:
            formatted_issue_summaries = []
            for issue in limited_issues:
                container_name = issue.get('container_name', 'UnknownContainer')
                analysis_text = issue.get('ollama_analysis', 'Analysis missing')
                if analysis_text.startswith("ERROR:"): analysis_text = analysis_text[len("ERROR:"):].strip()
                truncated_analysis = analysis_text[:ANALYSIS_TRUNCATE_LENGTH]
                if len(analysis_text) > ANALYSIS_TRUNCATE_LENGTH: truncated_analysis += "..."
                formatted_issue_summaries.append(f"- Container: {container_name}, Issue: {truncated_analysis}")
            summary_input_data = "\n".join(formatted_issue_summaries)

            # --- Prepare Prompt ---
            summary_prompt = f"""Analyze the following list of recent unresolved container issues.
Provide a concise (2-4 sentences) health summary identifying the most significant types of active problems.
**Crucially, for each significant problem type mentioned, list the primary container name(s) experiencing it.**
If the list is empty or says 'No unresolved issues detected', state that the system appears healthy. Avoid generic descriptions; focus on specific issues and their locations.

Recent Unresolved Issues:
{summary_input_data}

---
Health Summary (mentioning affected containers):"""

            # --- Call Analyzer ---
            logger.info(f"Generating health summary using Ollama model {model_to_use}...")
            # analyzer.summarize_recent_abnormalities now returns only summary text or error text
            analysis_result_text = analyzer.summarize_recent_abnormalities(
                abnormalities_data=None, # Data is in prompt
                api_url=ollama_url,
                model_name=model_to_use,
                prompt_template=summary_prompt
            )

            # Check the result format
            if analysis_result_text.startswith("Error:"):
                 # Error occurred during analysis
                 final_error = analysis_result_text # Use the error string from analyzer
                 status_for_db = 'error'
                 logger.error(f"AI Summary generation failed: {final_error}")
            elif analysis_result_text:
                 # Success
                 final_summary = analysis_result_text
                 status_for_db = 'success'
                 logger.info("AI Health Summary generated successfully.")
            else:
                 # Unexpected: No error, but no summary text
                 final_error = "AI analysis returned no summary text and no error."
                 status_for_db = 'error'
                 logger.error(final_error)

    except ValueError as ve: # Catch specific error for missing URL
        final_error = str(ve)
        status_for_db = 'skipped' # Treat missing config as skipped
        logger.error(f"AI Summary skipped: {final_error}")
    except RuntimeError as re: # Catch specific error for missing DB/analyzer function
        final_error = str(re)
        status_for_db = 'error'
        logger.error(f"AI Summary error: {final_error}")
    except Exception as e: # Catch all other errors during the process
        logger.exception("Unhandled error during AI health summary update task:")
        final_error = f"An unexpected error occurred: {e}"
        status_for_db = 'error'

    finally:
        # --- Update Global Cache ---
        try:
            # Use app context if needed, but direct access might work in background task
            with app.ai_summary_lock: # Assuming lock is accessible globally or via app
                if final_error:
                    app.ai_health_summary['summary'] = "Error generating health summary."
                    app.ai_health_summary['error'] = final_error
                else:
                    app.ai_health_summary['summary'] = final_summary
                    app.ai_health_summary['error'] = None
                app.ai_health_summary['last_updated'] = summary_start_time
        except Exception as cache_err:
            logger.exception(f"Failed to update AI summary cache: {cache_err}")

        # --- Save to DB History ---
            try:
                if hasattr(db, 'add_summary_history'):
                    # Call function without the status argument
                    db.add_summary_history(
                        timestamp=summary_start_time,
                        summary_text=final_summary if status_for_db == 'success' else None,
                        error_text=final_error if status_for_db != 'success' else None
                        # Removed status=status_for_db argument
                    )
                else:
                    logger.error("Cannot save summary history: db.add_summary_history function not found.")
            except Exception as history_save_err:
                 logger.exception(f"Failed to save summary result to history database: {history_save_err}")

    logger.info("AI health summary update finished.")
# <<< END REPLACEMENT: update_ai_health_summary FUNCTION (Optimized + History Save) >>>


# --- Scheduler Setup ---
scheduler = BackgroundScheduler(daemon=True, timezone=str(get_display_timezone()))
# Attach scheduler AFTER definition
app.scheduler = scheduler
logger.info(f"Scheduler initialized with timezone: {scheduler.timezone}")

# Attach background task functions to app context so blueprints can trigger them
app.scan_docker_logs_task = scan_docker_logs
app.update_ai_health_summary_task = update_ai_health_summary
logger.info("Attached background task functions to app context.")

# --- Register Blueprints (after state/functions attached) ---
# Note: url_prefix ensures API/Scheduler routes are distinct
app.register_blueprint(ui_bp, url_prefix='/')
app.register_blueprint(api_bp, url_prefix='/api')
app.register_blueprint(scheduler_bp, url_prefix='/scheduler')
logger.info("Registered Flask blueprints (ui, api, scheduler).")


# --- Signal Handling for Graceful Shutdown ---
def signal_handler(signum, frame):
    logger.warning(f"Received signal {signum}. Initiating graceful shutdown...")
    # Stop the scheduler first to prevent new jobs
    if scheduler and scheduler.running:
        try:
            # Don't wait for jobs to complete, just shut down triggering
            scheduler.shutdown(wait=False)
            logger.info("Scheduler shut down.")
        except Exception as e:
            logger.error(f"Error shutting down scheduler: {e}")

    # Allow some time for current requests/tasks to potentially finish? (Optional)
    # time.sleep(2)

    # Exit the application
    logger.info("Exiting Geordi application.")
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)
logger.info("Registered signal handlers for SIGTERM and SIGINT.")


# --- Main Execution ---
if __name__ == '__main__':
    logger.info("--- Starting Geordi Log Monitor ---")

    # Initialize Database Schema (if needed)
    try:
        logger.info("Initializing database...")
        db.init_db() # Ensure tables exist
        logger.info("Database initialization check complete.")
    except Exception as e:
        logger.exception("CRITICAL: Failed to initialize database! Cannot continue.")
        sys.exit(1) # Exit if DB init fails

    # Load settings from DB into cache
    load_settings() # Populates app_settings cache

    # Fetch initial list of Ollama models based on loaded settings
    fetch_initial_ollama_models() # Populates available_ollama_models cache

    # Get initial container statuses
    populate_initial_statuses() # Populates container_statuses cache

    # --- Schedule Background Tasks ---
    scan_interval_minutes = 5 # Default fallback
    summary_interval_hours = 12 # Default fallback
    try:
        with settings_lock:
             # Use .get for safety, default to strings before conversion
             scan_interval_str = app_settings.get('scan_interval_minutes', '5')
             summary_interval_str = app_settings.get('summary_interval_hours', '12')
             # Convert safely
             try: scan_interval_minutes = int(scan_interval_str)
             except: scan_interval_minutes = 5
             try: summary_interval_hours = int(summary_interval_str)
             except: summary_interval_hours = 12

             # Ensure positive intervals
             if scan_interval_minutes <= 0:
                 logger.warning(f"Scan interval ({scan_interval_str}) invalid, using 5 minutes.")
                 scan_interval_minutes = 5
             if summary_interval_hours <= 0:
                 logger.warning(f"Summary interval ({summary_interval_str}) invalid, using 12 hours.")
                 summary_interval_hours = 12

        # Get current time in scheduler's timezone
        scheduler_tz = scheduler.timezone
        now_local = datetime.now(scheduler_tz)

        # Add Scan Job
        # Delay first run slightly to ensure app is fully up
        first_scan_delay_seconds = 15
        first_scan_time = now_local + timedelta(seconds=first_scan_delay_seconds)
        scheduler.add_job(
            scan_docker_logs,
            trigger=IntervalTrigger(minutes=scan_interval_minutes),
            id='docker_log_scan_job',
            name='Docker Log Scan',
            replace_existing=True,
            next_run_time=first_scan_time, # Start slightly delayed
            max_instances=1, # Prevent multiple scans running concurrently if one overruns
            misfire_grace_time=60 # Allow 1 minute grace period if scheduler is busy
        )
        logger.info(f"Scheduled Docker log scan to run every {scan_interval_minutes} minutes, starting around {first_scan_time.strftime('%Y-%m-%d %H:%M:%S %Z')}.")

        # Add Summary Job
        # Delay first summary slightly more
        first_summary_delay_minutes = 2
        first_summary_time = now_local + timedelta(minutes=first_summary_delay_minutes)
        scheduler.add_job(
            update_ai_health_summary,
            trigger=IntervalTrigger(hours=summary_interval_hours),
            id='ai_summary_job',
            name='AI Health Summary Update',
            replace_existing=True,
            next_run_time=first_summary_time, # Start slightly delayed
            max_instances=1,
            misfire_grace_time=300 # Allow 5 minutes grace period
        )
        logger.info(f"Scheduled AI health summary update to run every {summary_interval_hours} hours, starting around {first_summary_time.strftime('%Y-%m-%d %H:%M:%S %Z')}.")

        # Start the scheduler
        scheduler.start()
        logger.info("APScheduler started.")

        # Initial status update for scan job
        with scan_status_lock:
            job = scheduler.get_job('docker_log_scan_job')
            if job and job.next_run_time:
                 scan_status['next_run_time'] = job.next_run_time
                 scan_status['last_run_status'] = "Scheduler started, initial scan pending."
            else:
                 scan_status['last_run_status'] = "Scheduler started, but scan job not found?!"


    except Exception as e:
        logger.exception("Failed to schedule background tasks!")
        # Decide if this is critical - perhaps the app can run without scheduling?
        # For now, we log the error and continue. User can trigger manually via UI/API.
        if scheduler and scheduler.running:
             logger.info("Attempting to shutdown scheduler due to setup error.")
             scheduler.shutdown(wait=False)

    # --- Run Flask App ---
    # Use Waitress for production, Flask dev server for debug
    use_waitress = os.environ.get("USE_WAITRESS", "true").lower() == "true"

    if use_waitress:
        try:
            from waitress import serve
            logger.info(f"Starting Waitress server on 0.0.0.0:{PORT}...")
            serve(app, host='0.0.0.0', port=PORT, threads=10) # Adjust threads as needed
        except ImportError:
            logger.warning("Waitress not installed. Falling back to Flask development server.")
            # Flask's development server is not recommended for production
            app.run(host='0.0.0.0', port=PORT, debug=False, use_reloader=False) # use_reloader=False is crucial with APScheduler
        except Exception as ws_err:
             logger.exception(f"Waitress server failed to start:")
             logger.info("Attempting Flask dev server fallback...")
             app.run(host='0.0.0.0', port=PORT, debug=False, use_reloader=False)

    else:
         logger.info(f"Starting Flask development server on 0.0.0.0:{PORT} (USE_WAITRESS != true)...")
         # Set debug=True only if specifically enabled via env var, e.g., FLASK_DEBUG=1
         flask_debug = os.environ.get("FLASK_DEBUG", "0") == "1"
         if flask_debug: logger.warning("Flask DEBUG mode is ON. Do not use in production.")
         app.run(host='0.0.0.0', port=PORT, debug=flask_debug, use_reloader=False) # use_reloader=False is crucial

    logger.info("--- Geordi Log Monitor Stopped ---")
