# app.py
import os
import logging
from datetime import datetime, timedelta, timezone
import threading
from threading import Lock
import json
import secrets # For API key generation
import functools # For API key decorator
from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify # Added jsonify
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.jobstores.base import JobLookupError
import pytz
import docker
from routes.ui_routes import ui_bp
from utils import get_display_timezone

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
app.register_blueprint(ui_bp)
logging.info("Registered UI Blueprint")

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
        try: app_settings['log_lines_to_fetch'] = int(app_settings.get('log_lines_to_fetch', 100))
        except: app_settings['log_lines_to_fetch'] = 100
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
        analyzer.OLLAMA_API_URL = app_settings.get('ollama_api_url')
        analyzer.LOG_LINES_TO_FETCH = app_settings.get('log_lines_to_fetch')
        analyzer.DEFAULT_OLLAMA_MODEL = app_settings.get('ollama_model')
        logging.info(f"Settings loaded. API Key configured: {'Yes' if app_settings.get('api_key') else 'No'}")

# --- API Key Authentication Decorator ---
def require_api_key(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        provided_key = None
        # Use thread-safe read for settings
        with settings_lock:
            api_key_setting = app_settings.get('api_key')
        if not api_key_setting:
            logging.warning(f"API access denied: Key not configured (Endpoint: {request.endpoint}).")
            return jsonify({"error": "API access requires configuration."}), 403
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '): provided_key = auth_header.split('Bearer ')[1]
        elif request.headers.get('X-Api-Key'): provided_key = request.headers.get('X-Api-Key')
        elif request.args.get('api_key'): provided_key = request.args.get('api_key')
        if not provided_key: return jsonify({"error": "API key required."}), 401
        # Use secrets.compare_digest for timing attack resistance
        if provided_key and api_key_setting and secrets.compare_digest(provided_key, api_key_setting):
            return f(*args, **kwargs)
        else:
            logging.warning(f"Invalid API key provided for endpoint '{request.endpoint}'.")
            return jsonify({"error": "Invalid API key."}), 401
    return decorated_function

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
                    last_status, db_id = db.get_last_known_status(container_id)
                else:
                    logging.error("CRITICAL: db.py does not have the required 'get_last_known_status' function. Cannot perform initial status population.")
                    last_status, db_id = 'error_db_lookup', None # Mark as error if function missing
            except Exception as db_lookup_err:
                logging.error(f"Error calling db.get_last_known_status for {container_name[:12]}: {db_lookup_err}")
                last_status, db_id = 'db_error', None


            current_app_status = 'pending' # Default, will be updated based on DB lookup

            if last_status == 'unresolved':
                current_app_status = 'unhealthy'
                logging.info(f"Initial status for {container_name[:12]}: Unhealthy (based on DB ID {db_id})")
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
                'db_id': db_id # Store ID only if status is unhealthy
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

            # Only analyze if Ollama URL is configured
            analysis_result = "NORMAL" # Default if no analysis performed
            if ollama_url:
                analysis_result = analyzer.analyze_logs_with_ollama(logs, model_to_use, custom_prompt=analysis_prompt)
            else:
                logging.debug(f"Skipping Ollama analysis for {container_name[:12]} - URL not configured.")


            if analysis_result != "NORMAL" and not analysis_result.startswith("ERROR:"):
                log_snippet = analyzer.extract_log_snippet(analysis_result, logs)
                # Check DB status for this specific abnormality
                existing_status = db.get_abnormality_status(container_id, log_snippet) if hasattr(db, 'get_abnormality_status') else 'unknown'

                if existing_status in ['resolved', 'ignored']:
                    # Even if abnormality found, if it's resolved/ignored in DB, treat as healthy for dashboard
                    current_scan_results[container_id].update({'status': 'healthy', 'db_id': None});
                    logging.info(f"Abnormality found for {container_name[:12]} but marked '{existing_status}' in DB. Treating as healthy.")
                    continue

                # Only log and add to DB if not resolved/ignored
                found_issues_this_scan += 1; logging.warning(f"Abnormality detected: {container_name[:12]}: {analysis_result[:100]}...")
                try:
                    # Ensure function exists before calling
                    if hasattr(db, 'add_or_update_abnormality') and hasattr(db, 'get_latest_unresolved_abnormality_id'):
                        db.add_or_update_abnormality(container_name, container_id, log_snippet, analysis_result)
                        db_id = db.get_latest_unresolved_abnormality_id(container_id, log_snippet)
                        current_scan_results[container_id].update({'status': 'unhealthy', 'details': {'analysis': analysis_result, 'snippet': log_snippet, 'timestamp': datetime.now(scan_timezone)}, 'db_id': db_id})
                    else:
                         logging.error("DB function 'add_or_update_abnormality' or 'get_latest_unresolved_abnormality_id' missing.")
                         current_scan_results[container_id].update({'status': 'error_db_log', 'details': {'analysis': 'DB function missing', 'snippet': log_snippet}})
                except Exception as db_err: logging.error(f"DB Error logging abnormality for {container_name[:12]}: {db_err}"); current_scan_results[container_id].update({'status': 'error_db_log', 'details': {'analysis': f'DB Error: {db_err}', 'snippet': log_snippet}})
            elif analysis_result.startswith("ERROR:"):
                logging.error(f"Analysis Error for {container_name[:12]}: {analysis_result}"); current_scan_results[container_id].update({'status': 'error_analysis', 'details': {'analysis': analysis_result, 'snippet': '(Analysis Failed)'}})
            else: # NORMAL result (or skipped analysis)
                # If the status was previously 'unhealthy' or 'awaiting_scan', now it's 'healthy'
                if current_scan_results[container_id]['status'] != 'healthy':
                    logging.info(f"{container_name[:12]} status changing to 'healthy'.")
                current_scan_results[container_id]['status'] = 'healthy'
                current_scan_results[container_id]['db_id'] = None # Ensure no stale DB ID if now healthy
                current_scan_results[container_id]['details'] = None # Clear old details if healthy
                logging.debug(f"{container_name[:12]} OK.")


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


def update_ai_health_summary():
    global ai_health_summary
    summary_start_time = datetime.now(timezone.utc) # Record start time regardless of settings
    try:
        with settings_lock:
            summary_hours = int(app_settings.get('summary_interval_hours', 12))
            model_to_use = app_settings.get('ollama_model')
            ollama_url = app_settings.get('ollama_api_url')
            # Check if Ollama URL is configured
            if not ollama_url:
                logging.warning("AI Health Summary skipped: Ollama API URL is not configured.")
                with ai_summary_lock:
                    ai_health_summary["summary"] = "Skipped - Ollama URL not set."
                    ai_health_summary["error"] = "Configuration needed."
                    ai_health_summary["last_updated"] = summary_start_time
                return
    except Exception as e:
         logging.error(f"Summary settings error: {e}"); summary_hours = 12; model_to_use=db.DEFAULT_SETTINGS['ollama_model']
         # Need to check URL again in case of error
         with settings_lock: ollama_url = app_settings.get('ollama_api_url')
         if not ollama_url:
             logging.warning("AI Health Summary skipped due to settings error and missing Ollama URL.")
             with ai_summary_lock:
                 ai_health_summary["summary"] = "Skipped - Settings Error/Ollama URL missing."
                 ai_health_summary["error"] = "Configuration needed."
                 ai_health_summary["last_updated"] = summary_start_time
             return


    logging.info(f"Starting AI health summary generation (using last {summary_hours} hours).")
    try:
        # Ensure DB function exists
        if hasattr(db, 'get_recent_abnormalities'):
            recent_abnormalities = db.get_recent_abnormalities(hours=summary_hours)
            summary_text = analyzer.summarize_recent_abnormalities(recent_abnormalities, model_to_use)
            with ai_summary_lock:
                ai_health_summary["last_updated"] = summary_start_time
                if summary_text.startswith("Error:"):
                     ai_health_summary["summary"], ai_health_summary["error"] = "Summary generation failed.", summary_text;
                     logging.error(f"AI Summary generation failed: {summary_text}")
                else:
                     ai_health_summary["summary"], ai_health_summary["error"] = summary_text, None;
                     logging.info("AI Health Summary updated successfully.")
        else:
            logging.error("DB function 'get_recent_abnormalities' missing. Cannot generate summary.")
            with ai_summary_lock:
                 ai_health_summary["summary"] = "Failed - DB Function Missing"
                 ai_health_summary["error"] = "Internal error (DB function)"
                 ai_health_summary["last_updated"] = summary_start_time

    except Exception as e:
        logging.exception("Unhandled error during AI health summary task:")
        with ai_summary_lock:
             ai_health_summary["summary"] = "Failed - Internal Error"
             ai_health_summary["error"] = str(e)
             ai_health_summary["last_updated"] = summary_start_time


# --- Scheduler Control Routes ---
@app.route('/pause_schedule', methods=['POST'])
def pause_schedule():
    global scan_status # Need to update status
    try:
        if scheduler.running:
            scheduler.pause_job('docker_log_scan_job');
            logging.info("Schedule paused by user."); flash("Schedule paused.", "success");
            scan_status["next_run_time"] = None # Explicitly set next run time to None
            # Update last status message?
            # scan_status["last_run_status"] = "Paused by user."
        else: flash("Scheduler not running.", "warning")
    except JobLookupError: flash("Job 'docker_log_scan_job' not found to pause.", "warning")
    except Exception as e: logging.error(f"Error pausing schedule: {e}"); flash(f"Error pausing schedule: {e}", "error")
    finally: return redirect(url_for('ui.index'))

@app.route('/resume_schedule', methods=['POST'])
def resume_schedule():
    global scan_status # Need to update status
    try:
        if scheduler.running:
            with settings_lock: scan_interval = app_settings.get('scan_interval_minutes', 180)
            next_run_time = datetime.now(get_display_timezone()) + timedelta(seconds=5)
            scheduler.reschedule_job(
                'docker_log_scan_job',
                trigger=IntervalTrigger(minutes=scan_interval),
                next_run_time=next_run_time
            )
            scan_status["next_run_time"] = next_run_time # Update status display immediately
            logging.info(f"Schedule resumed by user. Next scan at {next_run_time.strftime('%H:%M:%S %Z')}.")
            flash("Schedule resumed.", "success")
        else: flash("Scheduler not running.", "warning")
    except JobLookupError: flash("Job 'docker_log_scan_job' not found to resume.", "warning")
    except Exception as e: logging.error(f"Error resuming schedule: {e}"); flash(f"Error resuming schedule: {e}", "error")
    finally: return redirect(url_for('ui.index'))

@app.route('/stop_current_scan', methods=['POST'])
def stop_current_scan():
    if scan_status["running"]: stop_scan_event.set(); flash("Stop signal sent to running scan.", "info");
    else: flash("No scan is currently running.", "info");
    return redirect(url_for('ui.index'))

@app.route('/trigger_scan', methods=['POST'])
def trigger_scan():
    try:
        if scan_status["running"]: flash("Scan is already running.", "warning")
        else:
            # Run in a separate thread immediately to avoid scheduler interaction/delay
            scan_thread = threading.Thread(target=scan_docker_logs, name="ManualScanThread", daemon=True)
            scan_thread.start()
            logging.info(f"Manual log scan triggered directly via UI."); flash("Manual scan triggered.", "success")
    except Exception as outer_e: logging.error(f"Unexpected error in trigger_scan route: {outer_e}"); flash("An unexpected error occurred while triggering scan.", "error")
    finally: return redirect(url_for('ui.index'))

@app.route('/trigger_summary', methods=['POST'])
def trigger_summary():
    try:
        # Run in a separate thread immediately
        summary_thread = threading.Thread(target=update_ai_health_summary, name="ManualSummaryThread", daemon=True)
        summary_thread.start()
        logging.info(f"Manual AI summary triggered directly via UI."); flash("Manual summary triggered.", "success")
    except Exception as outer_e: logging.error(f"Unexpected error in trigger_summary route: {outer_e}"); flash("An unexpected error occurred while triggering summary.", "error")
    finally: return redirect(url_for('ui.index'))

# --- API Endpoints ---
@app.route('/api/status', methods=['GET'])
def api_status():
    with ai_summary_lock: summary_data = ai_health_summary.copy()
    last_updated = summary_data.get('last_updated'); last_updated_iso = last_updated.isoformat(timespec='seconds')+"Z" if isinstance(last_updated, datetime) else None
    next_run = scan_status.get('next_run_time') # Use the global status
    next_run_iso = next_run.astimezone(timezone.utc).isoformat(timespec='seconds')+"Z" if isinstance(next_run, datetime) else None

    # Check scheduler job status more reliably
    job = None; is_paused = False
    if scheduler.running:
        try:
            job = scheduler.get_job('docker_log_scan_job')
            # Check if job exists and next_run_time is None (APScheduler's way of indicating pause)
            if job and job.next_run_time is None: is_paused = True
        except JobLookupError: job = None
        except Exception as e: logging.error(f"Error checking job status in API: {e}")


    return jsonify({ "ai_summary": summary_data.get('summary'), "ai_summary_last_updated_utc": last_updated_iso,
        "ai_summary_error": summary_data.get('error'), "scan_last_status_message": scan_status.get('last_run_status'),
        "scan_running": scan_status.get('running'), "scan_next_run_utc": next_run_iso,
        "scheduler_running": scheduler.running,
        "scan_job_paused": is_paused })

@app.route('/api/containers', methods=['GET'])
def api_containers():
    with container_statuses_lock:
        statuses_copy = {}
        for cid, data in container_statuses.items(): statuses_copy[cid] = { "id": data.get("id"), "name": data.get("name"), "status": data.get("status"), "db_id": data.get("db_id") if data.get("status") == 'unhealthy' else None }
    return jsonify(statuses_copy)

@app.route('/api/issues', methods=['GET'])
def api_issues():
    allowed_statuses = ['unresolved', 'resolved', 'ignored', 'all']; status_filter = request.args.get('status', 'unresolved').lower()
    if status_filter not in allowed_statuses: return jsonify({"error": f"Invalid status filter. Allowed: {', '.join(allowed_statuses)}"}), 400
    try:
        limit_str = request.args.get('limit', '100')
        limit = int(limit_str)
        if limit <= 0: raise ValueError()
    except ValueError:
        return jsonify({"error": "Invalid limit parameter. Must be a positive integer."}), 400

    # Ensure DB function exists
    if not hasattr(db, 'get_abnormalities_by_status'):
        logging.error("API Error: Database function 'get_abnormalities_by_status' is missing.")
        return jsonify({"error": "Internal server error (database function unavailable)."}), 500

    try:
        issues = db.get_abnormalities_by_status(status=status_filter, limit=limit)
        # Convert datetime objects to ISO format strings for JSON compatibility
        for issue in issues:
            if isinstance(issue.get('timestamp'), datetime):
                issue['timestamp'] = issue['timestamp'].isoformat()
            if isinstance(issue.get('last_seen'), datetime):
                 issue['last_seen'] = issue['last_seen'].isoformat()
        return jsonify(issues)
    except Exception as e:
        logging.error(f"Error fetching issues for API: {e}")
        return jsonify({"error": "Failed to retrieve issues from database."}), 500


@app.route('/api/scan/trigger', methods=['POST'])
@require_api_key
def api_trigger_scan():
    if scan_status["running"]: return jsonify({"message": "Scan already in progress."}), 409
    else:
        try:
            # Run in a separate thread immediately
            scan_thread = threading.Thread(target=scan_docker_logs, name="APIScanThread", daemon=True)
            scan_thread.start()
            logging.info(f"API triggered log scan directly"); return jsonify({"message": "Log scan triggered."}), 202
        except Exception as e: logging.error(f"Error triggering API scan: {e}"); return jsonify({"error": f"Trigger failed: {e}"}), 500

@app.route('/api/summary/trigger', methods=['POST'])
@require_api_key
def api_trigger_summary():
    try:
        # Run in a separate thread immediately
        summary_thread = threading.Thread(target=update_ai_health_summary, name="APISummaryThread", daemon=True)
        summary_thread.start()
        logging.info(f"API triggered AI summary directly"); return jsonify({"message": "Summary generation triggered."}), 202
    except Exception as e: logging.error(f"Error triggering API summary: {e}"); return jsonify({"error": f"Trigger failed: {e}"}), 500

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
            scan_docker_logs,
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
            update_ai_health_summary,
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
        logging.info("Attached shared state to Flask app object.")
        app.analyzer = analyzer
    # --- End attaching state ---

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
