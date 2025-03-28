# app.py
import os
import logging
from datetime import datetime, timedelta
from threading import Lock
from flask import Flask, render_template, request, redirect, url_for, flash
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import pytz # For timezone handling

# --- Logging Setup ---
# Ensure logging is configured before other imports that might use it
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(), # Allow setting log level via ENV
    format='%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s' # Include thread name
)

# --- Local Imports ---
try:
    import db
    import analyzer
except ImportError as e:
    logging.critical(f"Failed to import local modules (db, analyzer): {e}")
    logging.critical("Ensure db.py and analyzer.py are in the same directory as app.py.")
    exit(1) # Exit if essential modules are missing

# --- Configuration ---
SCAN_INTERVAL_MINUTES = int(os.environ.get("SCAN_INTERVAL_MINUTES", "10"))
OLLAMA_API_URL = analyzer.OLLAMA_API_URL # Get from analyzer module
# DEFAULT_OLLAMA_MODEL now comes from analyzer
LOG_LINES_TO_FETCH = analyzer.LOG_LINES_TO_FETCH # Get from analyzer module
# Set timezone for scheduler (reads TZ env var or defaults to UTC)
SCHEDULER_TIMEZONE = os.environ.get("TZ", "UTC")

# --- Flask App Initialization ---
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change_this_in_production_please")
if app.secret_key == "change_this_in_production_please":
    logging.warning("FLASK_SECRET_KEY is set to its default value. Please change this in your environment for security.")

# --- Global State Variables ---
container_statuses = {} # Holds current status of all scanned containers
container_statuses_lock = Lock() # Protects access to container_statuses

scan_status = { # Holds information about the last/next scan
    "last_run_time": None,
    "last_run_status": "Not run yet",
    "next_run_time": None,
    "running": False
}

available_ollama_models = [] # List of model names found via API
# Initialize current model from environment (via analyzer), allow it to be changed
current_ollama_model = analyzer.DEFAULT_OLLAMA_MODEL
models_lock = Lock() # Protects access to model list and current model selection

# --- Helper Function ---
def get_display_timezone():
    """Gets a pytz timezone object based on SCHEDULER_TIMEZONE config."""
    try:
        return pytz.timezone(SCHEDULER_TIMEZONE)
    except pytz.exceptions.UnknownTimeZoneError:
        logging.warning(f"Invalid SCHEDULER_TIMEZONE '{SCHEDULER_TIMEZONE}'. Using UTC.")
        return pytz.utc # Fallback to UTC

# --- Background Scanning Task ---
def scan_docker_logs():
    """Scans containers, updates state, logs abnormalities."""
    global container_statuses, available_ollama_models, current_ollama_model

    # Check if previous scan is still running
    if scan_status["running"]:
        logging.warning("Scan task skipped: previous run still active.")
        return

    scan_status["running"] = True
    start_time = datetime.now()
    scan_status["last_run_time"] = start_time
    logging.info("Starting Docker log scan...")

    current_scan_results = {}
    found_issues_this_scan = 0
    containers_scanned_count = 0
    error_message = None
    scan_timezone = get_display_timezone()

    # --- Fetch Available Ollama Models ---
    try:
        fetched_models = analyzer.get_ollama_models()
        with models_lock:
            available_ollama_models = fetched_models
            # Validate current_ollama_model against fetched list
            if available_ollama_models and current_ollama_model not in available_ollama_models:
                logging.warning(f"Current model '{current_ollama_model}' not found in fetched list {available_ollama_models}.")
                # Attempt to reset to default or first available model
                if analyzer.DEFAULT_OLLAMA_MODEL in available_ollama_models:
                    logging.info(f"Resetting model to default: '{analyzer.DEFAULT_OLLAMA_MODEL}'")
                    current_ollama_model = analyzer.DEFAULT_OLLAMA_MODEL
                elif available_ollama_models:
                    logging.info(f"Resetting model to first available: '{available_ollama_models[0]}'")
                    current_ollama_model = available_ollama_models[0]
                else:
                    logging.error("Cannot reset model: Default not found and no models available.")
            elif not available_ollama_models:
                 logging.warning("Ollama API returned no available models.")

    except Exception as model_fetch_err:
         logging.error(f"Failed to fetch/update available models list: {model_fetch_err}")
         # Continue scan with potentially outdated model list/selection

    # --- Connect to Docker ---
    client = analyzer.get_docker_client()
    if not client:
        error_message = f"Failed to connect to Docker daemon at {datetime.now(scan_timezone).strftime('%Y-%m-%d %H:%M:%S %Z')}"
        scan_status["last_run_status"] = error_message
        scan_status["running"] = False
        logging.error(error_message)
        return

    # --- Scan Containers ---
    try:
        running_containers = client.containers.list()
        containers_scanned_count = len(running_containers)
        logging.info(f"Found {containers_scanned_count} running containers.")

        if not running_containers:
             logging.info("No running containers found to scan.")
             with container_statuses_lock: # Clear status if no containers
                container_statuses = {}
        else:
            for container in running_containers:
                container_id = container.id
                container_name = container.name
                logging.debug(f"Scanning container: {container_name} ({container_id[:12]})")

                current_scan_results[container_id] = {
                    'name': container_name, 'id': container_id, 'status': 'pending',
                    'details': None, 'db_id': None
                }

                logs = analyzer.fetch_container_logs(container)
                if logs is None:
                    logging.warning(f"Failed to fetch logs for {container_name} ({container_id[:12]})")
                    current_scan_results[container_id]['status'] = 'error_fetching_logs'
                    current_scan_results[container_id]['details'] = {'analysis': 'Failed to fetch logs', 'snippet': ''}
                    continue

                # Get the currently selected model safely
                with models_lock:
                    model_to_use_now = current_ollama_model

                analysis_result = analyzer.analyze_logs_with_ollama(logs, model_to_use_now)

                # Process analysis result
                if analysis_result != "NORMAL" and not analysis_result.startswith("ERROR:"):
                    found_issues_this_scan += 1
                    logging.warning(f"Abnormality detected in {container_name}: {analysis_result}")
                    log_snippet = analyzer.extract_log_snippet(analysis_result, logs)
                    try:
                        db.add_or_update_abnormality(container_name, container_id, log_snippet, analysis_result)
                    except Exception as db_err:
                         logging.error(f"DB Error logging abnormality for {container_name}: {db_err}")
                         # Continue scan, but flag this container potentially
                         current_scan_results[container_id]['status'] = 'error_db_log'
                         current_scan_results[container_id]['details'] = {'analysis': 'Failed to log abnormality to DB', 'snippet': ''}
                         continue # Skip trying to get db_id

                    db_id = db.get_latest_unresolved_abnormality_id(container_id, log_snippet)
                    current_scan_results[container_id].update({
                        'status': 'unhealthy',
                        'details': {'analysis': analysis_result, 'snippet': log_snippet, 'timestamp': datetime.now(scan_timezone)},
                        'db_id': db_id
                    })

                elif analysis_result.startswith("ERROR:"):
                     logging.error(f"Analysis error for {container_name}: {analysis_result}")
                     current_scan_results[container_id].update({
                        'status': 'error_analysis',
                        'details': {'analysis': analysis_result, 'snippet': '(Analysis failed)'}, 'db_id': None
                     })
                else:
                     current_scan_results[container_id]['status'] = 'healthy'
                     logging.debug(f"Container {container_name} logs appear normal.")

        # --- Update Global State ---
        logging.info(f"Scan processed {containers_scanned_count} containers. Preparing to update global state.")
        with container_statuses_lock:
            sorted_results = dict(sorted(current_scan_results.items(), key=lambda item: item[1]['name'].lower()))
            container_statuses = sorted_results
            logging.info(f"Global state updated. Size: {len(container_statuses)}")
            if container_statuses: # Log sample if state is not empty
                 first_key = list(container_statuses.keys())[0]
                 logging.debug(f"Sample after update - {first_key}: {container_statuses[first_key]['status']}")
            elif running_containers: # Log if containers were found but state is empty (shouldn't happen)
                 logging.warning("Global state is empty after processing running containers.")


        scan_status["last_run_status"] = (
            f"Completed at {datetime.now(scan_timezone).strftime('%Y-%m-%d %H:%M:%S %Z')}. "
            f"Scanned {containers_scanned_count} containers. "
            f"{found_issues_this_scan} unhealthy found/updated this scan."
        )
        logging.info(scan_status["last_run_status"]) # Log the final status message

    except Exception as e:
        logging.exception("Unhandled error during scan task execution:") # Log full traceback
        error_message = f"Error during scan execution at {datetime.now(scan_timezone).strftime('%Y-%m-%d %H:%M:%S %Z')}: {e}"
        scan_status["last_run_status"] = error_message
    finally:
        if client:
            try:
                client.close()
            except Exception as client_close_err:
                logging.warning(f"Error closing Docker client: {client_close_err}")
        scan_status["running"] = False
        # Update next run time
        try:
            # Ensure scheduler is running before getting job
            if scheduler.running:
                job = scheduler.get_job('docker_log_scan_job')
                if job and job.next_run_time:
                    scan_status["next_run_time"] = job.next_run_time
                else:
                    scan_status["next_run_time"] = None
                    if not job: logging.warning("Scan job not found in scheduler.")
            else:
                 scan_status["next_run_time"] = None
                 logging.warning("Scheduler not running, cannot determine next run time.")
        except Exception as e:
            logging.error(f"Could not get next run time: {e}")
            scan_status["next_run_time"] = None

# --- Flask Routes ---
@app.route('/')
def index():
    """Renders the main dashboard page."""
    # Get current state under locks
    with container_statuses_lock:
        current_statuses = container_statuses.copy()
    with models_lock:
        models_list = list(available_ollama_models) # Copy list
        selected_model = current_ollama_model

    logging.debug(f"Rendering index page. Statuses: {len(current_statuses)}, Models: {len(models_list)}, Selected: {selected_model}")
    if current_statuses:
         first_key = list(current_statuses.keys())[0]
         logging.debug(f"Sample during render - {first_key}: {current_statuses[first_key]['status']}")

    # Format next scan time for display
    next_run_time_str = "N/A"
    display_timezone = get_display_timezone() # Get timezone for display
    if scan_status["next_run_time"]:
         try:
            # Assume next_run_time is already timezone-aware from scheduler
            next_run_time_local = scan_status["next_run_time"].astimezone(display_timezone)
            next_run_time_str = next_run_time_local.strftime('%Y-%m-%d %H:%M:%S %Z')
         except Exception as tz_err:
            logging.warning(f"Error converting next run time to display timezone: {tz_err}")
            # Fallback to showing original timezone if conversion fails
            if hasattr(scan_status["next_run_time"], 'strftime'):
                 next_run_time_str = scan_status["next_run_time"].strftime('%Y-%m-%d %H:%M:%S %Z')
            else:
                 next_run_time_str = "Invalid Time"

    is_running = scan_status["running"] # Read the boolean value from the global scan_status dict

    return render_template('index.html',
                           container_statuses=current_statuses,
                           scan_status=scan_status["last_run_status"],
                           next_scan_time=next_run_time_str,
                           timezone=str(display_timezone), # Pass timezone name string
                           available_models=models_list,
                           current_model=selected_model,
			   scan_is_running=is_running)

@app.route('/set_model', methods=['POST'])
def set_model():
    """Handles the form submission to change the active Ollama model."""
    global current_ollama_model
    selected = request.form.get('selected_model')

    if not selected:
        flash('No model selected.', 'error')
        return redirect(url_for('index'))

    with models_lock:
        # Check if selected model is valid (optional but recommended)
        # Fetching models again here would be more robust but adds latency
        if available_ollama_models and selected not in available_ollama_models:
             logging.warning(f"User selected model '{selected}' which is not in the last fetched list {available_ollama_models}.")
             # flash(f'Warning: Model "{selected}" was not found in the last scan.', 'warning')
             # Allow setting it - maybe it was just added to Ollama

        if selected != current_ollama_model:
             logging.info(f"User changed Ollama model from '{current_ollama_model}' to '{selected}'")
             current_ollama_model = selected
             flash(f'Ollama model set to "{selected}". Change applies on the next scan.', 'success')
        else:
             flash(f'Ollama model is already set to "{selected}".', 'info')

    return redirect(url_for('index'))


@app.route('/manage/<int:abnormality_id>', methods=['GET', 'POST'])
def manage_abnormality(abnormality_id):
    """Displays and handles updates for a specific abnormality record."""
    abnormality = db.get_abnormality_by_id(abnormality_id)
    if not abnormality:
        flash(f'Abnormality with ID {abnormality_id} not found.', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        new_status = request.form.get('new_status')
        notes = request.form.get('notes', '').strip() # Get notes, default to empty string

        if new_status not in ['resolved', 'ignored', 'unresolved']:
            flash('Invalid status provided.', 'error')
        else:
            success = db.update_abnormality_status(abnormality_id, new_status, notes if notes else None) # Pass notes correctly
            if success:
                flash(f'Abnormality marked as {new_status}.', 'success')
                # In-memory state ('unhealthy' dot) will update on the next scan if issue persists/resolves.
                return redirect(url_for('index')) # Redirect back to dashboard
            else:
                flash('Failed to update abnormality status.', 'error')
        # If POST fails validation or DB update, re-render the manage page with current data
        # Re-fetch abnormality data in case notes were partially updated before failure? No, keep simple.
        return render_template('manage.html', abnormality=abnormality)

    # If GET request, just display the page
    return render_template('manage.html', abnormality=abnormality)


# --- Scheduler Setup ---
# This section must have NO indentation
scheduler = BackgroundScheduler(daemon=True, timezone=SCHEDULER_TIMEZONE)

def setup_scheduler():
    """Configures and starts the background task scheduler."""
    global SCHEDULER_TIMEZONE # Allow modification if TZ was invalid
    display_timezone = get_display_timezone() # Get validated timezone object

    logging.info(f"Scheduling log scan job every {SCAN_INTERVAL_MINUTES} mins in timezone {display_timezone}.")
    try:
        scheduler.add_job(
            scan_docker_logs,
            trigger=IntervalTrigger(minutes=SCAN_INTERVAL_MINUTES),
            id='docker_log_scan_job',
            name='Docker Log Scan',
            replace_existing=True,
            next_run_time=datetime.now(display_timezone) + timedelta(seconds=15) # Start shortly after boot
        )
    except Exception as schedule_err:
        logging.critical(f"Failed to add scan job to scheduler: {schedule_err}")
        # Consider exiting if scheduling fails?
        return # Prevent scheduler start if job add fails

    # Determine initial next run time for display
    try:
        job = scheduler.get_job('docker_log_scan_job')
        if job and job.next_run_time:
             scan_status["next_run_time"] = job.next_run_time
             logging.info(f"First scan scheduled around: {job.next_run_time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        else:
            logging.error("Scan job added but could not retrieve next run time.")
    except Exception as e:
        logging.error(f"Could not get initial next run time: {e}")

    try:
        scheduler.start()
        logging.info("Scheduler started successfully.")
    except Exception as start_err:
         logging.critical(f"Failed to start scheduler: {start_err}")
         # Application might still run but scans won't happen

# --- Main Execution Guard ---
if __name__ == '__main__':
    logging.info("Starting Docker Log Monitor application...")
    # Database is initialized when db.py is imported.
    # Ensure timezone is valid before starting scheduler
    validated_tz = get_display_timezone()
    if str(validated_tz) != SCHEDULER_TIMEZONE: # If it defaulted to UTC
        SCHEDULER_TIMEZONE = str(validated_tz) # Update global variable if needed

    setup_scheduler() # Configure and start the scheduler

    logging.info(f"Ollama Endpoint: {OLLAMA_API_URL}")
    logging.info(f"Initial Ollama Model: {current_ollama_model}")
    logging.info(f"Log Lines per Container: {LOG_LINES_TO_FETCH}")
    logging.info(f"Scan Interval: {SCAN_INTERVAL_MINUTES} minutes")
    logging.info(f"Timezone: {SCHEDULER_TIMEZONE}")
    logging.info(f"Flask app running on http://0.0.0.0:5000")

    # Run the Flask app (consider using Waitress/Gunicorn for production)
    # from waitress import serve
    # serve(app, host='0.0.0.0', port=5000, threads=4) # Example using Waitress
    app.run(host='0.0.0.0', port=5000, debug=False) # debug=False is important for prod/scheduler
