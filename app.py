# app.py
import os
import logging
from datetime import datetime, timedelta
import threading # For Event object
from threading import Lock
from flask import Flask, render_template, request, redirect, url_for, flash
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.jobstores.base import JobLookupError # For pause/resume error handling
import pytz # For timezone handling

# --- Logging Setup ---
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format='%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s'
)

# --- Local Imports ---
try:
    import db
    import analyzer
except ImportError as e:
    logging.critical(f"Failed to import local modules (db, analyzer): {e}")
    logging.critical("Ensure db.py and analyzer.py are in the same directory as app.py or mounted correctly.")
    exit(1) # Exit if essential modules are missing

# --- Configuration ---
SCAN_INTERVAL_MINUTES = int(os.environ.get("SCAN_INTERVAL_MINUTES", "180")) # Default to 3 hours
OLLAMA_API_URL = analyzer.OLLAMA_API_URL
LOG_LINES_TO_FETCH = analyzer.LOG_LINES_TO_FETCH
# Use a specific TZ database name like 'America/Los_Angeles' for Pacific Time
SCHEDULER_TIMEZONE = os.environ.get("TZ", "America/Los_Angeles")

# --- Flask App Initialization ---
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change_this_in_production_please")
if app.secret_key == "change_this_in_production_please":
    logging.warning("FLASK_SECRET_KEY is set to its default value. Please change this.")

# --- Global State Variables ---
container_statuses = {}
container_statuses_lock = Lock()
scan_status = {"last_run_time": None, "last_run_status": "Not run yet", "next_run_time": None, "running": False}
available_ollama_models = []
current_ollama_model = analyzer.DEFAULT_OLLAMA_MODEL
models_lock = Lock()

# --- Event for signaling scan cancellation ---
stop_scan_event = threading.Event()

# --- Scheduler (Defined globally for access by routes) ---
scheduler = BackgroundScheduler(daemon=True)

# --- Helper Function ---
def get_display_timezone():
    """Gets a pytz timezone object based on SCHEDULER_TIMEZONE config."""
    global SCHEDULER_TIMEZONE # Allow modification if invalid TZ was set
    try:
        tz = pytz.timezone(SCHEDULER_TIMEZONE)
        return tz
    except pytz.exceptions.UnknownTimeZoneError:
        logging.warning(f"Invalid SCHEDULER_TIMEZONE '{SCHEDULER_TIMEZONE}'. Using UTC.")
        SCHEDULER_TIMEZONE = "UTC" # Correct the global if invalid
        return pytz.utc

# --- Background Scanning Task ---
def scan_docker_logs():
    """Scans containers, updates state, logs abnormalities. Checks for cancellation."""
    global container_statuses, available_ollama_models, current_ollama_model

    # Prevent overlapping runs
    if scan_status["running"]:
        logging.warning("Scan task skipped: previous run still active.")
        return

    scan_status["running"] = True
    stop_scan_event.clear() # Ensure event is clear at the start of a new scan
    logging.info("Starting Docker log scan...")
    start_time = datetime.now(); scan_status["last_run_time"] = start_time
    current_scan_results = {}; found_issues_this_scan = 0; containers_scanned_count = 0
    error_message = None; scan_timezone = get_display_timezone()

    # Fetch Available Ollama Models
    try:
        fetched_models = analyzer.get_ollama_models()
        with models_lock:
            available_ollama_models = fetched_models
            # Validate/reset current model if needed
            if available_ollama_models and current_ollama_model not in available_ollama_models:
                logging.warning(f"Current model '{current_ollama_model}' not in list {available_ollama_models}.")
                if analyzer.DEFAULT_OLLAMA_MODEL in available_ollama_models:
                    current_ollama_model = analyzer.DEFAULT_OLLAMA_MODEL
                    logging.info(f"Resetting model to default: '{current_ollama_model}'")
                elif available_ollama_models:
                    current_ollama_model = available_ollama_models[0]
                    logging.info(f"Resetting model to first available: '{current_ollama_model}'")
                else:
                    logging.error("Cannot reset model: No models available.")
            elif not available_ollama_models:
                 logging.warning("Ollama API returned no available models.")
    except Exception as model_fetch_err:
         logging.error(f"Failed to fetch/update available models list: {model_fetch_err}")

    # Connect to Docker
    client = analyzer.get_docker_client()
    if not client:
        error_message = f"Failed Docker connect at {datetime.now(scan_timezone).strftime('%Y-%m-%d %H:%M:%S %Z')}"
        scan_status["last_run_status"] = error_message; scan_status["running"] = False; logging.error(error_message); return

    scan_cancelled = False # Flag
    try:
        running_containers = client.containers.list()
        containers_scanned_count = len(running_containers)
        logging.info(f"Found {containers_scanned_count} running containers.")

        if not running_containers:
             logging.info("No running containers found to scan.")
             with container_statuses_lock: container_statuses = {}
        else:
            for container in running_containers:
                # Check cancellation flag at start of each container's processing
                if stop_scan_event.is_set():
                    logging.warning("Scan cancellation detected. Stopping container loop.")
                    scan_cancelled = True
                    break # Exit the loop

                container_id = container.id; container_name = container.name
                logging.debug(f"Scanning: {container_name} ({container_id[:12]})")
                current_scan_results[container_id] = {'name': container_name, 'id': container_id, 'status': 'pending', 'details': None, 'db_id': None}

                logs = analyzer.fetch_container_logs(container)
                if logs is None:
                     logging.warning(f"Failed fetch logs for {container_name}"); current_scan_results[container_id]['status'] = 'error_fetching_logs'; current_scan_results[container_id]['details'] = {'analysis': 'Failed logs', 'snippet': ''}; continue

                with models_lock: model_to_use_now = current_ollama_model
                analysis_result = analyzer.analyze_logs_with_ollama(logs, model_to_use_now)

                # Process analysis result
                if analysis_result != "NORMAL" and not analysis_result.startswith("ERROR:"):
                    found_issues_this_scan += 1; logging.warning(f"Abnormality: {container_name}: {analysis_result[:100]}..."); log_snippet = analyzer.extract_log_snippet(analysis_result, logs)
                    try: db.add_or_update_abnormality(container_name, container_id, log_snippet, analysis_result)
                    except Exception as db_err: logging.error(f"DB Err: {container_name}: {db_err}"); current_scan_results[container_id]['status'] = 'error_db_log'; continue
                    db_id = db.get_latest_unresolved_abnormality_id(container_id, log_snippet)
                    current_scan_results[container_id].update({'status': 'unhealthy', 'details': {'analysis': analysis_result, 'snippet': log_snippet, 'timestamp': datetime.now(scan_timezone)}, 'db_id': db_id})
                elif analysis_result.startswith("ERROR:"):
                     logging.error(f"Analysis Err: {container_name}: {analysis_result}"); current_scan_results[container_id].update({'status': 'error_analysis', 'details': {'analysis': analysis_result, 'snippet': '(Failed)'}, 'db_id': None})
                else:
                     current_scan_results[container_id]['status'] = 'healthy'; logging.debug(f"{container_name} OK.")

        # --- Update Global State (only if not cancelled) ---
        if not scan_cancelled:
             logging.info(f"Scan loop finished normally. Updating global state.")
             with container_statuses_lock:
                 sorted_results = dict(sorted(current_scan_results.items(), key=lambda item: item[1]['name'].lower()))
                 container_statuses = sorted_results
                 logging.info(f"Global state updated. Size: {len(container_statuses)}")
                 if container_statuses: first_key = list(container_statuses.keys())[0]; logging.debug(f"Sample after update - {first_key}: {container_statuses[first_key]['status']}")
                 elif running_containers: logging.warning("Global state empty after processing containers.")
        else:
             logging.info("Global state not updated due to scan cancellation.")

        # --- Set final status message ---
        if scan_cancelled:
            scan_status["last_run_status"] = f"Scan cancelled by user at {datetime.now(scan_timezone).strftime('%Y-%m-%d %H:%M:%S %Z')}."
        else:
             scan_status["last_run_status"] = (f"Completed at {datetime.now(scan_timezone).strftime('%Y-%m-%d %H:%M:%S %Z')}. Scanned {containers_scanned_count}. {found_issues_this_scan} unhealthy.")
        logging.info(scan_status["last_run_status"])

    except Exception as e:
        logging.exception("Unhandled error during scan task execution:")
        error_message = f"Error during scan: {e}"
        scan_status["last_run_status"] = error_message
    finally: # --- Cleanup ---
        if client:
            try: client.close()
            except Exception as client_close_err: logging.warning(f"Error closing Docker client: {client_close_err}")
        scan_status["running"] = False # Mark scan as finished
        stop_scan_event.clear() # Clear cancellation event
        # Update next run time state
        try:
            if scheduler.running: job = scheduler.get_job('docker_log_scan_job'); scan_status["next_run_time"] = job.next_run_time if job else None
            else: scan_status["next_run_time"] = None
        except Exception as e: logging.error(f"Could not get next run time: {e}"); scan_status["next_run_time"] = None

# --- Flask Routes ---
@app.route('/')
def index():
    """Renders the main dashboard page."""
    with container_statuses_lock: current_statuses = container_statuses.copy()
    with models_lock: models_list = list(available_ollama_models); selected_model = current_ollama_model

    # Determine Job State and Format Next Run Time
    job_state = 'unknown'; next_run_time_str = "N/A"; display_timezone = get_display_timezone()
    job = None # Define job outside try block
    try:
        if scheduler.running:
            job = scheduler.get_job('docker_log_scan_job')
            if job: is_paused = job.next_run_time is None; job_state = 'paused' if is_paused else 'running'
            else: job_state = 'stopped'
        else: job_state = 'scheduler_stopped'

        # Format next run time based on state
        if job_state == 'paused': next_run_time_str = "Paused"
        elif job_state == 'running' and job and job.next_run_time: # Check job and next_run_time again
            scan_status["next_run_time"] = job.next_run_time
            try: next_run_time_local = job.next_run_time.astimezone(display_timezone); next_run_time_str = next_run_time_local.strftime('%Y-%m-%d %H:%M:%S %Z')
            except Exception: next_run_time_str = job.next_run_time.strftime('%Y-%m-%d %H:%M:%S %Z')
        elif job_state == 'stopped': next_run_time_str = "Job Not Found"; scan_status["next_run_time"] = None
        else: next_run_time_str = "Scheduler Stopped"; scan_status["next_run_time"] = None
    except Exception as e: logging.error(f"Error getting scheduler state: {e}"); job_state = 'error'; next_run_time_str = "Error"; scan_status["next_run_time"] = None

    is_scan_currently_executing = scan_status["running"]

    return render_template('index.html',
                           container_statuses=current_statuses,
                           scan_status=scan_status["last_run_status"],
                           next_scan_time=next_run_time_str,
                           timezone=str(display_timezone),
                           available_models=models_list,
                           current_model=selected_model,
                           scan_is_running=is_scan_currently_executing,
                           job_state=job_state)


# --- Route to handle setting the model ---
@app.route('/set_model', methods=['POST'])
def set_model():
    """Handles the form submission to change the active Ollama model."""
    global current_ollama_model
    selected = request.form.get('selected_model')

    if not selected:
        flash('No model selected.', 'error')
    else:
        with models_lock:
            if available_ollama_models and selected not in available_ollama_models:
                 logging.warning(f"User selected model '{selected}' not in list {available_ollama_models}.")
                 # Allow setting anyway

            if selected != current_ollama_model:
                 logging.info(f"User changed Ollama model from '{current_ollama_model}' to '{selected}'")
                 current_ollama_model = selected
                 flash(f'Ollama model set to "{selected}". Applies on next scan.', 'success')
            else:
                 flash(f'Ollama model is already set to "{selected}".', 'info')

    return redirect(url_for('index'))


# --- Route for managing abnormalities ---
@app.route('/manage/<int:abnormality_id>', methods=['GET', 'POST'])
def manage_abnormality(abnormality_id):
    """Displays and handles updates for a specific abnormality record."""
    abnormality = db.get_abnormality_by_id(abnormality_id)
    if not abnormality: flash(f'ID {abnormality_id} not found.', 'error'); return redirect(url_for('index'))
    if request.method == 'POST':
        new_status = request.form.get('new_status'); notes = request.form.get('notes', '').strip()
        if new_status not in ['resolved', 'ignored', 'unresolved']: flash('Invalid status.', 'error')
        else:
            success = db.update_abnormality_status(abnormality_id, new_status, notes if notes else None)
            if success: flash(f'Marked as {new_status}.', 'success'); return redirect(url_for('index'))
            else: flash('Failed to update status.', 'error')
        return render_template('manage.html', abnormality=abnormality)
    return render_template('manage.html', abnormality=abnormality)


# --- Routes for Scheduler Control ---
@app.route('/pause_schedule', methods=['POST'])
def pause_schedule():
    """Pauses the schedule for future scans."""
    try:
        if scheduler.running:
            scheduler.pause_job('docker_log_scan_job')
            logging.info("Scan schedule paused.")
            flash("Scan schedule paused successfully.", "success")
            scan_status["next_run_time"] = None
        else: flash("Scheduler not running.", "warning")
    except JobLookupError: flash("Scan job not found.", "warning")
    except Exception as e: logging.error(f"Error pausing schedule: {e}"); flash(f"Error: {e}", "error")
    return redirect(url_for('index'))

@app.route('/resume_schedule', methods=['POST'])
def resume_schedule():
    """Resumes the schedule for future scans."""
    try:
        if scheduler.running:
            display_timezone = get_display_timezone()
            # Resuming might trigger immediately if the next run time was in the past.
            # Optionally set a future run date to prevent this.
            next_run = datetime.now(display_timezone) + timedelta(seconds=5)
            scheduler.resume_job('docker_log_scan_job', run_date=next_run)
            logging.info("Scan schedule resumed.")
            flash("Scan schedule resumed. Next scan shortly.", "success")
        else: flash("Scheduler not running.", "warning")
    except JobLookupError: flash("Scan job not found.", "warning")
    except Exception as e: logging.error(f"Error resuming schedule: {e}"); flash(f"Error: {e}", "error")
    return redirect(url_for('index'))

@app.route('/stop_current_scan', methods=['POST'])
def stop_current_scan():
    """Signals the currently running scan to stop and pauses the schedule."""
    if scan_status["running"]:
        logging.warning("Stop requested for ongoing scan.")
        stop_scan_event.set() # Signal the scan loop to stop
        flash("Stop signal sent to current scan. Schedule also paused.", "info")
        # Also pause the schedule
        try:
            if scheduler.running:
                scheduler.pause_job('docker_log_scan_job')
                logging.info("Scan schedule paused following stop request.")
                scan_status["next_run_time"] = None
        except JobLookupError: logging.warning("Job not found when pausing after stop request.")
        except Exception as e: logging.error(f"Error pausing schedule after stop: {e}")
    else:
        flash("No scan is currently running.", "info")
    return redirect(url_for('index'))

@app.route('/trigger_scan', methods=['POST'])
def trigger_scan():
    """Adds a job to run the scan task immediately (if not already running)."""
    if scan_status["running"]:
        flash("Cannot start scan: A scan is already in progress.", "warning")
        logging.warning("Manual scan trigger ignored: scan already running.")
    elif not scheduler.running:
         flash("Cannot start scan: Scheduler is not running.", "error")
         logging.error("Manual scan trigger ignored: scheduler not running.")
    else:
        try:
            display_timezone = get_display_timezone()
            run_time = datetime.now(display_timezone) + timedelta(seconds=1)
            job_id = f'manual_scan_{int(run_time.timestamp())}' # Unique ID
            scheduler.add_job(scan_docker_logs,
                              trigger='date',
                              run_date=run_time,
                              id=job_id,
                              name='Manual Docker Log Scan',
                              misfire_grace_time=60)
            logging.info(f"Manual scan triggered with job ID {job_id}, runs around {run_time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
            flash("Manual scan triggered. It will start shortly.", "success")
        except Exception as e:
            logging.error(f"Error triggering manual scan: {e}")
            flash(f"Error triggering manual scan: {e}", "error")

    return redirect(url_for('index'))


# --- Scheduler Setup Function ---
def setup_scheduler():
    """Configures and starts the background task scheduler."""
    display_timezone = get_display_timezone() # Gets validated timezone
    logging.info(f"Configuring scheduler with timezone: {display_timezone}")
    try:
        scheduler.configure(timezone=display_timezone)
    except Exception as conf_err:
        logging.error(f"Error configuring scheduler timezone: {conf_err}")
        # Consider falling back or exiting

    logging.info(f"Scheduling log scan job every {SCAN_INTERVAL_MINUTES} mins.")
    try:
        scheduler.add_job(
            scan_docker_logs,
            trigger=IntervalTrigger(minutes=SCAN_INTERVAL_MINUTES),
            id='docker_log_scan_job', # Persistent ID for the main recurring job
            name='Docker Log Scan (Recurring)',
            replace_existing=True,
            next_run_time=datetime.now(display_timezone) + timedelta(seconds=15) # Start shortly
        )
    except Exception as schedule_err:
        logging.critical(f"Failed to add recurring scan job: {schedule_err}")
        return

    # Update initial next run time display state
    try:
        job = scheduler.get_job('docker_log_scan_job')
        if job and job.next_run_time:
             scan_status["next_run_time"] = job.next_run_time
             logging.info(f"First recurring scan scheduled: {job.next_run_time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        else: logging.error("Could not retrieve next run time for recurring job.")
    except Exception as e: logging.error(f"Could not get initial next run time: {e}")

    # Start the scheduler if not already running
    if not scheduler.running:
        try:
            scheduler.start()
            logging.info("Scheduler started successfully.")
        except Exception as start_err:
             logging.critical(f"Failed to start scheduler: {start_err}")
    else:
        logging.info("Scheduler already running.")

# --- Main Execution Guard ---
if __name__ == '__main__':
    logging.info("Starting Docker Log Monitor application...")
    setup_scheduler() # Configure and start the scheduler

    logging.info(f"Ollama Endpoint: {OLLAMA_API_URL}")
    logging.info(f"Initial Ollama Model: {current_ollama_model}")
    logging.info(f"Log Lines: {LOG_LINES_TO_FETCH}, Scan Interval: {SCAN_INTERVAL_MINUTES} mins, Timezone: {SCHEDULER_TIMEZONE}")
    logging.info(f"Flask app running on http://0.0.0.0:5000")

    # Run using Waitress if available
    try:
        from waitress import serve
        logging.info("Starting server with Waitress...")
        serve(app, host='0.0.0.0', port=5000, threads=4)
    except ImportError:
        logging.warning("Waitress not found. Falling back to Flask's development server.")
        # Use werkzeug reloader=False to prevent issues with scheduler running twice
        app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
