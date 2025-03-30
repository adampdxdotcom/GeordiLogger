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

# --- Logging Setup ---
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format='%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s'
)

# --- Local Imports ---
try: import db; import analyzer
except ImportError as e: logging.critical(f"Import Error: {e}"); exit(1)

# --- Configuration ---
SCHEDULER_TIMEZONE = os.environ.get("TZ", "America/Los_Angeles")

# --- Flask App Initialization ---
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change_this_in_production_please")
if app.secret_key == "change_this_in_production_please": logging.warning("FLASK_SECRET_KEY is default.")

# --- Global State Variables ---
container_statuses = {}; container_statuses_lock = Lock()
scan_status = {"last_run_time": None, "last_run_status": "Not run yet", "next_run_time": None, "running": False}
available_ollama_models = []; models_lock = Lock()
ai_health_summary = {"summary": "Summary generation pending...", "last_updated": None, "error": None}; ai_summary_lock = Lock()
app_settings = {}; settings_lock = Lock() # Populated by load_settings
stop_scan_event = threading.Event()
scheduler = BackgroundScheduler(daemon=True)

# --- Helper Functions ---
def get_display_timezone():
    global SCHEDULER_TIMEZONE
    try: return pytz.timezone(SCHEDULER_TIMEZONE)
    except pytz.exceptions.UnknownTimeZoneError:
        logging.warning(f"Invalid TZ '{SCHEDULER_TIMEZONE}'. Using UTC."); SCHEDULER_TIMEZONE = "UTC"; return pytz.utc

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
            app_settings['ignored_containers_list'] = json.loads(app_settings.get('ignored_containers', '[]'))
            if not isinstance(app_settings['ignored_containers_list'], list): app_settings['ignored_containers_list'] = []
        except: app_settings['ignored_containers_list'] = []
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
        if secrets.compare_digest(provided_key, api_key_setting): return f(*args, **kwargs)
        else: logging.warning(f"Invalid API key for endpoint '{request.endpoint}'."); return jsonify({"error": "Invalid API key."}), 401
    return decorated_function

# --- Background Tasks ---
def scan_docker_logs():
    global container_statuses, available_ollama_models
    if scan_status["running"]: logging.warning("Scan skipped: previous active."); return
    try:
        with settings_lock: current_settings = app_settings.copy()
        log_lines = int(current_settings.get('log_lines_to_fetch', 100))
        analysis_prompt = current_settings.get('analysis_prompt', db.DEFAULT_SETTINGS['analysis_prompt'])
        ignored_list = current_settings.get('ignored_containers_list', []); model_to_use = current_settings.get('ollama_model')
    except Exception as e: logging.error(f"Scan settings error: {e}"); log_lines=100; analysis_prompt=db.DEFAULT_SETTINGS['analysis_prompt']; ignored_list=[]; model_to_use=db.DEFAULT_SETTINGS['ollama_model']

    scan_status["running"] = True; stop_scan_event.clear(); logging.info("Starting Docker log scan...")
    start_time = datetime.now(); scan_status["last_run_time"] = start_time
    current_scan_results = {}; found_issues_this_scan = 0; containers_scanned_count = 0
    scan_timezone = get_display_timezone()

    try: # Fetch models
        fetched_models = analyzer.get_ollama_models();
        with models_lock: available_ollama_models = fetched_models
    except Exception as e: logging.error(f"Model fetch error: {e}")

    client = analyzer.get_docker_client()
    if not client: scan_status["last_run_status"]=f"Docker connect fail"; scan_status["running"]=False; logging.error("Docker connect fail"); return

    scan_cancelled = False
    try:
        running_containers = client.containers.list(); containers_scanned_count = len(running_containers)
        logging.info(f"Found {containers_scanned_count} containers.")
        active_container_ids = {c.id for c in running_containers}

        for container in running_containers:
            if stop_scan_event.is_set(): scan_cancelled = True; logging.warning("Scan cancelled by event."); break
            container_id = container.id; container_name = container.name
            if container_name in ignored_list: logging.info(f"Skipping ignored: {container_name}"); continue

            logging.debug(f"Scanning: {container_name[:12]}"); current_scan_results[container_id] = {'name': container_name, 'id': container_id, 'status': 'pending', 'details': None, 'db_id': None}
            logs = analyzer.fetch_container_logs(container)
            if logs is None: current_scan_results[container_id].update({'status': 'error_fetching_logs', 'details': {'analysis': 'Failed logs', 'snippet': ''}}); continue

            analysis_result = analyzer.analyze_logs_with_ollama(logs, model_to_use, custom_prompt=analysis_prompt)

            if analysis_result != "NORMAL" and not analysis_result.startswith("ERROR:"):
                log_snippet = analyzer.extract_log_snippet(analysis_result, logs)
                existing_status = db.get_abnormality_status(container_id, log_snippet)
                if existing_status in ['resolved', 'ignored']:
                    current_scan_results[container_id].update({'status': 'healthy', 'db_id': None}); continue # Treat as healthy
                found_issues_this_scan += 1; logging.warning(f"Abnormality: {container_name[:12]}: {analysis_result[:100]}...")
                try:
                    db.add_or_update_abnormality(container_name, container_id, log_snippet, analysis_result)
                    db_id = db.get_latest_unresolved_abnormality_id(container_id, log_snippet)
                    current_scan_results[container_id].update({'status': 'unhealthy', 'details': {'analysis': analysis_result, 'snippet': log_snippet, 'timestamp': datetime.now(scan_timezone)}, 'db_id': db_id})
                except Exception as db_err: logging.error(f"DB Err: {container_name[:12]}: {db_err}"); current_scan_results[container_id].update({'status': 'error_db_log', 'details': {'analysis': f'DB Error: {db_err}', 'snippet': log_snippet}})
            elif analysis_result.startswith("ERROR:"):
                logging.error(f"Analysis Err: {container_name[:12]}: {analysis_result}"); current_scan_results[container_id].update({'status': 'error_analysis', 'details': {'analysis': analysis_result, 'snippet': '(Analysis Failed)'}})
            else: current_scan_results[container_id]['status'] = 'healthy'; logging.debug(f"{container_name[:12]} OK.")

        if not scan_cancelled: # Update global state
             with container_statuses_lock:
                 for c_id, data in current_scan_results.items(): container_statuses[c_id] = data
                 ids_to_remove = set(container_statuses.keys()) - active_container_ids
                 for c_id in ids_to_remove:
                     if c_id in container_statuses: logging.info(f"Removing stopped: {container_statuses[c_id]['name'][:12]}"); del container_statuses[c_id]
                 container_statuses = dict(sorted(container_statuses.items(), key=lambda item: item[1]['name'].lower()))
                 logging.info(f"Global state updated. {len(container_statuses)} active.")
        else: logging.warning("Global state NOT updated due to cancellation.")

        if scan_cancelled: scan_status["last_run_status"] = f"Scan cancelled @ {datetime.now(scan_timezone).strftime('%H:%M:%S %Z')}"
        else: scan_status["last_run_status"] = f"Completed @ {datetime.now(scan_timezone).strftime('%H:%M:%S %Z')}. Scanned {containers_scanned_count} ({len(ignored_list)} ignored). {found_issues_this_scan} issues."
        logging.info(scan_status["last_run_status"])

    except docker.errors.DockerException as docker_err: logging.error(f"Docker error during scan: {docker_err}"); scan_status["last_run_status"] = f"Docker error: {docker_err}"
    except Exception as e: logging.exception("Unhandled scan error:"); scan_status["last_run_status"] = f"Critical error: {e}"
    finally:
        if client:
            try: client.close()
            except Exception as ce: logging.warning(f"Error closing Docker client: {ce}")
        scan_status["running"] = False; stop_scan_event.clear()
        try:
            if scheduler.running: job = scheduler.get_job('docker_log_scan_job'); scan_status["next_run_time"] = job.next_run_time if job else None
            else: scan_status["next_run_time"] = None
        except Exception as e: logging.error(f"Next run time error: {e}"); scan_status["next_run_time"] = None

def update_ai_health_summary():
    global ai_health_summary
    try:
        with settings_lock:
            summary_hours = int(app_settings.get('summary_interval_hours', 12))
            model_to_use = app_settings.get('ollama_model')
    except Exception as e:
         logging.error(f"Summary settings error: {e}"); summary_hours = 12; model_to_use=db.DEFAULT_SETTINGS['ollama_model']

    logging.info(f"Starting AI health summary ({summary_hours} hours).")
    summary_start_time = datetime.now(timezone.utc)
    try:
        recent_abnormalities = db.get_recent_abnormalities(hours=summary_hours)
        summary_text = analyzer.summarize_recent_abnormalities(recent_abnormalities, model_to_use)
        with ai_summary_lock:
            ai_health_summary["last_updated"] = summary_start_time
            if summary_text.startswith("Error:"): ai_health_summary["summary"], ai_health_summary["error"] = "Failed.", summary_text; logging.error(f"Summary failed: {summary_text}")
            else: ai_health_summary["summary"], ai_health_summary["error"] = summary_text, None; logging.info("Summary updated.")
    except Exception as e:
        logging.exception("Summary task error:");
        with ai_summary_lock: ai_health_summary["summary"], ai_health_summary["error"], ai_health_summary["last_updated"] = "Internal error.", str(e), summary_start_time


# --- Flask UI Routes ---

@app.route('/')
def index():
    display_timezone_obj = get_display_timezone()
    with container_statuses_lock: current_statuses = container_statuses.copy()
    with ai_summary_lock: current_summary = ai_health_summary.copy()
    with settings_lock: current_color_settings = {k: v for k, v in app_settings.items() if k.startswith('color_')}
    summary_last_updated_str = "Never"
    if current_summary.get("last_updated"):
         try: local_update_time = current_summary["last_updated"].astimezone(display_timezone_obj); summary_last_updated_str = local_update_time.strftime('%Y-%m-%d %H:%M:%S %Z')
         except Exception: summary_last_updated_str = current_summary["last_updated"].strftime('%Y-%m-%d %H:%M:%S UTC')

    job_state = 'unknown'; next_run_time_str = "N/A"; job = None
    try:
        if scheduler.running: job = scheduler.get_job('docker_log_scan_job'); job_state = 'paused' if job and job.next_run_time is None else ('running' if job else 'stopped')
        else: job_state = 'scheduler_stopped'
        if job_state == 'paused': next_run_time_str = "Paused"
        elif job_state == 'running' and job and job.next_run_time:
            scan_status["next_run_time"] = job.next_run_time; next_run_time_str = job.next_run_time.astimezone(display_timezone_obj).strftime('%Y-%m-%d %H:%M:%S %Z')
        else: next_run_time_str = "N/A"; scan_status["next_run_time"] = None
        if job_state == 'stopped': next_run_time_str = "Job Not Found"
        elif job_state == 'scheduler_stopped': next_run_time_str = "Scheduler Stopped"
        elif job_state == 'error': next_run_time_str = "Error"
    except Exception as e: logging.error(f"Scheduler state error: {e}"); job_state = 'error'; next_run_time_str = "Error"

    return render_template('index.html', container_statuses=current_statuses, scan_status=scan_status["last_run_status"],
                           next_scan_time=next_run_time_str, timezone=str(display_timezone_obj),
                           scan_is_running=scan_status["running"], job_state=job_state, ai_summary=current_summary["summary"],
                           ai_summary_last_updated=summary_last_updated_str, ai_summary_error=current_summary["error"],
                           color_settings=current_color_settings)

@app.route('/manage/<int:abnormality_id>', methods=['GET', 'POST'])
def manage_abnormality(abnormality_id):
    abnormality = db.get_abnormality_by_id(abnormality_id)
    if not abnormality: flash(f'ID {abnormality_id} not found.', 'error'); return redirect(url_for('index'))
    with settings_lock: current_color_settings = {k: v for k, v in app_settings.items() if k.startswith('color_')}
    if request.method == 'POST':
        new_status = request.form.get('new_status'); notes = request.form.get('notes', '').strip()
        if new_status not in ['resolved', 'ignored', 'unresolved']: flash('Invalid status.', 'error'); return render_template('manage.html', abnormality=abnormality, color_settings=current_color_settings)
        success = db.update_abnormality_status(abnormality_id, new_status, notes if notes else None)
        if success:
            flash(f'Status updated to {new_status}.', 'success')
            target_container_id = abnormality.get('container_id')
            if target_container_id:
                 with container_statuses_lock:
                      if target_container_id in container_statuses:
                           current_cont_status = container_statuses[target_container_id].get('status')
                           if new_status in ['resolved', 'ignored'] and current_cont_status == 'unhealthy':
                                container_statuses[target_container_id]['status'] = 'awaiting_scan'; container_statuses[target_container_id]['db_id'] = None; logging.info(f"Set {target_container_id[:12]} to awaiting_scan.")
                           elif new_status == 'unresolved' and current_cont_status != 'unhealthy':
                                container_statuses[target_container_id]['status'] = 'unhealthy'; container_statuses[target_container_id]['db_id'] = abnormality_id; logging.info(f"Set {target_container_id[:12]} back to unhealthy.")
            return redirect(url_for('index'))
        else: flash('DB update failed.', 'error'); return render_template('manage.html', abnormality=abnormality, color_settings=current_color_settings)
    return render_template('manage.html', abnormality=abnormality, color_settings=current_color_settings)

@app.route('/history/<string:container_id>')
def container_history(container_id):
    if not container_id or len(container_id) < 12: abort(404)
    history_records = db.get_abnormalities_by_container(container_id)
    container_name = history_records[0]['container_name'] if history_records else f"ID: {container_id[:12]}"
    display_timezone_obj = get_display_timezone()
    with settings_lock: current_color_settings = {k: v for k, v in app_settings.items() if k.startswith('color_')}
    return render_template('history.html', records=history_records, container_name=container_name, container_id=container_id, timezone_obj=display_timezone_obj, color_settings=current_color_settings)

# --- NEW Help Page Route ---
@app.route('/help')
def help_page():
    """Displays the static help/manual page."""
    logging.debug("Rendering help page.")
    # You could potentially pass settings or other info here if needed later
    return render_template('help.html')
# --- END NEW Help Page Route ---


# --- CORRECTED /settings route ---
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    restart_required_settings = ['scan_interval_minutes', 'summary_interval_hours']
    needs_restart_msg = False
    if request.method == 'POST':
        logging.info("Processing MAIN settings form update...")
        form_data = request.form.to_dict(); new_settings = {}; validation_errors = []
        expected_keys = list(db.DEFAULT_SETTINGS.keys())
        for key in expected_keys:
            if key == 'ignored_containers':
                 ignored_list = request.form.getlist('ignored_containers')
                 try: new_settings[key] = json.dumps(ignored_list)
                 except Exception as e: validation_errors.append(f"Error processing ignore list: {e}")
            elif key in form_data:
                 value = form_data[key].strip()
                 if key in ['scan_interval_minutes', 'summary_interval_hours', 'log_lines_to_fetch']:
                     try: int_val = int(value); assert int_val > 0; new_settings[key] = str(int_val)
                     except: validation_errors.append(f"Invalid positive integer for {key.replace('_',' ')}.")
                     else: # Check restart needed only if validation passes
                          with settings_lock:
                               if key in restart_required_settings and str(app_settings.get(key)) != str(int_val): needs_restart_msg = True
                 elif key.startswith('color_'):
                     if not value.startswith('#') or len(value) != 7: validation_errors.append(f"Invalid color format for {key.replace('_', ' ').title()}. Use #rrggbb.")
                     else: # Check hex validity
                          try: int(value[1:], 16); new_settings[key] = value
                          except ValueError: validation_errors.append(f"Invalid hex color value for {key.replace('_', ' ').title()}.")
                 elif key == 'ollama_api_url':
                     if not value.startswith(('http://', 'https://')): validation_errors.append("Ollama URL must start http:// or https://")
                     else: new_settings[key] = value
                 elif key == 'api_key': new_settings[key] = value # Allow empty
                 else: new_settings[key] = value # Model, Prompt
        # --- After validation loop ---
        if validation_errors:
            for error in validation_errors: flash(error, 'error')
            # Need to repopulate data for rendering template with errors
            with settings_lock: current_display_settings = app_settings.copy()
            with container_statuses_lock: running_names = {d['name'] for d in container_statuses.values()}
            # Use the *current* value from cache/DB for ignored list, not from failed form data
            ignored_list_display = current_display_settings.get('ignored_containers_list', [])
            all_names_display = sorted(list(running_names.union(set(ignored_list_display))))
            with models_lock: current_models = list(available_ollama_models)
            return render_template('settings.html', settings=current_display_settings, available_models=current_models, all_container_names=all_names_display, ignored_container_list=ignored_list_display)
        else:
             # Save validated settings
             save_success = True; failed_key = None
             # --- CORRECTED Indentation for 'with settings_lock:' ---
             with settings_lock:
                 for key, value in new_settings.items():
                     # Only save if value actually changed
                     if str(app_settings.get(key)) != str(value):
                          logging.info(f"Attempting to save changed setting: {key}")
                          if db.set_setting(key, value):
                               app_settings[key] = value # Update cache
                               # Update derived/typed values in cache
                               if key == 'ignored_containers': app_settings['ignored_containers_list'] = json.loads(value)
                               if key in ['scan_interval_minutes','summary_interval_hours','log_lines_to_fetch']: app_settings[key] = int(value)
                               # Update analyzer config directly
                               if key == 'ollama_api_url': analyzer.OLLAMA_API_URL = value
                               if key == 'ollama_model': analyzer.DEFAULT_OLLAMA_MODEL = value
                               if key == 'log_lines_to_fetch': analyzer.LOG_LINES_TO_FETCH = int(value)
                          else:
                              save_success = False; failed_key = key
                              logging.error(f"DB save failed for key: '{key}'")
                              flash(f"Error saving setting: '{key.replace('_', ' ').title()}'", 'error')
                              break # Stop saving if one fails
                     else:
                          logging.debug(f"Skipping save for unchanged setting: {key}")
             # --- END CORRECTED Indentation ---

             # Flash messages outside the lock
             if save_success:
                 flash("Settings saved successfully.", 'success')
             # else: # Error message already flashed in loop

             if needs_restart_msg:
                 flash("Interval changes require app restart.", 'warning')

             # Redirect after attempting save
             return redirect(url_for('settings'))

    else: # GET Request
        with settings_lock: current_settings_display = app_settings.copy()
        logging.info(f"Rendering settings page via GET request.")
        key_to_log = current_settings_display.get('api_key', 'Not Set or Empty')
        logging.info(f"API Key value being passed to template ends with: ...{key_to_log[-4:] if key_to_log else 'N/A'}")
        with container_statuses_lock: running_names = {d['name'] for d in container_statuses.values()}
        ignored_list_display = current_settings_display.get('ignored_containers_list', [])
        all_names_display = sorted(list(running_names.union(set(ignored_list_display))))
        with models_lock: current_models_display = list(available_ollama_models)
        return render_template('settings.html', settings=current_settings_display, available_models=current_models_display, all_container_names=all_names_display, ignored_container_list=ignored_list_display)
# --- END CORRECTED /settings route ---

@app.route('/settings/regenerate_api_key', methods=['POST'])
def regenerate_api_key():
    new_key = secrets.token_urlsafe(32)
    logging.info(f"Regenerating API key route hit. New key generated (starts with: {new_key[:4]}...).")
    save_ok = db.set_setting('api_key', new_key)
    if save_ok:
         with settings_lock: app_settings['api_key'] = new_key
         logging.info(f"Regenerate: API key updated in DB and cache. Cache now ends with: ...{app_settings.get('api_key', 'ERROR')[-4:]}")
         flash("API Key successfully regenerated!", 'success') # Distinct message
    else:
         logging.error("Regenerate: Failed to save new API key to database.")
         flash("Error: Failed to save regenerated API key to database.", 'error')
    logging.info("Regenerate: Redirecting back to settings page...")
    return redirect(url_for('settings'))

# --- Scheduler Control Routes ---
@app.route('/pause_schedule', methods=['POST'])
def pause_schedule():
    try:
        if scheduler.running:
            scheduler.pause_job('docker_log_scan_job');
            logging.info("Schedule paused by user."); flash("Schedule paused.", "success"); scan_status["next_run_time"] = None
        else: flash("Scheduler not running.", "warning")
    except JobLookupError: flash("Job not found to pause.", "warning")
    except Exception as e: logging.error(f"Error pausing schedule: {e}"); flash(f"Error: {e}", "error")
    finally: return redirect(url_for('index'))

@app.route('/resume_schedule', methods=['POST'])
def resume_schedule():
    try:
        if scheduler.running:
            scheduler.resume_job('docker_log_scan_job');
            logging.info("Schedule resumed by user."); flash("Schedule resumed.", "success")
        else: flash("Scheduler not running.", "warning")
    except JobLookupError: flash("Job not found to resume.", "warning")
    except Exception as e: logging.error(f"Error resuming schedule: {e}"); flash(f"Error: {e}", "error")
    finally: return redirect(url_for('index'))

@app.route('/stop_current_scan', methods=['POST'])
def stop_current_scan():
    if scan_status["running"]: stop_scan_event.set(); flash("Stop signal sent.", "info");
    else: flash("No scan running.", "info");
    return redirect(url_for('index'))

@app.route('/trigger_scan', methods=['POST'])
def trigger_scan():
    try:
        if scan_status["running"]: flash("Scan already running.", "warning")
        elif not scheduler.running: flash("Scheduler not running.", "error")
        else:
            try:
                run_time = datetime.now(get_display_timezone()) + timedelta(seconds=1); job_id = f'manual_scan_{int(run_time.timestamp())}'
                scheduler.add_job(scan_docker_logs, trigger='date', run_date=run_time, id=job_id, name='Manual Log Scan', misfire_grace_time=60, max_instances=1)
                logging.info(f"Manual log scan triggered ({job_id})"); flash("Manual scan triggered.", "success")
            except Exception as e: logging.error(f"Error triggering manual scan: {e}"); flash(f"Error: {e}", "error")
    except Exception as outer_e: logging.error(f"Unexpected error in trigger_scan route: {outer_e}"); flash("An unexpected error occurred.", "error")
    finally: return redirect(url_for('index'))

@app.route('/trigger_summary', methods=['POST'])
def trigger_summary():
    try:
        if not scheduler.running: flash("Scheduler not running.", "error")
        else:
            try:
                run_time = datetime.now(get_display_timezone()) + timedelta(seconds=1); job_id = f'manual_summary_{int(run_time.timestamp())}'
                scheduler.add_job(update_ai_health_summary, trigger='date', run_date=run_time, id=job_id, name='Manual AI Summary', misfire_grace_time=60, max_instances=1)
                logging.info(f"Manual AI summary triggered ({job_id})"); flash("Manual summary triggered.", "success")
            except Exception as e: logging.error(f"Error triggering manual summary: {e}"); flash(f"Error: {e}", "error")
    except Exception as outer_e: logging.error(f"Unexpected error in trigger_summary route: {outer_e}"); flash("An unexpected error occurred.", "error")
    finally: return redirect(url_for('index'))

# --- API Endpoints ---
@app.route('/api/status', methods=['GET'])
def api_status():
    with ai_summary_lock: summary_data = ai_health_summary.copy()
    last_updated = summary_data.get('last_updated'); last_updated_iso = last_updated.isoformat()+"Z" if isinstance(last_updated, datetime) else None
    next_run = scan_status.get('next_run_time')
    next_run_iso = next_run.astimezone(timezone.utc).isoformat()+"Z" if isinstance(next_run, datetime) else None
    return jsonify({ "ai_summary": summary_data.get('summary'), "ai_summary_last_updated_utc": last_updated_iso,
        "ai_summary_error": summary_data.get('error'), "scan_last_status_message": scan_status.get('last_run_status'),
        "scan_running": scan_status.get('running'), "scan_next_run_utc": next_run_iso })

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
    issues = db.get_abnormalities_by_status(status=status_filter); return jsonify(issues)

@app.route('/api/scan/trigger', methods=['POST'])
@require_api_key
def api_trigger_scan():
    if scan_status["running"]: return jsonify({"message": "Scan already in progress."}), 409
    elif not scheduler.running: return jsonify({"error": "Scheduler not running."}), 503
    else:
        try:
            run_time = datetime.now(get_display_timezone()) + timedelta(seconds=1); job_id = f'api_scan_{int(run_time.timestamp())}'
            scheduler.add_job(scan_docker_logs, trigger='date', run_date=run_time, id=job_id, name='API Triggered Log Scan', misfire_grace_time=60, max_instances=1)
            logging.info(f"API triggered log scan ({job_id})"); return jsonify({"message": "Log scan triggered.", "job_id": job_id}), 202
        except Exception as e: logging.error(f"Error API scan trigger: {e}"); return jsonify({"error": f"Trigger failed: {e}"}), 500

@app.route('/api/summary/trigger', methods=['POST'])
@require_api_key
def api_trigger_summary():
    if not scheduler.running: return jsonify({"error": "Scheduler not running."}), 503
    else:
        try:
            run_time = datetime.now(get_display_timezone()) + timedelta(seconds=1); job_id = f'api_summary_{int(run_time.timestamp())}'
            scheduler.add_job(update_ai_health_summary, trigger='date', run_date=run_time, id=job_id, name='API Triggered AI Summary', misfire_grace_time=60, max_instances=1)
            logging.info(f"API triggered AI summary ({job_id})"); return jsonify({"message": "Summary generation triggered.", "job_id": job_id}), 202
        except Exception as e: logging.error(f"Error API summary trigger: {e}"); return jsonify({"error": f"Trigger failed: {e}"}), 500

# --- Scheduler Setup ---
def setup_scheduler():
    global scheduler; display_timezone = get_display_timezone()
    logging.info(f"Configuring scheduler with TZ: {display_timezone}")
    try: scheduler.configure(timezone=display_timezone)
    except Exception as e: logging.error(f"Scheduler TZ config error: {e}")
    with settings_lock:
        scan_interval = app_settings.get('scan_interval_minutes', 180);
        summary_interval = app_settings.get('summary_interval_hours', 12)
    try: # Add Scan Job
        first_scan = datetime.now(display_timezone) + timedelta(seconds=20)
        scheduler.add_job(scan_docker_logs, trigger=IntervalTrigger(minutes=scan_interval), id='docker_log_scan_job', name='Log Scan', replace_existing=True, next_run_time=first_scan)
        scan_status["next_run_time"] = first_scan; logging.info(f"Scan job added: every {scan_interval}m.")
    except Exception as e: logging.critical(f"Failed scan job add: {e}")
    try: # Add Summary Job
        first_summary = datetime.now(display_timezone) + timedelta(minutes=1)
        scheduler.add_job(update_ai_health_summary, trigger=IntervalTrigger(hours=summary_interval), id='ai_summary_job', name='AI Summary', replace_existing=True, next_run_time=first_summary)
        logging.info(f"Summary job added: every {summary_interval}h.")
    except Exception as e: logging.error(f"Failed summary job add: {e}")
    if not scheduler.running:
        try: scheduler.start(); logging.info("Scheduler started.")
        except Exception as e: logging.critical(f"Scheduler start failed: {e}")
    else: logging.info("Scheduler already running.")

# --- Main Execution ---
if __name__ == '__main__':
    logging.info("Starting Docker Log Monitor...")
    load_settings()
    setup_scheduler()

    try:
        port = int(os.environ.get("PORT", "5001"))
        if not 1 <= port <= 65535: raise ValueError("Port must be 1-65535")
    except ValueError as e:
         logging.warning(f"Invalid PORT: {e}. Defaulting to 5001."); port = 5001

    logging.info(f"Flask app starting - listening on port {port}")
    use_waitress = os.environ.get("USE_WAITRESS", "true").lower() == "true"

    if use_waitress:
        try:
            from waitress import serve
            logging.info(f"Starting server with Waitress on http://0.0.0.0:{port}")
            serve(app, host='0.0.0.0', port=port, threads=8)
        except ImportError:
            logging.warning("Waitress not found... Falling back to Flask dev server.")
            app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
    else:
        logging.info(f"Starting with Flask's development server on http://0.0.0.0:{port}")
        app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
