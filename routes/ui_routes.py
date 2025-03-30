# routes/ui_routes.py
import logging
from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, abort, current_app, jsonify # Added jsonify just in case
)
from datetime import datetime
import json # For settings processing
import secrets # For API key generation in regenerate route

# Import local modules needed
import db
import analyzer # Needed by settings GET for listing models, and POST for updating config

# Import shared utility function
try:
    from utils import get_display_timezone
except ImportError:
    logging.error("Failed to import get_display_timezone from utils. Timezone functionality may be impaired.")
    # Provide a fallback if critical, otherwise routes might fail later
    def get_display_timezone():
        import pytz
        return pytz.utc

# Define the Blueprint for UI routes
ui_bp = Blueprint('ui', __name__, template_folder='../templates')

# --- UI Route Definitions ---

@ui_bp.route('/')
def index():
    """Renders the main dashboard page."""
    display_timezone_obj = get_display_timezone()

    # Initialize variables outside the try block with default/error values
    current_statuses = {}
    current_summary = {"summary": "Error loading summary", "last_updated": None, "error": "State access failed"}
    current_color_settings = {}
    current_scan_status = {"last_run_status": "Error loading status", "running": False, "next_run_time": None}
    current_scheduler = None
    summary_last_updated_str = "Error" # Default/error value
    job_state = 'error'
    next_run_time_str = "Error"

    try:
        # --- Access shared state via current_app ---
        with current_app.container_statuses_lock:
            current_statuses = current_app.container_statuses.copy()

        with current_app.ai_summary_lock:
            current_summary = current_app.ai_health_summary.copy()

        with current_app.settings_lock:
             # Only fetch color settings needed for index
             current_color_settings = {k: v for k, v in current_app.app_settings.items() if k.startswith('color_')}

        current_scan_status = current_app.scan_status
        current_scheduler = current_app.scheduler
        # --- End access shared state ---

        # --- Process fetched data ---
        summary_last_updated_str = "Never"
        if current_summary.get("last_updated"):
             try:
                  local_update_time = current_summary["last_updated"].astimezone(display_timezone_obj)
                  summary_last_updated_str = local_update_time.strftime('%Y-%m-%d %H:%M:%S %Z')
             except Exception as tz_err:
                  logging.warning(f"Timezone conversion error for summary update time: {tz_err}")
                  summary_last_updated_str = current_summary["last_updated"].strftime('%Y-%m-%d %H:%M:%S UTC') + " (UTC)"

        job = None
        if current_scheduler and current_scheduler.running:
             job = current_scheduler.get_job('docker_log_scan_job')
             job_state = 'paused' if job and job.next_run_time is None else ('running' if job else 'stopped')
        elif not current_scheduler:
             job_state = 'scheduler_missing'
             logging.error("Scheduler object not found on current_app in index route.")
        else: # Scheduler not running
             job_state = 'scheduler_stopped'

        if job_state == 'paused':
             next_run_time_str = "Paused"
        elif job_state == 'running' and job and job.next_run_time:
             try:
                 next_run_time_obj = job.next_run_time.astimezone(display_timezone_obj)
                 next_run_time_str = next_run_time_obj.strftime('%Y-%m-%d %H:%M:%S %Z')
             except Exception as tz_err_next:
                 logging.warning(f"Timezone conversion error for next scan time: {tz_err_next}")
                 next_run_time_str = job.next_run_time.strftime('%Y-%m-%d %H:%M:%S UTC') + " (UTC)"
        elif job_state == 'stopped':
             next_run_time_str = "Scan Job Not Found"
        elif job_state in ['scheduler_stopped', 'scheduler_missing']:
             next_run_time_str = "Scheduler Stopped/Unavailable"
        else: # Error or unknown state
             next_run_time_str = "N/A"

    except AttributeError as e:
         logging.exception(f"Failed to access shared state via current_app attribute in index route! Missing attribute: {e}")
         return f"Error: Application state attribute not found ({e}). Check logs.", 500
    except Exception as e:
         logging.exception(f"Unexpected error in index route processing: {e}")
         return f"Error: An unexpected error occurred processing dashboard data ({e}). Check logs.", 500

    # --- Render the template ---
    return render_template('index.html',
                           container_statuses=current_statuses,
                           scan_status=current_scan_status.get("last_run_status", "Status N/A"),
                           next_scan_time=next_run_time_str,
                           timezone=str(display_timezone_obj),
                           scan_is_running=current_scan_status.get("running", False),
                           job_state=job_state,
                           ai_summary=current_summary.get("summary", "Summary N/A"),
                           ai_summary_last_updated=summary_last_updated_str,
                           ai_summary_error=current_summary.get("error"),
                           color_settings=current_color_settings)


@ui_bp.route('/manage/<int:abnormality_id>', methods=['GET', 'POST'])
def manage_abnormality(abnormality_id):
    """Handles viewing and updating the status of a specific abnormality."""
    abnormality = db.get_abnormality_by_id(abnormality_id)
    if not abnormality:
        flash(f'Abnormality ID {abnormality_id} not found.', 'error')
        return redirect(url_for('ui.index')) # Use blueprint prefix

    current_color_settings = {}
    try:
        with current_app.settings_lock:
             current_color_settings = {k: v for k, v in current_app.app_settings.items() if k.startswith('color_')}

        if request.method == 'POST':
            new_status = request.form.get('new_status')
            notes = request.form.get('notes', '').strip()
            if new_status not in ['resolved', 'ignored', 'unresolved']:
                 flash('Invalid status selected.', 'error')
                 return render_template('manage.html', abnormality=abnormality, color_settings=current_color_settings)

            success = db.update_abnormality_status(abnormality_id, new_status, notes if notes else None)

            if success:
                 flash(f'Status successfully updated to {new_status}.', 'success')
                 target_container_id = abnormality.get('container_id')
                 if target_container_id:
                      with current_app.container_statuses_lock:
                           container_statuses_ref = current_app.container_statuses
                           if target_container_id in container_statuses_ref:
                                current_cont_status = container_statuses_ref[target_container_id].get('status')
                                if new_status in ['resolved', 'ignored'] and current_cont_status == 'unhealthy':
                                     container_statuses_ref[target_container_id]['status'] = 'awaiting_scan'
                                     container_statuses_ref[target_container_id]['db_id'] = None
                                     logging.info(f"Set {target_container_id[:12]} to awaiting_scan via manage page.")
                                elif new_status == 'unresolved' and current_cont_status != 'unhealthy':
                                     container_statuses_ref[target_container_id]['status'] = 'unhealthy'
                                     container_statuses_ref[target_container_id]['db_id'] = abnormality_id
                                     logging.info(f"Set {target_container_id[:12]} back to unhealthy via manage page.")
                 return redirect(url_for('ui.index')) # Use blueprint prefix
            else:
                 flash('Database update failed. Please check logs.', 'error')
                 return render_template('manage.html', abnormality=abnormality, color_settings=current_color_settings)

        # GET Request: Render the template
        return render_template('manage.html', abnormality=abnormality, color_settings=current_color_settings)

    except AttributeError as e:
        logging.exception(f"Failed to access shared state via current_app attribute in manage route! Missing attribute: {e}")
        flash(f"Error: Application state attribute not found ({e}). Check logs.", "error")
        return redirect(url_for('ui.index'))
    except Exception as e:
        logging.exception(f"Unexpected error in manage route processing: {e}")
        flash(f"Error: An unexpected error occurred loading manage page ({e}). Check logs.", "error")
        return redirect(url_for('ui.index'))


@ui_bp.route('/history/<string:container_id>')
def container_history(container_id):
    """Displays the abnormality history for a specific container."""
    if not container_id or len(container_id) < 12:
        abort(404)

    history_records = db.get_abnormalities_by_container(container_id)
    container_name = history_records[0]['container_name'] if history_records else f"ID: {container_id[:12]}"
    display_timezone_obj = get_display_timezone()
    current_color_settings = {}

    try:
        with current_app.settings_lock:
             current_color_settings = {k: v for k, v in current_app.app_settings.items() if k.startswith('color_')}
    except AttributeError as e:
        logging.error(f"Failed to access settings lock/dict in history route: {e}")
        flash("Could not load color settings.", "warning")
    except Exception as e:
        logging.exception(f"Unexpected error getting colors in history route: {e}")
        flash("Error loading color settings.", "error")

    return render_template('history.html',
                           records=history_records,
                           container_name=container_name,
                           container_id=container_id,
                           timezone_obj=display_timezone_obj,
                           color_settings=current_color_settings)


@ui_bp.route('/help')
def help_page():
    """Displays the static help/manual page."""
    logging.debug("Rendering help page.")
    return render_template('help.html')


@ui_bp.route('/settings', methods=['GET', 'POST'])
def settings():
    """Handles viewing and updating application settings (excluding API key)."""
    restart_required_settings = ['scan_interval_minutes', 'summary_interval_hours']
    needs_restart_msg = False

    try:
        if request.method == 'POST':
            logging.info("Processing CORE settings form update...") # Note: Excludes API Key
            form_data = request.form.to_dict()
            new_settings = {}
            validation_errors = []
            # Define expected keys *excluding* api_key
            expected_keys = [k for k in db.DEFAULT_SETTINGS.keys() if k != 'api_key']

            # --- Validation Loop ---
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
                         else:
                              with current_app.settings_lock:
                                   if key in restart_required_settings and str(current_app.app_settings.get(key)) != str(int_val): needs_restart_msg = True
                     elif key.startswith('color_'):
                         if not value.startswith('#') or not (len(value) == 7 or len(value) == 4):
                             validation_errors.append(f"Invalid color format for {key.replace('_', ' ').title()}. Use #rrggbb or #rgb.")
                         else:
                              try: int(value[1:], 16); new_settings[key] = value
                              except ValueError: validation_errors.append(f"Invalid hex color value for {key.replace('_', ' ').title()}.")
                     elif key == 'ollama_api_url':
                         if not value.startswith(('http://', 'https://')): validation_errors.append("Ollama URL must start http:// or https://")
                         else: new_settings[key] = value.rstrip('/')
                     # No api_key handling needed here
                     else: new_settings[key] = value # Model, Prompt

# --- Handle Validation Results ---
            if validation_errors:
                for error in flash_errors: flash(error, 'error') # Assuming flash_errors exists

                # Repopulate data for re-rendering (fetch everything including api_key for display)
                # Use a try block around operations that might fail (like accessing app attributes)
                try:
                    # Indent these lines one level further, inside the try block
                    with current_app.settings_lock:
                        current_display_settings = current_app.app_settings.copy()
                    with current_app.container_statuses_lock:
                        # Ensure the line below is complete and correct in your actual code
                        running_names = {d['name'] for d in current_app.container_statuses.values()}
                    ignored_list_display = current_display_settings.get('ignored_containers_list', [])
                    all_names_display = sorted(list(running_names.union(set(ignored_list_display))))

                    # Wrap the model fetching specifically, as this seems to be the target of the except blocks
                    try:
                        # Indent these lines relative to the inner try
                        with current_app.models_lock:
                             # Make sure the variable name matches where it's used below
                             current_models_display = list(current_app.available_ollama_models)
                        logging.info(f"Models passed to settings template: {current_models_display}") # Log fetched models

                    # These except blocks now correspond to the inner try
                    except AttributeError:
                        logging.error("Failed to get models_lock or available_ollama_models from current_app")
                        current_models_display = [] # Set default on error
                    except Exception as e_models: # Use a different variable name for clarity
                        logging.exception(f"Error getting models for settings page: {e_models}")
                        current_models_display = [] # Set default on error

                    # This return is now inside the outer try block but after the inner try/except
                    # Ensure the line below is complete and correct in your actual code
                    return render_template('settings.html',
                                           settings=current_display_settings,
                                           available_models=current_models_display,
                                           # Add other necessary context variables
                                           all_container_names=all_names_display,
                                           ignored_container_list=ignored_list_display)

                except Exception as e_outer:
                    # Catch potential errors from accessing locks or other app attributes before model fetching
                    logging.exception(f"Outer error preparing settings page data after validation failure: {e_outer}")
                    flash("An error occurred while preparing the settings page.", "error")
                    # Redirect or render an error page might be safer here
                    return redirect(url_for('ui.index')) # Redirect to index on major error

            # --- Save Validated Settings ---
            else:
                 save_success = True; failed_key = None
                 with current_app.settings_lock:
                     app_settings_ref = current_app.app_settings
                     for key, value in new_settings.items(): # Loop through validated (non-api_key) data
                         if str(app_settings_ref.get(key)) != str(value):
                              logging.info(f"Attempting to save core setting: {key}")
                              if db.set_setting(key, value):
                                   app_settings_ref[key] = value
                                   if key == 'ignored_containers': app_settings_ref['ignored_containers_list'] = json.loads(value) if value else []
                                   if key in ['scan_interval_minutes','summary_interval_hours','log_lines_to_fetch']: app_settings_ref[key] = int(value) if value else 0
                                   # Propagate relevant settings to analyzer
                                   try:
                                        analyzer_instance = current_app.analyzer
                                        if key == 'ollama_api_url': analyzer_instance.OLLAMA_API_URL = value
                                        if key == 'ollama_model': analyzer_instance.DEFAULT_OLLAMA_MODEL = value
                                        if key == 'log_lines_to_fetch': analyzer_instance.LOG_LINES_TO_FETCH = int(value) if value else 100
                                        logging.debug(f"Propagated setting '{key}' to analyzer module.")
                                   except AttributeError: logging.error("Could not find analyzer attached to current_app to propagate settings.")
                              else: # db save failed
                                  save_success = False; failed_key = key; break
                         else:
                              logging.debug(f"Skipping save for unchanged core setting: {key}")

                 if save_success: flash("Core settings saved successfully.", 'success')
                 if needs_restart_msg: flash("Interval changes require an application restart to take effect.", 'warning')
                 return redirect(url_for('ui.settings'))

        # --- GET Request ---
        else:
            # Fetch all settings, including api_key for display
            with current_app.settings_lock:
                current_settings_display = current_app.app_settings.copy()
            with current_app.container_statuses_lock:
                running_names = {d['name'] for d in current_app.container_statuses.values()}
            with current_app.models_lock:
                current_models_display = list(current_app.available_ollama_models)

            ignored_list_display = current_settings_display.get('ignored_containers_list', [])
            all_names_display = sorted(list(running_names.union(set(ignored_list_display))))

            return render_template('settings.html',
                                   settings=current_settings_display, # Pass all settings for display
                                   available_models=current_models_display,
                                   all_container_names=all_names_display,
                                   ignored_container_list=ignored_list_display)

    except AttributeError as e:
        logging.exception(f"Failed to access shared state via current_app attribute in settings route! Missing attribute: {e}")
        flash(f"Error: Application state attribute not found ({e}) loading settings page. Check logs.", "error")
        return redirect(url_for('ui.index'))
    except Exception as e:
        logging.exception(f"Unexpected error in settings route processing: {e}")
        flash(f"Error: An unexpected error occurred processing settings ({e}). Check logs.", "error")
        return redirect(url_for('ui.index'))


@ui_bp.route('/settings/regenerate_api_key', methods=['POST'])
def regenerate_api_key():
    """Generates and saves a new API key."""
    new_key = secrets.token_urlsafe(32)
    logging.info(f"Regenerating API key via UI route. New key generated (starts with: {new_key[:4]}...).")
    save_ok = db.set_setting('api_key', new_key)

    if save_ok:
         try:
             with current_app.settings_lock:
                 current_app.app_settings['api_key'] = new_key
             logging.info(f"Regenerate: API key updated in DB and cache.")
             flash("API Key successfully regenerated!", 'success')
         except AttributeError:
             logging.error("Regenerate: Failed to update API key in app cache (AttributeError). DB was updated.")
             flash("API Key regenerated in DB, but failed to update cache. Restart may be needed.", 'warning')
         except Exception as e_cache:
             logging.exception(f"Regenerate: Error updating cache: {e_cache}")
             flash("API Key regenerated in DB, but cache update failed.", 'warning')
    else:
         logging.error("Regenerate: Failed to save new API key to database.")
         flash("Error: Failed to save regenerated API key to database.", 'error')

    return redirect(url_for('ui.settings')) # Use blueprint prefix
