# routes/ui_routes.py
import logging
from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, abort, current_app, jsonify, Response # Added Response
)
# <<< Make sure datetime is imported from datetime >>>
from datetime import datetime, timezone
import json # For settings processing
import secrets # For API key generation in regenerate route
import docker # Import docker library for logs route errors
import pytz # Import pytz if get_display_timezone uses it
# <<< Add email validation helper (optional but good) >>>
import re

# Import local modules needed
import db
import analyzer # Needed by settings GET for listing models, and POST for updating config, and logs route

# Import shared utility function
try:
    from utils import get_display_timezone
except ImportError:
    logging.error("Failed to import get_display_timezone from utils. Timezone functionality may be impaired.")
    # Provide a fallback if critical
    def get_display_timezone():
        return pytz.utc # Default to UTC

logger = logging.getLogger(__name__)

# Define the Blueprint for UI routes
# Assuming templates are in ../templates relative to where app.py is run
ui_bp = Blueprint('ui', __name__, template_folder='../templates', static_folder='../static')

# --- Optional: Simple Email Regex ---
# Very basic check, assumes type="email" in HTML does most work
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

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
             app_settings_local = getattr(current_app, 'app_settings', {}) # Safely get app_settings
             current_color_settings = {k: v for k, v in app_settings_local.items() if k.startswith('color_')}

        # Use get() with default for robustness
        current_scan_status = getattr(current_app, 'scan_status', {"last_run_status": "Scan status unavailable", "running": False, "next_run_time": None})
        current_scheduler = getattr(current_app, 'scheduler', None)
        # --- End access shared state ---

        # --- Process fetched data ---
        summary_last_updated_str = "Never"
        if current_summary.get("last_updated"):
             try:
                  local_update_time = current_summary["last_updated"].astimezone(display_timezone_obj)
                  summary_last_updated_str = local_update_time.strftime('%Y-%m-%d %H:%M:%S %Z')
             except Exception as tz_err:
                  logging.warning(f"Timezone conversion error for summary update time: {tz_err}")
                  # Fallback formatting if timezone conversion fails
                  summary_last_updated_str = current_summary["last_updated"].strftime('%Y-%m-%d %H:%M:%S UTC') + " (UTC)"

        job = None
        if current_scheduler and current_scheduler.running:
             try:
                 job = current_scheduler.get_job('docker_log_scan_job')
                 job_state = 'paused' if job and job.next_run_time is None else ('running' if job else 'stopped')
             except Exception as scheduler_err:
                  logging.error(f"Error getting scheduler job state: {scheduler_err}")
                  job_state = 'scheduler_error'
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
        elif job_state in ['scheduler_stopped', 'scheduler_missing', 'scheduler_error']:
             next_run_time_str = "Scheduler Stopped/Unavailable/Error"
        else: # Error or unknown state
             next_run_time_str = "N/A"

    except AttributeError as e:
         logging.exception(f"Failed to access shared state via current_app attribute in index route! Missing attribute: {e}")
         # Render error template or redirect? Returning string is okay for simple cases
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
             # Use get() with default for robustness
             app_settings_local = getattr(current_app, 'app_settings', {})
             current_color_settings = {k: v for k, v in app_settings_local.items() if k.startswith('color_')}

        if request.method == 'POST':
            new_status = request.form.get('new_status')
            notes = request.form.get('notes', '').strip()
            if new_status not in ['resolved', 'ignored', 'unresolved']:
                 flash('Invalid status selected.', 'error')
                 # Re-render with abnormality data and colors
                 return render_template('manage.html', abnormality=abnormality, color_settings=current_color_settings)

            # Assuming db.update_abnormality_status exists and returns True/False
            success = db.update_abnormality_status(abnormality_id, new_status, notes if notes else None)

            if success:
                 flash(f'Status successfully updated to {new_status}.', 'success')
                 target_container_id = abnormality.get('container_id')
                 if target_container_id:
                      # Safely access container statuses
                      container_statuses_ref = getattr(current_app, 'container_statuses', None)
                      if container_statuses_ref is not None:
                           with current_app.container_statuses_lock:
                                if target_container_id in container_statuses_ref:
                                     current_cont_status = container_statuses_ref[target_container_id].get('status')
                                     if new_status in ['resolved', 'ignored'] and current_cont_status == 'unhealthy':
                                          container_statuses_ref[target_container_id]['status'] = 'awaiting_scan'
                                          # Keep db_id linked for resolved/ignored cases, maybe?
                                          # Or clear it? Let's keep it for now to allow linking back from index if needed.
                                          container_statuses_ref[target_container_id]['db_id'] = abnormality_id
                                          logging.info(f"Set {target_container_id[:12]} to awaiting_scan via manage page (issue {abnormality_id} {new_status}).")
                                     elif new_status == 'unresolved' and current_cont_status != 'unhealthy':
                                          container_statuses_ref[target_container_id]['status'] = 'unhealthy'
                                          container_statuses_ref[target_container_id]['db_id'] = abnormality_id # Relink the ID
                                          logging.info(f"Set {target_container_id[:12]} back to unhealthy via manage page (issue {abnormality_id} reopened).")
                 # Redirect to index after successful update and cache modification
                 return redirect(url_for('ui.index')) # Use blueprint prefix
            else:
                 flash('Database update failed. Please check logs.', 'error')
                 # Re-render with abnormality data and colors on failure
                 return render_template('manage.html', abnormality=abnormality, color_settings=current_color_settings)

        # --- GET Request ---
        # Render the template with abnormality data and colors
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
    # Basic validation for container ID format (adjust if needed)
    if not container_id or not all(c in '0123456789abcdefABCDEF' for c in container_id) or len(container_id) < 12:
        logging.warning(f"Invalid container ID format requested in history: {container_id}")
        abort(404) # Not Found for invalid ID format

    # Assuming db.get_abnormalities_by_container exists
    logger.info(f"Fetching history for container_id: {container_id}")
    history_records = db.get_abnormalities_by_container(container_id)
    logger.info(f"Found {len(history_records)} history records for {container_id}.")
    container_name = history_records[0]['container_name'] if history_records else f"Unknown Container (ID: {container_id[:12]}...)"
    display_timezone_obj = get_display_timezone()
    current_color_settings = {}

    try:
        # Safely access settings
        app_settings_local = getattr(current_app, 'app_settings', None)
        if app_settings_local is not None:
             with current_app.settings_lock:
                  current_color_settings = {k: v for k, v in app_settings_local.items() if k.startswith('color_')}
        else:
            logging.error("App settings not found on current_app in history route.")
            flash("Could not load color settings (app state missing).", "warning")

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
                           timezone_obj=display_timezone_obj, # Pass timezone object for potential use in template filters
                           color_settings=current_color_settings)


@ui_bp.route('/help')
def help_page():
    """Displays the static help/manual page."""
    logging.debug("Rendering help page.")
    return render_template('help.html')


# --- UPDATED ROUTE: AI Summary History ---
@ui_bp.route('/summary_history')
def summary_history():
    """Displays the history of generated AI health summaries."""
    limit = 50 # How many recent summaries to show
    history_records = []
    error_message = None
    display_timezone_obj = get_display_timezone() # Get the actual timezone object

    try:
        # Check if the DB function exists
        if hasattr(db, 'get_summary_history'):
            raw_records = db.get_summary_history(limit=limit)
            # db.py's _row_to_dict_with_parsed_dates now handles parsing the timestamp

            # --- START: Format timestamps before sending to template ---
            formatted_records = []
            for record in raw_records:
                if record and isinstance(record.get('timestamp'), datetime):
                    try:
                        # Convert to local timezone and format
                        local_time = record['timestamp'].astimezone(display_timezone_obj)
                        record['formatted_timestamp'] = local_time.strftime('%Y-%m-%d %H:%M:%S %Z')
                    except Exception as fmt_err:
                        logging.warning(f"Error formatting timestamp {record['timestamp']}: {fmt_err}")
                        # Fallback to ISO string if formatting fails
                        record['formatted_timestamp'] = record['timestamp'].isoformat()
                elif record and record.get('timestamp'):
                     # If it exists but isn't a datetime, display as is
                     record['formatted_timestamp'] = str(record['timestamp'])
                elif record:
                     record['formatted_timestamp'] = 'N/A' # Handle missing timestamp case

                if record: # Ensure record is not None before appending
                     formatted_records.append(record)
            # --- END: Format timestamps ---

            history_records = formatted_records # Use the list with formatted timestamps

            if not history_records:
                logging.info("No AI summary history found in the database.")
        else:
            error_message = "Internal Error: Summary history feature not available (DB function missing)."
            logging.error(error_message)

    except Exception as e:
        error_message = f"An unexpected error occurred while fetching summary history: {e}"
        logging.exception("Error fetching summary history:")

    return render_template('summary_history.html',
                           records=history_records, # Pass the modified records
                           limit=limit,
                           error_message=error_message,
                           # Pass timezone name for display, template doesn't need the object now
                           display_timezone_name=str(display_timezone_obj))


@ui_bp.route('/settings', methods=['GET', 'POST'])
def settings():
    """Handles viewing and updating application settings (excluding API key)."""
    restart_required_settings = ['scan_interval_minutes', 'summary_interval_hours']
    needs_restart_msg = False

    try:
        if request.method == 'POST':
            logging.info("Processing CORE settings form update...")
            form_data = request.form.to_dict() # Gets regular form fields
            new_settings = {}
            validation_errors = []
            # --- START: Define expected keys including gravatar_email ---
            expected_keys = [k for k in db.DEFAULT_SETTINGS.keys() if k != 'api_key']
            # Ensure new keys from defaults are included if db hasn't been updated yet
            # (Assuming db.py DEFAULT_SETTINGS has been updated)
            if 'scan_on_startup' not in expected_keys:
                expected_keys.append('scan_on_startup')
                logging.warning("Adding 'scan_on_startup' to expected keys (missing from db.DEFAULT_SETTINGS?)")
            if 'gravatar_email' not in expected_keys:
                expected_keys.append('gravatar_email')
                logging.warning("Adding 'gravatar_email' to expected keys (missing from db.DEFAULT_SETTINGS?)")
            # --- END: Define expected keys ---


            # --- Validation Loop ---
            for key in expected_keys:
                # --- START: Handle scan_on_startup checkbox ---
                if key == 'scan_on_startup':
                    # Checkbox value is 'true' if checked, otherwise key is absent in form_data
                    value = 'true' if key in form_data else 'false'
                    new_settings[key] = value # Store 'true' or 'false' string
                    continue # Skip to next key
                # --- END: Handle scan_on_startup checkbox ---

                # --- START: Handle gravatar_email ---
                elif key == 'gravatar_email':
                     value = form_data.get(key, '').strip()
                     # Optional validation: check if it's not empty and looks like an email
                     if value and not re.match(EMAIL_REGEX, value):
                         validation_errors.append("Invalid format for Gravatar Email.")
                     else:
                         new_settings[key] = value # Store empty string or valid-looking email
                     continue # Skip to next key
                # --- END: Handle gravatar_email ---

                # Handle ignored containers list (multi-select)
                elif key == 'ignored_containers':
                    ignored_list = request.form.getlist('ignored_containers') # Use getlist here
                    ignored_list = [name for name in ignored_list if name] # Clean empty strings
                    try:
                        new_settings[key] = json.dumps(ignored_list)
                        form_data['ignored_containers_textarea'] = "\n".join(ignored_list) # Keep for potential error re-render consistency
                    except Exception as e:
                        validation_errors.append(f"Error processing ignore list: {e}")
                    continue # Skip to next key

                # Handle other keys (numeric, color, text etc.)
                else:
                    value = form_data.get(key, '').strip() # Use get() with default

                    if key in ['scan_interval_minutes', 'summary_interval_hours', 'log_lines_to_fetch']:
                         try:
                             int_val = int(value)
                             if int_val <= 0: raise ValueError("Value must be positive.")
                             new_settings[key] = str(int_val) # Store as string
                             # Check if restart needed
                             try:
                                 app_settings_local = getattr(current_app, 'app_settings', {})
                                 with current_app.settings_lock:
                                     # Compare new string value with cached INT value (needs cast)
                                     if key in restart_required_settings and str(app_settings_local.get(key)) != str(int_val):
                                          needs_restart_msg = True
                             except (AttributeError, ValueError, KeyError, threading.ThreadError) as check_err: # Added ThreadError
                                  logging.error(f"Could not check restart status for {key}: {check_err}")
                         except ValueError:
                             validation_errors.append(f"Invalid positive integer required for '{key.replace('_', ' ').title()}'.")

                    elif key.startswith('color_'):
                         if not value: validation_errors.append(f"Color value for '{key.replace('_', ' ').title()}' cannot be empty.")
                         elif not value.startswith('#') or not (len(value) == 7 or len(value) == 4): validation_errors.append(f"Invalid color format for '{key.replace('_', ' ').title()}'. Use #rrggbb or #rgb.")
                         else:
                             try: int(value[1:], 16); new_settings[key] = value # Validate hex
                             except ValueError: validation_errors.append(f"Invalid hex color value for '{key.replace('_', ' ').title()}'.")
                    elif key == 'ollama_api_url':
                         if not value: validation_errors.append("Ollama API URL cannot be empty.")
                         elif not value.startswith(('http://', 'https://')): validation_errors.append("Ollama API URL must start with http:// or https://")
                         else: new_settings[key] = value.rstrip('/') # Remove trailing slash
                    elif key == 'ollama_model':
                         manual_model = form_data.get('ollama_model_manual', '').strip()
                         selected_model = value # Original value from select/hidden field in form_data
                         final_model = manual_model if manual_model else selected_model
                         if not final_model: validation_errors.append("Ollama Model cannot be empty (select or enter manually).")
                         else: new_settings[key] = final_model; form_data['ollama_model'] = final_model # Update form_data too
                    elif key == 'analysis_prompt':
                         if not value: validation_errors.append("Analysis Prompt cannot be empty.")
                         else: new_settings[key] = value
                    # Add other specific validations if needed

            # --- Handle Validation Results ---
            if validation_errors:
                for error in validation_errors: flash(error, 'error') # Show all errors

                # --- Repopulate data for re-rendering form on validation error ---
                try:
                    app_settings_local = getattr(current_app, 'app_settings', {})
                    container_statuses_local = getattr(current_app, 'container_statuses', {})
                    models_local = getattr(current_app, 'available_ollama_models', [])
                    models_lock_local = getattr(current_app, 'models_lock', None)
                    settings_lock_local = getattr(current_app, 'settings_lock', None)
                    container_lock_local = getattr(current_app, 'container_statuses_lock', None)

                    # Get current saved settings as base
                    if settings_lock_local:
                         with settings_lock_local: current_display_settings = app_settings_local.copy()
                    else: logging.error("Settings lock missing..."); current_display_settings = {}

                    # Get current running container names
                    if container_lock_local:
                        with container_lock_local: running_names = {d['name'] for d in container_statuses_local.values() if isinstance(d, dict) and 'name' in d}
                    else: logging.error("Container statuses lock missing..."); running_names = set()

                    # Get currently saved ignore list from display settings (safer)
                    ignored_list_display = current_display_settings.get('ignored_containers_list', [])
                    if not isinstance(ignored_list_display, list): ignored_list_display = []

                    # Combine running and ignored for the multi-select options
                    all_names_display = sorted(list(running_names.union(set(ignored_list_display))))

                    # Get available models
                    if models_lock_local:
                         with models_lock_local: current_models_display = list(models_local)
                    else: logging.error("Models lock missing..."); current_models_display = []

                    logging.info(f"Validation Error: Re-rendering settings with models: {current_models_display}")

                    # --- Override display settings with submitted form data ---
                    # Use form_data for most fields
                    for key, value in form_data.items():
                         # Ensure we only update keys that are expected settings or helper fields
                         if key in expected_keys or key in ['ignored_containers_textarea', 'ollama_model_manual']:
                              current_display_settings[key] = value

                    # Explicitly handle scan_on_startup boolean for re-render based on form presence
                    current_display_settings['scan_on_startup'] = 'true' if 'scan_on_startup' in form_data else 'false'
                    current_display_settings['scan_on_startup_bool'] = (current_display_settings['scan_on_startup'] == 'true')

                    # Ensure color defaults
                    default_colors = db.DEFAULT_SETTINGS
                    for setting_key in default_colors:
                         if setting_key.startswith('color_'): current_display_settings.setdefault(setting_key, default_colors[setting_key])

                    # Get the submitted ignored list for the multi-select state
                    submitted_ignored_list = request.form.getlist('ignored_containers')
                    submitted_ignored_list = [name for name in submitted_ignored_list if name]

                    # --- Ensure gravatar_email uses submitted value on re-render ---
                    current_display_settings['gravatar_email'] = form_data.get('gravatar_email', '')

                    return render_template('settings.html',
                                           settings=current_display_settings, # Pass merged form/saved data
                                           available_models=current_models_display,
                                           all_container_names=all_names_display,
                                           ignored_container_list=submitted_ignored_list) # Pass submitted list for selection

                except Exception as e_re_render:
                     logging.exception(f"Error preparing settings page data after validation failure: {e_re_render}")
                     flash("An unexpected error occurred while preparing the settings page.", "error")
                     return redirect(url_for('ui.index'))


            # --- Save Validated Settings (No validation errors) ---
            else:
                 save_success = True
                 failed_key = None
                 app_settings_ref = getattr(current_app, 'app_settings', None)
                 settings_lock_local = getattr(current_app, 'settings_lock', None)
                 analyzer_instance = getattr(current_app, 'analyzer', None)

                 if app_settings_ref is None or settings_lock_local is None:
                      logging.error("Cannot save settings: app_settings or settings_lock not found.")
                      flash("Internal application error: Cannot access settings state.", "error")
                      save_success = False
                 else:
                     with settings_lock_local:
                         for key, value in new_settings.items(): # Loop through validated data
                             current_value_in_cache = app_settings_ref.get(key)
                             changed = False # Default to not changed

                             # Compare based on type
                             if key == 'ignored_containers':
                                 try:
                                     current_list = json.loads(current_value_in_cache) if isinstance(current_value_in_cache, str) else (current_value_in_cache if isinstance(current_value_in_cache, list) else [])
                                     new_list = json.loads(value)
                                     changed = set(current_list) != set(new_list)
                                 except (json.JSONDecodeError, TypeError): changed = True
                             # Compare string values directly for others (including 'true'/'false' for scan_on_startup)
                             else:
                                 # Special check for gravatar_email allowing empty string
                                 if key == 'gravatar_email':
                                     changed = str(current_value_in_cache) != str(value)
                                 else:
                                     # Compare strings, default to changed if cache value is None/missing
                                     changed = str(current_value_in_cache) != str(value) if current_value_in_cache is not None else True

                             if changed:
                                  logging.info(f"Attempting to save core setting: {key} = {value[:50] if isinstance(value, str) else value}...")
                                  if db.set_setting(key, value):
                                       app_settings_ref[key] = value # Update cache (stores string)

                                       # --- Update derived cache values ---
                                       if key == 'scan_on_startup':
                                            app_settings_ref['scan_on_startup_bool'] = (value == 'true')
                                            logging.debug(f"Updated scan_on_startup_bool in cache to: {app_settings_ref['scan_on_startup_bool']}")
                                       elif key == 'ignored_containers':
                                           try:
                                               parsed_list = json.loads(value)
                                               app_settings_ref['ignored_containers_list'] = parsed_list
                                               app_settings_ref['ignored_containers_textarea'] = "\n".join(parsed_list)
                                           except Exception as parse_err:
                                               logging.error(f"Error parsing saved ignored_containers JSON: {parse_err}")
                                               app_settings_ref['ignored_containers_list'] = []
                                               app_settings_ref['ignored_containers_textarea'] = ""
                                       elif key in ['scan_interval_minutes','summary_interval_hours','log_lines_to_fetch']:
                                           try:
                                               app_settings_ref[key] = int(value) # Store as int in cache
                                           except (ValueError, TypeError):
                                               logging.warning(f"Failed to cast {key} to int for cache, storing as string.")
                                               # Keep string value in cache if int cast fails post-DB save
                                       # --- gravatar_email does not need derived values ---

                                       # Propagate relevant settings to analyzer (not needed for gravatar)
                                       if analyzer_instance:
                                            try:
                                                 if key == 'ollama_api_url': analyzer_instance.OLLAMA_API_URL = value
                                                 if key == 'ollama_model': analyzer_instance.DEFAULT_OLLAMA_MODEL = value
                                                 # Only log if it's a relevant key
                                                 if key in ['ollama_api_url', 'ollama_model']:
                                                      logging.debug(f"Propagated setting '{key}' to analyzer module.")
                                            except Exception as prop_err: logging.error(f"Error propagating setting '{key}' to analyzer: {prop_err}")
                                       elif key in ['ollama_api_url', 'ollama_model']:
                                            # Log warning only if propagation was actually needed
                                            logging.warning("Analyzer instance not found, cannot propagate settings.")
                                  else: # db save failed
                                      logging.error(f"Database save failed for setting: {key}")
                                      save_success = False; failed_key = key; break # Stop saving on first failure
                             else:
                                  logging.debug(f"Skipping save for unchanged core setting: {key}")

                 if save_success:
                     flash("Core settings saved successfully.", 'success')
                     if needs_restart_msg:
                          flash("Interval changes require an application restart to take effect.", 'warning')
                 else:
                     flash(f"Failed to save setting '{failed_key or 'N/A'}' to the database. Check logs.", 'error') # Handle failed_key potentially being None

                 return redirect(url_for('ui.settings')) # Redirect back after POST

        # --- GET Request ---
        else:
            logging.info("SETTINGS GET: Fetching data for settings page...")
            current_settings_display = {}
            running_names = set()
            current_models_display = []
            ignored_list_display = []

            settings_lock_local = getattr(current_app, 'settings_lock', None)
            container_lock_local = getattr(current_app, 'container_statuses_lock', None)
            models_lock_local = getattr(current_app, 'models_lock', None)
            app_settings_local = getattr(current_app, 'app_settings', {}) # Get from app context
            container_statuses_local = getattr(current_app, 'container_statuses', {})
            models_local = getattr(current_app, 'available_ollama_models', [])

            if settings_lock_local:
                with settings_lock_local:
                    current_settings_display = app_settings_local.copy()
                    # --- Ensure boolean version exists for template ---
                    if 'scan_on_startup_bool' not in current_settings_display:
                         current_settings_display['scan_on_startup_bool'] = current_settings_display.get('scan_on_startup', 'false').lower() == 'true'
                         logging.debug(f"SETTINGS GET: Added derived scan_on_startup_bool: {current_settings_display['scan_on_startup_bool']}")
                    # --- Ensure gravatar_email exists (even if empty) ---
                    if 'gravatar_email' not in current_settings_display:
                        current_settings_display['gravatar_email'] = '' # Add empty string if missing entirely
                logging.debug("SETTINGS GET: Settings fetched.")
            else:
                logging.error("SETTINGS GET: Settings lock missing!")
                # Provide defaults if lock is missing
                current_settings_display = db.DEFAULT_SETTINGS.copy() # Start with defaults
                current_settings_display['scan_on_startup_bool'] = False
                current_settings_display['gravatar_email'] = ''


            # Fetch container names
            if container_lock_local:
                with container_lock_local: running_names = {d['name'] for d in container_statuses_local.values() if isinstance(d, dict) and 'name' in d}
                logging.debug("SETTINGS GET: Container names fetched.")
            else: logging.error("SETTINGS GET: Container statuses lock missing!")

            # Fetch models
            if models_lock_local:
                with models_lock_local: current_models_display = list(models_local)
                logging.debug(f"SETTINGS GET: Models fetched: {len(current_models_display)}")
            else: logging.error("SETTINGS GET: Models lock missing!")

            # Get ignored list from fetched settings
            ignored_list_display = current_settings_display.get('ignored_containers_list', [])
            if not isinstance(ignored_list_display, list): ignored_list_display = []
            all_names_display = sorted(list(running_names.union(set(ignored_list_display))))

            # Ensure default colors are present
            default_settings_all = db.DEFAULT_SETTINGS
            for key, default_value in default_settings_all.items():
                 if key.startswith('color_'): current_settings_display.setdefault(key, default_value)

            # Ensure textarea representation exists if needed
            current_settings_display.setdefault('ignored_containers_textarea', "\n".join(ignored_list_display))

            logging.info(f"SETTINGS GET: Preparing to render template...")

            return render_template('settings.html',
                                   settings=current_settings_display, # Pass updated settings dict (includes gravatar_email)
                                   available_models=current_models_display,
                                   all_container_names=all_names_display,
                                   ignored_container_list=ignored_list_display
                                   )

    except AttributeError as e:
        logging.exception(f"Failed to access shared state attribute in settings route! Missing attribute: {e}")
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
    # Assuming db.set_setting exists and returns True/False
    save_ok = db.set_setting('api_key', new_key)

    if save_ok:
         try:
             # Safely access settings lock and dictionary
             settings_lock_local = getattr(current_app, 'settings_lock', None)
             app_settings_local = getattr(current_app, 'app_settings', None)
             if settings_lock_local and app_settings_local is not None:
                 with settings_lock_local:
                     app_settings_local['api_key'] = new_key
                 logging.info(f"Regenerate: API key updated in DB and cache.")
                 flash("API Key successfully regenerated!", 'success')
             else:
                  logging.error("Regenerate: Failed to update API key in app cache (state/lock missing). DB was updated.")
                  flash("API Key regenerated in DB, but failed to update cache. Restart may be needed.", 'warning')

         except Exception as e_cache:
             logging.exception(f"Regenerate: Error updating cache: {e_cache}")
             flash("API Key regenerated in DB, but cache update failed.", 'warning')
    else:
         logging.error("Regenerate: Failed to save new API key to database.")
         flash("Error: Failed to save regenerated API key to database.", 'error')

    return redirect(url_for('ui.settings')) # Use blueprint prefix


# --- NEW ROUTE: View Container Logs ---
@ui_bp.route('/logs/<string:container_id>')
def view_logs(container_id):
    """Displays the most recent logs for a specific container."""
    # Basic validation for container ID format
    # Use full container ID length check (64 chars)
    if not container_id or not all(c in '0123456789abcdefABCDEF' for c in container_id.lower()) or len(container_id) != 64:
        logging.warning(f"Invalid container ID format requested in logs view: {container_id}")
        abort(404)

    lines_param = request.args.get('lines', '200') # Default to 200 lines
    try:
        num_lines = int(lines_param)
        if num_lines <= 0 or num_lines > 5000: # Add an upper limit
            flash(f"Number of lines must be between 1 and 5000. Using {'5000' if num_lines > 5000 else '200'}.", "warning")
            num_lines = min(max(num_lines, 1), 5000) if num_lines > 0 else 200
    except ValueError:
        flash("Invalid number of lines specified, using default (200).", "warning")
        num_lines = 200

    logs_content = ""
    container_name = f"Unknown (ID: {container_id[:12]})"
    error_message = None
    docker_client = None

    try:
        # Use the analyzer module function which might handle client caching/closing
        docker_client = analyzer.get_docker_client()
        if not docker_client: # Corrected variable name here
            # Raise a specific error if client creation failed internally
            raise ConnectionError("Failed to get Docker client from analyzer.")

        container = docker_client.containers.get(container_id)
        container_name = container.name

        # Fetch logs - returns bytes
        logging.info(f"Fetching last {num_lines} log lines for container {container_name} ({container_id[:12]})")
        # Use the analyzer function to fetch logs, passing num_lines
        logs_str = analyzer.fetch_container_logs(container, num_lines=num_lines)
        if logs_str is None:
             # fetch_container_logs returns None on Docker/API errors
             raise ConnectionError("Failed to fetch logs via analyzer function.")
        logs_content = logs_str

    except docker.errors.NotFound:
        error_message = f"Container with ID '{container_id}' not found."
        logging.warning(error_message)
        flash(error_message, "error")
        # Optional: redirect back or show error on the logs page
        # return redirect(url_for('ui.index'))
    except (docker.errors.APIError, ConnectionError, Exception) as e:
        error_message = f"Error fetching logs for container {container_id}: {e}"
        logging.exception(f"Error fetching logs for container {container_id}:")
        flash(error_message, "error")
        # Keep logs_content empty or set it to the error message
        logs_content = f"--- ERROR FETCHING LOGS ---\n{error_message}\n--- END ERROR ---"
    finally:
        # Assuming analyzer.get_docker_client doesn't manage closing itself
        if docker_client:
             try:
                  docker_client.close()
                  logging.debug("Docker client closed in logs route finally block.")
             except Exception as ce:
                  logging.warning(f"Exception closing Docker client in logs route: {ce}")


    return render_template('logs.html',
                           container_id=container_id,
                           container_name=container_name,
                           logs_content=logs_content,
                           num_lines=num_lines,
                           error_message=error_message) # Pass error message explicitly


# --- START: New Delete Summary History Route ---
@ui_bp.route('/summary_history/delete/<int:record_id>', methods=['POST'])
def delete_summary_history_record(record_id):
    """Handles deletion of a specific summary history record."""
    logger.info(f"Attempting to delete summary history record ID: {record_id}")
    deleted = False
    error_msg = None

    try:
        # Check if the DB function exists
        if hasattr(db, 'delete_summary_history'):
            deleted = db.delete_summary_history(record_id)
            if not deleted:
                # This might happen if the record was already deleted in another request
                error_msg = f"Summary record ID {record_id} not found or already deleted."
                logging.warning(error_msg)
        else:
            error_msg = "Internal Error: Delete summary history feature not available (DB function missing)."
            logging.error(error_msg)

    except Exception as e:
        error_msg = f"An unexpected error occurred while deleting summary record ID {record_id}: {e}"
        logging.exception(f"Error deleting summary record ID {record_id}:")

    # Flash message based on outcome
    if deleted:
        flash(f"Summary record ID {record_id} deleted successfully.", 'success')
    else:
        # Use a warning category if not found, error if exception occurred
        flash(error_msg or f"Failed to delete summary record ID {record_id}.", 'warning' if error_msg and "not found" in error_msg else 'danger')

    # Redirect back to the history page
    return redirect(url_for('ui.summary_history'))
# --- END: New Delete Summary History Route ---

# --- Keep any other routes below ---
