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
# Assuming templates are in ../templates relative to where app.py is run
ui_bp = Blueprint('ui', __name__, template_folder='../templates', static_folder='../static')

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
                                          container_statuses_ref[target_container_id]['db_id'] = None # Don't link resolved/ignored ID on dashboard
                                          logging.info(f"Set {target_container_id[:12]} to awaiting_scan via manage page.")
                                     elif new_status == 'unresolved' and current_cont_status != 'unhealthy':
                                          container_statuses_ref[target_container_id]['status'] = 'unhealthy'
                                          container_statuses_ref[target_container_id]['db_id'] = abnormality_id # Relink the ID
                                          logging.info(f"Set {target_container_id[:12]} back to unhealthy via manage page.")
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
    history_records = db.get_abnormalities_by_container(container_id)
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
            # Define expected keys *excluding* api_key using default settings as base
            expected_keys = [k for k in db.DEFAULT_SETTINGS.keys() if k != 'api_key']

            # --- Validation Loop ---
            for key in expected_keys:
                value = form_data.get(key, '').strip() # Use get() with default

                if key == 'ignored_containers':
                     # Handle potentially multi-line input for ignored containers
                     ignored_raw = form_data.get('ignored_containers', '')
                     ignored_list = [line.strip() for line in ignored_raw.splitlines() if line.strip()]
                     try:
                         new_settings[key] = json.dumps(ignored_list)
                     except Exception as e:
                         validation_errors.append(f"Error processing ignore list: {e}")
                elif key in ['scan_interval_minutes', 'summary_interval_hours', 'log_lines_to_fetch']:
                     try:
                         int_val = int(value)
                         if int_val <= 0: raise ValueError("Value must be positive.")
                         new_settings[key] = str(int_val) # Store as string in dict, DB handles type
                         # Check if restart needed
                         app_settings_local = getattr(current_app, 'app_settings', {})
                         with current_app.settings_lock:
                             if key in restart_required_settings and str(app_settings_local.get(key)) != str(int_val):
                                  needs_restart_msg = True
                     except ValueError:
                         validation_errors.append(f"Invalid positive integer required for '{key.replace('_', ' ').title()}'.")
                     except AttributeError: # Handle case where current_app or settings_lock is missing
                          logging.error(f"Could not check restart status for {key} due to missing app state.")
                elif key.startswith('color_'):
                     if not value:
                          validation_errors.append(f"Color value for '{key.replace('_', ' ').title()}' cannot be empty.")
                     elif not value.startswith('#') or not (len(value) == 7 or len(value) == 4):
                         validation_errors.append(f"Invalid color format for '{key.replace('_', ' ').title()}'. Use #rrggbb or #rgb.")
                     else:
                          try:
                              int(value[1:], 16) # Validate hex
                              new_settings[key] = value
                          except ValueError:
                              validation_errors.append(f"Invalid hex color value for '{key.replace('_', ' ').title()}'.")
                elif key == 'ollama_api_url':
                     if not value:
                         validation_errors.append("Ollama API URL cannot be empty.")
                     elif not value.startswith(('http://', 'https://')):
                         validation_errors.append("Ollama API URL must start with http:// or https://")
                     else:
                         new_settings[key] = value.rstrip('/') # Remove trailing slash
                elif key == 'ollama_model':
                     if not value:
                          validation_errors.append("Ollama Model cannot be empty.")
                     else:
                          new_settings[key] = value
                elif key == 'analysis_prompt':
                     if not value:
                          validation_errors.append("Analysis Prompt cannot be empty.")
                     else:
                          new_settings[key] = value
                # No explicit handling for api_key here, it's done in regenerate route

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

                    if settings_lock_local:
                         with settings_lock_local:
                              current_display_settings = app_settings_local.copy()
                    else:
                        logging.error("Settings lock missing on current_app, cannot safely copy settings.")
                        current_display_settings = {} # Or provide defaults

                    if container_lock_local:
                        with container_lock_local:
                            running_names = {d['name'] for d in container_statuses_local.values() if isinstance(d, dict) and 'name' in d}
                    else:
                        logging.error("Container statuses lock missing on current_app.")
                        running_names = set()


                    ignored_list_display = current_display_settings.get('ignored_containers_list', [])
                    if not isinstance(ignored_list_display, list): ignored_list_display = [] # Ensure it's a list
                    all_names_display = sorted(list(running_names.union(set(ignored_list_display))))

                    if models_lock_local:
                         with models_lock_local:
                              current_models_display = list(models_local) # Make copy under lock
                    else:
                         logging.error("Models lock missing on current_app.")
                         current_models_display = []

                    logging.info(f"Validation Error: Re-rendering settings with models: {current_models_display}")

                    # Pass the *partially updated form data back* so user doesn't lose all input
                    # Override display settings with submitted form data where available
                    for key, value in form_data.items():
                         if key in current_display_settings: # Only update keys relevant to settings
                              current_display_settings[key] = value
                              # Special handling for ignore list textarea
                              if key == 'ignored_containers':
                                   current_display_settings['ignored_containers_textarea'] = value

                    # Ensure color defaults are present if missing from saved settings/form
                    default_colors = json.loads(db.DEFAULT_SETTINGS.get('status_colors', '{}'))
                    for color_key, default_color_val in default_colors.items():
                         setting_color_key = f"color_{color_key.lower().replace(' ','_')}"
                         current_display_settings.setdefault(setting_color_key, default_color_val)


                    return render_template('settings.html',
                                           settings=current_display_settings, # Pass merged form/saved data
                                           available_models=current_models_display,
                                           all_container_names=all_names_display,
                                           ignored_container_list=ignored_list_display)

                except AttributeError as e_attr:
                    logging.exception(f"AttributeError preparing settings page data after validation failure: {e_attr}")
                    flash("An application state error occurred while preparing the settings page.", "error")
                    return redirect(url_for('ui.index'))
                except Exception as e_outer:
                    logging.exception(f"Outer error preparing settings page data after validation failure: {e_outer}")
                    flash("An unexpected error occurred while preparing the settings page.", "error")
                    return redirect(url_for('ui.index'))


            # --- Save Validated Settings (No validation errors) ---
            else:
                 save_success = True
                 failed_key = None
                 app_settings_ref = getattr(current_app, 'app_settings', None)
                 settings_lock_local = getattr(current_app, 'settings_lock', None)
                 analyzer_instance = getattr(current_app, 'analyzer', None) # Get analyzer instance

                 if app_settings_ref is None or settings_lock_local is None:
                      logging.error("Cannot save settings: app_settings or settings_lock not found on current_app.")
                      flash("Internal application error: Cannot access settings state.", "error")
                      save_success = False
                 else:
                     with settings_lock_local:
                         for key, value in new_settings.items(): # Loop through validated (non-api_key) data
                             if str(app_settings_ref.get(key)) != str(value): # Check if value actually changed
                                  logging.info(f"Attempting to save core setting: {key} = {value[:50] if isinstance(value, str) else value}...")
                                  if db.set_setting(key, value):
                                       app_settings_ref[key] = value # Update cache
                                       # Update derived/parsed values in cache
                                       if key == 'ignored_containers':
                                           try: app_settings_ref['ignored_containers_list'] = json.loads(value)
                                           except: app_settings_ref['ignored_containers_list'] = []
                                       if key in ['scan_interval_minutes','summary_interval_hours','log_lines_to_fetch']:
                                           try: app_settings_ref[key] = int(value)
                                           except: app_settings_ref[key] = 0 # Or keep default?
                                       # Propagate relevant settings to analyzer
                                       if analyzer_instance:
                                            try:
                                                 if key == 'ollama_api_url': analyzer_instance.OLLAMA_API_URL = value
                                                 if key == 'ollama_model': analyzer_instance.DEFAULT_OLLAMA_MODEL = value
                                                 if key == 'log_lines_to_fetch': analyzer_instance.LOG_LINES_TO_FETCH = int(value)
                                                 logging.debug(f"Propagated setting '{key}' to analyzer module.")
                                            except Exception as prop_err:
                                                 logging.error(f"Error propagating setting '{key}' to analyzer: {prop_err}")
                                       else:
                                            logging.warning("Analyzer instance not found on current_app, cannot propagate settings.")
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
                     flash(f"Failed to save setting '{failed_key}' to the database. Check logs.", 'error')

                 return redirect(url_for('ui.settings')) # Redirect back after POST

        # --- GET Request ---
        else:
            # <<< START OF ADDED LOGGING FOR GET >>>
            logging.info("SETTINGS GET: Fetching data for settings page...") # <<< ADD 1
            # Fetch all settings, including api_key for display
            current_settings_display = {}
            running_names = set()
            current_models_display = []
            ignored_list_display = []

            settings_lock_local = getattr(current_app, 'settings_lock', None)
            container_lock_local = getattr(current_app, 'container_statuses_lock', None)
            models_lock_local = getattr(current_app, 'models_lock', None)
            app_settings_local = getattr(current_app, 'app_settings', {})
            container_statuses_local = getattr(current_app, 'container_statuses', {})
            models_local = getattr(current_app, 'available_ollama_models', [])

            if settings_lock_local:
                with settings_lock_local:
                    current_settings_display = app_settings_local.copy()
                logging.debug("SETTINGS GET: Settings fetched.") # <<< ADD 2
            else:
                logging.error("SETTINGS GET: Settings lock missing!")

            if container_lock_local:
                with container_lock_local:
                    running_names = {d['name'] for d in container_statuses_local.values() if isinstance(d, dict) and 'name' in d}
                logging.debug("SETTINGS GET: Container names fetched.") # <<< ADD 3
            else:
                 logging.error("SETTINGS GET: Container statuses lock missing!")


            # Add log before accessing models lock
            logging.info("SETTINGS GET: Attempting to access models list...") # <<< ADD 4
            if models_lock_local:
                with models_lock_local:
                    # Add log inside lock
                    logging.info(f"SETTINGS GET: Inside models_lock. Current models in app state: {models_local}") # <<< ADD 5
                    current_models_display = list(models_local) # Make copy under lock
                    # Add log after reading
                    logging.info(f"SETTINGS GET: Read models into current_models_display: {current_models_display}") # <<< ADD 6
            else:
                logging.error("SETTINGS GET: Models lock missing!")
                current_models_display = []


            ignored_list_display = current_settings_display.get('ignored_containers_list', [])
            if not isinstance(ignored_list_display, list): ignored_list_display = [] # Ensure list
            all_names_display = sorted(list(running_names.union(set(ignored_list_display))))

            # Ensure default colors are present for the template if missing in saved settings
            default_colors = json.loads(db.DEFAULT_SETTINGS.get('status_colors', '{}'))
            for color_key, default_color_val in default_colors.items():
                 setting_color_key = f"color_{color_key.lower().replace(' ','_')}" # Construct key like 'color_healthy'
                 current_settings_display.setdefault(setting_color_key, default_color_val)

            # Ensure ignored_containers_textarea has the right format
            current_settings_display['ignored_containers_textarea'] = "\n".join(ignored_list_display)

            logging.info(f"SETTINGS GET: Preparing to render template with models: {current_models_display}") # <<< ADD 7
            # <<< END OF ADDED LOGGING FOR GET >>>

            return render_template('settings.html',
                                   settings=current_settings_display, # Pass all settings for display
                                   available_models=current_models_display, # Pass the fetched models
                                   all_container_names=all_names_display,
                                   ignored_container_list=ignored_list_display # Pass list for potential logic
                                   )

    except AttributeError as e:
        # Catch errors if locks or state dictionaries themselves are missing from current_app
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
