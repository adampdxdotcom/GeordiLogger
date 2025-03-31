# routes/scheduler_routes.py
import logging
import threading
from datetime import datetime, timedelta

from flask import Blueprint, redirect, url_for, flash, current_app
from apscheduler.jobstores.base import JobLookupError
from apscheduler.triggers.interval import IntervalTrigger

# Import background task functions if needed for triggering
# Get them via current_app instead to avoid circular imports
# from app import scan_docker_logs, update_ai_health_summary

# Import utility if needed for timezone
try:
    from utils import get_display_timezone
except ImportError:
    def get_display_timezone():
        import pytz
        return pytz.utc

logger = logging.getLogger(__name__)

# Define the blueprint with a URL prefix
scheduler_bp = Blueprint('scheduler', __name__, url_prefix='/scheduler')

# --- Scheduler Control Routes ---

@scheduler_bp.route('/pause', methods=['POST'])
def pause():
    """Pauses the main docker log scan job."""
    scan_status_local = getattr(current_app, 'scan_status', {})
    scheduler_local = getattr(current_app, 'scheduler', None)
    if not scheduler_local:
        flash("Scheduler not available.", "error")
        return redirect(url_for('ui.index'))

    try:
        if scheduler_local.running:
            job = scheduler_local.get_job('docker_log_scan_job')
            if job and job.next_run_time is not None: # Check if not already paused
                scheduler_local.pause_job('docker_log_scan_job')
                logging.info("Scan schedule paused by user via UI.")
                flash("Scan schedule paused.", "success")
                # Update status display immediately
                with current_app.scan_status_lock:
                     scan_status_local["next_run_time"] = None
                     # Optionally update last_run_status message
                     # scan_status_local["last_run_status"] = "Paused by user."
            elif job and job.next_run_time is None:
                 flash("Schedule is already paused.", "info")
            else: # Job doesn't exist
                 flash("Scan job not found in scheduler.", "warning")
        else:
            flash("Scheduler is not running.", "warning")
    except JobLookupError:
        flash("Scan job 'docker_log_scan_job' not found.", "warning")
    except Exception as e:
        logger.exception("Error pausing schedule via UI:")
        flash(f"Error pausing schedule: {e}", "error")
    finally:
        return redirect(url_for('ui.index')) # Redirect back to dashboard


@scheduler_bp.route('/resume', methods=['POST'])
def resume():
    """Resumes the main docker log scan job."""
    scan_status_local = getattr(current_app, 'scan_status', {})
    scheduler_local = getattr(current_app, 'scheduler', None)
    settings_local = getattr(current_app, 'app_settings', {})

    if not scheduler_local:
        flash("Scheduler not available.", "error")
        return redirect(url_for('ui.index'))

    try:
        if scheduler_local.running:
            job = scheduler_local.get_job('docker_log_scan_job')
            if job and job.next_run_time is None: # Check if paused
                 with current_app.settings_lock:
                     # Use the correct interval key from settings
                     scan_interval_minutes = settings_local.get('scan_interval_minutes', 5) # Default if missing

                 # Schedule next run soon (e.g., 5 seconds from now)
                 display_timezone = get_display_timezone()
                 next_run = datetime.now(display_timezone) + timedelta(seconds=5)

                 # Reschedule with the interval trigger
                 scheduler_local.reschedule_job(
                     'docker_log_scan_job',
                     trigger=IntervalTrigger(minutes=scan_interval_minutes, timezone=display_timezone),
                     next_run_time=next_run
                 )
                 # Update status display immediately
                 with current_app.scan_status_lock:
                      scan_status_local["next_run_time"] = next_run # Show the immediate next run
                 logging.info(f"Scan schedule resumed by user via UI. Next immediate run at {next_run.strftime('%H:%M:%S %Z')}.")
                 flash("Scan schedule resumed.", "success")
            elif job and job.next_run_time is not None:
                 flash("Schedule is already running.", "info")
            else: # Job doesn't exist
                 flash("Scan job not found in scheduler.", "warning")

        else:
            flash("Scheduler is not running.", "warning")
    except JobLookupError:
        flash("Scan job 'docker_log_scan_job' not found.", "warning")
    except Exception as e:
        logger.exception("Error resuming schedule via UI:")
        flash(f"Error resuming schedule: {e}", "error")
    finally:
        return redirect(url_for('ui.index'))


@scheduler_bp.route('/stop_scan', methods=['POST'])
def stop_current():
    """Signals the currently running scan (if any) to stop."""
    scan_status_local = getattr(current_app, 'scan_status', {})
    stop_event = getattr(current_app, 'stop_scan_event', None)

    if stop_event is None:
         flash("Stop event mechanism not available.", "error")
    elif scan_status_local.get("running"):
        stop_event.set()
        flash("Stop signal sent to running scan.", "info")
        logging.info("Stop scan signal sent via UI.")
    else:
        flash("No scan is currently running.", "info")

    return redirect(url_for('ui.index'))


@scheduler_bp.route('/trigger_scan', methods=['POST'])
def trigger_scan_now():
    """Triggers a background log scan immediately via UI."""
    scan_status_local = getattr(current_app, 'scan_status', {})
    scan_func = getattr(current_app, 'scan_docker_logs_func', None)

    if scan_status_local.get("running"):
        flash("Scan is already running.", "warning")
    elif not scan_func:
         logger.error("UI trigger scan failed: Scan function not found on current_app.")
         flash("Internal server error: Trigger mechanism unavailable.", "error")
    else:
        try:
            # Run in a separate thread immediately
            scan_thread = threading.Thread(target=scan_func, name="UIScanThread", daemon=True)
            scan_thread.start()
            logging.info(f"Manual log scan triggered directly via UI.")
            flash("Manual scan triggered.", "success")
        except Exception as e:
             logger.exception("Error triggering scan via UI:")
             flash(f"Trigger failed due to internal server error: {e}", "error")

    return redirect(url_for('ui.index'))


@scheduler_bp.route('/trigger_summary', methods=['POST'])
def trigger_summary_now():
    """Triggers background AI summary generation immediately via UI."""
    summary_func = getattr(current_app, 'update_ai_health_summary_func', None)

    if not summary_func:
        logger.error("UI trigger summary failed: Summary function not found on current_app.")
        flash("Internal server error: Trigger mechanism unavailable.", "error")
    else:
        try:
            # Run in a separate thread immediately
            summary_thread = threading.Thread(target=summary_func, name="UISummaryThread", daemon=True)
            summary_thread.start()
            logging.info(f"Manual AI summary triggered directly via UI.")
            flash("Manual summary triggered.", "success")
        except Exception as e:
             logger.exception("Error triggering summary via UI:")
             flash(f"Trigger failed due to internal server error: {e}", "error")

    return redirect(url_for('ui.index'))
