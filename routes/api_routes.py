# routes/api_routes.py
import logging
import secrets
import functools
from datetime import datetime, timezone
import threading # Needed for triggering background threads

from flask import Blueprint, jsonify, request, current_app, Response

# Import necessary local modules if needed (e.g., for db queries)
import db
# <<< NO import from app here anymore for background tasks >>>

logger = logging.getLogger(__name__)

# Define the blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api') # Add url_prefix

# --- API Key Authentication Decorator (Adapted for Blueprint Context) ---
def require_api_key(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        provided_key = None
        # Access settings via current_app
        try:
            # Use locks for thread-safe read, though less critical for read-only
            with current_app.settings_lock:
                api_key_setting = current_app.app_settings.get('api_key')

            if not api_key_setting:
                logger.warning(f"API access denied: Key not configured (Endpoint: {request.endpoint}).")
                # Use Response for consistent JSON error
                return Response(response=jsonify({"error": "API access requires configuration."}).get_data(), status=403, mimetype='application/json')

            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                provided_key = auth_header.split('Bearer ')[1]
            elif request.headers.get('X-Api-Key'):
                provided_key = request.headers.get('X-Api-Key')
            elif request.args.get('api_key'): # Check query params too
                provided_key = request.args.get('api_key')

            if not provided_key:
                 return Response(response=jsonify({"error": "API key required."}).get_data(), status=401, mimetype='application/json')

            # Use secrets.compare_digest for timing attack resistance
            if secrets.compare_digest(provided_key, api_key_setting):
                return f(*args, **kwargs)
            else:
                logger.warning(f"Invalid API key provided for endpoint '{request.endpoint}'.")
                return Response(response=jsonify({"error": "Invalid API key."}).get_data(), status=401, mimetype='application/json')

        except AttributeError as e:
             logger.error(f"Error accessing app state in require_api_key: {e}")
             return Response(response=jsonify({"error": "Internal server error accessing configuration."}).get_data(), status=500, mimetype='application/json')
        except Exception as e:
             logger.exception(f"Unexpected error in require_api_key:")
             return Response(response=jsonify({"error": "Internal server error during authentication."}).get_data(), status=500, mimetype='application/json')

    return decorated_function

# --- API Endpoint Routes ---

@api_bp.route('/status', methods=['GET'])
def api_status():
    """Returns the current AI summary and scan status."""
    try:
        with current_app.ai_summary_lock:
            summary_data = current_app.ai_health_summary.copy()
        # Use getattr for safe access to scan_status and scheduler
        scan_status_local = getattr(current_app, 'scan_status', {})
        scheduler_local = getattr(current_app, 'scheduler', None)

        last_updated = summary_data.get('last_updated')
        last_updated_iso = last_updated.isoformat(timespec='seconds')+"Z" if isinstance(last_updated, datetime) else None

        next_run = scan_status_local.get('next_run_time')
        next_run_iso = next_run.astimezone(timezone.utc).isoformat(timespec='seconds')+"Z" if isinstance(next_run, datetime) else None

        # Check scheduler job status more reliably
        job = None; is_paused = False
        scheduler_is_running = False
        if scheduler_local and scheduler_local.running:
            scheduler_is_running = True
            try:
                job = scheduler_local.get_job('docker_log_scan_job')
                if job and job.next_run_time is None:
                    is_paused = True
            except Exception as e: # Catch JobLookupError etc.
                logger.error(f"Error checking job status in API: {e}")
                job = None # Treat as job not found if error occurs

        return jsonify({
            "ai_summary": summary_data.get('summary'),
            "ai_summary_last_updated_utc": last_updated_iso,
            "ai_summary_error": summary_data.get('error'),
            "scan_last_status_message": scan_status_local.get('last_run_status'),
            "scan_running": scan_status_local.get('running'),
            "scan_next_run_utc": next_run_iso,
            "scheduler_running": scheduler_is_running,
            "scan_job_paused": is_paused
        })

    except AttributeError as e:
         logger.error(f"Error accessing app state in api_status: {e}")
         return jsonify({"error": "Internal server error accessing application state."}), 500
    except Exception as e:
        logger.exception("Unexpected error in api_status:")
        return jsonify({"error": "Internal server error processing status."}), 500


@api_bp.route('/containers', methods=['GET'])
def api_containers():
    """Returns the status of monitored containers."""
    try:
        statuses_copy = {}
        container_statuses_local = getattr(current_app, 'container_statuses', {})
        with current_app.container_statuses_lock:
            # Create a serializable copy
            for cid, data in container_statuses_local.items():
                statuses_copy[cid] = {
                    "id": data.get("id"), # Assuming 'id' key exists in your status dict
                    "name": data.get("name"),
                    "status": data.get("status"),
                    # Only include db_id if status is unhealthy AND db_id exists
                    "db_id": data.get("db_id") if data.get("status") == 'unhealthy' and data.get("db_id") is not None else None
                }
        return jsonify(statuses_copy)

    except AttributeError as e:
         logger.error(f"Error accessing app state in api_containers: {e}")
         return jsonify({"error": "Internal server error accessing application state."}), 500
    except Exception as e:
        logger.exception("Unexpected error in api_containers:")
        return jsonify({"error": "Internal server error processing container list."}), 500


@api_bp.route('/issues', methods=['GET'])
def api_issues():
    """Returns a list of abnormalities, filterable by status."""
    allowed_statuses = ['unresolved', 'resolved', 'ignored', 'all']
    status_filter = request.args.get('status', 'unresolved').lower()
    if status_filter not in allowed_statuses:
        return jsonify({"error": f"Invalid status filter. Allowed: {', '.join(allowed_statuses)}"}), 400

    try:
        limit_str = request.args.get('limit', '100')
        limit = int(limit_str)
        if limit <= 0 or limit > 1000: # Add a reasonable upper limit
             limit = 100 # Reset to default if invalid or too large
    except ValueError:
        limit = 100 # Default on error

    # Ensure DB function exists before calling
    if not hasattr(db, 'get_abnormalities_by_status'):
        logger.error("API Error: Database function 'get_abnormalities_by_status' is missing.")
        return jsonify({"error": "Internal server error (database function unavailable)."}), 500

    try:
        issues = db.get_abnormalities_by_status(status=status_filter, limit=limit)
        # Convert datetime objects to ISO format strings for JSON compatibility
        # Iterate through a copy if modifying in place, or create new list
        serializable_issues = []
        for issue in issues:
             issue_copy = issue.copy() # Work on a copy
             for key, value in issue_copy.items():
                  if isinstance(value, datetime):
                       # Ensure timezone awareness or assume UTC if naive
                       if value.tzinfo is None:
                            value = value.replace(tzinfo=timezone.utc)
                       issue_copy[key] = value.isoformat(timespec='seconds') + "Z" # Standard ISO format
             serializable_issues.append(issue_copy)

        return jsonify(serializable_issues)
    except Exception as e:
        logger.exception(f"Error fetching issues for API:")
        return jsonify({"error": "Failed to retrieve or serialize issues from database."}), 500


# --- Action Endpoints (Require API Key) ---

@api_bp.route('/scan/trigger', methods=['POST'])
@require_api_key
def api_trigger_scan():
    """Triggers a background log scan immediately."""
    try:
        scan_status_local = getattr(current_app, 'scan_status', {})
        # <<< Get the function from current_app >>>
        scan_func = getattr(current_app, 'scan_docker_logs_func', None)

        if scan_status_local.get("running"):
            return jsonify({"message": "Scan already in progress."}), 409 # Conflict
        elif not scan_func:
             logger.error("API trigger scan failed: Scan function not found on current_app.")
             return jsonify({"error": "Internal server error: Trigger mechanism unavailable."}), 500
        else:
            # Run in a separate thread using the function from current_app
            scan_thread = threading.Thread(target=scan_func, name="APIScanThread", daemon=True)
            scan_thread.start()
            logger.info(f"API triggered log scan directly.")
            return jsonify({"message": "Log scan triggered."}), 202 # Accepted
    except AttributeError as e:
         logger.error(f"Error accessing app state in api_trigger_scan: {e}")
         return jsonify({"error": "Internal server error accessing application state."}), 500
    except Exception as e:
        logger.exception(f"Error triggering API scan:")
        return jsonify({"error": f"Trigger failed due to internal server error."}), 500


@api_bp.route('/summary/trigger', methods=['POST'])
@require_api_key
def api_trigger_summary():
    """Triggers background AI summary generation immediately."""
    try:
        # <<< Get the function from current_app >>>
        summary_func = getattr(current_app, 'update_ai_health_summary_func', None)

        if not summary_func:
            logger.error("API trigger summary failed: Summary function not found on current_app.")
            return jsonify({"error": "Internal server error: Trigger mechanism unavailable."}), 500
        else:
            # Run in a separate thread using the function from current_app
            summary_thread = threading.Thread(target=summary_func, name="APISummaryThread", daemon=True)
            summary_thread.start()
            logger.info(f"API triggered AI summary directly.")
            return jsonify({"message": "Summary generation triggered."}), 202 # Accepted
    except Exception as e:
        logger.exception(f"Error triggering API summary:")
        return jsonify({"error": f"Trigger failed due to internal server error."}), 500
