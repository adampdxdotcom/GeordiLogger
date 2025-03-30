# utils.py
import pytz
import logging
import os # Need os for the TZ environment variable

# You might need to adjust this if SCHEDULER_TIMEZONE needs to be shared/configured differently
# For now, keep its definition logic similar to how it was in app.py
# A better approach might be to pass the timezone string from settings
SCHEDULER_TIMEZONE = os.environ.get("TZ", "America/Los_Angeles")

def get_display_timezone():
    """Gets the display timezone object, falling back to UTC if invalid."""
    global SCHEDULER_TIMEZONE # Allow modification on fallback
    try:
        return pytz.timezone(SCHEDULER_TIMEZONE)
    except pytz.exceptions.UnknownTimeZoneError:
        logging.warning(f"Invalid TZ '{SCHEDULER_TIMEZONE}' specified. Using UTC.")
        SCHEDULER_TIMEZONE = "UTC" # Update the global for consistency if needed
        return pytz.utc
