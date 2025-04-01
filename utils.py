# utils.py
import pytz
import hashlib # <<< ADD HASHING LIB >>>
import logging
import os # Still needed if db.py uses it, or remove if db dependency is fixed

logger = logging.getLogger(__name__)

# --- Add local db import for get_display_timezone if needed ---
# This creates a dependency cycle if utils is imported by db.
# Consider moving timezone setting logic or passing it if necessary.
try:
    import db
    db_import_successful = True
except ImportError:
    db_import_successful = False
    logger.warning("utils.py: Could not import db module, timezone setting will default to UTC.")


# Keep existing get_display_timezone function (MODIFIED to use DB setting)
def get_display_timezone():
    """Gets the display timezone object."""
    tz_name = 'UTC' # Default value
    if db_import_successful:
        try:
            tz_name = db.get_setting('timezone', 'UTC') # Assuming timezone is stored in settings DB
        except Exception as e:
            # Error fetching from DB, use default
            logger.warning(f"Could not load timezone setting from DB, defaulting to UTC: {e}")
            tz_name = 'UTC'
    else:
        # DB module wasn't imported, use default
        pass # tz_name is already 'UTC'

    # Now try to get the pytz object
    try:
        return pytz.timezone(tz_name)
    except pytz.exceptions.UnknownTimeZoneError:
        # Fallback to UTC if tz_name is invalid
        logger.warning(f"Invalid timezone name '{tz_name}' found. Defaulting to UTC.")
        return pytz.utc
    except Exception as e:
        # Catch any other error during pytz.timezone call
        logger.error(f"Unexpected error creating timezone object for '{tz_name}', defaulting to UTC: {e}")
        return pytz.utc


# --- START: New Gravatar Function ---
def generate_gravatar_url(email, size=40, default='identicon'):
    """
    Generates a Gravatar URL for a given email address.

    Args:
        email (str): The email address.
        size (int): The desired image size in pixels.
        default (str): The default image type if email has no Gravatar.
                       Options include 'mp', 'identicon', 'monsterid', 'wavatar',
                       'retro', 'robohash', 'blank', or a URL-encoded image URL.

    Returns:
        str: The Gravatar image URL, or None if email is invalid/empty.
    """
    if not email or not isinstance(email, str):
        return None # Return None if no valid email provided

    try:
        # 1. Trim leading/trailing whitespace.
        # 2. Force all characters lowercase.
        # 3. md5 hash the final string.
        email_processed = email.strip().lower()
        email_hash = hashlib.md5(email_processed.encode('utf-8')).hexdigest()

        # 4. Construct the URL
        # Using https for security
        gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?s={size}&d={default}"
        return gravatar_url
    except Exception as e:
        logger.error(f"Error generating Gravatar URL for email: {e}")
        return None # Return None on any error
# --- END: New Gravatar Function ---
