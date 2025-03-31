# analyzer.py
import docker
import requests
import logging
import os
import json
from datetime import datetime, timedelta

# --- Local DB import needed for default prompt fallback ---
# This creates a slight dependency, but simplifies getting the default
try:
    import db # Used ONLY to access DEFAULT_SETTINGS for the prompt fallback
except ImportError:
    logging.warning("Could not import db in analyzer.py; default prompt fallback may use a hardcoded value.")
    # IMPORTANT: Keep this fallback prompt reasonably short and aligned with db.py's intent
    DEFAULT_ANALYSIS_PROMPT_FALLBACK = """Analyze the following Docker container logs STRICTLY for CRITICAL errors, security issues (like authentication failures), or persistent connection problems. Ignore standard startup/shutdown messages, INFO/DEBUG logs unless they clearly indicate a critical fault. If no significant issues are found, respond ONLY with the word 'NORMAL'. If issues ARE found, briefly describe the main problem and include the MOST relevant log line(s) EXACTLY as they appear, prefixed with 'Relevant Log(s):'. Example: 'Database connection refused. Relevant Log(s): ERROR: Connection refused: localhost:5432'

Logs:
{logs}"""

# Basic logging setup - Assuming configured elsewhere, but get logger here
logger = logging.getLogger(__name__)

# --- Configuration (Values are set/updated by app.py's load_settings) ---
# These act as initial defaults if load_settings hasn't run yet, but app.py should override
# Make sure these global names match exactly what app.py sets
OLLAMA_API_URL = os.environ.get("OLLAMA_API_URL", "http://localhost:11434") # Default to base URL
DEFAULT_OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "phi3")
# Default LOG_LINES_TO_FETCH (will be overridden by app.py load_settings)
LOG_LINES_TO_FETCH = int(os.environ.get("LOG_LINES_TO_FETCH", "100"))
DOCKER_SOCKET_PATH = "/var/run/docker.sock"
# Read timeouts from environment or set defaults
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "120")) # Timeout for analysis
OLLAMA_SUMMARY_TIMEOUT = int(os.environ.get("OLLAMA_SUMMARY_TIMEOUT", "180")) # Longer timeout for summary
OLLAMA_MODEL_LIST_TIMEOUT = 20 # Shorter timeout for just listing models


def get_docker_client():
    """Initializes and returns a Docker client connected via the socket."""
    try:
        if not os.path.exists(DOCKER_SOCKET_PATH):
            logger.error(f"Docker socket not found at {DOCKER_SOCKET_PATH}. Is Docker running and the socket mounted correctly?")
            return None

        # Use unix scheme explicitly
        client = docker.DockerClient(base_url=f'unix://{DOCKER_SOCKET_PATH}')
        if client.ping():
            logger.info("Successfully connected to Docker daemon via socket.")
            return client
        else:
            logger.error("Ping to Docker daemon failed, but no exception raised.")
            return None
    except docker.errors.DockerException as e:
        logger.error(f"DockerException connecting to Docker daemon: {e}")
        if "Permission denied" in str(e):
            logger.error("Permission denied accessing the Docker socket. Ensure the user running this application has permissions (e.g., is in the 'docker' group or uses appropriate privileges).")
        else:
            logger.error("Check if Docker daemon is running and the socket path is correct.")
        return None
    except requests.exceptions.ConnectionError as e:
         logger.error(f"Connection error connecting to Docker socket {DOCKER_SOCKET_PATH}: {e}. Is Docker daemon running?")
         return None
    except Exception as e:
        logger.exception(f"Unexpected error connecting to Docker daemon:")
        return None

def fetch_container_logs(container, num_lines=100):
    """Fetches the specified number of recent log lines for a container."""
    # Allow passing container object or ID string
    container_name = "Unknown"
    container_id_short = "Unknown"
    try:
        if isinstance(container, str): # If ID was passed
             client = get_docker_client()
             if not client: return None # Cannot proceed without client
             container_obj = client.containers.get(container)
             container_id_short = container_obj.short_id
             container_name = container_obj.name
        else: # Assume container object was passed
             container_obj = container
             container_id_short = container_obj.short_id
             container_name = container_obj.name

        logger.debug(f"Fetching last {num_lines} lines for {container_name} ({container_id_short}).")
        logs_bytes = container_obj.logs(tail=num_lines, timestamps=True, stream=False) # Add timestamps for context
        logs_str = logs_bytes.decode('utf-8', errors='replace')

        if not logs_str.strip():
            logger.debug(f"Container {container_name} ({container_id_short}) returned empty logs.")
            return ""
        return logs_str

    except docker.errors.NotFound:
        logger.warning(f"Container ({container_id_short}/{container_name}) not found during log fetch (may have stopped).")
        return None
    except docker.errors.APIError as e:
        logger.error(f"Docker API error fetching logs for {container_name} ({container_id_short}): {e}")
        return None
    except Exception as e:
        logger.exception(f"Unexpected error fetching logs for {container_name} ({container_id_short}):")
        return None

# --- Function modified to return specific error strings ---
def analyze_logs_with_ollama(logs, model_to_use=None, custom_prompt=None):
    """
    Sends logs to Ollama for analysis.
    Returns 'NORMAL', the AI's abnormality description (may start with 'ERROR:'),
    or an 'ERROR: <process failure description>' string.
    """
    global DEFAULT_OLLAMA_MODEL, OLLAMA_API_URL, OLLAMA_TIMEOUT # Access globals

    if not logs or logs.isspace():
        logger.debug("No logs provided to analyze.")
        return "NORMAL"

    effective_model = model_to_use or DEFAULT_OLLAMA_MODEL
    if not effective_model:
         logger.error("Ollama model name is missing. Cannot analyze logs.")
         return "ERROR: Ollama model not configured. Check settings." # Return prefixed error

    logger.info(f"Analyzing logs using Ollama model: {effective_model}")

    # --- Get and format prompt ---
    prompt_to_use = custom_prompt
    if not prompt_to_use:
        try:
            if hasattr(db, 'DEFAULT_SETTINGS') and 'analysis_prompt' in db.DEFAULT_SETTINGS:
                prompt_to_use = db.DEFAULT_SETTINGS['analysis_prompt']
            else: raise AttributeError
        except (NameError, AttributeError):
             logger.warning("db module or prompt setting not available, using hardcoded prompt fallback.")
             prompt_to_use = DEFAULT_ANALYSIS_PROMPT_FALLBACK

    try:
        if "{logs}" not in prompt_to_use:
            logger.error("Analysis prompt configuration error: '{logs}' placeholder is missing!")
            return "ERROR: Invalid analysis prompt configuration (missing '{logs}'). Check settings."
        final_prompt = prompt_to_use.format(logs=logs)
    except KeyError as ke:
        logger.error(f"Failed to format prompt - KeyError: {ke}. Check prompt template placeholders.")
        return f"ERROR: Invalid analysis prompt configuration (KeyError: {ke})."
    except Exception as fmt_err:
        logger.exception(f"Unexpected error formatting analysis prompt:")
        return f"ERROR: Prompt formatting failed - {fmt_err}"

    # --- Prepare API call ---
    generate_url = OLLAMA_API_URL
    if not generate_url:
         logger.error("Ollama API URL is not configured!")
         return "ERROR: Ollama API URL is not set. Check settings."

    if not generate_url.startswith(('http://', 'https://')):
         logger.error(f"Invalid Ollama API URL format: {generate_url}. Must start with http:// or https://")
         return "ERROR: Invalid Ollama API URL format."

    # Construct the correct /api/generate endpoint
    if '/api/' in generate_url: base_url = generate_url.split('/api/', 1)[0]
    else: base_url = generate_url.rstrip('/')
    api_endpoint = f"{base_url}/api/generate"

    payload = {
        "model": effective_model, "prompt": final_prompt, "stream": False,
        "options": { "temperature": 0.15 }
    }

    # --- Make API Call with Error Handling ---
    try:
        logger.debug(f"Sending analysis request to Ollama: {api_endpoint}, Model: {effective_model}, Timeout: {OLLAMA_TIMEOUT}s")
        response = requests.post(api_endpoint, json=payload, timeout=OLLAMA_TIMEOUT)

        if response.status_code == 404:
            logger.error(f"Ollama API endpoint not found ({response.status_code}): {api_endpoint}")
            response_text = response.text[:500]
            logger.error(f"Response: {response_text}")
            if f"model '{effective_model}' not found" in response.text:
                return f"ERROR: Ollama model '{effective_model}' not found on the server."
            else:
                return f"ERROR: Ollama endpoint not found ({response.status_code}) at {api_endpoint}"

        response.raise_for_status() # Raise HTTPError for other bad responses (4xx or 5xx)

        result = response.json()
        analysis_text = result.get('response', '').strip()

        if analysis_text.upper() == "NORMAL" or analysis_text.upper() == "NORMAL.":
            return "NORMAL"
        elif not analysis_text:
            logger.warning(f"Ollama model {effective_model} returned an empty response for analysis.")
            return "ERROR: Ollama returned empty response" # Treat empty as an error condition
        else:
            # Return the AI's response (which might start with "ERROR:" as per prompt instructions)
            return analysis_text

    except requests.exceptions.Timeout:
         logger.error(f"Timeout ({OLLAMA_TIMEOUT}s) contacting Ollama API at {api_endpoint}.")
         return f"ERROR: Ollama request timed out ({OLLAMA_TIMEOUT}s)" # Prefixed error
    except requests.exceptions.ConnectionError as e:
         logger.error(f"Connection error contacting Ollama API at {api_endpoint}: {e}")
         return f"ERROR: Could not connect to Ollama API at {OLLAMA_API_URL}. Connection refused/No route?" # Prefixed error
    except requests.exceptions.HTTPError as e:
        response_text = getattr(response, 'text', '(No response text available)')[:500]
        logger.error(f"Ollama API request failed with status {response.status_code}: {response_text}")
        return f"ERROR: Ollama API request failed (Status {response.status_code}). Check Ollama logs." # Prefixed error
    except requests.exceptions.RequestException as e:
        error_detail = str(e)
        logger.error(f"Error communicating with Ollama API at {api_endpoint}: {error_detail}")
        return f"ERROR: Ollama communication failed - {error_detail}" # Prefixed error
    except json.JSONDecodeError as e:
         response_text = getattr(response, 'text', '(No response text available)')[:500]
         logging.error(f"Error decoding JSON response from Ollama API at {api_endpoint}: {e}. Response: {response_text}")
         return f"ERROR: Invalid JSON response from Ollama" # Prefixed error
    except Exception as e:
        logger.exception(f"Unexpected error during Ollama analysis (model: {effective_model}):")
        return f"ERROR: Unexpected analysis failure - {e}" # Prefixed error


def extract_log_snippet(analysis_result, full_logs):
    """
    Extracts the relevant log snippet mentioned by Ollama or finds a relevant line as fallback.
    """
    # Keep existing logic, seems reasonable
    prefix = "Relevant Log(s):"
    snippet = "(No specific log line identified in analysis)"

    if prefix in analysis_result:
        try:
            snippet_raw = analysis_result.split(prefix, 1)[1].strip()
            snippet = snippet_raw[:500]
            if len(snippet_raw) > 500: snippet += "..."
            logging.debug(f"Extracted snippet based on prefix: '{snippet[:100]}...'")
        except Exception as e:
            logging.warning(f"Error splitting analysis result to get snippet after finding prefix: {e}")
            snippet = "(Error extracting snippet from analysis)"

    if snippet.startswith("("):
         logging.debug("Attempting snippet extraction fallback.")
         keywords = ['error', 'warning', 'failed', 'exception', 'critical', 'traceback', 'fatal', 'refused', 'denied', 'unauthorized', 'timeout', 'unavailable']
         log_lines = full_logs.strip().split('\n')
         best_match_line = None
         for line in reversed(log_lines):
             line_strip = line.strip()
             if not line_strip: continue
             line_lower = line_strip.lower()
             if any(keyword in line_lower for keyword in keywords):
                 best_match_line = line_strip
                 break
         if best_match_line:
             snippet = best_match_line[:500]
             if len(best_match_line) > 500: snippet += "..."
             logging.debug(f"Using best keyword match as snippet: '{snippet[:100]}...'")
         else:
             logging.debug("No keyword match found, using last non-empty line(s).")
             non_empty_lines = [line.strip() for line in log_lines if line.strip()]
             if non_empty_lines:
                  fallback_lines = "\n".join(non_empty_lines[-3:])
                  snippet = fallback_lines[:500]
                  if len(fallback_lines) > 500: snippet += "..."
             else:
                  snippet = "(No log lines available for snippet)"

    return snippet.strip()

# --- Function modified to return empty list on failure ---
def get_ollama_models():
    """Queries Ollama API for available models. Returns list of names or empty list on failure."""
    global OLLAMA_API_URL, OLLAMA_MODEL_LIST_TIMEOUT # Access globals

    if not OLLAMA_API_URL:
         logger.warning("Cannot fetch models, Ollama API URL is not configured.")
         return [] # Return empty list

    tags_url = ""
    try:
        # Construct the /api/tags URL robustly
        if '/api/' in OLLAMA_API_URL: base_url = OLLAMA_API_URL.split('/api/', 1)[0]
        else: base_url = OLLAMA_API_URL.rstrip('/')
        tags_url = f"{base_url}/api/tags"

        logger.info(f"Querying available Ollama models from {tags_url}")
        response = requests.get(tags_url, timeout=OLLAMA_MODEL_LIST_TIMEOUT)
        response.raise_for_status()
        data = response.json()

        raw_models = data.get('models', [])
        if isinstance(raw_models, list):
            model_names = [m.get('name') for m in raw_models if isinstance(m, dict) and m.get('name')]
            models = sorted(list(set(model_names)))
            logger.info(f"Successfully fetched available Ollama models: {models}")
            return models # Return list of names on success
        else:
             logger.warning(f"Ollama API response for models at {tags_url} was not a list. Response: {data}")
             return [] # Return empty list if format unexpected

    except requests.exceptions.Timeout:
        logger.error(f"Timeout ({OLLAMA_MODEL_LIST_TIMEOUT}s) fetching models from Ollama at {tags_url}.")
    except requests.exceptions.ConnectionError as e:
         logger.error(f"Connection error fetching models from Ollama at {tags_url}: {e}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Could not fetch models from Ollama at {tags_url}: {e}")
    except json.JSONDecodeError as e:
        response_text = getattr(response, 'text', '(No response text available)')[:200]
        logger.error(f"Error decoding JSON model list from Ollama at {tags_url}: {e}. Response: {response_text}")
    except Exception as e:
        logger.exception(f"Unexpected error parsing model list from Ollama:")
    return [] # Return empty list in all error cases

# <<< START REPLACEMENT: summarize_recent_abnormalities FUNCTION (Optimized) >>>
def summarize_recent_abnormalities(abnormalities_data, api_url, model_name, prompt_template):
    """
    Generates health summary using Ollama based on a pre-formatted prompt.
    Returns summary string or 'Error: ...' string.

    Args:
        abnormalities_data: (Ignored) Kept for signature consistency, data is in prompt_template.
        api_url (str): The full base URL for the Ollama API.
        model_name (str): The name of the Ollama model to use.
        prompt_template (str): The fully constructed prompt containing the concise issue list.
    """
    # Access global only for timeout setting, other params are passed in
    global OLLAMA_SUMMARY_TIMEOUT

    # --- Input Validation ---
    if not model_name:
         logger.error("Ollama model name is missing. Cannot generate summary.")
         return "Error: Ollama model not configured." # Return prefixed error

    if not api_url:
         logger.error("Cannot generate summary, Ollama API URL is not configured!")
         return "Error: Ollama API URL is not set." # Return prefixed error

    if not prompt_template:
         logger.error("Cannot generate summary, the prompt template is empty!")
         return "Error: Internal error - summary prompt is missing." # Return prefixed error

    # Construct endpoint from the passed api_url
    try:
        if '/api/' in api_url: base_url = api_url.split('/api/', 1)[0]
        else: base_url = api_url.rstrip('/')
        api_endpoint = f"{base_url}/api/generate"
    except Exception as url_err:
        logger.error(f"Error constructing API endpoint from URL '{api_url}': {url_err}")
        return f"Error: Invalid Ollama API URL provided ({url_err})."


    logging.info(f"Generating health summary using Ollama model: {model_name}")

    # --- Use the directly passed prompt ---
    # The logic to format abnormalities_list is removed, as the caller (app.py) now does this.
    prompt = prompt_template # Use the prompt passed as an argument

    payload = {
        "model": model_name, # Use the passed model name
        "prompt": prompt,
        "stream": False,
        "options": { "temperature": 0.4 } # Keep summary slightly creative
    }

    # --- Make API Call with Error Handling ---
    try:
        logger.debug(f"Sending request for health summary: {api_endpoint}, Model: {model_name}, Timeout: {OLLAMA_SUMMARY_TIMEOUT}s")
        response = requests.post(api_endpoint, json=payload, timeout=OLLAMA_SUMMARY_TIMEOUT)

        if response.status_code == 404:
            logger.error(f"Ollama API endpoint not found ({response.status_code}) for summary: {api_endpoint}")
            response_text = response.text[:500]
            if f"model '{model_name}' not found" in response_text:
                return f"Error: Summary failed - Ollama model '{model_name}' not found." # Prefixed error
            else:
                return f"Error: Summary failed - Ollama endpoint not found ({response.status_code})." # Prefixed error

        response.raise_for_status() # Raise HTTPError for other bad responses (4xx or 5xx)

        result = response.json()
        summary_text = result.get('response', '').strip()

        if not summary_text:
            logger.warning(f"Ollama model {model_name} returned an empty summary response.")
            return "Error: AI returned an empty summary." # Return prefixed error
        else:
             logger.info(f"Ollama health summary generated.") # Don't log full summary here potentially
             return summary_text # Return successful summary

    except requests.exceptions.Timeout:
         logger.error(f"Timeout ({OLLAMA_SUMMARY_TIMEOUT}s) generating AI summary from {api_endpoint}.")
         # Make error slightly more specific to the task
         return f"Error: AI summary request timed out ({OLLAMA_SUMMARY_TIMEOUT}s). Consider increasing OLLAMA_SUMMARY_TIMEOUT env var or using a faster model." # Return prefixed error
    except requests.exceptions.ConnectionError as e:
         logger.error(f"Connection error generating AI summary from {api_endpoint}: {e}")
         return f"Error: Could not connect to Ollama API at {api_url} for summary." # Return prefixed error
    except requests.exceptions.HTTPError as e:
        response_text = getattr(response, 'text', '(No response text available)')[:500]
        logger.error(f"Ollama API request failed for summary with status {response.status_code}: {response_text}")
        return f"Error: Summary failed - Ollama API request error (Status {response.status_code}). Check Ollama logs." # Return prefixed error
    except requests.exceptions.RequestException as e:
        error_detail = str(e)
        logger.error(f"Error communicating with Ollama API for summary at {api_endpoint}: {error_detail}")
        return f"Error: AI summary failed - communication error: {error_detail}" # Return prefixed error
    except json.JSONDecodeError as e:
         response_text = getattr(response, 'text', '(No response text available)')[:500]
         logging.error(f"Error decoding JSON summary response from Ollama at {api_endpoint}: {e}. Response: {response_text}")
         return f"Error: Invalid JSON summary response from AI." # Return prefixed error
    except Exception as e:
        logger.exception(f"Unexpected error during AI summary generation:")
        # Make error slightly more specific
        return f"Error: Unexpected internal failure during AI summary: {e}." # Return prefixed error
# <<< END REPLACEMENT: summarize_recent_abnormalities FUNCTION (Optimized) >>>
