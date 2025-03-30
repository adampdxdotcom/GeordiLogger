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
    # Define a hardcoded fallback here if db import fails, matching db.py's default
    # IMPORTANT: Keep this fallback prompt reasonably short and aligned with db.py's intent
    DEFAULT_ANALYSIS_PROMPT_FALLBACK = """Analyze the following Docker container logs STRICTLY for CRITICAL errors, security issues (like authentication failures), or persistent connection problems. Ignore standard startup/shutdown messages, INFO/DEBUG logs unless they clearly indicate a critical fault. If no significant issues are found, respond ONLY with the word 'NORMAL'. If issues ARE found, briefly describe the main problem and include the MOST relevant log line(s) EXACTLY as they appear, prefixed with 'Relevant Log(s):'. Example: 'Database connection refused. Relevant Log(s): ERROR: Connection refused: localhost:5432'

Logs:
{logs}"""

# Basic logging setup
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(),
                    format='%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s')

# --- Configuration (Values are set/updated by app.py's load_settings) ---
# These act as initial defaults if load_settings hasn't run yet, but app.py should override
OLLAMA_API_URL = os.environ.get("OLLAMA_API_URL", "http://localhost:11434/api/generate")
DEFAULT_OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "phi3")
# Default LOG_LINES_TO_FETCH (will be overridden by app.py load_settings)
LOG_LINES_TO_FETCH = int(os.environ.get("LOG_LINES_TO_FETCH", "100"))
DOCKER_SOCKET_PATH = "/var/run/docker.sock"
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "300"))
OLLAMA_SUMMARY_TIMEOUT = int(os.environ.get("OLLAMA_SUMMARY_TIMEOUT", "120"))


def get_docker_client():
    """Initializes and returns a Docker client connected via the socket."""
    try:
        # Ensure the socket path exists for a clearer error message if not found
        if not os.path.exists(DOCKER_SOCKET_PATH):
            logging.error(f"Docker socket not found at {DOCKER_SOCKET_PATH}. Is Docker running and the socket mounted correctly?")
            return None

        client = docker.DockerClient(base_url=f'unix://{DOCKER_SOCKET_PATH}')
        # Use ping() to verify the connection
        if client.ping():
            logging.info("Successfully connected to Docker daemon via socket.")
            return client
        else:
            # This case might be rare if ping() throws exception on failure, but good to have
            logging.error("Ping to Docker daemon failed, but no exception raised.")
            return None
    except docker.errors.DockerException as e:
        logging.error(f"DockerException connecting to Docker daemon: {e}")
        # Provide more specific guidance based on common issues
        if "Permission denied" in str(e):
            logging.error("Permission denied accessing the Docker socket. Ensure the user running this application has permissions (e.g., is in the 'docker' group or uses appropriate privileges).")
        else:
            logging.error("Check if Docker daemon is running and the socket path is correct.")
        return None
    except requests.exceptions.ConnectionError as e:
         # This often indicates the socket file exists but nothing is listening
         logging.error(f"Connection error connecting to Docker socket {DOCKER_SOCKET_PATH}: {e}. Is Docker daemon running?")
         return None
    except Exception as e:
        # Log the full traceback for unexpected errors
        logging.exception(f"Unexpected error connecting to Docker daemon:")
        return None

# --- MODIFIED FUNCTION ---
def fetch_container_logs(container, num_lines=100): # Added num_lines parameter with a default
    """Fetches the specified number of recent log lines for a container."""
    container_name = container.name
    container_id_short = container.id[:12] # For logging brevity
    # Use the passed-in num_lines argument directly
    logging.debug(f"Fetching last {num_lines} lines for {container_name} ({container_id_short}) using argument.")
    try:
        # Pass the num_lines argument to the docker call
        logs_bytes = container.logs(tail=num_lines, timestamps=False, stream=False)
        logs_str = logs_bytes.decode('utf-8', errors='replace')
        # Check if logs are just whitespace or empty
        if not logs_str.strip():
            logging.debug(f"Container {container_name} ({container_id_short}) returned empty logs.")
            return "" # Return empty string is safer than None for subsequent processing
        return logs_str
    except docker.errors.NotFound:
        logging.warning(f"Container {container_name} ({container_id_short}) not found during log fetch (may have stopped).")
        return None # Indicate failure clearly
    except docker.errors.APIError as e:
        # Log specific Docker API errors
        logging.error(f"Docker API error fetching logs for {container_name} ({container_id_short}): {e}")
        return None # Indicate failure clearly
    except Exception as e:
        # Log the full traceback for unexpected errors
        logging.exception(f"Unexpected error fetching logs for {container_name} ({container_id_short}):")
        return None # Indicate failure clearly
# --- END MODIFIED FUNCTION ---


# --- MODIFIED FUNCTION SIGNATURE ---
def analyze_logs_with_ollama(logs, model_to_use=None, custom_prompt=None):
    """
    Sends logs to Ollama for analysis using the specified model and prompt.
    Returns 'NORMAL', an error description string, or the Ollama analysis result.
    """
    if not logs or logs.isspace():
        logging.debug("No logs provided to analyze.")
        return "NORMAL"

    # Use model passed, or the default set by load_settings
    effective_model = model_to_use or DEFAULT_OLLAMA_MODEL
    if not effective_model: # Double check if default was empty
         logging.error("Ollama model name is missing. Cannot analyze logs.")
         return "ERROR: Ollama model not configured. Check settings."

    logging.info(f"Analyzing logs using Ollama model: {effective_model}")

    # --- Use custom_prompt if provided, otherwise use the default from db.py ---
    prompt_to_use = custom_prompt # Start with custom if provided
    if not prompt_to_use: # If no custom prompt, try DB default
        try:
            # Ensure DEFAULT_SETTINGS and the key exist
            if hasattr(db, 'DEFAULT_SETTINGS') and 'analysis_prompt' in db.DEFAULT_SETTINGS:
                prompt_to_use = db.DEFAULT_SETTINGS['analysis_prompt']
            else:
                 raise AttributeError # Trigger fallback if structure is wrong
        except (NameError, AttributeError):
             logging.warning("db module or DEFAULT_SETTINGS['analysis_prompt'] not available, using hardcoded prompt fallback.")
             prompt_to_use = DEFAULT_ANALYSIS_PROMPT_FALLBACK # Use fallback defined above

    # --- Fill prompt with logs ---
    try:
        # Use .format() to insert the logs into the prompt template
        # Ensure the prompt template actually contains '{logs}'
        if "{logs}" not in prompt_to_use:
            logging.error("Analysis prompt configuration error: '{logs}' placeholder is missing!")
            return "ERROR: Invalid analysis prompt configuration (missing '{logs}'). Check settings."
        final_prompt = prompt_to_use.format(logs=logs)
    except KeyError as ke:
        # This error specifically means a placeholder other than 'logs' might be expected/missing
        logging.error(f"Failed to format prompt - KeyError: {ke}. Check prompt template placeholders.")
        return f"ERROR: Invalid analysis prompt configuration (KeyError: {ke})."
    except Exception as fmt_err:
        logging.exception(f"Unexpected error formatting analysis prompt:")
        return f"ERROR: Prompt formatting failed - {fmt_err}"


    payload = {
        "model": effective_model,
        "prompt": final_prompt, # Use the formatted prompt
        "stream": False,
        "options": {
             "temperature": 0.15 # Keep low for consistency
             # Consider adding other options like 'num_predict' if needed
        }
    }

    # --- API URL is now set globally in analyzer by app.py load_settings ---
    generate_url = OLLAMA_API_URL
    if not generate_url:
         logging.error("Ollama API URL is not configured!")
         return "ERROR: Ollama API URL is not set. Check settings."

    # Basic validation/correction for common URL mistakes
    if not generate_url.startswith(('http://', 'https://')):
         logging.error(f"Invalid Ollama API URL format: {generate_url}. Must start with http:// or https://")
         return f"ERROR: Invalid Ollama API URL format."

    # Correct endpoint if needed (handle base URL or specific endpoint)
    if '/api/' not in generate_url:
        # Assume it's a base URL, append /api/generate
        corrected_url = f"{generate_url.rstrip('/')}/api/generate"
        logging.debug(f"Assuming base Ollama URL provided. Using endpoint: {corrected_url}")
        generate_url = corrected_url
    # Allow common endpoints like generate or chat, but log if unexpected
    elif not generate_url.endswith(('/api/generate', '/api/chat')):
        logging.warning(f"Ollama URL {generate_url} doesn't end with standard /api/generate or /api/chat. Using as is, but check configuration.")
        # Attempt to fix common case: user provided only base URL ending in /api/
        if generate_url.endswith('/api/'):
             generate_url = generate_url + 'generate'
             logging.info(f"Corrected Ollama URL ending in /api/ to: {generate_url}")


    try:
        logging.debug(f"Sending request to Ollama: {generate_url}, Model: {effective_model}, Timeout: {OLLAMA_TIMEOUT}s")
        response = requests.post(generate_url, json=payload, timeout=OLLAMA_TIMEOUT)

        # Check status code carefully
        if response.status_code == 404:
             logging.error(f"Ollama API endpoint not found ({response.status_code}): {generate_url}")
             logging.error(f"Response: {response.text[:500]}")
             # Check if it's likely a missing model
             if f"model '{effective_model}' not found" in response.text:
                 return f"ERROR: Ollama model '{effective_model}' not found on the server."
             else:
                 return f"ERROR: Ollama endpoint not found ({response.status_code}) at {generate_url}"

        response.raise_for_status() # Raise HTTPError for other bad responses (4xx or 5xx)

        result = response.json()
        analysis_text = result.get('response', '').strip()

        logging.debug(f"Ollama Raw Response (model: {effective_model}): '{analysis_text}'")

        # Strict check for "NORMAL" (allow optional trailing period, case-insensitive)
        if analysis_text.upper() == "NORMAL" or analysis_text.upper() == "NORMAL.":
            logging.debug("Ollama analysis result: NORMAL")
            return "NORMAL"
        elif not analysis_text:
            logging.warning(f"Ollama model {effective_model} returned an empty response.")
            # Consider if this should be an error or treated as normal depending on strictness needed
            return "ERROR: Ollama returned empty response"
        # Any other non-empty response is treated as an abnormality description
        else:
            logging.info(f"Ollama analysis (model: {effective_model}) detected potential abnormality: {analysis_text[:150]}...")
            return analysis_text

    except requests.exceptions.Timeout:
         logging.error(f"Timeout ({OLLAMA_TIMEOUT}s) contacting Ollama API at {generate_url}.")
         return f"ERROR: Ollama request timed out after {OLLAMA_TIMEOUT}s"
    except requests.exceptions.RequestException as e:
        # Provide more context in the error log and the returned error string
        error_detail = str(e)
        if hasattr(e, 'response') and e.response is not None:
             try: error_detail += f" - Status: {e.response.status_code}, Resp: {e.response.text[:200]}"
             except Exception: pass # Ignore errors formatting the response detail
        logging.error(f"Error communicating with Ollama API at {generate_url}: {error_detail}")
        return f"ERROR: Ollama communication failed - {error_detail}"
    except json.JSONDecodeError as e:
         # Log more of the response on JSON decode errors
         response_text = getattr(response, 'text', '(No response text available)')
         logging.error(f"Error decoding JSON response from Ollama API at {generate_url}: {e}")
         logging.error(f"Received text (up to 500 chars): {response_text[:500]}")
         return f"ERROR: Invalid JSON response from Ollama"
    except Exception as e:
        logging.exception(f"Unexpected error during Ollama analysis (model: {effective_model}):")
        return f"ERROR: Unexpected analysis failure - {e}"


def extract_log_snippet(analysis_result, full_logs):
    """
    Extracts the relevant log snippet mentioned by Ollama or finds a relevant line as fallback.
    """
    prefix = "Relevant Log(s):"
    snippet = "(No specific log line identified in analysis)" # Default/placeholder

    # 1. Try extracting based on the prefix
    if prefix in analysis_result:
        try:
            # Split only once, take the part after the prefix
            snippet_raw = analysis_result.split(prefix, 1)[1].strip()
            # Limit length and add ellipsis if truncated
            snippet = snippet_raw[:500]
            if len(snippet_raw) > 500: snippet += "..."
            logging.debug(f"Extracted snippet based on prefix: '{snippet[:100]}...'")
        except Exception as e:
            logging.warning(f"Error splitting analysis result to get snippet after finding prefix: {e}")
            snippet = "(Error extracting snippet from analysis)" # Mark as error, fallback will still try below

    # 2. Fallback if prefix wasn't found OR extraction failed
    # Use the default/error message as the trigger for fallback
    if snippet.startswith("("):
         logging.debug("Attempting snippet extraction fallback (prefix not found or extraction failed).")
         # Keywords to search for in log lines (lowercase)
         keywords = ['error', 'warning', 'failed', 'exception', 'critical', 'traceback', 'fatal', 'refused', 'denied', 'unauthorized', 'timeout', 'unavailable']
         log_lines = full_logs.strip().split('\n')
         best_match_line = None

         # Iterate backwards through logs to find the most recent relevant line
         for line in reversed(log_lines):
             line_strip = line.strip()
             if not line_strip: continue # Skip empty lines
             line_lower = line_strip.lower()

             # Basic level check (optional, might miss errors logged at INFO)
             # is_info = "info" in line_lower[:20] # Rough check for INFO level

             # Check if any keyword exists in the line
             contains_critical_keyword = any(keyword in line_lower for keyword in keywords)

             if contains_critical_keyword:
                 # Prioritize the first keyword match found when searching backwards
                 best_match_line = line_strip
                 logging.debug(f"Found keyword match (fallback): '{best_match_line[:100]}...'")
                 break # Stop searching once a keyword match is found

         if best_match_line:
             # Limit length and add ellipsis if truncated
             snippet = best_match_line[:500]
             if len(best_match_line) > 500: snippet += "..."
             logging.debug(f"Using best keyword match as snippet: '{snippet[:100]}...'")
         else:
             # 3. Final fallback: Use last non-empty line(s) if no keywords found
             logging.debug("No keyword match found, using last non-empty line(s) as final fallback snippet.")
             non_empty_lines = [line.strip() for line in log_lines if line.strip()]
             if non_empty_lines:
                  # Take up to the last 3 lines, join them
                  fallback_lines = "\n".join(non_empty_lines[-3:])
                  snippet = fallback_lines[:500] # Limit total length
                  if len(fallback_lines) > 500: snippet += "..."
             else:
                  # Should be rare if full_logs was not empty
                  snippet = "(No log lines available for snippet)"

    return snippet.strip()


def get_ollama_models():
    """Queries the Ollama API's /api/tags endpoint to get a list of available models."""
    models = []
    # Use the current OLLAMA_API_URL which might have been updated from settings
    current_api_url = OLLAMA_API_URL
    if not current_api_url:
         logging.warning("Cannot fetch models, Ollama API URL is not configured.")
         return []

    # Construct the /api/tags URL from the base API URL
    tags_url = ""
    try:
        # Handle cases where URL might end with /generate, /chat, /api/, or just the base
        if '/api/' in current_api_url:
             base_url = current_api_url.split('/api/', 1)[0]
        else:
             base_url = current_api_url.rstrip('/')
        tags_url = f"{base_url}/api/tags"

        logging.info(f"Querying available Ollama models from {tags_url}")
        response = requests.get(tags_url, timeout=20) # Reasonable timeout for listing tags
        response.raise_for_status() # Check for HTTP errors
        data = response.json()

        # Process the response structure (usually a list of model dicts)
        raw_models = data.get('models', [])
        if isinstance(raw_models, list):
            # Extract the 'name' from each model dictionary
            model_names = [m.get('name') for m in raw_models if isinstance(m, dict) and m.get('name')]
            # Ensure uniqueness and sort alphabetically
            models = sorted(list(set(model_names)))
            logging.info(f"Successfully fetched available Ollama models: {models}")
        else:
             logging.warning(f"Ollama API response for models at {tags_url} was not a list as expected. Response: {data}")

    except requests.exceptions.Timeout: logging.error(f"Timeout ({20}s) fetching models from Ollama at {tags_url}.")
    except requests.exceptions.RequestException as e: logging.error(f"Could not fetch models from Ollama at {tags_url}: {e}")
    except json.JSONDecodeError as e:
        response_text = getattr(response, 'text', '(No response text available)')
        logging.error(f"Error decoding JSON model list from Ollama at {tags_url}: {e}. Response: {response_text[:200]}")
    except Exception as e: logging.exception(f"Unexpected error parsing model list from Ollama:") # Log full traceback
    return models


def summarize_recent_abnormalities(abnormalities_list, model_to_use=None):
    """Generates a brief system health summary from recent abnormality data using Ollama."""
    if not abnormalities_list:
        logging.info("No recent abnormalities provided for summary.")
        return "No recent abnormalities detected in the monitored period."

    # Use model passed, or the default set by load_settings
    effective_model = model_to_use or DEFAULT_OLLAMA_MODEL
    if not effective_model: # Double check if default was empty
         logging.error("Ollama model name is missing. Cannot generate summary.")
         return "Error: Ollama model not configured."

    # --- Check Ollama URL before proceeding ---
    generate_url = OLLAMA_API_URL
    if not generate_url:
         logging.error("Cannot generate summary, Ollama API URL is not configured!")
         return "Error: Ollama API URL is not set."
    # Correct endpoint if needed (similar logic to analysis)
    if '/api/' not in generate_url: generate_url = f"{generate_url.rstrip('/')}/api/generate"
    elif not generate_url.endswith(('/api/generate','/api/chat')): # Allow chat too, might be used for summarization
         logging.warning(f"Using potentially non-standard endpoint for summary: {generate_url}")
         if generate_url.endswith('/api/'): generate_url += 'generate'


    logging.info(f"Generating health summary using Ollama model: {effective_model}")

    formatted_list = ""
    unresolved_count = 0
    container_issues = {} # Track issues per container

    for item in abnormalities_list:
        # Safely get values, provide defaults
        cont_name = item.get('container_name', 'N/A')
        status = item.get('status', 'N/A')
        analysis = item.get('ollama_analysis', 'N/A')
        first_ts = item.get('first_detected_timestamp')
        last_ts = item.get('last_detected_timestamp')

        # Format timestamps robustly
        try: first_ts_str = first_ts.strftime('%Y-%m-%d %H:%M') if isinstance(first_ts, datetime) else str(first_ts)
        except: first_ts_str = str(first_ts) # Fallback
        try: last_ts_str = last_ts.strftime('%Y-%m-%d %H:%M') if isinstance(last_ts, datetime) else str(last_ts)
        except: last_ts_str = str(last_ts) # Fallback


        formatted_list += (
            f"- Container: {cont_name}, Status: {status}, Last Seen: {last_ts_str}, "
            f"Desc: {analysis[:100]}{'...' if len(analysis)>100 else ''}\n"
        )
        if status == 'unresolved':
            unresolved_count += 1
            container_issues[cont_name] = container_issues.get(cont_name, 0) + 1

    # Enhanced prompt for better summary
    prompt = f"""You are an IT operations assistant analyzing system health based on recent container issues.
Provide a concise (1-3 sentences) summary focusing on the overall health trend. Mention the total number of unresolved issues. If specific containers have multiple unresolved issues, highlight them briefly. Avoid listing every single issue.

Recent Container Issues (within monitored period):
{formatted_list}
--- End List ---

Overall System Health Summary:"""

    payload = {
        "model": effective_model,
        "prompt": prompt,
        "stream": False,
        "options": { "temperature": 0.4 } # Slightly higher temp for more natural summary
    }


    try:
        logging.debug(f"Sending request for health summary: {generate_url}, Model: {effective_model}, Timeout: {OLLAMA_SUMMARY_TIMEOUT}s")
        response = requests.post(generate_url, json=payload, timeout=OLLAMA_SUMMARY_TIMEOUT)

        # Check status code carefully (similar to analysis)
        if response.status_code == 404:
             logging.error(f"Ollama API endpoint not found ({response.status_code}) for summary: {generate_url}")
             # Check if it's likely a missing model
             if f"model '{effective_model}' not found" in response.text:
                 return f"Error: Summary failed - Ollama model '{effective_model}' not found."
             else:
                 return f"Error: Summary failed - Ollama endpoint not found ({response.status_code})."

        response.raise_for_status() # Raise HTTPError for other bad responses

        result = response.json()
        summary_text = result.get('response', '').strip()

        if not summary_text:
            logging.warning(f"Ollama model {effective_model} returned an empty summary response.")
            return "Error: AI returned an empty summary."
        else:
             logging.info(f"Ollama health summary generated: {summary_text}")
             return summary_text

    except requests.exceptions.Timeout:
         logging.error(f"Timeout ({OLLAMA_SUMMARY_TIMEOUT}s) generating AI summary from {generate_url}.")
         return f"Error: AI summary timed out ({OLLAMA_SUMMARY_TIMEOUT}s)."
    except requests.exceptions.RequestException as e:
        error_detail = str(e)
        if hasattr(e, 'response') and e.response is not None:
             try: error_detail += f" - Status: {e.response.status_code}, Resp: {e.response.text[:200]}"
             except Exception: pass
        logging.error(f"Error communicating with Ollama API for summary at {generate_url}: {error_detail}")
        return f"Error: AI summary failed - communication error: {error_detail}"
    except json.JSONDecodeError as e:
         response_text = getattr(response, 'text', '(No response text available)')
         logging.error(f"Error decoding JSON summary response from Ollama at {generate_url}: {e}")
         logging.error(f"Received text (up to 500 chars): {response_text[:500]}")
         return f"Error: Invalid JSON summary response from AI."
    except Exception as e:
        logging.exception(f"Unexpected error during AI summary generation:")
        return f"Error: Unexpected failure during AI summary: {e}."
