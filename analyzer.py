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
    DEFAULT_ANALYSIS_PROMPT_FALLBACK = """Analyze the following Docker container logs STRICTLY for CRITICAL errors... (rest of prompt)..."""
    # A better approach might be to pass the default prompt from app.py if needed

# Basic logging setup
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(),
                    format='%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s')

# --- Configuration (Values are set/updated by app.py's load_settings) ---
# These act as initial defaults if load_settings hasn't run yet, but app.py should override
OLLAMA_API_URL = os.environ.get("OLLAMA_API_URL", "http://localhost:11434/api/generate")
DEFAULT_OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "phi3")
LOG_LINES_TO_FETCH = int(os.environ.get("LOG_LINES_TO_FETCH", "100"))
DOCKER_SOCKET_PATH = "/var/run/docker.sock"
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "300"))
OLLAMA_SUMMARY_TIMEOUT = int(os.environ.get("OLLAMA_SUMMARY_TIMEOUT", "120"))


def get_docker_client():
    """Initializes and returns a Docker client connected via the socket."""
    try:
        client = docker.DockerClient(base_url=f'unix://{DOCKER_SOCKET_PATH}')
        if client.ping():
            logging.info("Successfully connected to Docker daemon via socket.")
            return client
        else:
            logging.error("Ping to Docker daemon failed.")
            return None
    except docker.errors.DockerException as e:
        logging.error(f"DockerException connecting to Docker daemon: {e}")
        logging.error("Ensure socket is mounted and permissions correct.")
        return None
    except requests.exceptions.ConnectionError as e:
         logging.error(f"Connection error connecting to Docker socket {DOCKER_SOCKET_PATH}: {e}")
         return None
    except Exception as e:
        logging.error(f"Unexpected error connecting to Docker daemon: {e}", exc_info=True)
        return None

def fetch_container_logs(container, lines_to_fetch=LOG_LINES_TO_FETCH): # Add argument with default
    """Fetches recent logs for a given container object."""
    container_name = container.name
    container_id_short = container.id[:12]
    try:
        # Use the passed argument 'lines_to_fetch' instead of the global
        logging.debug(f"Fetching {lines_to_fetch} log lines for {container_name} ({container_id_short})")
        logs_bytes = container.logs(tail=lines_to_fetch, stream=False, timestamps=False)
        logs_str = logs_bytes.decode('utf-8', errors='replace')
        logging.debug(f"Successfully fetched logs for {container_name} ({container_id_short})")
        return logs_str
    except docker.errors.NotFound:
        logging.warning(f"Container {container_name} ({container_id_short}) not found during log fetch.")
        return None
    except Exception as e:
        logging.error(f"Error fetching logs for container {container_name} ({container_id_short}): {e}")
        return None

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
    logging.info(f"Analyzing logs using Ollama model: {effective_model}")

    # --- Use custom_prompt if provided, otherwise use the default from db.py ---
    # This relies on db.py being importable or uses the hardcoded fallback
    try:
        default_prompt_from_db = db.DEFAULT_SETTINGS['analysis_prompt']
    except (NameError, AttributeError):
         logging.warning("db module or DEFAULT_SETTINGS not available, using hardcoded prompt fallback.")
         default_prompt_from_db = DEFAULT_ANALYSIS_PROMPT_FALLBACK # Use fallback defined above

    prompt_to_use = custom_prompt or default_prompt_from_db

    # Add {logs} placeholder if missing (basic check)
    if "{logs}" not in prompt_to_use:
         logging.warning("'{logs}' placeholder missing in analysis prompt! Appending logs at the end.")
         # Append a basic structure to ensure logs are included
         prompt_to_use += "\n\n--- LOGS ---\n{logs}\n--- END LOGS ---"

    # --- Fill prompt with logs ---
    try:
        # Use .format() to insert the logs into the prompt template
        final_prompt = prompt_to_use.format(logs=logs)
    except KeyError:
        logging.error("Failed to format prompt - likely missing '{logs}' placeholder correctly.")
        return "ERROR: Invalid analysis prompt configuration (missing '{logs}'). Check settings."
    except Exception as fmt_err:
        logging.error(f"Error formatting prompt: {fmt_err}")
        return f"ERROR: Prompt formatting failed - {fmt_err}"


    payload = {
        "model": effective_model,
        "prompt": final_prompt, # Use the formatted prompt
        "stream": False,
        "options": {
             "temperature": 0.15 # Keep low for consistency
        }
    }

    # --- API URL is now set globally in analyzer by app.py load_settings ---
    generate_url = OLLAMA_API_URL
    if not generate_url:
         logging.error("Ollama API URL is not configured!")
         return "ERROR: Ollama API URL is not set. Check settings."
    # Endpoint correction logic
    if '/api/' not in generate_url: generate_url = f"{generate_url.rstrip('/')}/api/generate"
    elif not generate_url.endswith('/api/generate'):
        try: base_url = generate_url.split('/api/', 1)[0]; generate_url = f"{base_url}/api/generate"
        except Exception: logging.warning(f"Couldn't fix generate endpoint for {generate_url}, using as is.")

    try:
        logging.debug(f"Sending request to Ollama: {generate_url}, Model: {effective_model}, Timeout: {OLLAMA_TIMEOUT}s")
        response = requests.post(generate_url, json=payload, timeout=OLLAMA_TIMEOUT)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        result = response.json()
        analysis_text = result.get('response', '').strip()

        logging.debug(f"Ollama Raw Response (model: {effective_model}): '{analysis_text}'")

        # Strict check for "NORMAL" (allow optional trailing period)
        if analysis_text == "NORMAL" or analysis_text == "NORMAL.":
            logging.debug("Ollama analysis result: NORMAL")
            return "NORMAL"
        elif not analysis_text:
            logging.warning(f"Ollama model {effective_model} returned an empty response.")
            return "ERROR: Ollama returned empty response"
        # Any other non-empty response is treated as an abnormality description
        else:
            logging.info(f"Ollama analysis (model: {effective_model}) detected potential abnormality: {analysis_text[:150]}...")
            return analysis_text

    except requests.exceptions.Timeout:
         logging.error(f"Timeout ({OLLAMA_TIMEOUT}s) contacting Ollama API at {generate_url}.")
         return f"ERROR: Ollama request timed out after {OLLAMA_TIMEOUT}s"
    except requests.exceptions.RequestException as e:
        error_detail = str(e)
        if hasattr(e, 'response') and e.response is not None:
             try: error_detail += f" - Status: {e.response.status_code}, Resp: {e.response.text[:200]}"
             except Exception: pass
        logging.error(f"Error communicating with Ollama API at {generate_url}: {error_detail}")
        return f"ERROR: Ollama communication failed - {error_detail}"
    except json.JSONDecodeError as e:
         logging.error(f"Error decoding JSON response from Ollama API at {generate_url}: {e}")
         logging.error(f"Received text: {response.text[:500]}")
         return f"ERROR: Invalid JSON response from Ollama"
    except Exception as e:
        logging.error(f"Unexpected error during Ollama analysis (model: {effective_model}): {e}", exc_info=True)
        return f"ERROR: Unexpected analysis failure - {e}"


def extract_log_snippet(analysis_result, full_logs):
    """
    Extracts the relevant log snippet mentioned by Ollama or finds a relevant line as fallback.
    """
    prefix = "Relevant Log(s):"
    snippet = "(No specific log line identified in analysis)"

    if prefix in analysis_result:
        try:
            snippet_raw = analysis_result.split(prefix, 1)[1].strip()
            snippet = snippet_raw[:500]
            if len(snippet_raw) > 500: snippet += "..."
            logging.debug(f"Extracted snippet based on prefix: '{snippet[:100]}...'")
        except Exception as e:
            logging.warning(f"Error splitting analysis result to get snippet: {e}")
            snippet = "(Error extracting snippet from analysis)" # Fallback will still try below if error
    else:
         logging.debug("Prefix 'Relevant Log(s):' not found. Using fallback.")


    # Fallback only if prefix extraction failed or wasn't applicable
    if snippet.startswith("("): # Check if default or error message is set
        keywords = ['error', 'warning', 'failed', 'exception', 'critical', 'traceback', 'fatal', 'refused', 'denied', 'unauthorized']
        log_lines = full_logs.strip().split('\n')
        best_match_line = None

        for line in reversed(log_lines):
            line_strip = line.strip()
            if not line_strip: continue
            line_lower = line_strip.lower()

            is_info = line_strip.upper().startswith("INFO")
            contains_critical_keyword = any(keyword in line_lower for keyword in keywords)

            # Prioritize lines that are NOT INFO level OR are INFO but contain a keyword
            if contains_critical_keyword and not is_info:
                best_match_line = line_strip
                logging.debug(f"Found keyword match in non-INFO line: '{best_match_line[:100]}...'")
                break
            elif is_info and contains_critical_keyword and best_match_line is None: # If only INFO matches found so far
                 best_match_line = line_strip # Tentatively select INFO line
                 logging.debug(f"Found keyword match in INFO line (tentative): '{best_match_line[:100]}...'")
                 # Continue searching for a non-INFO match

        if best_match_line:
             snippet = best_match_line[:500]
             if len(best_match_line) > 500: snippet += "..."
             logging.debug(f"Extracted snippet based on fallback: '{snippet[:100]}...'")
        else:
             logging.debug("No keyword match found, using last non-empty line(s) as fallback snippet.")
             non_empty_lines = [line.strip() for line in log_lines if line.strip()]
             if non_empty_lines:
                  fallback_lines = "\n".join(non_empty_lines[-3:])
                  snippet = fallback_lines[:500]
                  if len(fallback_lines) > 500: snippet += "..."
             else:
                  snippet = "(No log lines available for snippet)"

    return snippet.strip()


def get_ollama_models():
    """Queries the Ollama API's /api/tags endpoint to get a list of available models."""
    models = []
    tags_url = ""
    # Use the current OLLAMA_API_URL which might have been updated from settings
    current_api_url = OLLAMA_API_URL
    if not current_api_url:
         logging.error("Cannot fetch models, Ollama API URL is not set.")
         return []
    try:
        base_url = current_api_url.split('/api/', 1)[0].rstrip('/')
        tags_url = f"{base_url}/api/tags"

        logging.info(f"Querying available Ollama models from {tags_url}")
        response = requests.get(tags_url, timeout=20)
        response.raise_for_status()
        data = response.json()

        raw_models = data.get('models', [])
        if isinstance(raw_models, list):
            model_names = [m.get('name') for m in raw_models if isinstance(m, dict) and m.get('name')]
            models = sorted(list(set(model_names)))
            logging.info(f"Successfully fetched available Ollama models: {models}")
        else:
             logging.warning(f"Ollama API response for models at {tags_url} not a list. Response: {data}")

    except requests.exceptions.Timeout: logging.error(f"Timeout fetching models from Ollama at {tags_url}.")
    except requests.exceptions.RequestException as e: logging.error(f"Could not fetch models from Ollama at {tags_url}: {e}")
    except json.JSONDecodeError as e: logging.error(f"Error decoding JSON model list from Ollama at {tags_url}: {e}. Response: {response.text[:200]}")
    except Exception as e: logging.error(f"Error parsing model list from Ollama: {e}", exc_info=True)
    return models


def summarize_recent_abnormalities(abnormalities_list, model_to_use=None):
    """Generates a brief system health summary from recent abnormality data using Ollama."""
    if not abnormalities_list:
        logging.info("No recent abnormalities provided for summary.")
        return "No recent abnormalities detected in the monitored period."

    # Use model passed, or the default set by load_settings
    effective_model = model_to_use or DEFAULT_OLLAMA_MODEL
    logging.info(f"Generating health summary using Ollama model: {effective_model}")

    formatted_list = ""
    for item in abnormalities_list:
        first_ts = item.get('first_detected_timestamp'); last_ts = item.get('last_detected_timestamp')
        try:
            # Format datetime objects if they are, otherwise use string representation
            first_ts_str = first_ts.strftime('%Y-%m-%d %H:%M') if isinstance(first_ts, datetime) else str(first_ts)
            last_ts_str = last_ts.strftime('%Y-%m-%d %H:%M') if isinstance(last_ts, datetime) else str(last_ts)
        except: first_ts_str = str(first_ts); last_ts_str = str(last_ts)

        formatted_list += (
            f"- Cont: {item.get('container_name', 'N/A')}, Stat: {item.get('status', 'N/A')}, Last: {last_ts_str}, Desc: {item.get('ollama_analysis', 'N/A')[:100]}...\n"
        )

    prompt = f"""Based ONLY on the following list of container issues from the last 24 hours, provide a brief (1-3 sentences) overall system health summary. Focus on patterns, count unresolved issues. If few/no unresolved issues, state that.

Issues:
{formatted_list}
--- End List ---

System Health Summary:"""

    payload = {
        "model": effective_model, "prompt": prompt, "stream": False,
        "options": { "temperature": 0.4 }
    }

    # Use current OLLAMA_API_URL
    generate_url = OLLAMA_API_URL
    if not generate_url: return "Error: Ollama API URL not set."
    # Fix endpoint if needed
    if '/api/' not in generate_url: generate_url = f"{generate_url.rstrip('/')}/api/generate"
    elif not generate_url.endswith('/api/generate'):
        try: base_url = generate_url.split('/api/', 1)[0]; generate_url = f"{base_url}/api/generate"
        except Exception: pass

    try:
        logging.debug(f"Sending request for health summary: {generate_url}, Model: {effective_model}, Timeout: {OLLAMA_SUMMARY_TIMEOUT}s")
        response = requests.post(generate_url, json=payload, timeout=OLLAMA_SUMMARY_TIMEOUT)
        response.raise_for_status()
        result = response.json()
        summary_text = result.get('response', '').strip()

        if not summary_text: return "Error: AI returned an empty summary."
        else: logging.info(f"Ollama health summary generated: {summary_text}"); return summary_text

    except requests.exceptions.Timeout: return f"Error: AI summary timed out ({OLLAMA_SUMMARY_TIMEOUT}s)."
    except requests.exceptions.RequestException as e: error_detail=str(e); # ... format ...
    except json.JSONDecodeError as e: return f"Error: Invalid JSON summary response from AI."
    except Exception as e: return f"Error: Unexpected failure during AI summary: {e}."
