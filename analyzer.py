# analyzer.py
import docker
import requests
import logging
import os
import json
from datetime import datetime, timedelta

# Basic logging setup
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(),
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- Configuration from Environment Variables ---
# API URL for Ollama (e.g., http://host:port/api/generate)
OLLAMA_API_URL = os.environ.get("OLLAMA_API_URL", "http://localhost:11434/api/generate")
# Default Ollama model name to use if not specified otherwise
DEFAULT_OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "phi3")
# Number of log lines to fetch per container
LOG_LINES_TO_FETCH = int(os.environ.get("LOG_LINES_TO_FETCH", "100")) # Default reduced
# Path to Docker socket inside the container
DOCKER_SOCKET_PATH = "/var/run/docker.sock"
# Timeout for Ollama API requests in seconds
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "300")) # Default increased


def get_docker_client():
    """Initializes and returns a Docker client connected via the socket."""
    try:
        # Connect using the standard Docker socket path mounted into the container
        client = docker.DockerClient(base_url=f'unix://{DOCKER_SOCKET_PATH}')
        # Test the connection
        if client.ping():
            logging.info("Successfully connected to Docker daemon via socket.")
            return client
        else:
            logging.error("Ping to Docker daemon failed, though client initialized.")
            return None
    except docker.errors.DockerException as e:
        logging.error(f"DockerException connecting to Docker daemon: {e}")
        logging.error("Ensure the Docker socket is correctly mounted and permissions are set.")
        return None
    except Exception as e:
        logging.error(f"Unexpected error connecting to Docker daemon: {e}")
        return None

def fetch_container_logs(container):
    """Fetches recent logs for a given container object."""
    container_name = container.name
    container_id_short = container.id[:12]
    try:
        logging.debug(f"Fetching {LOG_LINES_TO_FETCH} log lines for {container_name} ({container_id_short})")
        # Fetch logs as bytes, specify tail
        logs_bytes = container.logs(tail=LOG_LINES_TO_FETCH, stream=False, timestamps=False)
        # Decode bytes to string, replacing errors
        logs_str = logs_bytes.decode('utf-8', errors='replace')
        logging.debug(f"Successfully fetched logs for {container_name} ({container_id_short})")
        return logs_str
    except docker.errors.NotFound:
        logging.warning(f"Container {container_name} ({container_id_short}) not found during log fetch (may have stopped).")
        return None
    except Exception as e:
        logging.error(f"Error fetching logs for container {container_name} ({container_id_short}): {e}")
        return None

def analyze_logs_with_ollama(logs, model_to_use=None):
    """
    Sends logs to Ollama for analysis using the specified model.
    Returns 'NORMAL', an error description string, or the Ollama analysis result.
    """
    if not logs or logs.isspace():
        logging.debug("No logs provided to analyze.")
        return "NORMAL" # No logs means normal for our purposes

    # Determine which model to use
    effective_model = model_to_use or DEFAULT_OLLAMA_MODEL
    logging.info(f"Analyzing logs using Ollama model: {effective_model}")

    # Define the prompt for Ollama
    prompt = f"""
Analyze the following Docker container logs for potential errors, warnings, or unusual patterns.
Focus on exceptions, crashes, keywords like 'error', 'warning', 'failed', 'exception', 'critical', stack traces, or security-related messages.
Respond ONLY with the word 'NORMAL' if no significant issues are found.
If abnormalities ARE found, provide a SHORT (1-2 sentences) description of the potential issue and quote the MOST RELEVANT log line(s) directly after your description, prefixed with 'Relevant Log(s):'. Do not include introductory phrases like "Here is the analysis".

--- LOGS ---
{logs}
--- END LOGS ---

Analysis Result:"""

    # Prepare the payload for the Ollama API
    payload = {
        "model": effective_model,
        "prompt": prompt,
        "stream": False, # Get the full response at once
        "options": {
             "temperature": 0.2 # Lower temperature for more deterministic output
        }
    }

    # Ensure we are using the correct generate endpoint URL
    generate_url = OLLAMA_API_URL
    if not generate_url.endswith('/api/generate'):
        try:
            base_url = generate_url.split('/api/', 1)[0] # Handle URLs with or without trailing slash before /api/
            generate_url = f"{base_url}/api/generate"
            logging.debug(f"Constructed generate URL: {generate_url}")
        except Exception:
            logging.error(f"Could not reliably determine generate endpoint from base URL: {OLLAMA_API_URL}. Using as is.")
            # Proceed using OLLAMA_API_URL as given, hoping it's correct

    # Make the request to Ollama
    try:
        logging.debug(f"Sending request to Ollama at {generate_url} with model {effective_model}")
        response = requests.post(generate_url, json=payload, timeout=OLLAMA_TIMEOUT)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        result = response.json()
        analysis_text = result.get('response', '').strip()

        logging.debug(f"Ollama Raw Response: '{analysis_text}'")

        # Interpret the response
        if not analysis_text:
            logging.warning("Ollama returned an empty response.")
            return "ERROR: Ollama returned empty response"
        elif analysis_text.upper() == "NORMAL":
            logging.debug("Ollama analysis: NORMAL")
            return "NORMAL"
        # More robust check for 'NORMAL' in case of slight variations
        elif "NORMAL" in analysis_text.upper() and len(analysis_text) < 20:
             logging.debug("Ollama analysis: NORMAL (short response)")
             return "NORMAL"
        # Check if it looks like an abnormality report (keywords or expected structure)
        elif "Relevant Log(s):" in analysis_text or any(keyword in analysis_text.lower() for keyword in ['error', 'warning', 'failed', 'exception', 'critical', 'unusual', 'issue']):
            logging.info(f"Ollama analysis detected potential abnormality: {analysis_text[:100]}...")
            return analysis_text # Return the detected abnormality description
        else:
             # If Ollama returns something unexpected, log it but treat as normal for now
             logging.warning(f"Ollama returned unexpected format, treating as NORMAL: '{analysis_text}'")
             return "NORMAL"

    except requests.exceptions.Timeout:
         logging.error(f"Timeout connecting to or reading from Ollama API at {generate_url} after {OLLAMA_TIMEOUT} seconds.")
         return f"ERROR: Ollama request timed out - {OLLAMA_TIMEOUT}s"
    except requests.exceptions.RequestException as e:
        logging.error(f"Error communicating with Ollama API at {generate_url}: {e}")
        return f"ERROR: Could not contact Ollama - {e}"
    except Exception as e:
        logging.error(f"Unexpected error during Ollama analysis: {e}", exc_info=True) # Log traceback
        return f"ERROR: Analysis failed - {e}"


def extract_log_snippet(analysis_result, full_logs):
    """
    Extracts the relevant log snippet mentioned by Ollama or finds a relevant line.
    """
    prefix = "Relevant Log(s):"
    snippet = "(No specific log line identified)" # Default

    if prefix in analysis_result:
        try:
            # Take the text after the prefix, limit length
            snippet_raw = analysis_result.split(prefix, 1)[1].strip()
            snippet = snippet_raw[:500] # Limit to 500 chars
            logging.debug(f"Extracted snippet based on prefix: '{snippet[:100]}...'")
        except Exception as e:
            logging.warning(f"Error splitting analysis result to get snippet: {e}")
            # Fallback below will be attempted

    if snippet == "(No specific log line identified)":
        # Fallback: Try to find keywords in the original logs if Ollama didn't provide a snippet
        keywords = ['error', 'warning', 'failed', 'exception', 'critical', 'traceback']
        log_lines = full_logs.strip().split('\n')
        for line in reversed(log_lines): # Check recent lines first
            line_lower = line.lower()
            if any(keyword in line_lower for keyword in keywords):
                snippet = line.strip()[:500] # Return the first relevant line found
                logging.debug(f"Extracted snippet based on keyword fallback: '{snippet[:100]}...'")
                break # Stop after finding the first relevant line

    # Ultimate fallback: if still no snippet, return the last non-empty line
    if snippet == "(No specific log line identified)":
        log_lines = full_logs.strip().split('\n')
        for line in reversed(log_lines):
            if line.strip():
                snippet = line.strip()[:500]
                logging.debug(f"Extracted snippet based on last line fallback: '{snippet[:100]}...'")
                break

    return snippet

def get_ollama_models():
    """Queries the Ollama API's /api/tags endpoint to get a list of available models."""
    models = []
    tags_url = "" # Initialize for logging in case of early failure
    try:
        # Construct the /api/tags URL from the configured base API URL
        # Handles cases where OLLAMA_API_URL might be base or include /api/generate
        base_url = OLLAMA_API_URL.split('/api/', 1)[0]
        tags_url = f"{base_url}/api/tags"

        logging.info(f"Querying available Ollama models from {tags_url}")
        response = requests.get(tags_url, timeout=15) # Increased timeout slightly for safety
        response.raise_for_status() # Check for HTTP errors
        data = response.json()

        # Extract model names, sort them, handle potential missing keys gracefully
        raw_models = data.get('models', [])
        if isinstance(raw_models, list):
            model_names = [m.get('name') for m in raw_models if isinstance(m, dict) and m.get('name')]
            models = sorted(list(set(model_names))) # Use set to remove duplicates, then sort
            logging.info(f"Found models: {models}")
        else:
             logging.warning("Ollama API response for models was not a list as expected.")

    except requests.exceptions.RequestException as e:
        logging.error(f"Could not fetch models from Ollama at {tags_url}: {e}")
    except Exception as e:
        logging.error(f"Error parsing model list from Ollama: {e}", exc_info=True) # Log traceback
    return models

# Example of how to test connection on module load (optional)
# if __name__ == "__main__":
#    logging.info("Testing Docker connection...")
#    test_client = get_docker_client()
#    if test_client:
#        logging.info("Docker client test successful.")
#        test_client.close()
#    else:
#        logging.error("Docker client test failed.")
#    logging.info("Testing Ollama model fetch...")
#    test_models = get_ollama_models()
#    logging.info(f"Ollama models test result: {test_models}")
