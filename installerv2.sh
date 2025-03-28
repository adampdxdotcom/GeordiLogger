#!/bin/bash

# Simple interactive installer for Docker Log Monitor
# Includes Ollama model detection and asks about compose first

# --- Helper Functions (Keep these as they are) ---
print_info() { echo -e "\033[1;34m[INFO]\033[0m $1"; }
print_warning() { echo -e "\033[1;33m[WARN]\033[0m $1"; }
print_error() { echo -e "\033[1;31m[ERROR]\033[0m $1"; }
print_success() { echo -e "\033[1;32m[SUCCESS]\033[0m $1"; }
prompt_user() {
    local prompt_text=$1 variable_name=$2 default_value=$3 current_value=""
    read -p "$(echo -e "\033[1;36m> $prompt_text [\033[0;36m${default_value}\033[1;36m]: \033[0m")" current_value
    eval "$variable_name=\"${current_value:-$default_value}\""
}
generate_secret_key() {
    if command -v openssl &> /dev/null; then openssl rand -hex 32;
    else head /dev/urandom | tr -dc A-Za-z0-9 | head -c 64; fi
}
# --- End Helper Functions ---

# --- Configuration Defaults (Keep these as they are) ---
DEFAULT_IMAGE_NAME="docker-log-monitor"
DEFAULT_CONTAINER_NAME="docker-log-monitor"
DEFAULT_HOST_PORT="5001"
DEFAULT_VOLUME_NAME="log_monitor_data"
DEFAULT_OLLAMA_API_URL="http://host.docker.internal:11434/api/generate"
if ip addr show docker0 > /dev/null 2>&1; then
    DOCKER_BRIDGE_IP=$(ip addr show docker0 | grep "inet\b" | awk '{print $2}' | cut -d/ -f1)
    DEFAULT_OLLAMA_API_URL_LINUX="http://${DOCKER_BRIDGE_IP:-172.17.0.1}:11434/api/generate"
    DEFAULT_OLLAMA_API_URL=$DEFAULT_OLLAMA_API_URL_LINUX
fi
DEFAULT_OLLAMA_MODEL="phi3"
DEFAULT_SCAN_INTERVAL_MINUTES="10"
DEFAULT_LOG_LINES_TO_FETCH="250"
DEFAULT_FLASK_SECRET_KEY=""
# --- End Configuration Defaults ---

# --- Pre-checks (Keep these as they are) ---
print_info "Checking prerequisites..."
# Docker Check
if ! command -v docker &> /dev/null; then print_error "Docker command not found."; exit 1; fi
if ! docker info > /dev/null 2>&1; then print_error "Cannot connect to Docker daemon."; exit 1; fi
print_success "Docker is available."
# Curl Check
if ! command -v curl &> /dev/null; then print_warning "curl not found. Cannot detect Ollama models."; CURL_AVAILABLE=0; else print_success "curl is available."; CURL_AVAILABLE=1; fi
# JQ Check
if ! command -v jq &> /dev/null; then print_warning "jq not found. Cannot detect Ollama models."; JQ_AVAILABLE=0; else print_success "jq is available."; JQ_AVAILABLE=1; fi
# --- End Pre-checks ---


# --- Determine Run Method FIRST ---
USE_COMPOSE="n"
ENV_FILE_GENERATED=0
COMPOSE_CMD="" # Will hold 'docker compose' or 'docker-compose'

if [ -f "docker-compose.yml" ]; then
    print_info "Found docker-compose.yml."
    read -p "$(echo -e '\033[1;36m> Use docker-compose to manage this application? (Y/n): \033[0m')" use_compose_input
    USE_COMPOSE=${use_compose_input:-Y} # Default to Yes if file exists

    if [[ "$USE_COMPOSE" =~ ^[Yy]$ ]]; then
        # Check if compose command exists
        if command -v docker-compose &> /dev/null; then
            COMPOSE_CMD="docker-compose"
        elif docker compose version &> /dev/null; then
            COMPOSE_CMD="docker compose" # Space for v2 plugin
        else
             print_warning "docker-compose command or 'compose' plugin not found. Will proceed using 'docker run' instead."
             USE_COMPOSE="n"
             COMPOSE_CMD=""
        fi
        if [ -n "$COMPOSE_CMD" ]; then
             print_info "Will use '$COMPOSE_CMD' and generate/update a '.env' file."
        fi
    else
        print_info "Will configure for manual 'docker run'."
    fi
else
    print_info "docker-compose.yml not found. Will configure for 'docker run'."
    USE_COMPOSE="n"
fi
# --- End Determine Run Method ---


# --- Gather Configuration ---
print_info "Please configure the Docker Log Monitor setup:"

# Ask for names/ports/volume ONLY if NOT using compose (or if compose command wasn't found)
if [[ ! "$USE_COMPOSE" =~ ^[Yy]$ || -z "$COMPOSE_CMD" ]]; then
    prompt_user "Enter Docker image name to build" IMAGE_NAME "$DEFAULT_IMAGE_NAME"
    prompt_user "Enter Docker container name" CONTAINER_NAME "$DEFAULT_CONTAINER_NAME"
    prompt_user "Enter Host Port to map to container's port 5000" HOST_PORT "$DEFAULT_HOST_PORT"
    prompt_user "Enter Docker Volume name for persistent data" VOLUME_NAME "$DEFAULT_VOLUME_NAME"
else
    # If using compose, still need image name for the build command
    prompt_user "Enter Docker image name to build" IMAGE_NAME "$DEFAULT_IMAGE_NAME"
    # For compose, container name, host port, and volume name are typically set in the YML file
    print_info "Container name, host port, and volume name should be configured in docker-compose.yml."
    # Set defaults for variables not asked, just in case they are needed later (e.g. if compose fails)
    CONTAINER_NAME="$DEFAULT_CONTAINER_NAME"
    HOST_PORT="$DEFAULT_HOST_PORT"
    VOLUME_NAME="$DEFAULT_VOLUME_NAME"
fi


print_info "--- Ollama Configuration ---"
# (Ollama URL info and prompt same as before)
echo "Common URLs:"
echo "  - Docker Desktop (Mac/Win): http://host.docker.internal:11434/api/generate"
if [[ -n "$DEFAULT_OLLAMA_API_URL_LINUX" ]]; then echo "  - Linux (detected docker0): $DEFAULT_OLLAMA_API_URL_LINUX (Verify!)"; fi
echo "  - Linux (common default): http://172.17.0.1:11434/api/generate"
echo "  - Remote Ollama: Use its actual IP address, e.g., http://192.168.1.11:11434/api/generate"
prompt_user "Enter Ollama API URL (base or with /api/generate)" OLLAMA_API_URL "$DEFAULT_OLLAMA_API_URL"

# --- Attempt to Fetch Ollama Models (Keep this logic as is) ---
declare -a available_models=()
models_fetched=0
if [[ $CURL_AVAILABLE -eq 1 && $JQ_AVAILABLE -eq 1 ]]; then
    # ... (rest of model fetching logic remains the same) ...
    print_info "Attempting to fetch available models from Ollama..."
    OLLAMA_BASE_URL=$(echo "$OLLAMA_API_URL" | grep -oE '^https?://[^/]+')
    if [[ -z "$OLLAMA_BASE_URL" ]]; then
        print_warning "Could not parse base URL from '$OLLAMA_API_URL'. Unable to fetch models."
    else
        TAGS_URL="${OLLAMA_BASE_URL}/api/tags"
        print_info "Querying models endpoint: $TAGS_URL"
        models_json=$(curl -s -f --connect-timeout 5 "$TAGS_URL")
        curl_exit_code=$?
        if [[ $curl_exit_code -eq 0 ]]; then
            mapfile -t available_models < <(echo "$models_json" | jq -r '.models[].name')
            jq_exit_code=$?
            if [[ $jq_exit_code -eq 0 && ${#available_models[@]} -gt 0 ]]; then
                print_success "Successfully fetched ${#available_models[@]} models from Ollama."
                models_fetched=1
            elif [[ $jq_exit_code -eq 0 ]]; then print_warning "Connected to Ollama, but no models found or JSON format unexpected."; else print_warning "Connected to Ollama, but failed to parse model list using jq (Error code: $jq_exit_code)."; fi
        else print_warning "Failed to connect to Ollama at $TAGS_URL (curl Error code: $curl_exit_code). Check URL and Ollama status."; fi
    fi
else print_info "Skipping model detection (curl or jq not available)."; fi

# --- Prompt for Ollama Model (Keep this logic as is) ---
if [[ $models_fetched -eq 1 ]]; then
    echo "-------------------------------------"; echo "Available models detected:"; printf "  - %s\n" "${available_models[@]}"; echo "-------------------------------------"
    first_detected_model="${available_models[0]}"; is_default_available=0
    for model in "${available_models[@]}"; do if [[ "$model" == "$DEFAULT_OLLAMA_MODEL" ]]; then is_default_available=1; break; fi; done
    if [[ $is_default_available -eq 0 && -n "$first_detected_model" ]]; then DEFAULT_OLLAMA_MODEL_SUGGESTED="$first_detected_model"; print_info "Default '$DEFAULT_OLLAMA_MODEL' not found, suggesting '$DEFAULT_OLLAMA_MODEL_SUGGESTED'."; else DEFAULT_OLLAMA_MODEL_SUGGESTED="$DEFAULT_OLLAMA_MODEL"; fi
    prompt_user "Enter Ollama Model to use (select from list or enter manually)" OLLAMA_MODEL "$DEFAULT_OLLAMA_MODEL_SUGGESTED"
else
    prompt_user "Enter Ollama Model to use" OLLAMA_MODEL "$DEFAULT_OLLAMA_MODEL"
fi
# --- End Ollama Config ---


print_info "--- Scanning Configuration ---"
prompt_user "Scan interval in minutes" SCAN_INTERVAL_MINUTES "$DEFAULT_SCAN_INTERVAL_MINUTES"
prompt_user "Number of log lines to fetch per container per scan" LOG_LINES_TO_FETCH "$DEFAULT_LOG_LINES_TO_FETCH"

print_info "--- Web Application Configuration ---"
prompt_user "Enter Flask Secret Key (leave empty to generate one)" FLASK_SECRET_KEY "$DEFAULT_FLASK_SECRET_KEY"
if [ -z "$FLASK_SECRET_KEY" ]; then print_info "Generating Flask Secret Key..."; FLASK_SECRET_KEY=$(generate_secret_key); print_success "Generated Key: $FLASK_SECRET_KEY"; fi


# --- Confirm Docker Socket Mount (Keep as is) ---
print_warning "This application requires mounting the Docker socket (/var/run/docker.sock)."
print_warning "Ensure you understand the security implications."
read -p "$(echo -e '\033[1;33m> Acknowledge and continue? (y/N): \033[0m')" confirm_socket
if [[ ! "$confirm_socket" =~ ^[Yy]$ ]]; then print_error "Aborted by user."; exit 1; fi

# --- Build Docker Image (Keep as is) ---
print_info "Building the Docker image '$IMAGE_NAME'..."
if ! docker build -t "$IMAGE_NAME" .; then print_error "Docker image build failed."; exit 1; fi
print_success "Docker image '$IMAGE_NAME' built successfully."

# --- Prepare for Running (Generate .env if using compose) ---
if [[ "$USE_COMPOSE" =~ ^[Yy]$ && -n "$COMPOSE_CMD" ]]; then
    print_info "Generating/Updating .env file for docker-compose..."
    cat > .env << EOF
# Generated/Updated by install.sh on $(date)
OLLAMA_API_URL=$OLLAMA_API_URL
OLLAMA_MODEL=$OLLAMA_MODEL
SCAN_INTERVAL_MINUTES=$SCAN_INTERVAL_MINUTES
LOG_LINES_TO_FETCH=$LOG_LINES_TO_FETCH
FLASK_SECRET_KEY=$FLASK_SECRET_KEY
# Note: Service name, port mapping, volume name, network should be set in docker-compose.yml
EOF
    ENV_FILE_GENERATED=1
    print_success "Generated/Updated .env file."
fi

# --- Prompt to Start Container (Keep logic as is, relies on USE_COMPOSE) ---
echo ""
print_info "Setup complete. Ready to start the container."
read -p "$(echo -e '\033[1;36m> Start the container now? (Y/n): \033[0m')" start_now
if [[ "$start_now" =~ ^[Yy]$ || -z "$start_now" ]]; then

    # --- Container removal logic (uses CONTAINER_NAME, which is now conditional) ---
    # If using compose, read container name from yml if possible, otherwise use default.
    ACTUAL_CONTAINER_NAME_TO_CHECK=$CONTAINER_NAME
    if [[ "$USE_COMPOSE" =~ ^[Yy]$ && -n "$COMPOSE_CMD" ]]; then
         # Try reading from compose file (simple grep, might fail)
         COMPOSE_CONTAINER_NAME=$(grep -oP '^\s*container_name:\s*\K\S+' docker-compose.yml || echo "")
         if [ -n "$COMPOSE_CONTAINER_NAME" ]; then
             ACTUAL_CONTAINER_NAME_TO_CHECK=$COMPOSE_CONTAINER_NAME
             print_info "Checking for existing container named '$ACTUAL_CONTAINER_NAME_TO_CHECK' (from docker-compose.yml)."
         fi
    fi

    if [ "$(docker ps -aq -f name=^/${ACTUAL_CONTAINER_NAME_TO_CHECK}$)" ]; then
        print_warning "Container '$ACTUAL_CONTAINER_NAME_TO_CHECK' already exists."
        # If using compose, 'down' is better than manual stop/rm
        if [[ "$USE_COMPOSE" =~ ^[Yy]$ && -n "$COMPOSE_CMD" ]]; then
             read -p "$(echo -e '\033[1;33m> Run '$COMPOSE_CMD' down to stop and remove it? (y/N): \033[0m')" remove_existing
             if [[ "$remove_existing" =~ ^[Yy]$ ]]; then
                 print_info "Running '$COMPOSE_CMD down'..."
                 if ! $COMPOSE_CMD down; then print_warning "'$COMPOSE_CMD down' failed, manual removal might be needed."; fi
                 print_success "Existing compose services stopped/removed."
             else print_error "Aborted. Cannot start new container."; exit 1; fi
        else # Using docker run
            read -p "$(echo -e '\033[1;33m> Stop and remove it? (y/N): \033[0m')" remove_existing
            if [[ "$remove_existing" =~ ^[Yy]$ ]]; then
                print_info "Stopping/Removing existing container '$ACTUAL_CONTAINER_NAME_TO_CHECK'..."
                docker stop "$ACTUAL_CONTAINER_NAME_TO_CHECK" > /dev/null && docker rm "$ACTUAL_CONTAINER_NAME_TO_CHECK" > /dev/null
                print_success "Existing container removed."
            else print_error "Aborted. Cannot start new container."; exit 1; fi
        fi
    fi
    # --- End container removal logic ---


    if [[ "$USE_COMPOSE" =~ ^[Yy]$ && -n "$COMPOSE_CMD" ]]; then
        print_info "Starting container using '$COMPOSE_CMD up -d'..."
        if $COMPOSE_CMD up -d; then
            print_success "Container started via docker-compose."
            # Try reading host port from compose file for info message
            COMPOSE_HOST_PORT=$(grep -oP '^\s*-\s*"\K[0-9]+(?=:5000")' docker-compose.yml | head -n 1)
            if [ -z "$COMPOSE_HOST_PORT" ]; then COMPOSE_HOST_PORT="<Check YML>"; fi # Fallback
            print_info "Access UI likely at: http://localhost:$COMPOSE_HOST_PORT (Port defined in docker-compose.yml)"
            print_info "View logs: $COMPOSE_CMD logs -f"
        else print_error "Failed to start via docker-compose."; exit 1; fi
    else # Use docker run
        print_info "Starting container using 'docker run'..."
        DOCKER_RUN_CMD="docker run -d --name \"$CONTAINER_NAME\" \
          --restart unless-stopped \
          -p \"$HOST_PORT:5000\" \
          -v \"/var/run/docker.sock:/var/run/docker.sock:ro\" \
          -v \"$VOLUME_NAME:/app\" \
          -e OLLAMA_API_URL=\"$OLLAMA_API_URL\" \
          -e OLLAMA_MODEL=\"$OLLAMA_MODEL\" \
          -e SCAN_INTERVAL_MINUTES=\"$SCAN_INTERVAL_MINUTES\" \
          -e LOG_LINES_TO_FETCH=\"$LOG_LINES_TO_FETCH\" \
          -e FLASK_SECRET_KEY=\"$FLASK_SECRET_KEY\" \
          \"$IMAGE_NAME\""
        echo "Executing:"
        echo "$DOCKER_RUN_CMD"
        if eval "$DOCKER_RUN_CMD"; then
            print_success "Container '$CONTAINER_NAME' started."
            print_info "Access UI: http://localhost:$HOST_PORT"
            print_info "View logs: docker logs -f $CONTAINER_NAME"
        else print_error "Failed to start using 'docker run'."; exit 1; fi
    fi
else # User chose not to start now
    print_info "Container not started."
    if [[ "$USE_COMPOSE" =~ ^[Yy]$ && -n "$COMPOSE_CMD" ]]; then
        print_info "To start later using docker-compose (ensure .env file is present):"
        print_info "  $COMPOSE_CMD up -d"
        print_info "To stop: $COMPOSE_CMD down"
        if [ $ENV_FILE_GENERATED -eq 1 ]; then print_warning "Review the generated '.env' file before starting."; fi
    else
         print_info "To start later using docker run:"
         echo "docker run -d --name \"$CONTAINER_NAME\" \\"
         echo "  --restart unless-stopped -p \"$HOST_PORT:5000\" \\"
         echo "  -v \"/var/run/docker.sock:/var/run/docker.sock:ro\" -v \"$VOLUME_NAME:/app\" \\"
         echo "  -e OLLAMA_API_URL=\"$OLLAMA_API_URL\" -e OLLAMA_MODEL=\"$OLLAMA_MODEL\" \\"
         echo "  -e SCAN_INTERVAL_MINUTES=\"$SCAN_INTERVAL_MINUTES\" -e LOG_LINES_TO_FETCH=\"$LOG_LINES_TO_FETCH\" \\"
         echo "  -e FLASK_SECRET_KEY=\"$FLASK_SECRET_KEY\" \\"
         echo "  \"$IMAGE_NAME\""
         echo ""
         print_info "To stop: docker stop $CONTAINER_NAME"; print_info "To remove: docker rm $CONTAINER_NAME"
    fi
fi

echo ""
print_info "Installation script finished."
