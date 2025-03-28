#!/bin/bash

# Simple interactive installer for Docker Log Monitor
# Includes Ollama model detection

# --- Configuration Defaults ---
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

# --- Helper Functions ---
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

# --- Pre-checks ---
print_info "Checking prerequisites..."
# Docker Check
if ! command -v docker &> /dev/null; then print_error "Docker command not found."; exit 1; fi
if ! docker info > /dev/null 2>&1; then print_error "Cannot connect to Docker daemon."; exit 1; fi
print_success "Docker is available."
# Curl Check
if ! command -v curl &> /dev/null; then
    print_warning "curl command not found. Cannot automatically detect Ollama models. Please install curl or enter the model name manually."
    CURL_AVAILABLE=0
else
    print_success "curl is available."
    CURL_AVAILABLE=1
fi
# JQ Check
if ! command -v jq &> /dev/null; then
    print_warning "jq command not found. Cannot automatically detect Ollama models. Please install jq or enter the model name manually."
    JQ_AVAILABLE=0
else
    print_success "jq is available."
    JQ_AVAILABLE=1
fi


# --- Gather Configuration ---
print_info "Please configure the Docker Log Monitor setup:"
prompt_user "Enter Docker image name" IMAGE_NAME "$DEFAULT_IMAGE_NAME"
prompt_user "Enter Docker container name" CONTAINER_NAME "$DEFAULT_CONTAINER_NAME"
prompt_user "Enter Host Port to map to container's port 5000" HOST_PORT "$DEFAULT_HOST_PORT"
prompt_user "Enter Docker Volume name for persistent data" VOLUME_NAME "$DEFAULT_VOLUME_NAME"

print_info "--- Ollama Configuration ---"
echo "Common URLs:"
echo "  - Docker Desktop (Mac/Win): http://host.docker.internal:11434/api/generate"
if [[ -n "$DEFAULT_OLLAMA_API_URL_LINUX" ]]; then echo "  - Linux (detected docker0): $DEFAULT_OLLAMA_API_URL_LINUX (Verify!)"; fi
echo "  - Linux (common default): http://172.17.0.1:11434/api/generate"
echo "  - If Ollama runs in another container ('ollama') on the same Docker network: http://ollama:11434/api/generate"
prompt_user "Enter Ollama API URL (base or with /api/generate)" OLLAMA_API_URL "$DEFAULT_OLLAMA_API_URL"

# --- Attempt to Fetch Ollama Models ---
declare -a available_models=() # Bash array to hold model names
models_fetched=0
if [[ $CURL_AVAILABLE -eq 1 && $JQ_AVAILABLE -eq 1 ]]; then
    print_info "Attempting to fetch available models from Ollama..."
    # Construct the /api/tags URL from the potentially longer URL provided
    # Extracts the http(s)://host:port part
    OLLAMA_BASE_URL=$(echo "$OLLAMA_API_URL" | grep -oE '^https?://[^/]+')
    if [[ -z "$OLLAMA_BASE_URL" ]]; then
        print_warning "Could not parse base URL from '$OLLAMA_API_URL'. Unable to fetch models."
    else
        TAGS_URL="${OLLAMA_BASE_URL}/api/tags"
        print_info "Querying models endpoint: $TAGS_URL"
        # Make the request with a timeout, fail on HTTP errors, suppress progress
        models_json=$(curl -s -f --connect-timeout 5 "$TAGS_URL")
        curl_exit_code=$?

        if [[ $curl_exit_code -eq 0 ]]; then
            # Parse the JSON response for model names
            mapfile -t available_models < <(echo "$models_json" | jq -r '.models[].name')
            jq_exit_code=$?

            if [[ $jq_exit_code -eq 0 && ${#available_models[@]} -gt 0 ]]; then
                print_success "Successfully fetched ${#available_models[@]} models from Ollama."
                models_fetched=1
            elif [[ $jq_exit_code -eq 0 ]]; then
                print_warning "Connected to Ollama, but no models found or JSON format unexpected."
            else
                print_warning "Connected to Ollama, but failed to parse model list using jq (Error code: $jq_exit_code)."
            fi
        else
             print_warning "Failed to connect to Ollama at $TAGS_URL (curl Error code: $curl_exit_code)."
             print_warning "Check if Ollama is running and the URL is correct."
        fi
    fi
else
    print_info "Skipping model detection (curl or jq not available)."
fi

# --- Prompt for Ollama Model ---
if [[ $models_fetched -eq 1 ]]; then
    echo "-------------------------------------"
    echo "Available models detected:"
    printf "  - %s\n" "${available_models[@]}"
    echo "-------------------------------------"
    # Suggest the first detected model as default if the original default isn't in the list
    first_detected_model="${available_models[0]}"
    is_default_available=0
    for model in "${available_models[@]}"; do
        if [[ "$model" == "$DEFAULT_OLLAMA_MODEL" ]]; then
            is_default_available=1
            break
        fi
    done
    if [[ $is_default_available -eq 0 && -n "$first_detected_model" ]]; then
       DEFAULT_OLLAMA_MODEL_SUGGESTED="$first_detected_model"
       print_info "Default '$DEFAULT_OLLAMA_MODEL' not found in list, suggesting '$DEFAULT_OLLAMA_MODEL_SUGGESTED'."
    else
        DEFAULT_OLLAMA_MODEL_SUGGESTED="$DEFAULT_OLLAMA_MODEL"
    fi
    prompt_user "Enter Ollama Model to use (select from list or enter manually)" OLLAMA_MODEL "$DEFAULT_OLLAMA_MODEL_SUGGESTED"
else
    # Fallback if models couldn't be fetched
    prompt_user "Enter Ollama Model to use" OLLAMA_MODEL "$DEFAULT_OLLAMA_MODEL"
fi
# --- End Ollama Config ---


print_info "--- Scanning Configuration ---"
prompt_user "Scan interval in minutes" SCAN_INTERVAL_MINUTES "$DEFAULT_SCAN_INTERVAL_MINUTES"
prompt_user "Number of log lines to fetch per container per scan" LOG_LINES_TO_FETCH "$DEFAULT_LOG_LINES_TO_FETCH"

print_info "--- Web Application Configuration ---"
prompt_user "Enter Flask Secret Key (leave empty to generate one)" FLASK_SECRET_KEY "$DEFAULT_FLASK_SECRET_KEY"
if [ -z "$FLASK_SECRET_KEY" ]; then
    print_info "Generating Flask Secret Key..."
    FLASK_SECRET_KEY=$(generate_secret_key)
    print_success "Generated Key: $FLASK_SECRET_KEY"
fi


# --- Confirm Docker Socket Mount ---
print_warning "This application requires mounting the Docker socket (/var/run/docker.sock)."
print_warning "Ensure you understand the security implications."
read -p "$(echo -e '\033[1;33m> Acknowledge and continue? (y/N): \033[0m')" confirm_socket
if [[ ! "$confirm_socket" =~ ^[Yy]$ ]]; then print_error "Aborted by user."; exit 1; fi

# --- Build Docker Image ---
print_info "Building the Docker image '$IMAGE_NAME'..."
if ! docker build -t "$IMAGE_NAME" .; then print_error "Docker image build failed."; exit 1; fi
print_success "Docker image '$IMAGE_NAME' built successfully."

# --- Prepare for Running ---
USE_COMPOSE="n"
ENV_FILE_GENERATED=0
if [ -f "docker-compose.yml" ]; then
    read -p "$(echo -e '\033[1;36m> Found docker-compose.yml. Use docker-compose? (Y/n): \033[0m')" use_compose_input
    USE_COMPOSE=${use_compose_input:-Y}

    if [[ "$USE_COMPOSE" =~ ^[Yy]$ ]]; then
        if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
             print_warning "docker-compose/compose plugin not found. Proceeding with 'docker run'."
             USE_COMPOSE="n"
        else
            print_info "Generating .env file for docker-compose..."
            cat > .env << EOF
# Generated by install.sh on $(date)
OLLAMA_API_URL=$OLLAMA_API_URL
OLLAMA_MODEL=$OLLAMA_MODEL
SCAN_INTERVAL_MINUTES=$SCAN_INTERVAL_MINUTES
LOG_LINES_TO_FETCH=$LOG_LINES_TO_FETCH
FLASK_SECRET_KEY=$FLASK_SECRET_KEY
EOF
            ENV_FILE_GENERATED=1
            print_success "Generated .env file."
            if command -v docker-compose &> /dev/null; then COMPOSE_CMD="docker-compose";
            else COMPOSE_CMD="docker compose"; fi
        fi
    fi
fi

# --- Prompt to Start Container ---
echo ""
print_info "Setup complete. Ready to start the container."
read -p "$(echo -e '\033[1;36m> Start the container now? (Y/n): \033[0m')" start_now
if [[ "$start_now" =~ ^[Yy]$ || -z "$start_now" ]]; then

    if [ "$(docker ps -aq -f name=^/${CONTAINER_NAME}$)" ]; then
        print_warning "Container '$CONTAINER_NAME' already exists."
        read -p "$(echo -e '\033[1;33m> Stop and remove it? (y/N): \033[0m')" remove_existing
        if [[ "$remove_existing" =~ ^[Yy]$ ]]; then
            print_info "Stopping/Removing existing container..."
            docker stop "$CONTAINER_NAME" > /dev/null && docker rm "$CONTAINER_NAME" > /dev/null
            print_success "Existing container removed."
        else
            print_error "Aborted. Please manually handle existing container '$CONTAINER_NAME'."; exit 1
        fi
    fi

    if [[ "$USE_COMPOSE" =~ ^[Yy]$ ]]; then
        print_info "Starting container using '$COMPOSE_CMD up -d'..."
        if $COMPOSE_CMD up -d; then
            print_success "Container started via docker-compose."
            print_info "Access UI: http://localhost:$HOST_PORT (Port may differ if changed in compose file)"
            print_info "View logs: $COMPOSE_CMD logs -f"
        else
            print_error "Failed to start via docker-compose."; exit 1
        fi
    else
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
        else
            print_error "Failed to start using 'docker run'."; exit 1
        fi
    fi
else
    print_info "Container not started."
    # (Instructions for manual start remain the same as in the previous script version)
    if [[ "$USE_COMPOSE" =~ ^[Yy]$ ]]; then
        print_info "To start later using docker-compose (ensure .env file is present):"
        print_info "  $COMPOSE_CMD up -d"
        print_info "To stop: $COMPOSE_CMD down"
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
         print_info "To stop: docker stop $CONTAINER_NAME"
         print_info "To remove: docker rm $CONTAINER_NAME"
    fi
    if [ $ENV_FILE_GENERATED -eq 1 ]; then print_warning "Review the generated '.env' file."; fi
fi

echo ""
print_info "Installation script finished."
