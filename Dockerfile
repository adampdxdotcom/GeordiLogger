# Dockerfile

# Use a lightweight Python base image
FROM python:3.11-slim

# Set common environment variables
# Prevents creation of .pyc files
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1      
# Prevents python output buffering
ENV PORT=5001               
# Default port application listens on
ENV TZ="UTC"                
# Default timezone (override if needed)

# Set the working directory
WORKDIR /app

# Install system dependencies (if any - not needed for this basic setup)
# RUN apt-get update && apt-get install -y --no-install-recommends some-package && rm -rf /var/lib/apt/lists/*

# Copy requirements file first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
# Consider using a virtual environment for better isolation, though less critical in a container
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
# Use .dockerignore to exclude unnecessary files/dirs (e.g., .git, .venv, __pycache__)
COPY . .

# Expose the port the app runs on (matches ENV PORT)
EXPOSE 5001

# Set application-specific environment variables (defaults can be overridden at runtime)
# FLASK_APP is often not needed when using CMD ["python", "app.py"] but doesn't hurt
# ENV FLASK_APP=app.py
# ENV FLASK_RUN_HOST=0.0.0.0 # Host is set in app.py run command

# --- Ollama Configuration Defaults ---
# Adjust OLLAMA_API_URL via environment variable (-e or .env file) based on your setup:
# - Docker Desktop (Mac/Win): http://host.docker.internal:11434
# - Linux host network access (find IP with `ip addr show docker0`): e.g., http://172.17.0.1:11434
# - Ollama in another container ('ollama') on same network: http://ollama:11434
ENV OLLAMA_API_URL="http://host.docker.internal:11434"
ENV OLLAMA_MODEL="phi3"

# --- Scan Configuration Defaults ---
ENV SCAN_INTERVAL_MINUTES="10"
ENV LOG_LINES_TO_FETCH="200"
ENV SUMMARY_INTERVAL_HOURS="12" 
# Add default if app.py uses it
ENV OLLAMA_TIMEOUT="120" 
# Add default if app.py uses it
ENV OLLAMA_SUMMARY_TIMEOUT="180" 
# Add default if app.py uses it

# --- Flask Configuration Default ---
# CHANGE FLASK_SECRET_KEY via environment variable for security!
ENV FLASK_SECRET_KEY="change_this_in_production"

# --- Server Choice ---
# Set to "true" to use Waitress by default if available
ENV USE_WAITRESS="true"

# --- Logging Level ---
ENV LOG_LEVEL="INFO"

# --- End Environment Variables ---

# Command to run the application using python directly
# This ensures app.py's `if __name__ == '__main__':` block runs
CMD ["python", "app.py"]
