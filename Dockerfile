# Use a lightweight Python base image
FROM python:3.11-slim

# Set the working directory
WORKDIR /app

# Install system dependencies (if any - not needed for this basic setup)
# RUN apt-get update && apt-get install -y --no-install-recommends some-package && rm -rf /var/lib/apt/lists/*

# Copy requirements file first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the port the app runs on
EXPOSE 5000

# Set environment variables (defaults can be overridden at runtime)
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

# --- Ollama Configuration Defaults ---
# Adjust OLLAMA_API_URL via environment variable (-e or .env file) based on your setup:
# - Docker Desktop (Mac/Win): http://host.docker.internal:11434/api/generate
# - Linux host network access (find IP with `ip addr show docker0`): e.g., http://172.17.0.1:11434/api/generate
# - Ollama in another container ('ollama') on same network: http://ollama:11434/api/generate
ENV OLLAMA_API_URL="http://host.docker.internal:11434/api/generate"
ENV OLLAMA_MODEL="phi3"

# --- Scan Configuration Defaults ---
ENV SCAN_INTERVAL_MINUTES="10"
ENV LOG_LINES_TO_FETCH="200"

# --- Flask Configuration Default ---
# CHANGE FLASK_SECRET_KEY via environment variable for security!
ENV FLASK_SECRET_KEY="change_this_in_production"

# --- End Environment Variables ---
# Command to run the application
# Using Flask's built-in server for simplicity. For production, use Gunicorn or Waitress.
# CMD ["flask", "run"]
# Using python directly to ensure background scheduler works reliably
CMD ["python", "app.py"]
