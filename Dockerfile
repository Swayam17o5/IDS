FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for Scapy, libpcap, and C extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy and install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code and models
COPY . /app

# Ensure PYTHONPATH is configured
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Expose FastAPI service port
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Start the NIDS inference service and dashboard
CMD ["uvicorn", "services.inference.app:app", "--host", "0.0.0.0", "--port", "8000"]
