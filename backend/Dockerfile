# Base Image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies (needed for some Python packages)
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install (incluye los modelos de spaCy)
COPY requirements.txt .
# The default Linux torch wheel drags ~3.4 GB of CUDA libraries. Nothing here
# touches a GPU, so the CPU build goes in first; PEP 440 treats 2.11.0+cpu as
# satisfying the plain ==2.11.0 pin, so requirements.txt stays portable.
RUN pip install --no-cache-dir \
        --index-url https://download.pytorch.org/whl/cpu torch==2.11.0+cpu \
 && pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/

# Expose backend port
EXPOSE 8080

# Run the application
CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8080"]
