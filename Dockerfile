# Multi-stage Dockerfile for Enterprise Cybersecurity Toolkit
FROM python:3.11-slim

# Install system dependencies (nmap, libmagic, net-tools, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libmagic1 \
    curl \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency specifications
COPY requirements.txt requirements-advanced.txt ./

# Install python packages
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -r requirements-advanced.txt || true

# Copy full application
COPY . .

# Create non-root user for security best practices
RUN useradd -m -s /bin/bash security && \
    chown -R security:security /app

# Switch to security user
USER security

EXPOSE 5000

# Set entrypoint
ENTRYPOINT ["python"]
CMD ["dashboard/app.py"]
