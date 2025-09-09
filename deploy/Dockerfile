# Network Security Agent - Dockerfile
# Multi-stage build for optimized production container

FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpcap-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    nftables \
    iptables \
    ipset \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create non-root user
RUN groupadd -r security-agent && \
    useradd -r -g security-agent security-agent && \
    mkdir -p /var/log/security-agent && \
    chown security-agent:security-agent /var/log/security-agent

# Create application directory
WORKDIR /app

# Copy application code
COPY src/ ./src/
COPY config/ ./config/
COPY scripts/ ./scripts/

# Make scripts executable
RUN chmod +x scripts/*.sh

# Create data directories
RUN mkdir -p /app/data /app/logs && \
    chown -R security-agent:security-agent /app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/status || exit 1

# Expose ports
EXPOSE 8080 9090

# Set user
USER security-agent

# Default command
CMD ["python", "src/security_agent.py", "--config", "config/security_agent.yaml"]
