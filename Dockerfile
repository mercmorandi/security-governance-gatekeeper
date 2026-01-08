# ===========================================
# DOCKERFILE - Security Gatekeeper
# ===========================================

FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy and install Python dependencies
COPY pyproject.toml ./
COPY src/ ./src/
RUN pip install --upgrade pip && pip install .

# Download spaCy models (English and Italian)
RUN python -m spacy download en_core_web_sm && \
    python -m spacy download it_core_news_sm

# Copy config
COPY config/ ./config/

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["uvicorn", "security_governance_gatekeeper.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
