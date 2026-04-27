# syntax=docker/dockerfile:1
FROM python:3.12-slim

# Install uv and build dependencies for compiling native extensions (twofish, pycryptodomex)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Install build tools and openssl
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc-dev \
    libffi-dev \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

# Create directories for mounts
RUN mkdir -p /app/instance /app/logs /etc/pki/tls/certs /etc/pki/tls/private /etc/pki/tls/csr_2026 /etc/pki/tls/backup

# Copy dependency files first for better caching
COPY pyproject.toml uv.lock* ./

# Install dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

# Copy application code
COPY . .

# Install the project itself
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# Set default environment variables
ENV FLASK_APP=app.py \
    FLASK_ENV=production \
    SECRET_KEY=change-me-in-production

# Expose port
EXPOSE 5000

# Run with gunicorn for production
CMD ["uv", "run", "gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:create_app()"]
