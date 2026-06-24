#!/bin/bash
set -e

echo "=========================================="
echo "SSL Certificate Manager - Starting"
echo "=========================================="

# Run database migrations
echo "Running database migrations..."
if uv run python migrate_add_theme.py; then
    echo "✓ Database migrations completed successfully"
else
    echo "⚠ Migration script returned an error or theme column already exists"
fi

echo ""
echo "Starting application..."
echo "=========================================="

# Execute the CMD from Dockerfile (gunicorn)
exec "$@"
