#!/bin/bash
set -e

echo "=========================================="
echo "SSL Certificate Manager - Starting"
echo "=========================================="

# Run database migrations
echo "Running database migrations..."

# Migration 1: Add theme column
if uv run python migrate_add_theme.py; then
    echo "✓ Theme migration completed successfully"
else
    echo "⚠ Theme migration returned an error or theme column already exists"
fi

# Migration 2: Add CASCADE delete to alert_instances and alert_logs
echo ""
echo "Running alert instances CASCADE migration..."
if uv run python migrate_alert_instances.py; then
    echo "✓ Alert instances migration completed successfully"
else
    echo "⚠ Alert instances migration returned an error"
fi

echo ""
echo "Starting application..."
echo "=========================================="

# Execute the CMD from Dockerfile (gunicorn)
exec "$@"
