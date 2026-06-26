#!/bin/bash
set -e

echo "=========================================="
echo "SSL Certificate Manager - Starting"
echo "=========================================="

# Run database migrations
MIGRATION_DIR="migrations"

if [ -d "$MIGRATION_DIR" ]; then
    echo "Checking for database migrations..."
    
    # Find all Python files starting with "migrate_" in the migrations folder
    MIGRATION_FILES=$(find "$MIGRATION_DIR" -maxdepth 1 -name "migrate_*.py" -type f | sort)
    
    if [ -n "$MIGRATION_FILES" ]; then
        echo "Found migration files, running..."
        
        # Run each migration file
        for migration in $MIGRATION_FILES; do
            migration_name=$(basename "$migration")
            echo ""
            echo "→ Running migration: $migration_name"
            
            if uv run python "$migration"; then
                echo "  ✓ $migration_name completed successfully"
            else
                echo "  ⚠ $migration_name returned an error (may already be applied)"
            fi
        done
    else
        echo "No migration files found (this is normal for fresh installations)"
    fi
else
    echo "No migrations directory found, skipping migrations"
fi

echo ""
echo "Starting application..."
echo "=========================================="

# Execute the CMD from Dockerfile (gunicorn)
exec "$@"
