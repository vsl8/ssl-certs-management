# Database Migrations

This directory contains database migration scripts that are automatically executed when the application starts in Docker.

## How It Works

- All Python files starting with `migrate_` in this directory are automatically detected and run
- Migrations are executed in alphabetical order (sorted by filename)
- Each migration should be idempotent (safe to run multiple times)

## Migration Naming Convention

Use the following naming pattern:
```
migrate_<number>_<descriptive_name>.py
```

Examples:
- `migrate_001_add_theme.py`
- `migrate_002_alert_instances_cascade.py`
- `migrate_003_add_new_feature.py`

## When Are Migrations Needed?

**Fresh Installations:** No migrations needed! The `init_db()` function in `models.py` creates all tables with the correct schema automatically.

**Existing Installations:** Migrations are required when upgrading from older versions to apply schema changes to existing databases.

## Creating a New Migration

1. Create a new file in this directory: `migrate_<number>_<description>.py`
2. Follow the pattern from existing migration files
3. Make it idempotent (check if changes are needed before applying)
4. Test locally before deploying

## Current Migrations

- `migrate_add_theme.py` - Adds theme column to users table
- `migrate_alert_instances.py` - Adds CASCADE delete constraints to alert_instances and alert_logs tables

## Running Migrations Manually

```bash
# Run all migrations
for migration in migrations/migrate_*.py; do
    uv run python "$migration"
done

# Run a specific migration
uv run python migrations/migrate_add_theme.py
```
