# Docker Deployment Guide

## Rebuilding the Container with Theme Support

The theme feature requires a database migration. Follow these steps to update your Docker deployment:

### Step 1: Stop the Running Container
```bash
docker compose down
```

### Step 2: Rebuild the Image
```bash
docker build -t ssl-cert-manager:latest .
```

### Step 3: Start the Container
```bash
docker compose up -d
```

The container will automatically run the database migration on startup via the `docker-entrypoint.sh` script.

### Step 4: Verify the Container is Running
```bash
docker compose ps
docker compose logs -f certmanager
```

You should see:
```
Running database migrations...
✓ Database migrations completed successfully
Starting application...
```

## Alternative: Manual Migration Inside Running Container

If you prefer to run the migration manually inside an existing container:

```bash
# Enter the container
docker exec -it ssl-cert-manager bash

# Run the migration
uv run python migrate_add_theme.py

# Exit the container
exit

# Restart the container
docker compose restart
```

## Troubleshooting

### Theme Not Showing After Update
1. **Clear browser cache**: Press Ctrl+Shift+R (or Cmd+Shift+R on Mac)
2. **Check logs**: `docker compose logs certmanager`
3. **Verify migration**: `docker exec -it ssl-cert-manager uv run python -c "from models import db, User; print(User.query.first().theme if User.query.first() else 'No users')"`

### Database Volume Issues
If you want to start fresh (⚠️ This will delete all certificates and data):

```bash
# Stop and remove containers and volumes
docker compose down -v

# Rebuild and start
docker build -t ssl-cert-manager:latest .
docker compose up -d
```

### Preserving Existing Data
The database is stored in the `certmanager_data` volume. The migration script safely adds the theme column without affecting existing data.

## Environment Variables

Make sure your `.env` file includes (optional):
```
SECRET_KEY=your-secret-key-here
DB_TYPE=sqlite
```

For production, always set a strong SECRET_KEY!
