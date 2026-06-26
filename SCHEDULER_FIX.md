# Duplicate Alert Notification Fix

## Problem
When running with gunicorn `--workers 2`, each worker process creates its own APScheduler instance, resulting in duplicate alert notifications being sent.

## Root Cause
- `Dockerfile` uses `--workers 2`
- Each worker calls `create_app()` → `_setup_scheduler()` → creates a BackgroundScheduler
- Two schedulers run `check_and_send_alerts()` simultaneously every 60 minutes

## Solution Applied (Option 1)
Changed to single worker with multiple threads in `Dockerfile`:
```dockerfile
CMD ["uv", "run", "gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "app:create_app()"]
```

This prevents multiple schedulers while maintaining some concurrency through threads.

## Alternative Solution (Option 2) - For Higher Load
If you need multiple workers for performance, modify `app.py` to run scheduler only in one worker:

```python
def _setup_scheduler(app):
    """Setup background scheduler for certificate alert checks and scheduled backups."""
    import os
    
    # Only run scheduler in the first worker process
    # Gunicorn workers inherit from master but can check their own identity
    worker_id = os.environ.get('GUNICORN_WORKER_ID', '0')
    if worker_id != '0':
        log.info(f'Skipping scheduler in worker {worker_id}')
        return
    
    log.info('Starting scheduler in worker 0')
    from notifications import check_and_send_alerts
    from backup_utils import run_scheduled_backup, get_backup_schedule

    scheduler = BackgroundScheduler(daemon=True)
    # ... rest of setup ...
```

Then use gunicorn hooks to set worker IDs. Create `gunicorn_config.py`:
```python
def post_worker_init(worker):
    """Set worker ID in environment after worker initialization."""
    import os
    os.environ['GUNICORN_WORKER_ID'] = str(worker.age)
```

And update Dockerfile CMD:
```dockerfile
CMD ["uv", "run", "gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--config", "gunicorn_config.py", "app:create_app()"]
```

## Alternative Solution (Option 3) - Separate Scheduler Container
For production at scale, run the scheduler in a dedicated container:

1. Create `scheduler.py`:
```python
from app import create_app
from notifications import check_and_send_alerts
from backup_utils import run_scheduled_backup, get_backup_schedule
from apscheduler.schedulers.blocking import BlockingScheduler

app = create_app()

with app.app_context():
    scheduler = BlockingScheduler()
    
    scheduler.add_job(
        func=lambda: check_and_send_alerts(app),
        trigger='interval',
        minutes=60,
        id='cert_alert_check',
    )
    
    schedule = get_backup_schedule()
    # ... setup backup job ...
    
    scheduler.start()
```

2. Add to `docker-compose.yaml`:
```yaml
services:
  web:
    # ... existing config, remove scheduler from app.py ...
  
  scheduler:
    build: .
    command: ["uv", "run", "python", "scheduler.py"]
    environment:
      # Same as web service
    volumes:
      # Same as web service
```

## Testing
After applying the fix:
1. Rebuild: `docker build -t ssl-cert-manager:latest .`
2. Restart: `docker compose down && docker compose up -d`
3. Monitor logs: `docker compose logs -f`
4. Wait for next scheduled alert check and verify only one notification is sent

## Prevention
- Document scheduler architecture in CLAUDE.md
- Add integration test that checks for duplicate notifications
- Consider moving to Option 3 (separate scheduler container) for production
