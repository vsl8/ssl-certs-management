# SSL Certificate Manager

## Build, test, and run commands

- Install dependencies with `uv sync`. The repo also keeps `requirements.txt`, but the primary workflow in `README.md`, `Dockerfile`, and `uv.lock` is `uv`.
- Run the app locally with `uv run flask run` or `uv run flask run --debug`.
- Build the production image with `docker build -t ssl-cert-manager:latest .`.
- Start the containerized app with `docker compose up -d`.
- The README documents tests as `uv run pytest`, but `pytest` is not declared in `pyproject.toml` and there are currently no checked-in test files. If tests are added in a local environment that already has pytest, run one file with `uv run pytest path/to/test_file.py` or one test with `uv run pytest path/to/test_file.py -k test_name`.
- No lint command is configured in the repository.

## High-level architecture

- `app.py` is the application factory. It loads `Config`, initializes SQLAlchemy via `init_db(app)`, wires Flask-Login, sets up logging after the database is ready, registers all blueprints, injects config/settings into templates, and starts APScheduler jobs.
- `models.py` is both the schema and the bootstrap layer. `init_db()` creates tables and `_seed_defaults()` inserts the default admin user, default alert rules, and the runtime settings rows the rest of the app depends on.
- The app is a server-rendered Flask UI with JSON endpoints mixed into the same blueprints. Templates under `templates/` drive the UI, while many actions are handled by `fetch()`/jQuery AJAX calls that expect JSON success/error payloads rather than redirects.
- Route modules under `routes/` directly orchestrate database writes and filesystem operations; there is no separate service layer. The main blueprints are:
  - `auth`: login/logout, profile updates, session unlock verification
  - `dashboard`: summary stats and expiry views
  - `certificates`: upload/edit/delete/download plus Sectigo download flows
  - `settings`: general settings, alerts, notification channels, backups
  - `conversion`: format conversion endpoints
  - `csr`: CSR template management and CSR generation with `openssl`
- Persistence is split between the database and the filesystem. Certificate metadata, alert rules, notification channels, settings, and CSR records live in SQLAlchemy models; the actual certificate files, generated CSR/CNF files, logs, and backups live on disk.
- Storage locations are runtime-configurable through the `settings` table (`cert_storage_path`, `csr_storage_path`, `backup_path`, `log_file_path`). Routes typically use the configured path when it exists and fall back to the Flask upload directory otherwise.
- Background behavior is startup-driven. APScheduler always adds the hourly alert check, and also adds the scheduled backup job based on the saved backup schedule at app startup.
- Core domain logic is concentrated in utility modules:
  - `cert_utils.py`: parse certificates/keys, extract metadata, refresh expiry, extract chains
  - `conversion_utils.py`: cross-format conversion, including PFX/P12, PKCS7, and JKS
  - `sectigo_utils.py`: download and combine Sectigo/InCommon certificates
  - `notifications.py`: alert selection and delivery through SMTP, Slack, Teams, and generic webhooks
  - `backup_utils.py`: ZIP certificate backups and SQL database export
  - `logger.py`: central logging setup and runtime log reconfiguration

## Key repository-specific conventions

- Treat the `settings` table as the source of truth for mutable application behavior. When adding a new runtime option, follow the existing pattern: seed a default in `models._seed_defaults()`, read it through `Setting.query`, and update any live subsystem explicitly if the change should apply immediately.
- Logging is centralized. Modules obtain loggers with `get_logger('<module>')`; do not create ad-hoc logging setup inside route or utility files.
- Expiry state is refreshed lazily in request/job flows by calling `refresh_cert_expiry()` and then committing before rendering tables, dashboard stats, or sending alerts. Do not assume `days_until_expiry` is permanently current unless the relevant flow refreshed it.
- Several model fields intentionally store JSON inside `Text` columns, especially `Certificate.san_domains`, `CSRRequest.san_domains`, and `NotificationChannel.webhook_headers`. Existing code manually `json.dumps()`/`json.loads()` these values and often keeps graceful fallbacks for malformed stored data.
- The UI expects JSON responses for many mutations even on server-rendered pages. When changing routes used by settings, certificates, profile, conversion, CSR, or Sectigo screens, preserve the `{success, message, ...}` response shape that the frontend scripts already consume.
- Filesystem writes should preserve the current safety pattern: sanitize filenames with `secure_filename`, avoid overwriting by suffixing `_1`, `_2`, etc., and use configurable storage paths before falling back to `UPLOAD_FOLDER`.
- Sectigo downloads use server-side temp files in `/tmp/sectigo_certs` and only store lightweight metadata in the Flask session. Keep large certificate payloads out of session storage.
- CSR generation is intentionally shell-backed: `routes/csr.py` writes a CNF file, invokes `openssl req`, then stores the resulting file paths and SAN list in the database. Changes in this area need to keep the filesystem record and database record in sync.
- Backup scheduling is not fully live-reloaded. The settings route persists schedule changes immediately, but the scheduler job picks them up only after an app restart unless the scheduling code is extended.
