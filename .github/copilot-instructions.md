# SSL Certificate Manager — Copilot Instructions

## Build, test, and run commands

- **Install dependencies:** `uv sync` (primary workflow; `requirements.txt` kept for reference)
- **Run locally:** `uv run flask run` or `uv run flask run --debug` (auto-reload)
- **Build Docker image:** `docker build -t ssl-cert-manager:latest .`
- **Run containerized:** `docker compose up -d`
- **Tests:** No test suite currently configured. If tests are added: `uv run pytest path/to/test_file.py` (single file) or `uv run pytest path/to/test_file.py -k test_name` (single test)
- **Linting:** No lint command configured in the repository

## High-level architecture

### Application structure
- **`app.py`** — Application factory. Loads `Config`, initializes SQLAlchemy via `init_db(app)`, wires Flask-Login, sets up logging after the database is ready, registers all blueprints, injects config/settings into templates, and starts APScheduler jobs.
- **`models.py`** — Both schema and bootstrap layer. `init_db()` creates tables; `_seed_defaults()` seeds default admin user, alert rules, and settings rows that the app depends on.
- **Hybrid rendering:** Server-rendered Flask UI (templates/) with JSON endpoints mixed into the same blueprints. Frontend uses `fetch()`/jQuery AJAX calls expecting `{success, message, ...}` payloads, not redirects.

### Route modules (routes/)
- **`auth.py`** — Login/logout, password changes, profile updates, session management
- **`dashboard.py`** — Summary stats, certificate expiry views, bulk operations
- **`certificates.py`** — Core CRUD for certificates; includes Sectigo download flows
- **`settings.py`** — Runtime configuration (alert rules, notification channels, backup schedules, storage paths)
- **`conversion.py`** — Format conversion (PEM, DER, PFX/P12, P7B, etc.)
- **`csr.py`** — CSR template management and CSR generation via `openssl`

All routes directly orchestrate database writes and filesystem operations — there is no separate service layer.

### Core domain logic (utility modules)
- **`cert_utils.py`** — Certificate parsing (subject, issuer, SANs, expiry, fingerprints), metadata extraction, expiry refresh
- **`conversion_utils.py`** — Cross-format conversion (PEM ↔ DER ↔ PFX/P12 ↔ PKCS7, etc.)
- **`sectigo_utils.py`** — Sectigo/InCommon download, certificate chain combining, SSL ID validation
- **`notifications.py`** — Alert rule selection, multi-channel delivery (SMTP, Slack, Teams, webhooks)
- **`backup_utils.py`** — ZIP-based certificate backups, SQL database export, backup scheduling, cleanup
- **`logger.py`** — Centralized logging setup and runtime log reconfiguration

### Persistence model
- **Database:** Metadata (Certificate, User, Setting, AlertRule, AlertLog, CSRRequest, NotificationChannel) via SQLAlchemy
- **Filesystem:** Certificate files, generated CSR/CNF files, logs, backups
- **Storage paths:** Runtime-configurable (`cert_storage_path`, `csr_storage_path`, `backup_path`, `log_file_path` in `settings` table). Routes use configured path when it exists, fall back to `UPLOAD_FOLDER`.

### Background behavior
- **APScheduler jobs:** Always adds hourly alert check (`check_and_send_alerts()`); adds scheduled backup job based on `backup_schedule` in settings at startup
- **Startup-driven:** Jobs registered only at app initialization. Schedule changes picked up after restart (not live-reloaded).

## Key repository-specific conventions

### Settings and configuration
- Treat `settings` table as source of truth for mutable application behavior. New runtime options follow the pattern: seed a default in `models._seed_defaults()`, read via `Setting.query.filter_by(key='...')`, and update live subsystems explicitly if change should apply immediately (especially for logging, backup schedule).
- Database type via `DB_TYPE` env var (`sqlite` default, or `mariadb` with connection details). See `config.py` and `.env.example`.

### Logging and debugging
- Centralized logging: modules use `get_logger('<module>')` from `logger.py`. Do not create ad-hoc logging setup in route or utility files.
- Log level and file path are runtime-configurable via `settings` table.

### Expiry and freshness
- Expiry state (`days_until_expiry`) is **lazily refreshed** in request/job flows by calling `refresh_cert_expiry()` and committing before rendering tables or sending alerts.
- **Do not assume `days_until_expiry` is current** unless the relevant flow refreshed it. This is especially important in alert jobs.

### Data storage patterns
- **JSON in text columns:** `Certificate.san_domains`, `CSRRequest.san_domains`, `NotificationChannel.webhook_headers` store JSON in `Text` columns. Existing code manually `json.dumps()`/`json.loads()` with graceful fallbacks for malformed data.
- **UI response format:** JSON endpoints expect `{success: bool, message: str, ...}` shape. Routes used by settings, certificates, profile, conversion, CSR, and Sectigo screens must preserve this contract so frontend scripts work correctly.

### Filesystem operations
- **Filename safety:** Always sanitize with `secure_filename()`, avoid overwrites by suffixing `_1`, `_2`, etc., use configurable storage paths before falling back to `UPLOAD_FOLDER`.
- **Sectigo temp files:** Large certificate payloads live in `/tmp/sectigo_certs` server-side; only lightweight metadata stored in Flask session.

### CSR and openssl integration
- **Shell-backed:** `routes/csr.py` writes a `.cnf` file, invokes `openssl req`, then stores resulting file paths and SAN list in the database.
- **Dual record sync:** Changes here must keep filesystem and database records in sync (e.g., deleting a CSR should clean up both the `.cnf` and the database row).

### Backup scheduling
- **Not fully live-reloaded:** Settings route persists schedule changes immediately, but the APScheduler job picks them up only after app restart. Extend the scheduling code if live reload is needed.

## Configuration and environment

- **Database:** `DB_TYPE=sqlite` (default) or `mariadb` with `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASS`
- **Paths:** Defaults point to `/etc/pki/tls/certs` and `/etc/pki/tls/backup`, but are overridden at runtime via `settings` table
- **Default credentials:** `admin` / `Root@123456789` (seeded in `models._seed_defaults()` — change immediately in production)

## Database migrations

- Migrations live in `migrations/` directory
- Any file named `migrate_*.py` auto-executes on Docker container startup in alphabetical order
- Each migration should be idempotent (safe to run multiple times)
- Fresh installations do not require migrations — schema in `models.py` is already correct
- Migrations are only needed when upgrading existing databases from older versions
- Follow naming: `migrate_<number>_<description>.py`
- See `migrations/README.md` for detailed guidance

## Using the knowledge graph

This project has a built-in knowledge graph at `graphify-out/graph.json` with god nodes, community structure, and cross-file relationships. Use it for architecture questions:

- **For codebase questions:** Run `graphify query "<question>"` (BFS traversal). Example: `graphify query "How does certificate upload work?"` returns the call chain from `add_cert()` → `parse_certificate()` → metadata extraction → database storage.
- **For relationships:** Use `graphify path "<node_a>" "<node_b>"` to find shortest path. Example: `graphify path "add_cert()" "send_alerts()"` shows whether and how uploads trigger alerts.
- **For focused concepts:** Use `graphify explain "<concept>"` for plain-language explanation. Example: `graphify explain "refresh_cert_expiry()"` explains what it does and why it exists.
- **For navigation:** If `graphify-out/wiki/index.md` exists, use it instead of raw source browsing.
- **For broad architecture:** Read `graphify-out/GRAPH_REPORT.md` only when query/path/explain don't surface enough context.
- **Keep it fresh:** After code changes, run `graphify update .` to update the graph (AST-only, no API cost).

## God nodes (architectural hubs)

From the knowledge graph, these are the most-connected abstractions — understand them first when working on related features:

1. **`get_logger()`** — 14 connections: central logging hub across all modules
2. **`Setting`** — 12 connections: runtime configuration model
3. **`User`** — 10 connections: authentication model
4. **`check_and_send_alerts()`** — 10 connections: hourly background job that orchestrates alert logic
5. **`refresh_cert_expiry()`** — 9 connections: lazily updates expiry calculations

## Callflow visualizations

The project includes auto-generated Mermaid call diagrams:
- **`graphify-out/graph.html`** — Interactive graph visualization (open in browser)
- **`graphify-out/ssl-certs-management-callflow.html`** — Call-flow diagrams by module, showing function relationships
- Both are regenerated automatically when code changes (if graphify hooks are installed)
