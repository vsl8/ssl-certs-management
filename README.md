# SSL Certificate Manager

A modern Flask-based web application for managing, monitoring, and converting SSL/TLS certificates with automated expiry alerts.

![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.x-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## Features

- **Dashboard** - Overview of all certificates with expiry status and statistics
- **Certificate Management** - Upload, view, edit, download, and delete certificates
- **Certificate Parsing** - Automatically extracts certificate details (CN, SAN, issuer, validity, fingerprints)
- **Format Conversion** - Convert between PEM, DER, CRT, CER, PFX/P12, P7B, and KEY formats
- **CSR Generation** - Create Certificate Signing Requests (CSR) with customizable parameters and templates
- **Sectigo/InCommon Integration** - Download and manage certificates from Sectigo/InCommon
- **Expiry Alerts** - Configurable alert rules with multiple notification channels
- **Notifications** - Email (SMTP), Slack, Microsoft Teams, and generic Webhook support
- **Certificate Backup & Restore** - Automated and manual backups of certificates and database
- **Authentication** - Secure login with password hashing
- **Logging** - Configurable logging with file rotation and runtime configuration
- **Docker Ready** - Production-ready Docker and Docker Compose setup

## Supported Certificate Formats

| Format | Extensions | Description |
|--------|------------|-------------|
| PEM | `.pem` | Base64 encoded, most common format |
| DER | `.der` | Binary format |
| CRT/CER | `.crt`, `.cer` | Certificate files (usually PEM or DER) |
| PFX/P12 | `.pfx`, `.p12` | PKCS#12 archive with certificate and private key |
| P7B | `.p7b` | PKCS#7 certificate chain |
| KEY | `.key` | Private key file |

## Quick Start

### Prerequisites

- Python 3.12 or higher
- [uv](https://docs.astral.sh/uv/) package manager (recommended) or pip

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd ssl-cert-project
   ```

2. **Install dependencies using uv**
   ```bash
   uv sync
   ```
   
   Or using pip:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

4. **Run the application**
   ```bash
   uv run flask run
   # Or for development with auto-reload:
   uv run flask run --debug
   ```

5. **Access the application**
   
   Open http://localhost:5000 in your browser

### Default Credentials

| Username | Password |
|----------|----------|
| `admin` | `Root@123456789` |

> ⚠️ **Important:** Change the default password immediately after first login!

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | Random | Flask secret key (required for production) |
| `DB_TYPE` | `sqlite` | Database type: `sqlite` or `mariadb` |
| `DB_HOST` | `localhost` | MariaDB host |
| `DB_PORT` | `3306` | MariaDB port |
| `DB_NAME` | `certmanager` | MariaDB database name |
| `DB_USER` | `certmanager` | MariaDB username |
| `DB_PASS` | - | MariaDB password |
| `FLASK_ENV` | `production` | Flask environment (`development` or `production`) |
| `LOG_LEVEL` | `INFO` | Default logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `UPLOAD_FOLDER` | `uploads/` | Default certificate upload directory |
| `MAX_CONTENT_LENGTH` | 16MB | Maximum file upload size |

### Database Options

**SQLite (Default)** - No configuration needed. Database is stored in `instance/certmanager.db`

**MariaDB** - Set `DB_TYPE=mariadb` and configure the connection variables in `.env`

## Docker Deployment

### Build and Run

```bash
# Build the image
docker build -t ssl-cert-manager:latest .

# Run with Docker Compose
docker-compose up -d
```

### Docker Compose Configuration

The default `docker-compose.yaml` includes:

- Application container with Gunicorn (2 workers)
- Volume mounts for data persistence:
  - `certmanager_data` → `/app/instance` (SQLite database)
  - `certmanager_logs` → `/app/logs` (Log files)
  - `/etc/pki/tls/certs` → Certificate storage
  - `/etc/pki/tls/backup` → Backup storage
- Health checks
- Optional MariaDB service (uncomment to use)

### Using MariaDB with Docker

1. Uncomment the MariaDB service in `docker-compose.yaml`
2. Set the following in your `.env` file:
   ```env
   DB_TYPE=mariadb
   DB_HOST=mariadb
   DB_PORT=3306
   DB_NAME=certmanager
   DB_USER=certmanager
   DB_PASS=your-secure-password
   ```

## Project Structure

```
ssl-cert-project/
├── app.py                      # Application factory and scheduler setup
├── config.py                   # Configuration settings
├── models.py                   # SQLAlchemy database models and bootstrap
├── cert_utils.py               # Certificate parsing and manipulation utilities
├── conversion_utils.py         # Format conversion functions (PEM, DER, PFX, etc.)
├── sectigo_utils.py            # Sectigo/InCommon integration utilities
├── backup_utils.py             # Backup and restore utilities
├── notifications.py            # Alert notification system (Email, Slack, Teams, Webhooks)
├── logger.py                   # Centralized logging configuration
├── routes/
│   ├── auth.py                 # Authentication and user management
│   ├── dashboard.py            # Dashboard and overview
│   ├── certificates.py         # Certificate CRUD and Sectigo operations
│   ├── settings.py             # Settings, alerts, notifications, backups
│   ├── conversion.py           # Format conversion
│   ├── csr.py                  # CSR generation and templates
│   └── __init__.py             # Blueprint registration
├── templates/                  # Jinja2 HTML templates
│   ├── base.html               # Base template with navigation
│   ├── auth/                   # Authentication templates
│   ├── certificates/           # Certificate management templates
│   ├── settings/               # Settings templates (alerts, backups, etc.)
│   ├── csr/                    # CSR generation templates
│   ├── conversion/             # Format conversion template
│   └── dashboard.html          # Dashboard template
├── static/                     # CSS, JavaScript, images
├── migrations/                 # Database migration scripts
├── instance/                   # Instance-specific files (SQLite database, auto-created)
├── uploads/                    # Uploaded certificate files storage
├── logs/                       # Application logs
├── graphify-out/               # Knowledge graph outputs (auto-generated)
├── .github/                    # GitHub configuration
├── Dockerfile                  # Docker container definition
├── docker-compose.yaml         # Docker Compose multi-container setup
├── pyproject.toml              # Python dependencies and project metadata (uv)
├── requirements.txt            # Python dependencies (pip)
├── .env.example                # Example environment variables
├── CLAUDE.md                   # AI assistant instructions
├── AGENTS.md                   # Agent integration guide
└── README.md                   # This file
```

## Architecture & Knowledge Graph

This project includes a built-in knowledge graph for architectural analysis:

- **Graph Location:** `graphify-out/graph.json` (auto-generated)
- **Visualizations:**
  - `graphify-out/graph.html` — Interactive architectural graph
  - `graphify-out/ssl-certs-management-callflow.html` — Call-flow diagrams by module
- **Query Tools:**
  - `graphify query "<question>"` — Ask architectural questions
  - `graphify path "<A>" "<B>"` — Find relationships between components
  - `graphify explain "<concept>"` — Get explanations of key functions

**Key Components (God Nodes):**
- `get_logger()` — Centralized logging (14+ connections)
- `Setting` — Runtime configuration hub (12+ connections)
- `check_and_send_alerts()` — Background alert job (10+ connections)
- `refresh_cert_expiry()` — Expiry calculation (9+ connections)

## Features Guide

### Certificate Management

1. **Add Certificates** - Upload certificate files or paste PEM content directly
2. **View Details** - See all parsed certificate information including SAN domains
3. **Edit Metadata** - Add notes and tags to organize certificates
4. **Download** - Download the original certificate file
5. **Delete** - Remove certificates with optional file deletion

### Alert System

The application checks for expiring certificates every 60 minutes and sends notifications based on configured rules.

**Setting up alerts:**

1. Go to **Settings → Notification Channels**
2. Add a notification channel (Email, Slack, Teams, or Webhook)
3. Go to **Settings → Alert Rules**
4. Create rules specifying days before expiry and notification channel

### Certificate Conversion

Navigate to **Conversion** to convert certificates between formats:

- PEM ↔ DER, CRT, CER, PFX
- PFX/P12 → PEM, CRT, DER, KEY (extract private key)
- P7B → PEM, CRT, DER
- KEY → PEM, DER

### CSR Generation

Create Certificate Signing Requests (CSR) for obtaining new certificates from Certificate Authorities.

**Key Features:**

1. **CSR Templates** - Save and reuse common CSR configurations
2. **Flexible Configuration** - Customize all CSR parameters (CN, organization, country, etc.)
3. **SAN Support** - Add Subject Alternative Names (SANs) to CSRs
4. **Key Management** - Specify key size (2048, 4096) and algorithm
5. **File Management** - Download CSRs and private keys, manage existing requests

**Using CSR Generation:**

1. Go to **CSR → Templates** to create reusable configurations
2. Click **Generate CSR** and select or create a template
3. Review and customize parameters as needed
4. Download the CSR and private key (keep the private key secure!)
5. Submit the CSR to your Certificate Authority

**Important:** Private keys are generated and stored locally. Never share your private key with anyone.

### Sectigo/InCommon Integration

Download and manage certificates issued by Sectigo/InCommon directly within the application.

**Features:**

1. **Direct Download** - Fetch certificates from Sectigo/InCommon using SSL ID
2. **Certificate Chain** - Automatically combines root and intermediate certificates
3. **DNS Validation** - Extract DNS names from downloaded certificates
4. **Session Management** - Handles temporary certificate files securely

**Using Sectigo Download:**

1. Go to **Certificates → Sectigo Download**
2. Enter your Sectigo SSL ID
3. Click **Download Certificate**
4. Review the downloaded certificate
5. Save to your certificate store or download for use

### Backup & Restore

The application provides built-in backup functionality for certificates and database.

**Creating Backups:**

1. Go to **Settings → Backup**
2. Click **Backup Certificates** to create a ZIP archive of all certificate files
3. Click **Backup Database** to export the database in SQL format (MySQL/MariaDB compatible)

**Backup Features:**

| Feature | Description |
|---------|-------------|
| **Certificate Backup** | ZIP file containing all certificate files with a manifest |
| **Database Backup** | SQL file compatible with MySQL/MariaDB for easy import |
| **Auto-Retention** | Only the last 5 backups per type are kept; older ones are automatically deleted |
| **Timestamped Files** | Backup filenames include date/time (e.g., `certs_backup_2026-04-27_14-30-00.zip`) |
| **Download/Delete** | Download or delete individual backups from the UI |

**Backup Location:** `/etc/pki/tls/backup` (configurable)

**Restoring Database:**

To restore a database backup to MySQL/MariaDB:
```bash
mysql -u username -p database_name < db_backup_YYYY-MM-DD_HH-MM-SS.sql
```

### Notification Channels

| Channel | Configuration |
|---------|---------------|
| **Email** | SMTP server, port, credentials, TLS, from/to addresses |
| **Slack** | Webhook URL |
| **Microsoft Teams** | Webhook URL |
| **Webhook** | Custom URL for HTTP POST notifications |

## Logging

Logs are written to `logs/certmanager.log` with daily rotation.

Configure logging in **Settings → General**:
- Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
- Log file path

## Production Deployment

### Security Checklist

- [ ] Generate a strong `SECRET_KEY`
- [ ] Change the default admin password
- [ ] Use HTTPS (configure a reverse proxy like Nginx)
- [ ] Restrict network access to the application
- [ ] Use MariaDB for production workloads
- [ ] Regular database backups

### Reverse Proxy (Nginx Example)

```nginx
server {
    listen 443 ssl;
    server_name certs.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Background Jobs & Scheduling

The application uses **APScheduler** to manage background tasks:

### Hourly Alert Check
- Runs every 60 minutes automatically
- Checks for expiring certificates against configured alert rules
- Sends notifications to configured channels (Email, Slack, Teams, Webhook)
- Updates `AlertLog` with check results

### Scheduled Backups
- Configured in **Settings → Backup**
- Runs at the scheduled time to automatically backup certificates
- Creates timestamped ZIP and SQL backup files
- Automatically cleans up backups older than 5 (configurable)

**Important:** Background jobs are registered at application startup. Changes to backup schedules in the UI take effect immediately for new triggers, but job list is refreshed on app restart.

## Development

### Running in Development Mode

```bash
uv run flask run --debug
```

### Running Tests

```bash
uv run pytest
```

### Code Style

The project follows PEP 8 style guidelines.

## Troubleshooting

### Common Issues

**Database errors on startup**
- Ensure the `instance/` directory exists and is writable
- For MariaDB, verify connection settings in `.env`
- Check that the database user has CREATE/ALTER table privileges

**Certificate parsing fails**
- Check if the file is a valid certificate format
- For PFX/P12 files, ensure the correct password is provided
- Try uploading to the Conversion tool to debug format issues

**Notifications not sending**
- Verify notification channel configuration in **Settings → Notification Channels**
- Click "Test" button to validate channel settings
- Check application logs (`logs/certmanager.log`) for error messages
- For SMTP: verify server, port, authentication, and TLS settings
- For Slack/Teams/Webhook: verify URL is accessible and correct format

**Background jobs not running (alerts/backups)**
- Check that APScheduler is initialized properly
- Verify the application hasn't exited unexpectedly
- In development, run with `uv run flask run` (not via import)
- Check logs for job execution errors
- Restart the application to re-register jobs

**CSR generation fails**
- Ensure `openssl` is installed and accessible: `which openssl`
- Check CSR storage directory (`csr_storage_path`) exists and is writable
- For Windows, use WSL or Docker container

**Sectigo download issues**
- Verify SSL ID format and validity
- Check internet connectivity to Sectigo servers
- Ensure temporary directory `/tmp/sectigo_certs` is writable
- Check application logs for validation errors

**Login issues**
- Default credentials: `admin` / `Root@123456789`
- If locked out (SQLite): delete `instance/certmanager.db` to reset (loses all data)
- For MariaDB: manually delete the user from database
- Verify `SECRET_KEY` is consistent across restarts

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
