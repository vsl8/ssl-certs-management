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
- **Expiry Alerts** - Configurable alert rules with multiple notification channels
- **Notifications** - Email (SMTP), Slack, Microsoft Teams, and generic Webhook support
- **Authentication** - Secure login with password hashing
- **Logging** - Configurable logging with file rotation
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
├── app.py                 # Application factory and scheduler
├── config.py              # Configuration settings
├── models.py              # SQLAlchemy database models
├── cert_utils.py          # Certificate parsing utilities
├── conversion_utils.py    # Format conversion functions
├── backup_utils.py        # Backup and restore utilities
├── notifications.py       # Alert notification system
├── logger.py              # Logging configuration
├── routes/
│   ├── auth.py            # Authentication routes
│   ├── dashboard.py       # Dashboard routes
│   ├── certificates.py    # Certificate CRUD routes
│   ├── settings.py        # Settings, alerts, and backup routes
│   └── conversion.py      # Conversion routes
├── templates/             # Jinja2 HTML templates
├── static/                # CSS, JS, images
├── instance/              # SQLite database (auto-created)
├── uploads/               # Uploaded certificate files
├── logs/                  # Application logs
├── Dockerfile             # Docker build configuration
├── docker-compose.yaml    # Docker Compose setup
├── pyproject.toml         # Python dependencies (uv)
└── requirements.txt       # Python dependencies (pip)
```

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

**Certificate parsing fails**
- Check if the file is a valid certificate format
- For PFX/P12 files, ensure the correct password is provided

**Notifications not sending**
- Verify notification channel configuration
- Check logs for error messages
- Use the "Test" button to validate settings

**Login issues**
- Default credentials: `admin` / `Root@123456789`
- If locked out, delete `instance/certmanager.db` to reset (loses all data)

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
