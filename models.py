import os
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone

db = SQLAlchemy()


class User(UserMixin, db.Model):
    """User model for authentication."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(256), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        """Hash and set the user's password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check if the provided password matches the hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class Certificate(db.Model):
    __tablename__ = 'certificates'

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(512), nullable=False)
    file_type = db.Column(db.String(20), nullable=False)  # pem, crt, cer, pfx, p12, der, key
    file_path = db.Column(db.String(1024), nullable=False)
    file_size = db.Column(db.Integer, default=0)

    # Certificate details
    common_name = db.Column(db.String(512), nullable=True)
    organization = db.Column(db.String(512), nullable=True)
    organizational_unit = db.Column(db.String(512), nullable=True)
    country = db.Column(db.String(10), nullable=True)
    state = db.Column(db.String(256), nullable=True)
    locality = db.Column(db.String(256), nullable=True)
    email = db.Column(db.String(256), nullable=True)

    # Issuer details
    issuer_common_name = db.Column(db.String(512), nullable=True)
    issuer_organization = db.Column(db.String(512), nullable=True)
    issuer_country = db.Column(db.String(10), nullable=True)

    # Validity
    valid_from = db.Column(db.DateTime, nullable=True)
    valid_until = db.Column(db.DateTime, nullable=True)

    # Technical details
    serial_number = db.Column(db.String(256), nullable=True)
    signature_algorithm = db.Column(db.String(128), nullable=True)
    key_size = db.Column(db.Integer, nullable=True)
    version = db.Column(db.Integer, nullable=True)
    is_ca = db.Column(db.Boolean, default=False)
    fingerprint_sha256 = db.Column(db.String(128), nullable=True)
    fingerprint_sha1 = db.Column(db.String(64), nullable=True)

    # SAN (Subject Alternative Names)
    san_domains = db.Column(db.Text, nullable=True)  # JSON list of domains

    # Status
    is_expired = db.Column(db.Boolean, default=False)
    days_until_expiry = db.Column(db.Integer, nullable=True)

    # Metadata
    notes = db.Column(db.Text, nullable=True)
    tags = db.Column(db.String(512), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    alert_logs = db.relationship('AlertLog', backref='certificate', lazy=True,
                                 cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Certificate {self.common_name}>'

    @property
    def status(self):
        if self.is_expired or (self.days_until_expiry is not None and self.days_until_expiry <= 0):
            return 'expired'
        elif self.days_until_expiry is not None and self.days_until_expiry <= 7:
            return 'critical'
        elif self.days_until_expiry is not None and self.days_until_expiry <= 15:
            return 'warning'
        elif self.days_until_expiry is not None and self.days_until_expiry <= 30:
            return 'attention'
        return 'healthy'


class AlertRule(db.Model):
    __tablename__ = 'alert_rules'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False)
    days_before_expiry = db.Column(db.Integer, nullable=False)  # e.g. 30, 15, 7, 3, 1
    is_enabled = db.Column(db.Boolean, default=True)
    notification_channel_id = db.Column(db.Integer, db.ForeignKey('notification_channels.id'),
                                        nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    notification_channel = db.relationship('NotificationChannel', backref='alert_rules')
    alert_logs = db.relationship('AlertLog', backref='alert_rule', lazy=True,
                                 cascade='all, delete-orphan')

    def __repr__(self):
        return f'<AlertRule {self.name} - {self.days_before_expiry} days>'


class NotificationChannel(db.Model):
    __tablename__ = 'notification_channels'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False)
    channel_type = db.Column(db.String(50), nullable=False)  # email, slack, teams, webhook
    is_enabled = db.Column(db.Boolean, default=True)
    is_default = db.Column(db.Boolean, default=False)

    # Email settings
    smtp_host = db.Column(db.String(256), nullable=True)
    smtp_port = db.Column(db.Integer, nullable=True)
    smtp_username = db.Column(db.String(256), nullable=True)
    smtp_password = db.Column(db.String(512), nullable=True)
    smtp_use_tls = db.Column(db.Boolean, default=True)
    smtp_from_email = db.Column(db.String(256), nullable=True)
    smtp_to_emails = db.Column(db.Text, nullable=True)  # comma-separated

    # Slack settings
    slack_webhook_url = db.Column(db.String(1024), nullable=True)
    slack_channel = db.Column(db.String(256), nullable=True)

    # Teams settings
    teams_webhook_url = db.Column(db.String(1024), nullable=True)

    # Generic webhook
    webhook_url = db.Column(db.String(1024), nullable=True)
    webhook_method = db.Column(db.String(10), default='POST')
    webhook_headers = db.Column(db.Text, nullable=True)  # JSON headers

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<NotificationChannel {self.name} ({self.channel_type})>'


class AlertLog(db.Model):
    __tablename__ = 'alert_logs'

    id = db.Column(db.Integer, primary_key=True)
    certificate_id = db.Column(db.Integer, db.ForeignKey('certificates.id'), nullable=False)
    alert_rule_id = db.Column(db.Integer, db.ForeignKey('alert_rules.id'), nullable=True)
    channel_type = db.Column(db.String(50), nullable=True)
    message = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='sent')  # sent, failed
    error_message = db.Column(db.Text, nullable=True)
    sent_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<AlertLog cert={self.certificate_id} status={self.status}>'


class Setting(db.Model):
    __tablename__ = 'settings'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(256), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)
    description = db.Column(db.String(512), nullable=True)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<Setting {self.key}={self.value}>'


class CSRConfig(db.Model):
    """CSR Configuration template model."""
    __tablename__ = 'csr_configs'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False)
    file_path = db.Column(db.String(1024), nullable=False)
    
    # Template fields (stored for quick reference)
    country = db.Column(db.String(10), nullable=True)
    state = db.Column(db.String(256), nullable=True)
    locality = db.Column(db.String(256), nullable=True)
    organization = db.Column(db.String(512), nullable=True)
    organizational_unit = db.Column(db.String(512), nullable=True)
    email = db.Column(db.String(256), nullable=True)
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<CSRConfig {self.name}>'


class CSRRequest(db.Model):
    """CSR Request model to track generated CSRs."""
    __tablename__ = 'csr_requests'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False)
    csr_file_path = db.Column(db.String(1024), nullable=False)
    config_file_path = db.Column(db.String(1024), nullable=True)
    key_file_path = db.Column(db.String(1024), nullable=True)
    
    # CSR details
    common_name = db.Column(db.String(512), nullable=True)
    san_domains = db.Column(db.Text, nullable=True)  # JSON list of SAN domains
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<CSRRequest {self.name}>'


def init_db(app):
    """Initialize database and create tables."""
    db.init_app(app)
    with app.app_context():
        db.create_all()
        _seed_defaults()


def _seed_defaults():
    """Seed default settings and alert rules if they don't exist."""
    from datetime import datetime
    current_year = datetime.now().year
    
    # Default settings
    defaults = {
        'cert_storage_path': ('/etc/pki/tls/certs', 'Default certificate storage path'),
        'app_name': ('SSL Cert Manager', 'Application display name'),
        'alert_check_interval': ('60', 'Alert check interval in minutes'),
        'auto_refresh_expiry': ('true', 'Automatically refresh certificate expiry data'),
        'log_file_path': (os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs'), 'Directory where log files are stored'),
        'log_level': ('INFO', 'Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)'),
        'csr_storage_path': (f'/etc/pki/tls/csr_{current_year}', 'CSR and config files storage path'),
        'csr_default_key_path': ('/etc/pki/tls/private', 'Default path for private keys used in CSR generation'),
    }
    for key, (value, desc) in defaults.items():
        if not Setting.query.filter_by(key=key).first():
            db.session.add(Setting(key=key, value=value, description=desc))

    # Default alert rules
    default_rules = [
        ('30 Days Warning', 30),
        ('15 Days Warning', 15),
        ('7 Days Critical', 7),
        ('3 Days Urgent', 3),
        ('1 Day Emergency', 1),
    ]
    for name, days in default_rules:
        if not AlertRule.query.filter_by(days_before_expiry=days).first():
            db.session.add(AlertRule(name=name, days_before_expiry=days, is_enabled=True))

    # Default admin user
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@localhost')
        admin.set_password('Root@123456789')
        db.session.add(admin)

    db.session.commit()
