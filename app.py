"""
SSL Certificate Manager Application
A Flask-based web application for managing SSL/TLS certificates.
"""

import os
from flask import Flask
from flask_login import LoginManager
from apscheduler.schedulers.background import BackgroundScheduler

from config import Config
from models import init_db, User
from logger import setup_logging, get_logger
from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from routes.certificates import certificates_bp
from routes.settings import settings_bp
from routes.conversion import conversion_bp

log = get_logger('app')

# Flask-Login manager
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'


@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login."""
    return User.query.get(int(user_id))


def create_app():
    """Application factory."""
    app = Flask(__name__)
    app.config.from_object(Config)

    # Ensure required directories exist
    os.makedirs(app.config.get('UPLOAD_FOLDER', 'uploads'), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), 'instance'), exist_ok=True)

    # Initialize database
    init_db(app)

    # Initialize Flask-Login
    login_manager.init_app(app)

    # Setup logging (after DB so it can read persisted settings)
    with app.app_context():
        setup_logging(app)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(certificates_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(conversion_bp)

    # Make config available in templates
    @app.context_processor
    def inject_config():
        return {'config': app.config}

    # Setup alert scheduler
    _setup_scheduler(app)

    log.info('Application started successfully')

    return app


def _setup_scheduler(app):
    """Setup background scheduler for certificate alert checks."""
    from notifications import check_and_send_alerts

    scheduler = BackgroundScheduler(daemon=True)

    # Default: check every 60 minutes
    scheduler.add_job(
        func=check_and_send_alerts,
        trigger='interval',
        minutes=60,
        args=[app],
        id='cert_alert_check',
        replace_existing=True,
    )
    scheduler.start()

    # Register shutdown
    import atexit
    atexit.register(lambda: scheduler.shutdown(wait=False))


app = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
