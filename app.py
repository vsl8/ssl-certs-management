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
from routes.csr import csr_bp

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
    app.register_blueprint(csr_bp)

    # Block AJAX/API requests when session is server-side locked
    @app.before_request
    def enforce_session_lock():
        from flask import session as flask_session, request as flask_request, jsonify as flask_jsonify
        from flask_login import current_user as _cu
        skip = {'auth.login', 'auth.logout', 'auth.verify_password', 'auth.lock_session', 'static'}
        if flask_request.endpoint in skip:
            return
        if not _cu.is_authenticated:
            return
        if flask_session.get('session_locked'):
            is_ajax = (
                flask_request.headers.get('X-Requested-With') == 'XMLHttpRequest'
                or flask_request.is_json
                or flask_request.accept_mimetypes.best_match(
                    ['application/json', 'text/html']) == 'application/json'
            )
            if is_ajax:
                return flask_jsonify(
                    {'success': False, 'message': 'Session is locked.', 'locked': True}
                ), 423

    # Make config available in templates
    @app.context_processor
    def inject_config():
        return {'config': app.config}

    # Inject session lock settings into all templates
    @app.context_processor
    def inject_session_settings():
        from models import Setting
        try:
            settings = {s.key: s for s in Setting.query.all()}
            return {'settings': settings}
        except Exception:
            return {'settings': {}}

    # Setup alert scheduler
    _setup_scheduler(app)

    log.info('Application started successfully')

    return app


def _setup_scheduler(app):
    """Setup background scheduler for certificate alert checks and scheduled backups."""
    from notifications import check_and_send_alerts
    from backup_utils import run_scheduled_backup, get_backup_schedule

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
    
    # Scheduled backup job - runs at configured frequency
    with app.app_context():
        schedule = get_backup_schedule()
        
        # Build cron trigger kwargs based on frequency
        cron_kwargs = {
            'hour': schedule['hour'],
            'minute': schedule['minute'],
        }
        
        if schedule['frequency'] == 'weekly':
            # day_of_week: 0=Monday, 6=Sunday (APScheduler uses mon-sun or 0-6)
            cron_kwargs['day_of_week'] = schedule['day_of_week']
        elif schedule['frequency'] == 'monthly':
            cron_kwargs['day'] = schedule['day_of_month']
        # For 'daily', no additional kwargs needed (runs every day)
        
        scheduler.add_job(
            func=run_scheduled_backup,
            trigger='cron',
            args=[app],
            id='scheduled_backup',
            replace_existing=True,
            **cron_kwargs
        )
    scheduler.start()

    # Register shutdown
    import atexit
    atexit.register(lambda: scheduler.shutdown(wait=False))


app = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
