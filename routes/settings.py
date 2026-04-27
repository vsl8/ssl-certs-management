"""Settings, Alert Rules, and Notification Channel routes."""

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required
from models import db, Setting, AlertRule, NotificationChannel
from notifications import send_test_notification
from logger import get_logger, reconfigure_logging

log = get_logger('settings')
settings_bp = Blueprint('settings', __name__, url_prefix='/settings')


# ─── General Settings ───

@settings_bp.route('/')
@login_required
def general():
    """General settings page."""
    settings = {s.key: s for s in Setting.query.all()}
    return render_template('settings/general.html', settings=settings)


@settings_bp.route('/save', methods=['POST'])
@login_required
def save_settings():
    """Save general settings."""
    data = request.form.to_dict()
    for key, value in data.items():
        setting = Setting.query.filter_by(key=key).first()
        if setting:
            setting.value = value
        else:
            db.session.add(Setting(key=key, value=value))
    db.session.commit()

    log.info('Settings saved: %s', list(data.keys()))

    # Reconfigure logging if log settings changed
    new_log_dir = data.get('log_file_path')
    new_log_level = data.get('log_level')
    if new_log_dir or new_log_level:
        ok, msg = reconfigure_logging(log_dir=new_log_dir, log_level_name=new_log_level)
        if not ok:
            log.warning('Failed to reconfigure logging: %s', msg)
            return jsonify({'success': True, 'message': f'Settings saved, but logging update failed: {msg}'})
        log.info('Logging reconfigured: dir=%s level=%s', new_log_dir, new_log_level)

    return jsonify({'success': True, 'message': 'Settings saved successfully!'})


# ─── Alert Rules ───

@settings_bp.route('/alerts')
@login_required
def alerts():
    """Alert rules configuration page."""
    rules = AlertRule.query.order_by(AlertRule.days_before_expiry.desc()).all()
    channels = NotificationChannel.query.filter_by(is_enabled=True).all()
    return render_template('settings/alerts.html', rules=rules, channels=channels)


@settings_bp.route('/alerts/save', methods=['POST'])
@login_required
def save_alert():
    """Add or update an alert rule."""
    rule_id = request.form.get('rule_id')
    name = request.form.get('name', '').strip()
    days = request.form.get('days_before_expiry', type=int)
    is_enabled = request.form.get('is_enabled') == 'on'
    channel_id = request.form.get('notification_channel_id', type=int)

    if not name or not days:
        return jsonify({'success': False, 'message': 'Name and days are required.'}), 400

    if rule_id:
        rule = AlertRule.query.get_or_404(int(rule_id))
        rule.name = name
        rule.days_before_expiry = days
        rule.is_enabled = is_enabled
        rule.notification_channel_id = channel_id if channel_id else None
    else:
        rule = AlertRule(
            name=name,
            days_before_expiry=days,
            is_enabled=is_enabled,
            notification_channel_id=channel_id if channel_id else None,
        )
        db.session.add(rule)

    db.session.commit()
    return jsonify({'success': True, 'message': 'Alert rule saved successfully!'})


@settings_bp.route('/alerts/delete/<int:rule_id>', methods=['POST'])
@login_required
def delete_alert(rule_id):
    """Delete an alert rule."""
    rule = AlertRule.query.get_or_404(rule_id)
    db.session.delete(rule)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Alert rule deleted successfully!'})


@settings_bp.route('/alerts/toggle/<int:rule_id>', methods=['POST'])
@login_required
def toggle_alert(rule_id):
    """Toggle an alert rule on/off."""
    rule = AlertRule.query.get_or_404(rule_id)
    rule.is_enabled = not rule.is_enabled
    db.session.commit()
    return jsonify({
        'success': True,
        'message': f'Alert rule {"enabled" if rule.is_enabled else "disabled"} successfully!',
        'is_enabled': rule.is_enabled,
    })


# ─── Notification Channels ───

@settings_bp.route('/notifications')
@login_required
def notifications():
    """Notification channels page."""
    channels = NotificationChannel.query.order_by(NotificationChannel.created_at.desc()).all()
    return render_template('settings/notifications.html', channels=channels)


@settings_bp.route('/notifications/save', methods=['POST'])
@login_required
def save_notification():
    """Add or update a notification channel."""
    channel_id = request.form.get('channel_id')
    channel_type = request.form.get('channel_type', '').strip()
    name = request.form.get('name', '').strip()

    if not name or not channel_type:
        return jsonify({'success': False, 'message': 'Name and channel type are required.'}), 400

    if channel_id:
        channel = NotificationChannel.query.get_or_404(int(channel_id))
    else:
        channel = NotificationChannel()
        db.session.add(channel)

    channel.name = name
    channel.channel_type = channel_type
    channel.is_enabled = request.form.get('is_enabled') == 'on'
    channel.is_default = request.form.get('is_default') == 'on'

    # Email settings
    if channel_type == 'email':
        channel.smtp_host = request.form.get('smtp_host', '').strip()
        channel.smtp_port = request.form.get('smtp_port', type=int)
        channel.smtp_username = request.form.get('smtp_username', '').strip()
        if request.form.get('smtp_password', '').strip():
            channel.smtp_password = request.form.get('smtp_password', '').strip()
        channel.smtp_use_tls = request.form.get('smtp_use_tls') == 'on'
        channel.smtp_from_email = request.form.get('smtp_from_email', '').strip()
        channel.smtp_to_emails = request.form.get('smtp_to_emails', '').strip()

    # Slack settings
    elif channel_type == 'slack':
        channel.slack_webhook_url = request.form.get('slack_webhook_url', '').strip()
        channel.slack_channel = request.form.get('slack_channel', '').strip()

    # Teams settings
    elif channel_type == 'teams':
        channel.teams_webhook_url = request.form.get('teams_webhook_url', '').strip()

    # Webhook settings
    elif channel_type == 'webhook':
        channel.webhook_url = request.form.get('webhook_url', '').strip()
        channel.webhook_method = request.form.get('webhook_method', 'POST').strip()
        channel.webhook_headers = request.form.get('webhook_headers', '').strip()

    db.session.commit()
    return jsonify({'success': True, 'message': f'Notification channel "{name}" saved successfully!'})


@settings_bp.route('/notifications/delete/<int:channel_id>', methods=['POST'])
@login_required
def delete_notification(channel_id):
    """Delete a notification channel."""
    channel = NotificationChannel.query.get_or_404(channel_id)
    db.session.delete(channel)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Notification channel deleted successfully!'})


@settings_bp.route('/notifications/test/<int:channel_id>', methods=['POST'])
@login_required
def test_notification(channel_id):
    """Send a test notification."""
    channel = NotificationChannel.query.get_or_404(channel_id)
    result = send_test_notification(channel)
    return jsonify(result)


@settings_bp.route('/notifications/test-smtp', methods=['POST'])
@login_required
def test_smtp():
    """Test SMTP settings without saving the channel first."""
    from notifications import test_smtp_connection
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400

    result = test_smtp_connection(
        smtp_host=data.get('smtp_host', ''),
        smtp_port=int(data.get('smtp_port', 587)),
        smtp_username=data.get('smtp_username', ''),
        smtp_password=data.get('smtp_password', ''),
        smtp_use_tls=data.get('smtp_use_tls', True),
        smtp_from_email=data.get('smtp_from_email', ''),
        smtp_to_emails=data.get('smtp_to_emails', '')
    )
    return jsonify(result)


# ─── Backup Management ───

@settings_bp.route('/backup')
@login_required
def backup():
    """Backup management page."""
    from backup_utils import list_backups, get_backup_path, get_backup_schedule
    backups = list_backups()
    schedule = get_backup_schedule()
    return render_template('settings/backup.html', backups=backups, schedule=schedule)


@settings_bp.route('/backup/schedule', methods=['POST'])
@login_required
def save_backup_schedule():
    """Save backup schedule settings."""
    data = request.form.to_dict()
    
    # Update schedule settings
    schedule_settings = {
        'backup_schedule_enabled': data.get('backup_schedule_enabled', 'false'),
        'backup_schedule_time': data.get('backup_schedule_time', '02:00'),
        'backup_schedule_type': data.get('backup_schedule_type', 'both'),
        'backup_schedule_frequency': data.get('backup_schedule_frequency', 'daily'),
        'backup_schedule_day_of_week': data.get('backup_schedule_day_of_week', '0'),
        'backup_schedule_day_of_month': data.get('backup_schedule_day_of_month', '1'),
    }
    
    for key, value in schedule_settings.items():
        setting = Setting.query.filter_by(key=key).first()
        if setting:
            setting.value = value
        else:
            db.session.add(Setting(key=key, value=value))
    
    db.session.commit()
    
    log.info('Backup schedule updated: enabled=%s, frequency=%s, time=%s, type=%s', 
             schedule_settings['backup_schedule_enabled'],
             schedule_settings['backup_schedule_frequency'],
             schedule_settings['backup_schedule_time'],
             schedule_settings['backup_schedule_type'])
    
    # Note: The scheduler job will pick up the new settings on the next run,
    # but if the user wants immediate effect, they need to restart the app.
    # For production, you could reschedule the job here.
    
    return jsonify({
        'success': True, 
        'message': 'Backup schedule saved successfully! Changes will take effect after app restart.'
    })


@settings_bp.route('/backup/certs', methods=['POST'])
@login_required
def backup_certs():
    """Create a certificate backup."""
    from backup_utils import backup_certificates
    result = backup_certificates()
    return jsonify(result)


@settings_bp.route('/backup/db', methods=['POST'])
@login_required
def backup_db():
    """Create a database backup."""
    from backup_utils import backup_database
    result = backup_database()
    return jsonify(result)


@settings_bp.route('/backup/download/<filename>')
@login_required
def download_backup(filename):
    """Download a backup file."""
    from flask import send_file
    from backup_utils import get_backup_path
    import os
    
    backup_path = get_backup_path()
    file_path = os.path.join(backup_path, filename)
    
    # Security check
    if not os.path.abspath(file_path).startswith(os.path.abspath(backup_path)):
        return jsonify({'success': False, 'message': 'Invalid file path.'}), 400
    
    if not os.path.exists(file_path):
        return jsonify({'success': False, 'message': 'Backup file not found.'}), 404
    
    if not (filename.startswith('certs_backup_') or filename.startswith('db_backup_')):
        return jsonify({'success': False, 'message': 'Invalid backup file.'}), 400
    
    return send_file(file_path, as_attachment=True, download_name=filename)


@settings_bp.route('/backup/delete/<filename>', methods=['POST'])
@login_required
def delete_backup(filename):
    """Delete a backup file."""
    from backup_utils import delete_backup as delete_backup_file
    result = delete_backup_file(filename)
    return jsonify(result)
