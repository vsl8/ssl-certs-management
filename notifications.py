"""
Notification system for certificate expiry alerts.
Supports: Email (SMTP), Slack, Microsoft Teams, Generic Webhook.
"""

import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone

import requests

from models import db, Certificate, AlertRule, AlertLog, AlertInstance, NotificationChannel, Setting
from cert_utils import refresh_cert_expiry
from logger import get_logger

logger = get_logger('notifications')


def check_and_send_alerts(app):
    """Main alert check: find expiring certs and send notifications."""
    with app.app_context():
        # Refresh all certificate expiry data
        certs = Certificate.query.filter(Certificate.valid_until.isnot(None)).all()
        for cert in certs:
            refresh_cert_expiry(cert)
        db.session.commit()

        # Clean up any duplicate alert instances FIRST (before sending notifications)
        _cleanup_duplicate_alerts()

        # Auto-resolve alerts for certificates that are no longer expiring
        _auto_resolve_alerts()

        # Get enabled alert rules, sorted by threshold (smallest first)
        rules = AlertRule.query.filter_by(is_enabled=True).order_by(
            AlertRule.days_before_expiry.asc()
        ).all()

        if not rules:
            logger.info("No enabled alert rules found")
            return

        # Process certificates that are expiring
        expiring_certs = Certificate.query.filter(
            Certificate.days_until_expiry.isnot(None),
            Certificate.days_until_expiry > 0,
            Certificate.valid_until.isnot(None),
        ).all()

        for cert in expiring_certs:
            # Find the most appropriate (smallest matching) rule for this certificate
            # A cert expiring in 4 days should only trigger the 7-day rule, not 30, 15, etc.
            applicable_rule = None
            for rule in rules:
                if cert.days_until_expiry <= rule.days_before_expiry:
                    applicable_rule = rule
                    break  # Use the first (smallest) matching threshold
            
            if not applicable_rule:
                # Certificate doesn't match any rule threshold
                # Resolve any existing alerts for this cert
                _resolve_all_cert_alerts(cert.id)
                continue

            # Resolve any OTHER alert instances for this cert with different rules FIRST
            # This prevents duplicate notifications
            _resolve_other_cert_alerts(cert.id, applicable_rule.id)

            # Get or create alert instance for the applicable rule ONLY
            instance = AlertInstance.query.filter_by(
                certificate_id=cert.id,
                alert_rule_id=applicable_rule.id,
            ).filter(
                AlertInstance.state.in_(['firing', 'paused', 'acknowledged'])
            ).first()

            if not instance:
                # Create new alert instance
                instance = AlertInstance(
                    certificate_id=cert.id,
                    alert_rule_id=applicable_rule.id,
                    state='firing',
                )
                db.session.add(instance)
                db.session.commit()
                logger.info(f"New alert instance created for cert {cert.id} ('{cert.common_name or cert.filename}') with rule {applicable_rule.id} ({applicable_rule.days_before_expiry} days)")

            # Skip paused alerts
            if instance.state == 'paused':
                logger.debug(f"Skipping paused alert for cert {cert.id} rule {applicable_rule.id}")
                continue

            # Skip acknowledged alerts (don't send again today)
            if instance.state == 'acknowledged':
                logger.debug(f"Skipping acknowledged alert for cert {cert.id} rule {applicable_rule.id}")
                continue

            # Check if we already sent an alert for this cert + rule today
            today_start = datetime.now(timezone.utc).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            existing_log = AlertLog.query.filter(
                AlertLog.certificate_id == cert.id,
                AlertLog.alert_rule_id == applicable_rule.id,
                AlertLog.sent_at >= today_start,
            ).first()

            if existing_log:
                logger.debug(f"Alert already sent today for cert {cert.id} rule {applicable_rule.id}")
                continue

            # Update instance last fired time
            instance.last_fired_at = datetime.now(timezone.utc)
            db.session.commit()

            # Send to the rule's channel, or all default channels
            channels = []
            if applicable_rule.notification_channel_id:
                ch = NotificationChannel.query.get(applicable_rule.notification_channel_id)
                if ch and ch.is_enabled:
                    channels.append(ch)
            else:
                channels = NotificationChannel.query.filter_by(
                    is_enabled=True, is_default=True
                ).all()

            if not channels:
                logger.warning(f"No notification channels available for cert {cert.id} rule {applicable_rule.id}")
                continue

            logger.info(f"Sending alert for cert {cert.id} ('{cert.common_name or cert.filename}') "
                       f"expires in {cert.days_until_expiry} days, rule: {applicable_rule.name} ({applicable_rule.days_before_expiry}d)")

            for channel in channels:
                _send_notification(cert, applicable_rule, channel)


def _auto_resolve_alerts():
    """Automatically resolve alerts for certificates that are no longer expiring or have been renewed."""
    # Find firing/paused alerts
    active_instances = AlertInstance.query.filter(
        AlertInstance.state.in_(['firing', 'paused', 'acknowledged'])
    ).all()

    for instance in active_instances:
        cert = instance.certificate
        rule = instance.alert_rule

        # Resolve if certificate is now valid beyond the alert threshold
        if not cert or not cert.valid_until:
            continue

        if cert.days_until_expiry is None or cert.days_until_expiry > rule.days_before_expiry:
            instance.state = 'resolved'
            instance.resolved_at = datetime.now(timezone.utc)
            logger.info(f"Auto-resolved alert for cert {cert.id} rule {rule.id}")

    db.session.commit()


def _resolve_other_cert_alerts(cert_id, current_rule_id):
    """
    Resolve all alert instances for a certificate except the current applicable rule.
    This ensures only one alert (the most appropriate threshold) is active per certificate.
    """
    other_instances = AlertInstance.query.filter(
        AlertInstance.certificate_id == cert_id,
        AlertInstance.alert_rule_id != current_rule_id,
        AlertInstance.state.in_(['firing', 'paused', 'acknowledged'])
    ).all()

    for instance in other_instances:
        instance.state = 'resolved'
        instance.resolved_at = datetime.now(timezone.utc)
        logger.info(f"Auto-resolved alert instance {instance.id} for cert {cert_id} rule {instance.alert_rule_id} (superseded by rule {current_rule_id})")

    if other_instances:
        db.session.commit()


def _resolve_all_cert_alerts(cert_id):
    """
    Resolve all alert instances for a certificate.
    Used when a certificate no longer matches any rule threshold.
    """
    instances = AlertInstance.query.filter(
        AlertInstance.certificate_id == cert_id,
        AlertInstance.state.in_(['firing', 'paused', 'acknowledged'])
    ).all()

    for instance in instances:
        instance.state = 'resolved'
        instance.resolved_at = datetime.now(timezone.utc)
        logger.info(f"Auto-resolved alert instance {instance.id} for cert {cert_id} (no longer matches any threshold)")

    if instances:
        db.session.commit()


def _cleanup_duplicate_alerts():
    """
    Clean up duplicate alert instances for the same certificate.
    For each certificate, keep only the alert with the smallest matching threshold active.
    This handles cases where multiple alerts were created before the smart matching logic was implemented.
    """
    from sqlalchemy import func
    
    # Get all certificates with multiple active alert instances
    duplicate_certs = db.session.query(
        AlertInstance.certificate_id,
        func.count(AlertInstance.id).label('count')
    ).filter(
        AlertInstance.state.in_(['firing', 'paused', 'acknowledged'])
    ).group_by(
        AlertInstance.certificate_id
    ).having(
        func.count(AlertInstance.id) > 1
    ).all()
    
    if not duplicate_certs:
        return
    
    logger.info(f"Found {len(duplicate_certs)} certificates with duplicate alert instances, cleaning up...")
    
    # Get enabled rules sorted by threshold (smallest first)
    rules = AlertRule.query.filter_by(is_enabled=True).order_by(
        AlertRule.days_before_expiry.asc()
    ).all()
    
    rule_map = {rule.id: rule for rule in rules}
    
    for cert_id, count in duplicate_certs:
        # Get all active instances for this certificate
        instances = AlertInstance.query.filter(
            AlertInstance.certificate_id == cert_id,
            AlertInstance.state.in_(['firing', 'paused', 'acknowledged'])
        ).all()
        
        if not instances:
            continue
        
        # Get the certificate to check its expiry
        cert = Certificate.query.get(cert_id)
        if not cert or cert.days_until_expiry is None:
            continue
        
        # Find the most appropriate rule for this certificate
        applicable_rule_id = None
        for rule in rules:
            if cert.days_until_expiry <= rule.days_before_expiry:
                applicable_rule_id = rule.id
                break
        
        if not applicable_rule_id:
            # Certificate doesn't match any threshold, resolve all
            for instance in instances:
                instance.state = 'resolved'
                instance.resolved_at = datetime.now(timezone.utc)
            logger.info(f"Resolved {len(instances)} instances for cert {cert_id} (no matching threshold)")
            continue
        
        # Keep the instance matching the applicable rule, resolve others
        kept_instance = None
        for instance in instances:
            if instance.alert_rule_id == applicable_rule_id:
                kept_instance = instance
            else:
                instance.state = 'resolved'
                instance.resolved_at = datetime.now(timezone.utc)
                logger.info(f"Resolved duplicate alert instance {instance.id} for cert {cert_id} "
                          f"(keeping rule {applicable_rule_id}, removed rule {instance.alert_rule_id})")
        
        # If we don't have an instance for the applicable rule, keep the one with the smallest threshold
        if not kept_instance and instances:
            # Sort instances by their rule's threshold
            sorted_instances = sorted(instances, key=lambda i: rule_map.get(i.alert_rule_id).days_before_expiry 
                                     if i.alert_rule_id in rule_map else 999)
            kept_instance = sorted_instances[0]
            kept_instance.state = 'firing'  # Reset to firing if it was paused/acknowledged
            logger.info(f"Kept alert instance {kept_instance.id} for cert {cert_id} with rule {kept_instance.alert_rule_id}")
    
    db.session.commit()
    logger.info("Duplicate alert cleanup completed")


def cleanup_duplicate_alerts():
    """
    Public API to clean up duplicate alert instances.
    For each certificate, keeps only the alert with the smallest matching threshold active.
    Resolves all other duplicate alert instances.
    """
    return _cleanup_duplicate_alerts()


def _send_notification(cert, rule, channel):
    """Send a single notification through a channel."""
    message = _build_message(cert, rule)

    try:
        if channel.channel_type == 'email':
            _send_email(channel, cert, message)
            status = 'sent'
            error = None
        elif channel.channel_type == 'slack':
            _send_slack(channel, cert, message)
            status = 'sent'
            error = None
        elif channel.channel_type == 'teams':
            _send_teams(channel, cert, message)
            status = 'sent'
            error = None
        elif channel.channel_type == 'webhook':
            _send_webhook(channel, cert, message)
            status = 'sent'
            error = None
        else:
            status = 'failed'
            error = f'Unknown channel type: {channel.channel_type}'
    except Exception as e:
        status = 'failed'
        error = str(e)
        logger.error(f"Failed to send alert via {channel.channel_type}: {e}")

    # Log the alert
    log = AlertLog(
        certificate_id=cert.id,
        alert_rule_id=rule.id,
        channel_type=channel.channel_type,
        message=message,
        status=status,
        error_message=error,
    )
    db.session.add(log)
    db.session.commit()


def _build_message(cert, rule):
    """Build alert message text."""
    return (
        f"⚠️ SSL Certificate Expiry Alert\n\n"
        f"Certificate: {cert.common_name or cert.filename}\n"
        f"File: {cert.filename}\n"
        f"Expires: {cert.valid_until.strftime('%Y-%m-%d %H:%M UTC') if cert.valid_until else 'N/A'}\n"
        f"Days Remaining: {cert.days_until_expiry}\n"
        f"Alert Rule: {rule.name} ({rule.days_before_expiry} days)\n"
        f"Domains: {cert.san_domains or 'N/A'}\n"
        f"Issuer: {cert.issuer_organization or cert.issuer_common_name or 'N/A'}\n\n"
        f"Please renew this certificate before it expires."
    )


def _send_email(channel, cert, message):
    """Send alert via SMTP email."""
    if not all([channel.smtp_host, channel.smtp_port, channel.smtp_from_email, channel.smtp_to_emails]):
        raise ValueError("Incomplete SMTP configuration")

    msg = MIMEMultipart('alternative')
    msg['Subject'] = f"[SSL Alert] Certificate '{cert.common_name or cert.filename}' expires in {cert.days_until_expiry} days"
    msg['From'] = channel.smtp_from_email
    msg['To'] = channel.smtp_to_emails

    # HTML body
    html = f"""
    <html>
    <body style="font-family: Arial, sans-serif;">
        <div style="background: #f44336; color: white; padding: 15px; border-radius: 5px;">
            <h2>⚠️ SSL Certificate Expiry Alert</h2>
        </div>
        <div style="padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-top: 10px;">
            <table style="width: 100%; border-collapse: collapse;">
                <tr><td style="padding: 8px; font-weight: bold;">Certificate:</td><td style="padding: 8px;">{cert.common_name or cert.filename}</td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">File:</td><td style="padding: 8px;">{cert.filename}</td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">Expires:</td><td style="padding: 8px; color: #f44336; font-weight: bold;">{cert.valid_until.strftime('%Y-%m-%d %H:%M UTC') if cert.valid_until else 'N/A'}</td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">Days Remaining:</td><td style="padding: 8px; color: #f44336; font-weight: bold;">{cert.days_until_expiry}</td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">Domains:</td><td style="padding: 8px;">{cert.san_domains or 'N/A'}</td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">Issuer:</td><td style="padding: 8px;">{cert.issuer_organization or cert.issuer_common_name or 'N/A'}</td></tr>
            </table>
        </div>
        <p style="color: #666; margin-top: 15px;">Please renew this certificate before it expires.</p>
    </body>
    </html>
    """

    msg.attach(MIMEText(message, 'plain'))
    msg.attach(MIMEText(html, 'html'))

    recipients = [e.strip() for e in channel.smtp_to_emails.split(',') if e.strip()]

    if channel.smtp_use_tls:
        server = smtplib.SMTP(channel.smtp_host, channel.smtp_port, timeout=30)
        server.starttls()
    else:
        server = smtplib.SMTP(channel.smtp_host, channel.smtp_port, timeout=30)

    if channel.smtp_username and channel.smtp_password:
        server.login(channel.smtp_username, channel.smtp_password)

    server.sendmail(channel.smtp_from_email, recipients, msg.as_string())
    server.quit()


def _send_slack(channel, cert, message):
    """Send alert via Slack webhook."""
    if not channel.slack_webhook_url:
        raise ValueError("Slack webhook URL not configured")

    payload = {
        "channel": channel.slack_channel or None,
        "username": "SSL Cert Manager",
        "icon_emoji": ":lock:",
        "attachments": [{
            "color": "#f44336",
            "title": f"⚠️ Certificate '{cert.common_name or cert.filename}' expires in {cert.days_until_expiry} days",
            "text": message,
            "fields": [
                {"title": "Certificate", "value": cert.common_name or cert.filename, "short": True},
                {"title": "Days Remaining", "value": str(cert.days_until_expiry), "short": True},
                {"title": "Expires", "value": cert.valid_until.strftime('%Y-%m-%d') if cert.valid_until else 'N/A', "short": True},
                {"title": "Issuer", "value": cert.issuer_organization or 'N/A', "short": True},
            ]
        }]
    }

    resp = requests.post(channel.slack_webhook_url, json=payload, timeout=30)
    resp.raise_for_status()


def _send_teams(channel, cert, message):
    """Send alert via Microsoft Teams webhook."""
    if not channel.teams_webhook_url:
        raise ValueError("Teams webhook URL not configured")

    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "f44336",
        "summary": f"Certificate Expiry Alert: {cert.common_name or cert.filename}",
        "sections": [{
            "activityTitle": f"⚠️ SSL Certificate Expiry Alert",
            "facts": [
                {"name": "Certificate", "value": cert.common_name or cert.filename},
                {"name": "File", "value": cert.filename},
                {"name": "Expires", "value": cert.valid_until.strftime('%Y-%m-%d %H:%M UTC') if cert.valid_until else 'N/A'},
                {"name": "Days Remaining", "value": str(cert.days_until_expiry)},
                {"name": "Domains", "value": cert.san_domains or 'N/A'},
                {"name": "Issuer", "value": cert.issuer_organization or cert.issuer_common_name or 'N/A'},
            ],
            "markdown": True,
        }],
    }

    resp = requests.post(channel.teams_webhook_url, json=payload, timeout=30)
    resp.raise_for_status()


def _send_webhook(channel, cert, message):
    """Send alert via generic webhook."""
    if not channel.webhook_url:
        raise ValueError("Webhook URL not configured")

    payload = {
        "event": "certificate_expiry_alert",
        "certificate": {
            "id": cert.id,
            "common_name": cert.common_name,
            "filename": cert.filename,
            "valid_until": cert.valid_until.isoformat() if cert.valid_until else None,
            "days_until_expiry": cert.days_until_expiry,
            "issuer": cert.issuer_organization or cert.issuer_common_name,
            "domains": cert.san_domains,
        },
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    headers = {"Content-Type": "application/json"}
    if channel.webhook_headers:
        try:
            custom_headers = json.loads(channel.webhook_headers)
            headers.update(custom_headers)
        except json.JSONDecodeError:
            pass

    method = (channel.webhook_method or 'POST').upper()
    resp = requests.request(method, channel.webhook_url, json=payload, headers=headers, timeout=30)
    resp.raise_for_status()


def send_test_notification(channel):
    """Send a test notification through a channel to verify configuration."""
    test_message = (
        "🔔 Test Notification from SSL Cert Manager\n\n"
        "This is a test notification to verify your notification channel configuration.\n"
        "If you received this message, your channel is configured correctly!"
    )

    try:
        if channel.channel_type == 'email':
            if not all([channel.smtp_host, channel.smtp_port, channel.smtp_from_email, channel.smtp_to_emails]):
                raise ValueError("Incomplete SMTP configuration")
            msg = MIMEText(test_message)
            msg['Subject'] = '[SSL Cert Manager] Test Notification'
            msg['From'] = channel.smtp_from_email
            msg['To'] = channel.smtp_to_emails
            recipients = [e.strip() for e in channel.smtp_to_emails.split(',') if e.strip()]
            if channel.smtp_use_tls:
                server = smtplib.SMTP(channel.smtp_host, channel.smtp_port, timeout=30)
                server.starttls()
            else:
                server = smtplib.SMTP(channel.smtp_host, channel.smtp_port, timeout=30)
            if channel.smtp_username and channel.smtp_password:
                server.login(channel.smtp_username, channel.smtp_password)
            server.sendmail(channel.smtp_from_email, recipients, msg.as_string())
            server.quit()

        elif channel.channel_type == 'slack':
            if not channel.slack_webhook_url:
                raise ValueError("Slack webhook URL not configured")
            payload = {"text": test_message}
            resp = requests.post(channel.slack_webhook_url, json=payload, timeout=30)
            resp.raise_for_status()

        elif channel.channel_type == 'teams':
            if not channel.teams_webhook_url:
                raise ValueError("Teams webhook URL not configured")
            payload = {
                "@type": "MessageCard",
                "summary": "Test Notification",
                "sections": [{"activityTitle": "🔔 Test Notification", "text": test_message}],
            }
            resp = requests.post(channel.teams_webhook_url, json=payload, timeout=30)
            resp.raise_for_status()

        elif channel.channel_type == 'webhook':
            if not channel.webhook_url:
                raise ValueError("Webhook URL not configured")
            payload = {"event": "test", "message": test_message}
            headers = {"Content-Type": "application/json"}
            if channel.webhook_headers:
                try:
                    headers.update(json.loads(channel.webhook_headers))
                except json.JSONDecodeError:
                    pass
            resp = requests.request(
                (channel.webhook_method or 'POST').upper(),
                channel.webhook_url, json=payload, headers=headers, timeout=30
            )
            resp.raise_for_status()

        return {'success': True, 'message': 'Test notification sent successfully!'}
    except Exception as e:
        return {'success': False, 'message': f'Test failed: {str(e)}'}


def test_smtp_connection(smtp_host, smtp_port, smtp_username, smtp_password, smtp_use_tls, smtp_from_email, smtp_to_emails):
    """
    Test SMTP connection and send a test email without requiring a saved channel.
    Used for validating SMTP settings before saving.
    """
    test_message = (
        "🔔 SMTP Test from SSL Cert Manager\n\n"
        "This is a test email to verify your SMTP configuration.\n"
        "If you received this message, your SMTP settings are correct!\n\n"
        "Settings tested:\n"
        f"  - Host: {smtp_host}\n"
        f"  - Port: {smtp_port}\n"
        f"  - TLS: {'Yes' if smtp_use_tls else 'No'}\n"
        f"  - From: {smtp_from_email}\n"
    )

    try:
        if not all([smtp_host, smtp_port, smtp_from_email, smtp_to_emails]):
            raise ValueError("Missing required SMTP fields: Host, Port, From Email, and To Emails are required")

        msg = MIMEMultipart('alternative')
        msg['Subject'] = '[SSL Cert Manager] SMTP Test Successful'
        msg['From'] = smtp_from_email
        msg['To'] = smtp_to_emails

        # HTML body
        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <div style="background: #4CAF50; color: white; padding: 15px; border-radius: 5px;">
                <h2>✅ SMTP Test Successful</h2>
            </div>
            <div style="padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-top: 10px;">
                <p>This is a test email from <strong>SSL Cert Manager</strong>.</p>
                <p>Your SMTP settings are configured correctly!</p>
                <h4>Settings tested:</h4>
                <ul>
                    <li><strong>Host:</strong> {smtp_host}</li>
                    <li><strong>Port:</strong> {smtp_port}</li>
                    <li><strong>TLS:</strong> {'Yes' if smtp_use_tls else 'No'}</li>
                    <li><strong>From:</strong> {smtp_from_email}</li>
                </ul>
            </div>
        </body>
        </html>
        """

        msg.attach(MIMEText(test_message, 'plain'))
        msg.attach(MIMEText(html, 'html'))

        recipients = [e.strip() for e in smtp_to_emails.split(',') if e.strip()]

        logger.info('Testing SMTP connection to %s:%s', smtp_host, smtp_port)

        if smtp_use_tls:
            server = smtplib.SMTP(smtp_host, int(smtp_port), timeout=30)
            server.starttls()
        else:
            server = smtplib.SMTP(smtp_host, int(smtp_port), timeout=30)

        if smtp_username and smtp_password:
            server.login(smtp_username, smtp_password)

        server.sendmail(smtp_from_email, recipients, msg.as_string())
        server.quit()

        logger.info('SMTP test successful - email sent to %s', smtp_to_emails)
        return {'success': True, 'message': f'Test email sent successfully to {smtp_to_emails}'}

    except smtplib.SMTPAuthenticationError as e:
        logger.error('SMTP authentication failed: %s', e)
        return {'success': False, 'message': f'Authentication failed: Invalid username or password. Check your SMTP credentials.'}
    except smtplib.SMTPConnectError as e:
        logger.error('SMTP connection failed: %s', e)
        return {'success': False, 'message': f'Connection failed: Could not connect to {smtp_host}:{smtp_port}. Check host and port.'}
    except smtplib.SMTPServerDisconnected as e:
        logger.error('SMTP server disconnected: %s', e)
        return {'success': False, 'message': 'Server disconnected unexpectedly. Try enabling/disabling TLS.'}
    except Exception as e:
        logger.error('SMTP test failed: %s', e)
        return {'success': False, 'message': f'SMTP test failed: {str(e)}'}
