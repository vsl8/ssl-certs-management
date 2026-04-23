"""Dashboard routes."""

import json
from datetime import datetime, timezone, timedelta
from flask import Blueprint, render_template
from flask_login import login_required
from models import db, Certificate, AlertLog
from cert_utils import refresh_cert_expiry
from logger import get_logger

log = get_logger('dashboard')
dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
@login_required
def index():
    """Main dashboard with statistics."""
    # Refresh all expiry data
    certs = Certificate.query.filter(Certificate.valid_until.isnot(None)).all()
    for c in certs:
        refresh_cert_expiry(c)
    db.session.commit()

    total_certs = Certificate.query.count()
    now = datetime.now(timezone.utc)

    # Expiring counts
    expired = Certificate.query.filter(
        Certificate.days_until_expiry <= 0,
        Certificate.valid_until.isnot(None)
    ).count()

    expiring_7 = Certificate.query.filter(
        Certificate.days_until_expiry > 0,
        Certificate.days_until_expiry <= 7,
    ).count()

    expiring_15 = Certificate.query.filter(
        Certificate.days_until_expiry > 0,
        Certificate.days_until_expiry <= 15,
    ).count()

    expiring_30 = Certificate.query.filter(
        Certificate.days_until_expiry > 0,
        Certificate.days_until_expiry <= 30,
    ).count()

    # This month's expiring
    end_of_month = (now.replace(day=1) + timedelta(days=32)).replace(day=1)
    expiring_month = Certificate.query.filter(
        Certificate.valid_until >= now,
        Certificate.valid_until < end_of_month,
    ).count()

    # Healthy certificates
    healthy = Certificate.query.filter(
        Certificate.days_until_expiry > 30,
    ).count()

    # CA vs non-CA
    ca_certs = Certificate.query.filter_by(is_ca=True).count()

    # Recent alerts
    recent_alerts = AlertLog.query.order_by(AlertLog.sent_at.desc()).limit(10).all()

    # Certificates expiring soon (for table)
    expiring_soon = Certificate.query.filter(
        Certificate.days_until_expiry > 0,
        Certificate.days_until_expiry <= 30,
    ).order_by(Certificate.days_until_expiry.asc()).limit(10).all()

    # File type distribution
    type_counts = db.session.query(
        Certificate.file_type, db.func.count(Certificate.id)
    ).group_by(Certificate.file_type).all()

    # Monthly expiry chart data (next 12 months)
    monthly_data = []
    for i in range(12):
        month_start = (now.replace(day=1) + timedelta(days=32 * i)).replace(day=1)
        month_end = (month_start + timedelta(days=32)).replace(day=1)
        count = Certificate.query.filter(
            Certificate.valid_until >= month_start,
            Certificate.valid_until < month_end,
        ).count()
        monthly_data.append({
            'month': month_start.strftime('%b %Y'),
            'count': count,
        })

    return render_template('dashboard.html',
                           total_certs=total_certs,
                           expired=expired,
                           expiring_7=expiring_7,
                           expiring_15=expiring_15,
                           expiring_30=expiring_30,
                           expiring_month=expiring_month,
                           healthy=healthy,
                           ca_certs=ca_certs,
                           recent_alerts=recent_alerts,
                           expiring_soon=expiring_soon,
                           type_counts=type_counts,
                           monthly_data=json.dumps(monthly_data))
