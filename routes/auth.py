"""Authentication routes."""

from datetime import datetime, timezone
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User
from logger import get_logger

log = get_logger('auth')
auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login page."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            if not user.is_active:
                flash('Your account has been disabled.', 'danger')
                log.warning('Login attempt for disabled user: %s', username)
                return render_template('auth/login.html')

            login_user(user, remember=remember)
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()
            log.info('User logged in: %s', username)

            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('dashboard.index'))
        else:
            flash('Invalid username or password.', 'danger')
            log.warning('Failed login attempt for user: %s', username)

    return render_template('auth/login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    """Logout the current user."""
    log.info('User logged out: %s', current_user.username)
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile page for changing username/password."""
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'change_username':
            new_username = request.form.get('new_username', '').strip()
            current_password = request.form.get('current_password', '')

            if not new_username:
                return jsonify({'success': False, 'message': 'Username is required.'}), 400

            if not current_user.check_password(current_password):
                return jsonify({'success': False, 'message': 'Current password is incorrect.'}), 400

            if User.query.filter(User.username == new_username, User.id != current_user.id).first():
                return jsonify({'success': False, 'message': 'Username already taken.'}), 400

            old_username = current_user.username
            current_user.username = new_username
            db.session.commit()
            log.info('Username changed from %s to %s', old_username, new_username)
            return jsonify({'success': True, 'message': 'Username updated successfully!'})

        elif action == 'change_password':
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')

            if not current_user.check_password(current_password):
                return jsonify({'success': False, 'message': 'Current password is incorrect.'}), 400

            if len(new_password) < 8:
                return jsonify({'success': False, 'message': 'New password must be at least 8 characters.'}), 400

            if new_password != confirm_password:
                return jsonify({'success': False, 'message': 'New passwords do not match.'}), 400

            current_user.set_password(new_password)
            db.session.commit()
            log.info('Password changed for user: %s', current_user.username)
            return jsonify({'success': True, 'message': 'Password updated successfully!'})

        elif action == 'change_email':
            new_email = request.form.get('new_email', '').strip()
            current_user.email = new_email if new_email else None
            db.session.commit()
            log.info('Email updated for user: %s', current_user.username)
            return jsonify({'success': True, 'message': 'Email updated successfully!'})

    return render_template('auth/profile.html')


@auth_bp.route('/verify-password', methods=['POST'])
@login_required
def verify_password():
    """Verify current user's password for session unlock."""
    password = request.form.get('password', '')
    
    if current_user.check_password(password):
        log.info('Session unlocked for user: %s', current_user.username)
        return jsonify({'success': True, 'message': 'Session unlocked successfully!'})
    else:
        log.warning('Failed unlock attempt for user: %s', current_user.username)
        return jsonify({'success': False, 'message': 'Incorrect password.'}), 401
