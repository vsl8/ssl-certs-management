"""Certificate CRUD routes."""

import os
import json
from datetime import datetime, timezone
from flask import Blueprint, render_template, request, redirect, url_for, jsonify, current_app
from flask_login import login_required
from werkzeug.utils import secure_filename
from models import db, Certificate, Setting
from cert_utils import parse_certificate, is_supported_file, refresh_cert_expiry, SUPPORTED_EXTENSIONS
from logger import get_logger

log = get_logger('certificates')
certificates_bp = Blueprint('certificates', __name__, url_prefix='/certificates')


@certificates_bp.route('/')
@login_required
def list_certs():
    """List all certificates (page, DataTables fetches via API)."""
    return render_template('certificates/list.html')


@certificates_bp.route('/api/list')
@login_required
def api_list():
    """API endpoint for DataTables."""
    certs = Certificate.query.all()
    for c in certs:
        refresh_cert_expiry(c)
    db.session.commit()

    data = []
    for c in certs:
        san = ''
        if c.san_domains:
            try:
                domains = json.loads(c.san_domains)
                san = ', '.join(domains[:3])
                if len(domains) > 3:
                    san += f' (+{len(domains) - 3} more)'
            except (json.JSONDecodeError, TypeError):
                san = c.san_domains

        data.append({
            'id': c.id,
            'common_name': c.common_name or c.filename,
            'filename': c.filename,
            'file_type': c.file_type,
            'issuer': c.issuer_organization or c.issuer_common_name or 'N/A',
            'valid_from': c.valid_from.strftime('%Y-%m-%d') if c.valid_from else 'N/A',
            'valid_until': c.valid_until.strftime('%Y-%m-%d') if c.valid_until else 'N/A',
            'days_until_expiry': c.days_until_expiry,
            'status': c.status,
            'san_domains': san,
            'is_ca': c.is_ca,
        })

    return jsonify({'data': data})


@certificates_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_cert():
    """Add a new certificate."""
    if request.method == 'GET':
        return render_template('certificates/add.html')

    # Handle file upload
    if 'cert_file' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded'}), 400

    file = request.files['cert_file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400

    filename = secure_filename(file.filename)
    if not is_supported_file(filename):
        supported = ', '.join(sorted(SUPPORTED_EXTENSIONS))
        return jsonify({
            'success': False,
            'message': f'Unsupported file type. Supported: {supported}'
        }), 400

    # Read file data
    file_data = file.read()
    password = request.form.get('password', None)
    notes = request.form.get('notes', '')
    tags = request.form.get('tags', '')

    # Parse certificate
    details = parse_certificate(file_data, filename, password)

    if not details.get('success'):
        return jsonify({
            'success': False,
            'message': f"Failed to parse certificate: {details.get('error', 'Unknown error')}"
        }), 400

    # Get storage path from settings
    storage_path_setting = Setting.query.filter_by(key='cert_storage_path').first()
    storage_path = storage_path_setting.value if storage_path_setting else current_app.config.get('DEFAULT_CERT_PATH', '/etc/pki/tls/certs')

    # Save file to storage path
    upload_dir = current_app.config['UPLOAD_FOLDER']
    os.makedirs(upload_dir, exist_ok=True)

    # Use upload dir as fallback if storage path doesn't exist
    save_dir = storage_path if os.path.isdir(storage_path) else upload_dir
    file_path = os.path.join(save_dir, filename)

    # Avoid overwriting
    base, ext = os.path.splitext(filename)
    counter = 1
    while os.path.exists(file_path):
        filename = f"{base}_{counter}{ext}"
        file_path = os.path.join(save_dir, filename)
        counter += 1

    with open(file_path, 'wb') as f:
        f.write(file_data)

    # Create DB record
    cert = Certificate(
        filename=filename,
        file_type=details['file_type'],
        file_path=file_path,
        file_size=details.get('file_size', len(file_data)),
        common_name=details.get('common_name'),
        organization=details.get('organization'),
        organizational_unit=details.get('organizational_unit'),
        country=details.get('country'),
        state=details.get('state'),
        locality=details.get('locality'),
        email=details.get('email'),
        issuer_common_name=details.get('issuer_common_name'),
        issuer_organization=details.get('issuer_organization'),
        issuer_country=details.get('issuer_country'),
        valid_from=details.get('valid_from'),
        valid_until=details.get('valid_until'),
        serial_number=details.get('serial_number'),
        signature_algorithm=details.get('signature_algorithm'),
        key_size=details.get('key_size'),
        version=details.get('version'),
        is_ca=details.get('is_ca', False),
        fingerprint_sha256=details.get('fingerprint_sha256'),
        fingerprint_sha1=details.get('fingerprint_sha1'),
        san_domains=details.get('san_domains'),
        days_until_expiry=details.get('days_until_expiry'),
        is_expired=details.get('is_expired', False),
        notes=notes,
        tags=tags,
    )
    db.session.add(cert)
    db.session.commit()

    log.info('Certificate added: id=%s name=%s file=%s', cert.id, cert.common_name, cert.filename)

    return jsonify({
        'success': True,
        'message': f'Certificate "{cert.common_name or cert.filename}" added successfully!',
        'cert_id': cert.id,
    })


@certificates_bp.route('/view/<int:cert_id>')
@login_required
def view_cert(cert_id):
    """View certificate details."""
    cert = Certificate.query.get_or_404(cert_id)
    refresh_cert_expiry(cert)
    db.session.commit()

    san_list = []
    if cert.san_domains:
        try:
            san_list = json.loads(cert.san_domains)
        except (json.JSONDecodeError, TypeError):
            san_list = [cert.san_domains]

    return render_template('certificates/view.html', cert=cert, san_list=san_list)


@certificates_bp.route('/edit/<int:cert_id>', methods=['GET', 'POST'])
@login_required
def edit_cert(cert_id):
    """Edit certificate metadata (notes, tags)."""
    cert = Certificate.query.get_or_404(cert_id)

    if request.method == 'GET':
        return render_template('certificates/edit.html', cert=cert)

    cert.notes = request.form.get('notes', cert.notes)
    cert.tags = request.form.get('tags', cert.tags)
    cert.common_name = request.form.get('common_name', cert.common_name)
    db.session.commit()

    log.info('Certificate updated: id=%s name=%s', cert.id, cert.common_name or cert.filename)

    return jsonify({
        'success': True,
        'message': f'Certificate "{cert.common_name or cert.filename}" updated successfully!'
    })


@certificates_bp.route('/delete/<int:cert_id>', methods=['POST'])
@login_required
def delete_cert(cert_id):
    """Delete a certificate."""
    cert = Certificate.query.get_or_404(cert_id)
    cert_name = cert.common_name or cert.filename

    # Optionally remove file from disk
    if request.form.get('delete_file') == 'true' and cert.file_path:
        try:
            if os.path.exists(cert.file_path):
                os.remove(cert.file_path)
        except OSError:
            pass

    db.session.delete(cert)
    db.session.commit()

    log.info('Certificate deleted: id=%s name=%s', cert_id, cert_name)

    return jsonify({
        'success': True,
        'message': f'Certificate "{cert_name}" deleted successfully!'
    })


@certificates_bp.route('/download/<int:cert_id>')
@login_required
def download_cert(cert_id):
    """Download a certificate file."""
    from flask import send_file, abort

    cert = Certificate.query.get_or_404(cert_id)

    if not cert.file_path or not os.path.exists(cert.file_path):
        log.warning('Download failed: file not found for cert id=%s', cert_id)
        abort(404, description='Certificate file not found on disk')

    log.info('Certificate downloaded: id=%s name=%s', cert_id, cert.common_name or cert.filename)

    return send_file(
        cert.file_path,
        as_attachment=True,
        download_name=cert.filename
    )
