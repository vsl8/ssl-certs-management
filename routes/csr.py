"""CSR (Certificate Signing Request) generation routes."""

import os
import subprocess
import json
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required
from models import db, Setting, CSRConfig, CSRRequest
from logger import get_logger

log = get_logger('csr')
csr_bp = Blueprint('csr', __name__, url_prefix='/csr')


def get_csr_storage_path():
    """Get the CSR storage path from settings."""
    setting = Setting.query.filter_by(key='csr_storage_path').first()
    if setting and setting.value:
        return setting.value
    # Default to current year
    current_year = datetime.now().year
    return f'/etc/pki/tls/csr_{current_year}'


def get_default_key_path():
    """Get the default private key path from settings."""
    setting = Setting.query.filter_by(key='csr_default_key_path').first()
    if setting and setting.value:
        return setting.value
    return '/etc/pki/tls/private'


def ensure_csr_directory():
    """Ensure CSR storage directory exists."""
    path = get_csr_storage_path()
    os.makedirs(path, exist_ok=True)
    return path


# ─── CSR Generation Page ───

@csr_bp.route('/')
@login_required
def index():
    """CSR generation utility main page."""
    configs = CSRConfig.query.order_by(CSRConfig.created_at.desc()).all()
    csr_requests = CSRRequest.query.order_by(CSRRequest.created_at.desc()).all()
    csr_path = get_csr_storage_path()
    key_path = get_default_key_path()
    return render_template('csr/index.html', 
                           configs=configs, 
                           csr_requests=csr_requests,
                           csr_path=csr_path,
                           key_path=key_path)


# ─── Config Templates ───

@csr_bp.route('/configs')
@login_required
def list_configs():
    """List all CSR config templates."""
    configs = CSRConfig.query.order_by(CSRConfig.created_at.desc()).all()
    return render_template('csr/configs.html', configs=configs)


@csr_bp.route('/config/save', methods=['POST'])
@login_required
def save_config():
    """Save a new CSR config template."""
    name = request.form.get('name', '').strip()
    country = request.form.get('country', '').strip()
    state = request.form.get('state', '').strip()
    locality = request.form.get('locality', '').strip()
    organization = request.form.get('organization', '').strip()
    organizational_unit = request.form.get('organizational_unit', '').strip()
    email = request.form.get('email', '').strip()

    if not name:
        return jsonify({'success': False, 'message': 'Config name is required.'}), 400

    # Generate config file content
    config_content = _generate_cnf_content(
        country=country,
        state=state,
        locality=locality,
        organization=organization,
        organizational_unit=organizational_unit,
        email=email,
        common_name='${CN}',  # Placeholder
        alt_names=[]
    )

    # Save to file
    csr_dir = ensure_csr_directory()
    config_filename = f"{name.replace(' ', '_')}_template.cnf"
    config_path = os.path.join(csr_dir, config_filename)

    try:
        with open(config_path, 'w') as f:
            f.write(config_content)
    except Exception as e:
        log.error('Failed to save config template: %s', str(e))
        return jsonify({'success': False, 'message': f'Failed to save config: {str(e)}'}), 500

    # Save to database
    config = CSRConfig(
        name=name,
        file_path=config_path,
        country=country,
        state=state,
        locality=locality,
        organization=organization,
        organizational_unit=organizational_unit,
        email=email
    )
    db.session.add(config)
    db.session.commit()

    log.info('CSR config template saved: %s', name)
    return jsonify({'success': True, 'message': 'Config template saved successfully!'})


@csr_bp.route('/config/<int:config_id>')
@login_required
def get_config(config_id):
    """Get a config template details."""
    config = CSRConfig.query.get_or_404(config_id)
    
    # Read file content if exists
    file_content = ''
    if os.path.exists(config.file_path):
        try:
            with open(config.file_path, 'r') as f:
                file_content = f.read()
        except Exception as e:
            file_content = f'Error reading file: {str(e)}'

    return jsonify({
        'success': True,
        'config': {
            'id': config.id,
            'name': config.name,
            'file_path': config.file_path,
            'country': config.country,
            'state': config.state,
            'locality': config.locality,
            'organization': config.organization,
            'organizational_unit': config.organizational_unit,
            'email': config.email,
            'file_content': file_content,
            'created_at': config.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
    })


@csr_bp.route('/config/delete/<int:config_id>', methods=['POST'])
@login_required
def delete_config(config_id):
    """Delete a config template."""
    config = CSRConfig.query.get_or_404(config_id)
    
    # Delete file if exists
    if os.path.exists(config.file_path):
        try:
            os.remove(config.file_path)
        except Exception as e:
            log.warning('Failed to delete config file: %s', str(e))

    db.session.delete(config)
    db.session.commit()

    log.info('CSR config template deleted: %s', config.name)
    return jsonify({'success': True, 'message': 'Config template deleted successfully!'})


# ─── CSR Generation ───

@csr_bp.route('/generate', methods=['POST'])
@login_required
def generate_csr():
    """Generate a CSR using provided parameters."""
    # Get form data
    output_name = request.form.get('output_name', '').strip()
    key_file_path = request.form.get('key_file_path', '').strip()
    common_name = request.form.get('common_name', '').strip()
    alt_names_raw = request.form.get('alt_names', '').strip()
    
    # Config template or manual entry
    config_id = request.form.get('config_id')
    country = request.form.get('country', '').strip()
    state = request.form.get('state', '').strip()
    locality = request.form.get('locality', '').strip()
    organization = request.form.get('organization', '').strip()
    organizational_unit = request.form.get('organizational_unit', '').strip()
    email = request.form.get('email', '').strip()

    # Validation
    if not output_name:
        return jsonify({'success': False, 'message': 'Output name is required.'}), 400
    if not key_file_path:
        return jsonify({'success': False, 'message': 'Private key file path is required.'}), 400
    if not common_name:
        return jsonify({'success': False, 'message': 'Common Name (CN) is required.'}), 400

    # Check key file exists
    if not os.path.exists(key_file_path):
        return jsonify({'success': False, 'message': f'Private key file not found: {key_file_path}'}), 400

    # Parse alt names
    alt_names = []
    if alt_names_raw:
        alt_names = [name.strip() for name in alt_names_raw.split('\n') if name.strip()]

    # Get config template values if selected
    if config_id:
        config = CSRConfig.query.get(int(config_id))
        if config:
            country = country or config.country
            state = state or config.state
            locality = locality or config.locality
            organization = organization or config.organization
            organizational_unit = organizational_unit or config.organizational_unit
            email = email or config.email

    # Generate CNF content
    cnf_content = _generate_cnf_content(
        country=country,
        state=state,
        locality=locality,
        organization=organization,
        organizational_unit=organizational_unit,
        email=email,
        common_name=common_name,
        alt_names=alt_names
    )

    # Prepare file paths
    csr_dir = ensure_csr_directory()
    cnf_filename = f"{output_name}.cnf"
    csr_filename = f"{output_name}.csr"
    cnf_path = os.path.join(csr_dir, cnf_filename)
    csr_path = os.path.join(csr_dir, csr_filename)

    try:
        # Save CNF file
        with open(cnf_path, 'w') as f:
            f.write(cnf_content)
        log.info('CNF file created: %s', cnf_path)

        # Generate CSR using openssl
        cmd = [
            'openssl', 'req',
            '-key', key_file_path,
            '-new',
            '-out', csr_path,
            '-config', cnf_path
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            error_msg = result.stderr or 'Unknown error'
            log.error('OpenSSL CSR generation failed: %s', error_msg)
            return jsonify({'success': False, 'message': f'CSR generation failed: {error_msg}'}), 500

        log.info('CSR generated: %s', csr_path)

        # Read CSR content for display
        with open(csr_path, 'r') as f:
            csr_content = f.read()

        # Verify CSR
        verify_cmd = ['openssl', 'req', '-in', csr_path, '-text', '-noout', '-verify']
        verify_result = subprocess.run(verify_cmd, capture_output=True, text=True)
        csr_details = verify_result.stdout if verify_result.returncode == 0 else ''

        # Save to database
        csr_request = CSRRequest(
            name=output_name,
            csr_file_path=csr_path,
            config_file_path=cnf_path,
            key_file_path=key_file_path,
            common_name=common_name,
            san_domains=json.dumps(alt_names) if alt_names else None
        )
        db.session.add(csr_request)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'CSR generated successfully!',
            'csr_content': csr_content,
            'csr_details': csr_details,
            'csr_path': csr_path,
            'cnf_path': cnf_path
        })

    except Exception as e:
        log.error('CSR generation error: %s', str(e))
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


@csr_bp.route('/view/<int:csr_id>')
@login_required
def view_csr(csr_id):
    """View CSR content and details."""
    csr_request = CSRRequest.query.get_or_404(csr_id)
    
    csr_content = ''
    csr_details = ''
    config_content = ''
    
    # Read CSR file
    if os.path.exists(csr_request.csr_file_path):
        try:
            with open(csr_request.csr_file_path, 'r') as f:
                csr_content = f.read()
            
            # Get CSR details using openssl
            verify_cmd = ['openssl', 'req', '-in', csr_request.csr_file_path, '-text', '-noout', '-verify']
            verify_result = subprocess.run(verify_cmd, capture_output=True, text=True)
            csr_details = verify_result.stdout if verify_result.returncode == 0 else verify_result.stderr
        except Exception as e:
            csr_content = f'Error reading CSR file: {str(e)}'
    else:
        csr_content = 'CSR file not found on disk.'

    # Read config file
    if csr_request.config_file_path and os.path.exists(csr_request.config_file_path):
        try:
            with open(csr_request.config_file_path, 'r') as f:
                config_content = f.read()
        except Exception as e:
            config_content = f'Error reading config file: {str(e)}'

    return jsonify({
        'success': True,
        'csr': {
            'id': csr_request.id,
            'name': csr_request.name,
            'csr_file_path': csr_request.csr_file_path,
            'config_file_path': csr_request.config_file_path,
            'key_file_path': csr_request.key_file_path,
            'common_name': csr_request.common_name,
            'san_domains': json.loads(csr_request.san_domains) if csr_request.san_domains else [],
            'created_at': csr_request.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'csr_content': csr_content,
            'csr_details': csr_details,
            'config_content': config_content
        }
    })


@csr_bp.route('/delete/<int:csr_id>', methods=['POST'])
@login_required
def delete_csr(csr_id):
    """Delete a CSR record (optionally delete files)."""
    csr_request = CSRRequest.query.get_or_404(csr_id)
    delete_files = request.form.get('delete_files') == 'true'
    
    if delete_files:
        # Delete CSR file
        if os.path.exists(csr_request.csr_file_path):
            try:
                os.remove(csr_request.csr_file_path)
            except Exception as e:
                log.warning('Failed to delete CSR file: %s', str(e))
        
        # Delete config file
        if csr_request.config_file_path and os.path.exists(csr_request.config_file_path):
            try:
                os.remove(csr_request.config_file_path)
            except Exception as e:
                log.warning('Failed to delete config file: %s', str(e))

    db.session.delete(csr_request)
    db.session.commit()

    log.info('CSR record deleted: %s', csr_request.name)
    return jsonify({'success': True, 'message': 'CSR record deleted successfully!'})


# ─── Helper Functions ───

def _generate_cnf_content(country, state, locality, organization, organizational_unit, 
                          email, common_name, alt_names):
    """Generate OpenSSL config file content."""
    content = """[ req ]
default_bits        = 2048
prompt              = no
distinguished_name  = dn
req_extensions      = req_ext
default_md          = sha256

[ dn ]
"""
    if country:
        content += f"C  = {country}\n"
    if state:
        content += f"ST = {state}\n"
    if locality:
        content += f"L  = {locality}\n"
    if organization:
        content += f"O  = {organization}\n"
    if organizational_unit:
        content += f"OU = {organizational_unit}\n"
    if common_name:
        content += f"CN = {common_name}\n"
    if email:
        content += f"emailAddress = {email}\n"

    content += """
[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
"""
    # Add alt names
    if alt_names:
        for i, name in enumerate(alt_names, 1):
            content += f"DNS.{i} = {name}\n"
    elif common_name:
        # Add CN as first SAN if no alt names provided
        content += f"DNS.1 = {common_name}\n"

    return content
