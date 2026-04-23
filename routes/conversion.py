"""Certificate conversion routes."""

import os
import io
from flask import Blueprint, render_template, request, jsonify, send_file, current_app
from flask_login import login_required
from werkzeug.utils import secure_filename
from conversion_utils import convert_certificate, CONVERSION_MAP, INPUT_FORMATS, get_output_formats
from cert_utils import is_supported_file
from logger import get_logger

log = get_logger('conversion')
conversion_bp = Blueprint('conversion', __name__, url_prefix='/conversion')


@conversion_bp.route('/')
@login_required
def index():
    """Conversion utility page."""
    return render_template('conversion/index.html', conversion_map=CONVERSION_MAP)


@conversion_bp.route('/formats', methods=['POST'])
@login_required
def get_formats():
    """Get available output formats for a given input format."""
    input_fmt = request.json.get('input_format', '')
    outputs = get_output_formats(input_fmt)
    return jsonify({'formats': outputs})


@conversion_bp.route('/convert', methods=['POST'])
@login_required
def convert():
    """Convert a certificate file."""
    if 'cert_file' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded'}), 400

    file = request.files['cert_file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400

    filename = secure_filename(file.filename)
    output_format = request.form.get('output_format', '').strip()
    password = request.form.get('password', '').strip() or None
    export_password = request.form.get('export_password', '').strip() or None

    # Optional separate key file
    key_data = None
    key_password = request.form.get('key_password', '').strip() or None
    if 'key_file' in request.files:
        key_file = request.files['key_file']
        if key_file.filename:
            key_data = key_file.read()
            log.info('Separate key file provided: %s', secure_filename(key_file.filename))

    # Determine input format from extension
    _, ext = os.path.splitext(filename)
    input_format = ext.lstrip('.')

    if not output_format:
        return jsonify({'success': False, 'message': 'Output format is required'}), 400

    file_data = file.read()
    result = convert_certificate(
        file_data, input_format, output_format,
        password=password,
        export_password=export_password,
        key_data=key_data,
        key_password=key_password
    )

    if not result['success']:
        return jsonify(result), 400

    # Save to temp and return download
    base_name = os.path.splitext(filename)[0]
    out_filename = f"{base_name}_converted.{result['filename_ext']}"

    # Store in upload folder temporarily
    upload_dir = current_app.config['UPLOAD_FOLDER']
    os.makedirs(upload_dir, exist_ok=True)
    out_path = os.path.join(upload_dir, secure_filename(out_filename))
    with open(out_path, 'wb') as f:
        f.write(result['data'])

    return send_file(
        io.BytesIO(result['data']),
        as_attachment=True,
        download_name=out_filename,
        mimetype='application/octet-stream'
    )
