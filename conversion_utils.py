"""
Certificate conversion utilities.
Supports conversion between PEM, DER, CRT, CER, PFX/P12, P7B, KEY formats.
"""

import io
from logger import get_logger
from cryptography import x509

log = get_logger('conversion_utils')
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7, Encoding, NoEncryption
from cryptography.hazmat.backends import default_backend


# Supported input formats and what they can convert to
CONVERSION_MAP = {
    'pem': ['der', 'crt', 'cer', 'pfx', 'key'],
    'crt': ['pem', 'der', 'cer', 'pfx', 'key'],
    'cer': ['pem', 'der', 'crt', 'pfx', 'key'],
    'der': ['pem', 'crt', 'cer', 'pfx'],
    'pfx': ['pem', 'crt', 'der', 'key'],
    'p12': ['pem', 'crt', 'der', 'key'],
    'p7b': ['pem', 'crt', 'der'],
    'key': ['pem', 'der'],
}

INPUT_FORMATS = list(CONVERSION_MAP.keys())


def get_output_formats(input_format):
    """Get available output formats for a given input format."""
    return CONVERSION_MAP.get(input_format.lower().lstrip('.'), [])


def _try_load_private_key(data, password=None):
    """Attempt to load a private key from PEM or DER data."""
    pwd = password.encode() if password else None
    # Try PEM first
    try:
        return serialization.load_pem_private_key(data, password=pwd, backend=default_backend())
    except Exception:
        pass
    # Try DER
    try:
        return serialization.load_der_private_key(data, password=pwd, backend=default_backend())
    except Exception:
        pass
    return None


def _extract_key_from_pem(pem_data, password=None):
    """Try to extract private key from a combined PEM file (cert + key)."""
    pwd = password.encode() if password else None
    # Look for private key markers in PEM
    key_markers = [
        b'-----BEGIN PRIVATE KEY-----',
        b'-----BEGIN RSA PRIVATE KEY-----',
        b'-----BEGIN EC PRIVATE KEY-----',
        b'-----BEGIN ENCRYPTED PRIVATE KEY-----',
    ]
    for marker in key_markers:
        if marker in pem_data:
            try:
                return serialization.load_pem_private_key(pem_data, password=pwd, backend=default_backend())
            except Exception:
                pass
    return None


def convert_certificate(file_data, input_format, output_format, password=None, export_password=None, key_data=None, key_password=None):
    """
    Convert a certificate from one format to another.

    Args:
        file_data: Certificate file bytes
        input_format: Input file format (pem, crt, cer, der, pfx, p12, p7b, key)
        output_format: Output file format
        password: Password for encrypted input files (PFX/P12)
        export_password: Password for output PFX files
        key_data: Optional separate private key file bytes
        key_password: Password for encrypted key file

    Returns: dict with 'success', 'data' (bytes), 'filename_ext', and optionally 'key_data'.
    """
    input_fmt = input_format.lower().lstrip('.')
    output_fmt = output_format.lower().lstrip('.')

    if output_fmt not in get_output_formats(input_fmt):
        return {
            'success': False,
            'error': f'Conversion from {input_fmt} to {output_fmt} is not supported.'
        }

    try:
        # Step 1: Load the certificate/key from input format
        cert = None
        private_key = None
        additional_certs = None

        if input_fmt in ('pfx', 'p12'):
            pwd = password.encode() if password else None
            private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                file_data, pwd, default_backend()
            )
        elif input_fmt in ('p7b',):
            try:
                certs = pkcs7.load_pem_pkcs7_certificates(file_data)
            except Exception:
                certs = pkcs7.load_der_pkcs7_certificates(file_data)
            if certs:
                cert = certs[0]
                additional_certs = certs[1:] if len(certs) > 1 else None
        elif input_fmt == 'key':
            private_key = _try_load_private_key(file_data, password)
            if not private_key:
                return {'success': False, 'error': 'Could not load private key from file.'}
        else:
            # PEM, CRT, CER, DER - try to load certificate
            try:
                cert = x509.load_pem_x509_certificate(file_data, default_backend())
                # Also try to extract private key from combined PEM
                private_key = _extract_key_from_pem(file_data, password)
            except Exception:
                try:
                    cert = x509.load_der_x509_certificate(file_data, default_backend())
                except Exception:
                    pass

        # Step 1b: Load separate key file if provided
        if key_data and not private_key:
            private_key = _try_load_private_key(key_data, key_password)
            if not private_key:
                log.warning('Could not load private key from separate key file')

        # Step 2: Convert to output format
        result_data = None
        output_key_data = None
        filename_ext = output_fmt

        if output_fmt == 'pem':
            if cert:
                result_data = cert.public_bytes(Encoding.PEM)
                # Also include key if available
                if private_key:
                    output_key_data = private_key.private_bytes(
                        Encoding.PEM,
                        serialization.PrivateFormat.TraditionalOpenSSL,
                        NoEncryption()
                    )
            elif private_key:
                result_data = private_key.private_bytes(
                    Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    NoEncryption()
                )
            filename_ext = 'pem'

        elif output_fmt == 'der':
            if cert:
                result_data = cert.public_bytes(Encoding.DER)
            elif private_key:
                result_data = private_key.private_bytes(
                    Encoding.DER,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    NoEncryption()
                )
            filename_ext = 'der'

        elif output_fmt in ('crt', 'cer', 'cert'):
            if cert:
                result_data = cert.public_bytes(Encoding.PEM)
            filename_ext = output_fmt

        elif output_fmt == 'pfx':
            if cert:
                if not private_key:
                    return {
                        'success': False,
                        'error': 'Cannot create PFX without a private key. Please provide a separate .key file or use a PEM that contains the private key.'
                    }
                enc = (
                    serialization.BestAvailableEncryption(export_password.encode())
                    if export_password
                    else NoEncryption()
                )
                result_data = pkcs12.serialize_key_and_certificates(
                    name=None,
                    key=private_key,
                    cert=cert,
                    cas=additional_certs,
                    encryption_algorithm=enc,
                )
            filename_ext = 'pfx'

        elif output_fmt == 'key':
            if private_key:
                result_data = private_key.private_bytes(
                    Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    NoEncryption()
                )
            else:
                return {
                    'success': False,
                    'error': 'No private key found in the input file. The file must contain a private key to extract it.'
                }
            filename_ext = 'key'

        if result_data is None:
            return {
                'success': False,
                'error': f'Could not convert. The input file may not contain the required data for {output_fmt} output.'
            }

        return {
            'success': True,
            'data': result_data,
            'filename_ext': filename_ext,
            'key_data': output_key_data,
        }

    except Exception as e:
        return {
            'success': False,
            'error': f'Conversion failed: {str(e)}'
        }
