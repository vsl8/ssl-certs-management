"""
Certificate parsing utilities.
Supports: PEM, CRT, CER, DER, PFX/P12, KEY files.
"""

import os
import json
import hashlib
from datetime import datetime, timezone
from logger import get_logger

log = get_logger('cert_utils')
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.hazmat.backends import default_backend


SUPPORTED_EXTENSIONS = {
    '.pem', '.crt', '.cer', '.der', '.p12', '.pfx',
    '.key', '.pki', '.pkcs', '.cert', '.ca-bundle', '.p7b', '.p7c'
}


def get_file_extension(filename):
    """Get normalized file extension."""
    _, ext = os.path.splitext(filename.lower())
    return ext


def is_supported_file(filename):
    """Check if the file extension is supported."""
    return get_file_extension(filename) in SUPPORTED_EXTENSIONS


def parse_certificate(file_data, filename, password=None):
    """
    Parse a certificate file and return its details.
    Attempts multiple parsing strategies based on file extension.
    """
    ext = get_file_extension(filename)
    cert = None
    private_key = None
    parse_errors = []

    # Try PFX/P12 format
    if ext in ('.p12', '.pfx'):
        try:
            from cryptography.hazmat.primitives.serialization import pkcs12
            pwd = password.encode() if password else None
            private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                file_data, pwd, default_backend()
            )
        except Exception as e:
            parse_errors.append(f"PFX/P12 parse error: {str(e)}")

    # Try PKCS7/P7B format
    elif ext in ('.p7b', '.p7c'):
        try:
            from cryptography.hazmat.primitives.serialization import pkcs7
            certs = pkcs7.load_pem_pkcs7_certificates(file_data)
            if certs:
                cert = certs[0]
        except Exception:
            try:
                from cryptography.hazmat.primitives.serialization import pkcs7
                certs = pkcs7.load_der_pkcs7_certificates(file_data)
                if certs:
                    cert = certs[0]
            except Exception as e:
                parse_errors.append(f"PKCS7 parse error: {str(e)}")

    # Try KEY file (private key only)
    elif ext == '.key':
        try:
            pwd = password.encode() if password else None
            private_key = serialization.load_pem_private_key(
                file_data, password=pwd, backend=default_backend()
            )
            return _build_key_info(private_key, filename, ext, file_data)
        except Exception:
            try:
                private_key = serialization.load_der_private_key(
                    file_data, password=None, backend=default_backend()
                )
                return _build_key_info(private_key, filename, ext, file_data)
            except Exception as e:
                parse_errors.append(f"Key parse error: {str(e)}")

    # Try PEM format first, then DER
    else:
        try:
            cert = x509.load_pem_x509_certificate(file_data, default_backend())
        except Exception:
            try:
                cert = x509.load_der_x509_certificate(file_data, default_backend())
            except Exception as e:
                parse_errors.append(f"Certificate parse error: {str(e)}")

    if cert is None:
        return {
            'success': False,
            'error': '; '.join(parse_errors) if parse_errors else 'Unable to parse certificate',
            'filename': filename,
            'file_type': ext.lstrip('.'),
        }

    return _extract_cert_details(cert, filename, ext, file_data)


def _build_key_info(private_key, filename, ext, file_data):
    """Build info dict for a private key file."""
    key_size = None
    if isinstance(private_key, rsa.RSAPrivateKey):
        key_size = private_key.key_size
        key_type = 'RSA'
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        key_size = private_key.key_size
        key_type = 'EC'
    elif isinstance(private_key, dsa.DSAPrivateKey):
        key_size = private_key.key_size
        key_type = 'DSA'
    else:
        key_type = 'Unknown'

    sha256 = hashlib.sha256(file_data).hexdigest()

    return {
        'success': True,
        'filename': filename,
        'file_type': ext.lstrip('.'),
        'file_size': len(file_data),
        'common_name': f'Private Key ({key_type})',
        'organization': None,
        'organizational_unit': None,
        'country': None,
        'state': None,
        'locality': None,
        'email': None,
        'issuer_common_name': None,
        'issuer_organization': None,
        'issuer_country': None,
        'valid_from': None,
        'valid_until': None,
        'serial_number': None,
        'signature_algorithm': key_type,
        'key_size': key_size,
        'version': None,
        'is_ca': False,
        'fingerprint_sha256': sha256,
        'fingerprint_sha1': hashlib.sha1(file_data).hexdigest(),
        'san_domains': None,
    }


def _extract_cert_details(cert, filename, ext, file_data):
    """Extract all details from an x509 certificate object."""

    # Subject details
    subject = cert.subject
    common_name = _get_name_attr(subject, NameOID.COMMON_NAME)
    organization = _get_name_attr(subject, NameOID.ORGANIZATION_NAME)
    organizational_unit = _get_name_attr(subject, NameOID.ORGANIZATIONAL_UNIT_NAME)
    country = _get_name_attr(subject, NameOID.COUNTRY_NAME)
    state = _get_name_attr(subject, NameOID.STATE_OR_PROVINCE_NAME)
    locality = _get_name_attr(subject, NameOID.LOCALITY_NAME)
    email = _get_name_attr(subject, NameOID.EMAIL_ADDRESS)

    # Issuer details
    issuer = cert.issuer
    issuer_cn = _get_name_attr(issuer, NameOID.COMMON_NAME)
    issuer_org = _get_name_attr(issuer, NameOID.ORGANIZATION_NAME)
    issuer_country = _get_name_attr(issuer, NameOID.COUNTRY_NAME)

    # Validity
    valid_from = cert.not_valid_before_utc
    valid_until = cert.not_valid_after_utc

    # Technical
    serial = format(cert.serial_number, 'X')
    sig_algo = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid.dotted_string)

    key_size = None
    pub_key = cert.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey):
        key_size = pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_size = pub_key.key_size
    elif isinstance(pub_key, dsa.DSAPublicKey):
        key_size = pub_key.key_size

    version = cert.version.value

    # CA check
    is_ca = False
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        is_ca = basic_constraints.value.ca
    except x509.ExtensionNotFound:
        pass

    # Fingerprints
    fp_sha256 = cert.fingerprint(hashes.SHA256()).hex()
    fp_sha1 = cert.fingerprint(hashes.SHA1()).hex()

    # SAN
    san_domains = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san_domains = san_ext.value.get_values_for_type(x509.DNSName)
        try:
            san_domains += [str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)]
        except Exception:
            pass
    except x509.ExtensionNotFound:
        pass

    now = datetime.now(timezone.utc)
    days_until = (valid_until - now).days if valid_until else None
    is_expired = days_until is not None and days_until <= 0

    return {
        'success': True,
        'filename': filename,
        'file_type': ext.lstrip('.'),
        'file_size': len(file_data),
        'common_name': common_name,
        'organization': organization,
        'organizational_unit': organizational_unit,
        'country': country,
        'state': state,
        'locality': locality,
        'email': email,
        'issuer_common_name': issuer_cn,
        'issuer_organization': issuer_org,
        'issuer_country': issuer_country,
        'valid_from': valid_from,
        'valid_until': valid_until,
        'serial_number': serial,
        'signature_algorithm': sig_algo,
        'key_size': key_size,
        'version': version,
        'is_ca': is_ca,
        'fingerprint_sha256': fp_sha256,
        'fingerprint_sha1': fp_sha1,
        'san_domains': json.dumps(san_domains) if san_domains else None,
        'days_until_expiry': days_until,
        'is_expired': is_expired,
    }


def _get_name_attr(name, oid):
    """Safely get a name attribute from x509 Name object."""
    try:
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            return attrs[0].value
    except Exception:
        pass
    return None


def refresh_cert_expiry(cert_record):
    """Refresh the days_until_expiry and is_expired for a certificate record."""
    if cert_record.valid_until:
        now = datetime.now(timezone.utc)
        valid_until = cert_record.valid_until
        if valid_until.tzinfo is None:
            valid_until = valid_until.replace(tzinfo=timezone.utc)
        days = (valid_until - now).days
        cert_record.days_until_expiry = days
        cert_record.is_expired = days <= 0
    return cert_record


def extract_certificate_chain(file_path, password=None):
    """
    Extract certificate chain from a certificate file.
    Returns a list of certificate details in hierarchical order
    (end-entity first, then intermediates, then root).
    """
    chain = []
    
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
    except Exception as e:
        log.warning('Could not read certificate file for chain extraction: %s', e)
        return chain
    
    ext = get_file_extension(file_path)
    certs = []
    
    # Handle PFX/P12 format
    if ext in ('.p12', '.pfx'):
        try:
            from cryptography.hazmat.primitives.serialization import pkcs12
            pwd = password.encode() if password else None
            private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                file_data, pwd, default_backend()
            )
            if cert:
                certs.append(cert)
            if additional_certs:
                certs.extend(additional_certs)
        except Exception as e:
            log.warning('Could not parse PFX for chain: %s', e)
    
    # Handle PKCS7/P7B format
    elif ext in ('.p7b', '.p7c'):
        try:
            from cryptography.hazmat.primitives.serialization import pkcs7
            try:
                certs = pkcs7.load_pem_pkcs7_certificates(file_data)
            except Exception:
                certs = pkcs7.load_der_pkcs7_certificates(file_data)
        except Exception as e:
            log.warning('Could not parse P7B for chain: %s', e)
    
    # Handle PEM format (may contain multiple certificates)
    elif ext in ('.pem', '.crt', '.cer', '.cert', '.ca-bundle'):
        # Try to load multiple PEM certificates
        try:
            # Split by PEM markers
            pem_certs = []
            current = b''
            in_cert = False
            
            for line in file_data.split(b'\n'):
                if b'-----BEGIN CERTIFICATE-----' in line:
                    in_cert = True
                    current = line + b'\n'
                elif b'-----END CERTIFICATE-----' in line:
                    current += line + b'\n'
                    pem_certs.append(current)
                    current = b''
                    in_cert = False
                elif in_cert:
                    current += line + b'\n'
            
            for pem_data in pem_certs:
                try:
                    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
                    certs.append(cert)
                except Exception:
                    pass
            
            # If no PEM certs found, try DER
            if not certs:
                try:
                    cert = x509.load_der_x509_certificate(file_data, default_backend())
                    certs.append(cert)
                except Exception:
                    pass
        except Exception as e:
            log.warning('Could not parse certificate for chain: %s', e)
    
    # Handle DER format
    elif ext == '.der':
        try:
            cert = x509.load_der_x509_certificate(file_data, default_backend())
            certs.append(cert)
        except Exception as e:
            log.warning('Could not parse DER for chain: %s', e)
    
    # Extract details for each certificate in chain
    for cert in certs:
        try:
            subject = cert.subject
            issuer = cert.issuer
            
            # Check if self-signed (subject == issuer)
            is_self_signed = (subject == issuer)
            
            # CA check
            is_ca = False
            try:
                basic_constraints = cert.extensions.get_extension_for_oid(
                    ExtensionOID.BASIC_CONSTRAINTS
                )
                is_ca = basic_constraints.value.ca
            except x509.ExtensionNotFound:
                pass
            
            # Determine type
            if is_self_signed and is_ca:
                cert_type = 'Root CA'
            elif is_ca:
                cert_type = 'Intermediate CA'
            else:
                cert_type = 'End Entity'
            
            chain.append({
                'common_name': _get_name_attr(subject, NameOID.COMMON_NAME) or 'Unknown',
                'organization': _get_name_attr(subject, NameOID.ORGANIZATION_NAME),
                'issuer_common_name': _get_name_attr(issuer, NameOID.COMMON_NAME) or 'Unknown',
                'issuer_organization': _get_name_attr(issuer, NameOID.ORGANIZATION_NAME),
                'serial_number': format(cert.serial_number, 'X'),
                'valid_from': cert.not_valid_before_utc.strftime('%Y-%m-%d'),
                'valid_until': cert.not_valid_after_utc.strftime('%Y-%m-%d'),
                'is_ca': is_ca,
                'is_self_signed': is_self_signed,
                'cert_type': cert_type,
                'fingerprint_sha256': cert.fingerprint(hashes.SHA256()).hex()[:16] + '...',
            })
        except Exception as e:
            log.warning('Could not extract chain cert details: %s', e)
    
    # Sort chain: End Entity first, then Intermediates, then Root
    def sort_key(c):
        if c['cert_type'] == 'End Entity':
            return 0
        elif c['cert_type'] == 'Intermediate CA':
            return 1
        else:  # Root CA
            return 2
    
    chain.sort(key=sort_key)
    
    return chain
