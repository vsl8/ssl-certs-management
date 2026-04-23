"""
Certificate conversion utilities.
Supports conversion between PEM, DER, CRT, CER, PFX/P12, P7B, KEY, JKS formats.
"""

import io
from logger import get_logger
from cryptography import x509

log = get_logger('conversion_utils')
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7, Encoding, NoEncryption
from cryptography.hazmat.backends import default_backend

try:
    import jks
    JKS_AVAILABLE = True
except ImportError:
    JKS_AVAILABLE = False
    log.warning('pyjks not installed - JKS format will not be available')


# Supported input formats and what they can convert to
CONVERSION_MAP = {
    'pem': ['der', 'crt', 'cer', 'pfx', 'key', 'jks'],
    'crt': ['pem', 'der', 'cer', 'pfx', 'key', 'jks'],
    'cer': ['pem', 'der', 'crt', 'pfx', 'key', 'jks'],
    'der': ['pem', 'crt', 'cer', 'pfx', 'jks'],
    'pfx': ['pem', 'crt', 'der', 'key', 'jks'],
    'p12': ['pem', 'crt', 'der', 'key', 'jks'],
    'p7b': ['pem', 'crt', 'der', 'jks'],
    'key': ['pem', 'der'],
    'jks': ['pem', 'crt', 'cer', 'der', 'pfx', 'p12', 'key'],
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


def _load_jks_keystore(file_data, password=None):
    """
    Load a JKS keystore and extract certificates and private keys.
    
    Returns:
        tuple: (private_key, certificate, additional_certs) or raises exception
    """
    if not JKS_AVAILABLE:
        raise ValueError('JKS support not available. Install pyjks: pip install pyjks')
    
    pwd = password or ''
    keystore = jks.KeyStore.load(file_data, pwd)
    
    cert = None
    private_key = None
    additional_certs = []
    
    # Process private key entries (PrivateKeyEntry contains both key and cert chain)
    for alias, entry in keystore.private_keys.items():
        if hasattr(entry, 'pkey') and entry.pkey:
            # Decrypt the key if needed
            if entry.is_decrypted():
                key_der = entry.pkey
            else:
                entry.decrypt(pwd)
                key_der = entry.pkey
            
            try:
                private_key = serialization.load_der_private_key(
                    key_der, password=None, backend=default_backend()
                )
            except Exception:
                # Try loading as PKCS8
                try:
                    private_key = serialization.load_der_private_key(
                        key_der, password=None, backend=default_backend()
                    )
                except Exception as e:
                    log.warning(f'Could not load private key from JKS entry {alias}: {e}')
        
        # Get certificate chain from the entry
        if hasattr(entry, 'cert_chain') and entry.cert_chain:
            for cert_tuple in entry.cert_chain:
                cert_type, cert_der = cert_tuple
                try:
                    loaded_cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    if cert is None:
                        cert = loaded_cert
                    else:
                        additional_certs.append(loaded_cert)
                except Exception as e:
                    log.warning(f'Could not load certificate from chain: {e}')
    
    # Process trusted certificate entries
    for alias, entry in keystore.certs.items():
        if hasattr(entry, 'cert') and entry.cert:
            try:
                loaded_cert = x509.load_der_x509_certificate(entry.cert, default_backend())
                if cert is None:
                    cert = loaded_cert
                else:
                    additional_certs.append(loaded_cert)
            except Exception as e:
                log.warning(f'Could not load trusted certificate {alias}: {e}')
    
    if cert is None and private_key is None:
        raise ValueError('No certificates or private keys found in the JKS keystore')
    
    return private_key, cert, additional_certs if additional_certs else None


def _create_jks_keystore(cert, private_key=None, additional_certs=None, password=None, alias='mykey'):
    """
    Create a JKS keystore from a certificate and optional private key.
    
    Args:
        cert: x509 certificate object
        private_key: Optional private key object
        additional_certs: Optional list of additional certificates for the chain
        password: Password for the keystore
        alias: Alias for the entry in the keystore
    
    Returns:
        bytes: JKS keystore data
    """
    if not JKS_AVAILABLE:
        raise ValueError('JKS support not available. Install pyjks: pip install pyjks')
    
    pwd = password or 'changeit'  # Default JKS password
    
    if private_key:
        # Create a PrivateKeyEntry with certificate chain
        cert_der = cert.public_bytes(Encoding.DER)
        key_der = private_key.private_bytes(
            Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            NoEncryption()
        )
        
        # Build certificate chain
        cert_chain = [(b'X.509', cert_der)]
        if additional_certs:
            for c in additional_certs:
                cert_chain.append((b'X.509', c.public_bytes(Encoding.DER)))
        
        # Create the private key entry
        pke = jks.PrivateKeyEntry.new(alias, cert_chain, key_der, 'rsa_raw')
        
        # Create keystore with the private key entry
        keystore = jks.KeyStore.new('jks', [pke])
    else:
        # Create a TrustedCertEntry (certificate only, no private key)
        cert_der = cert.public_bytes(Encoding.DER)
        tce = jks.TrustedCertEntry.new(alias, cert_der)
        
        entries = [tce]
        # Add additional certs as separate trusted entries
        if additional_certs:
            for i, c in enumerate(additional_certs):
                c_der = c.public_bytes(Encoding.DER)
                tce_extra = jks.TrustedCertEntry.new(f'{alias}_chain_{i}', c_der)
                entries.append(tce_extra)
        
        keystore = jks.KeyStore.new('jks', entries)
    
    # Serialize the keystore
    return keystore.saves(pwd)


def convert_certificate(file_data, input_format, output_format, password=None, export_password=None, key_data=None, key_password=None):
    """
    Convert a certificate from one format to another.

    Args:
        file_data: Certificate file bytes
        input_format: Input file format (pem, crt, cer, der, pfx, p12, p7b, key, jks)
        output_format: Output file format
        password: Password for encrypted input files (PFX/P12/JKS)
        export_password: Password for output PFX/JKS files
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
        elif input_fmt == 'jks':
            # Load JKS keystore
            try:
                private_key, cert, additional_certs = _load_jks_keystore(file_data, password)
            except Exception as e:
                return {'success': False, 'error': f'Could not load JKS keystore: {str(e)}'}
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

        elif output_fmt == 'jks':
            if not JKS_AVAILABLE:
                return {
                    'success': False,
                    'error': 'JKS support not available. Install pyjks: pip install pyjks'
                }
            if cert:
                try:
                    jks_password = export_password or 'changeit'
                    result_data = _create_jks_keystore(
                        cert, private_key, additional_certs, jks_password
                    )
                except Exception as e:
                    return {
                        'success': False,
                        'error': f'Failed to create JKS keystore: {str(e)}'
                    }
            else:
                return {
                    'success': False,
                    'error': 'Cannot create JKS keystore without a certificate.'
                }
            filename_ext = 'jks'

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
