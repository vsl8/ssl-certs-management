"""
Sectigo Certificate Download Utilities.
Downloads SSL certificates from Sectigo (InCommon) using SSL ID.
"""

import os
import tempfile
import requests
from logger import get_logger

log = get_logger('sectigo_utils')

# Sectigo base URL for InCommon
SECTIGO_BASE_URL = "https://cert-manager.com/customer/InCommon/ssl"


class SectigoDownloadError(Exception):
    """Custom exception for Sectigo download errors."""
    pass


def download_certificate(ssl_id: str, cert_format: str, timeout: int = 30) -> bytes:
    """
    Download a certificate from Sectigo using SSL ID.
    
    Args:
        ssl_id: The Sectigo SSL certificate ID
        cert_format: Certificate format (x509CO, x509IO, x509, etc.)
        timeout: Request timeout in seconds
    
    Returns:
        Certificate data as bytes
    
    Raises:
        SectigoDownloadError: If download fails
    """
    url = f"{SECTIGO_BASE_URL}?action=download&sslId={ssl_id}&format={cert_format}"
    
    try:
        log.info(f"Downloading certificate: ssl_id={ssl_id}, format={cert_format}")
        response = requests.get(url, timeout=timeout)
        
        if response.status_code != 200:
            raise SectigoDownloadError(
                f"Failed to download certificate. Status: {response.status_code}"
            )
        
        # Check if response contains certificate data
        content = response.content
        if not content or len(content) < 100:
            raise SectigoDownloadError(
                "Downloaded content appears to be empty or invalid"
            )
        
        # Basic validation - check if it looks like a certificate
        content_str = content.decode('utf-8', errors='ignore')
        if 'BEGIN CERTIFICATE' not in content_str and not content_str.startswith('MII'):
            # Check if it's an error message from Sectigo
            if 'error' in content_str.lower() or 'invalid' in content_str.lower():
                raise SectigoDownloadError(f"Sectigo returned error: {content_str[:200]}")
        
        log.info(f"Successfully downloaded certificate: ssl_id={ssl_id}, format={cert_format}, size={len(content)} bytes")
        return content
        
    except requests.RequestException as e:
        log.error(f"Network error downloading certificate: {e}")
        raise SectigoDownloadError(f"Network error: {str(e)}")


def download_server_certificate(ssl_id: str) -> bytes:
    """
    Download the server certificate (x509CO - Certificate Only).
    
    Args:
        ssl_id: The Sectigo SSL certificate ID
    
    Returns:
        Server certificate data as bytes
    """
    return download_certificate(ssl_id, 'x509CO')


def download_intermediate_certificate(ssl_id: str) -> bytes:
    """
    Download the intermediate/CA certificate (x509IO - Intermediate Only).
    
    Args:
        ssl_id: The Sectigo SSL certificate ID
    
    Returns:
        Intermediate certificate data as bytes
    """
    return download_certificate(ssl_id, 'x509IO')


def download_and_combine_certificates(ssl_id: str, private_key_path: str = None) -> tuple:
    """
    Download server and intermediate certificates from Sectigo and combine them.
    
    Args:
        ssl_id: The Sectigo SSL certificate ID
        private_key_path: Optional path to private key file to include
    
    Returns:
        Tuple of (combined_cert_data, server_cert, intermediate_cert, errors)
    """
    errors = []
    server_cert = None
    intermediate_cert = None
    
    # Download server certificate
    try:
        server_cert = download_server_certificate(ssl_id)
        log.info(f"Server certificate downloaded successfully for ssl_id={ssl_id}")
    except SectigoDownloadError as e:
        errors.append(f"Server certificate: {str(e)}")
        log.error(f"Failed to download server certificate: {e}")
    
    # Download intermediate certificate
    try:
        intermediate_cert = download_intermediate_certificate(ssl_id)
        log.info(f"Intermediate certificate downloaded successfully for ssl_id={ssl_id}")
    except SectigoDownloadError as e:
        errors.append(f"Intermediate certificate: {str(e)}")
        log.error(f"Failed to download intermediate certificate: {e}")
    
    if not server_cert and not intermediate_cert:
        return None, None, None, errors
    
    # Combine certificates
    combined = b""
    
    if server_cert:
        combined += server_cert
        if not server_cert.endswith(b'\n'):
            combined += b'\n'
    
    if intermediate_cert:
        combined += intermediate_cert
        if not intermediate_cert.endswith(b'\n'):
            combined += b'\n'
    
    # Add private key if provided
    if private_key_path and os.path.exists(private_key_path):
        try:
            with open(private_key_path, 'rb') as f:
                private_key_data = f.read()
            combined += private_key_data
            if not private_key_data.endswith(b'\n'):
                combined += b'\n'
            log.info(f"Private key added from {private_key_path}")
        except Exception as e:
            errors.append(f"Private key: {str(e)}")
            log.error(f"Failed to read private key: {e}")
    
    return combined, server_cert, intermediate_cert, errors


def extract_dns_sans(cert_data: bytes) -> list:
    """
    Extract DNS Subject Alternative Names from a certificate.
    
    Args:
        cert_data: Certificate data as bytes
    
    Returns:
        List of DNS names found in the certificate
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID
        from cryptography.hazmat.backends import default_backend
        
        # Try to load as PEM first
        try:
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        except Exception:
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
        
        # Extract SAN extension
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            dns_names = san_ext.value.get_values_for_type(x509.DNSName)
            return dns_names
        except x509.ExtensionNotFound:
            # Try to get CN as fallback
            cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if cn:
                return [cn[0].value]
            return []
            
    except Exception as e:
        log.error(f"Failed to extract DNS SANs: {e}")
        return []


def validate_ssl_id(ssl_id: str) -> bool:
    """
    Basic validation of SSL ID format.
    
    Args:
        ssl_id: The SSL ID to validate
    
    Returns:
        True if valid, False otherwise
    """
    if not ssl_id:
        return False
    
    # SSL ID should be numeric
    return ssl_id.strip().isdigit()
