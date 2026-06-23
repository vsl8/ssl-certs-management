#!/bin/bash

# Script to generate test SSL certificates with various expiry dates
# This is useful for testing the SSL Certificate Manager's alert system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Output directory
OUTPUT_DIR="test_certs"

echo -e "${GREEN}SSL Certificate Generator for Testing${NC}"
echo "========================================"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Function to generate a certificate with specific validity
generate_cert() {
    local name=$1
    local days=$2
    local common_name=$3
    
    echo -e "${YELLOW}Generating certificate: ${name} (expires in ${days} days)${NC}"
    
    # Generate private key
    openssl genrsa -out "${OUTPUT_DIR}/${name}.key" 2048 2>/dev/null
    
    # Generate certificate with specific expiry
    openssl req -new -x509 -key "${OUTPUT_DIR}/${name}.key" \
        -out "${OUTPUT_DIR}/${name}.crt" \
        -days ${days} \
        -subj "/C=US/ST=Test/L=TestCity/O=TestOrg/OU=Testing/CN=${common_name}" \
        2>/dev/null
    
    # Get expiry date
    expiry_date=$(openssl x509 -in "${OUTPUT_DIR}/${name}.crt" -noout -enddate | cut -d= -f2)
    
    echo -e "${GREEN}✓ Created: ${name}.crt and ${name}.key${NC}"
    echo -e "  Common Name: ${common_name}"
    echo -e "  Expires: ${expiry_date}"
    echo ""
}

# Function to generate certificate with SAN (Subject Alternative Names)
generate_cert_with_san() {
    local name=$1
    local days=$2
    local common_name=$3
    local san_list=$4
    
    echo -e "${YELLOW}Generating certificate with SAN: ${name} (expires in ${days} days)${NC}"
    
    # Generate private key
    openssl genrsa -out "${OUTPUT_DIR}/${name}.key" 2048 2>/dev/null
    
    # Create temporary config file for SAN
    cat > "${OUTPUT_DIR}/${name}.cnf" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C=US
ST=Test
L=TestCity
O=TestOrg
OU=Testing
CN=${common_name}

[v3_req]
subjectAltName = @alt_names

[alt_names]
${san_list}
EOF
    
    # Generate CSR
    openssl req -new -key "${OUTPUT_DIR}/${name}.key" \
        -out "${OUTPUT_DIR}/${name}.csr" \
        -config "${OUTPUT_DIR}/${name}.cnf" \
        2>/dev/null
    
    # Generate self-signed certificate
    openssl x509 -req -in "${OUTPUT_DIR}/${name}.csr" \
        -signkey "${OUTPUT_DIR}/${name}.key" \
        -out "${OUTPUT_DIR}/${name}.crt" \
        -days ${days} \
        -extensions v3_req \
        -extfile "${OUTPUT_DIR}/${name}.cnf" \
        2>/dev/null
    
    # Clean up temporary files
    rm "${OUTPUT_DIR}/${name}.csr" "${OUTPUT_DIR}/${name}.cnf"
    
    # Get expiry date
    expiry_date=$(openssl x509 -in "${OUTPUT_DIR}/${name}.crt" -noout -enddate | cut -d= -f2)
    
    echo -e "${GREEN}✓ Created: ${name}.crt and ${name}.key (with SAN)${NC}"
    echo -e "  Common Name: ${common_name}"
    echo -e "  Expires: ${expiry_date}"
    echo ""
}

# Generate certificates with different expiry dates

echo "Generating certificates with various expiry dates..."
echo ""

# Critical - Expires in less than 1 day (12 hours)
# Note: We can't make it expire in less than 1 day using -days, so we'll use 1 day
generate_cert "cert_expires_1day" 1 "test-critical.example.com"

# Warning - Expires in 3 days
generate_cert "cert_expires_3days" 3 "test-warning-3days.example.com"

# Warning - Expires in 5 days
generate_cert "cert_expires_5days" 5 "test-warning-5days.example.com"

# Warning - Expires in 7 days
generate_cert "cert_expires_7days" 7 "test-warning-7days.example.com"

# Near expiry - Expires in 15 days
generate_cert "cert_expires_15days" 15 "test-info-15days.example.com"

# Valid - Expires in 30 days
generate_cert "cert_expires_30days" 30 "test-valid-30days.example.com"

# Valid - Expires in 90 days
generate_cert "cert_expires_90days" 90 "test-valid-90days.example.com"

# Certificate with multiple SANs - Expires in 2 days
generate_cert_with_san "cert_multi_domain_2days" 2 "multi.example.com" \
    "DNS.1=multi.example.com
DNS.2=www.multi.example.com
DNS.3=api.multi.example.com
DNS.4=admin.multi.example.com"

# Wildcard certificate - Expires in 4 days
generate_cert "cert_wildcard_4days" 4 "*.wildcard.example.com"

# Generate a certificate bundle (cert + intermediate + root simulation)
echo -e "${YELLOW}Generating certificate chain bundle (expires in 6 days)${NC}"

# Root CA
openssl genrsa -out "${OUTPUT_DIR}/root-ca.key" 2048 2>/dev/null
openssl req -new -x509 -key "${OUTPUT_DIR}/root-ca.key" \
    -out "${OUTPUT_DIR}/root-ca.crt" \
    -days 365 \
    -subj "/C=US/ST=Test/L=TestCity/O=TestOrg/OU=Root CA/CN=Test Root CA" \
    2>/dev/null

# Intermediate CA
openssl genrsa -out "${OUTPUT_DIR}/intermediate-ca.key" 2048 2>/dev/null
openssl req -new -key "${OUTPUT_DIR}/intermediate-ca.key" \
    -out "${OUTPUT_DIR}/intermediate-ca.csr" \
    -subj "/C=US/ST=Test/L=TestCity/O=TestOrg/OU=Intermediate CA/CN=Test Intermediate CA" \
    2>/dev/null
openssl x509 -req -in "${OUTPUT_DIR}/intermediate-ca.csr" \
    -CA "${OUTPUT_DIR}/root-ca.crt" \
    -CAkey "${OUTPUT_DIR}/root-ca.key" \
    -CAcreateserial \
    -out "${OUTPUT_DIR}/intermediate-ca.crt" \
    -days 180 \
    2>/dev/null

# End-entity certificate
openssl genrsa -out "${OUTPUT_DIR}/cert_chain_6days.key" 2048 2>/dev/null
openssl req -new -key "${OUTPUT_DIR}/cert_chain_6days.key" \
    -out "${OUTPUT_DIR}/cert_chain_6days.csr" \
    -subj "/C=US/ST=Test/L=TestCity/O=TestOrg/OU=Testing/CN=chain.example.com" \
    2>/dev/null
openssl x509 -req -in "${OUTPUT_DIR}/cert_chain_6days.csr" \
    -CA "${OUTPUT_DIR}/intermediate-ca.crt" \
    -CAkey "${OUTPUT_DIR}/intermediate-ca.key" \
    -CAcreateserial \
    -out "${OUTPUT_DIR}/cert_chain_6days.crt" \
    -days 6 \
    2>/dev/null

# Create full chain bundle
cat "${OUTPUT_DIR}/cert_chain_6days.crt" \
    "${OUTPUT_DIR}/intermediate-ca.crt" \
    "${OUTPUT_DIR}/root-ca.crt" \
    > "${OUTPUT_DIR}/cert_chain_6days_fullchain.crt"

# Clean up CSR files
rm "${OUTPUT_DIR}/intermediate-ca.csr" "${OUTPUT_DIR}/cert_chain_6days.csr"

echo -e "${GREEN}✓ Created certificate chain bundle${NC}"
echo ""

# Generate PFX/P12 file (expires in 5 days)
echo -e "${YELLOW}Generating PFX/P12 file (expires in 5 days)${NC}"
openssl genrsa -out "${OUTPUT_DIR}/cert_pfx_5days.key" 2048 2>/dev/null
openssl req -new -x509 -key "${OUTPUT_DIR}/cert_pfx_5days.key" \
    -out "${OUTPUT_DIR}/cert_pfx_5days.crt" \
    -days 5 \
    -subj "/C=US/ST=Test/L=TestCity/O=TestOrg/OU=Testing/CN=pfx.example.com" \
    2>/dev/null

openssl pkcs12 -export \
    -out "${OUTPUT_DIR}/cert_pfx_5days.pfx" \
    -inkey "${OUTPUT_DIR}/cert_pfx_5days.key" \
    -in "${OUTPUT_DIR}/cert_pfx_5days.crt" \
    -passout pass:test123 \
    2>/dev/null

echo -e "${GREEN}✓ Created PFX file (password: test123)${NC}"
echo ""

# Summary
echo "========================================"
echo -e "${GREEN}Certificate generation completed!${NC}"
echo ""
echo "Generated certificates in: ${OUTPUT_DIR}/"
echo ""
echo "Certificate Summary:"
echo "  • cert_expires_1day.*       - Expires in 1 day (CRITICAL)"
echo "  • cert_expires_3days.*      - Expires in 3 days"
echo "  • cert_expires_5days.*      - Expires in 5 days"
echo "  • cert_expires_7days.*      - Expires in 7 days"
echo "  • cert_expires_15days.*     - Expires in 15 days"
echo "  • cert_expires_30days.*     - Expires in 30 days"
echo "  • cert_expires_90days.*     - Expires in 90 days"
echo "  • cert_multi_domain_2days.* - Multi-domain cert (expires in 2 days)"
echo "  • cert_wildcard_4days.*     - Wildcard cert (expires in 4 days)"
echo "  • cert_chain_6days.*        - Certificate with chain (expires in 6 days)"
echo "  • cert_pfx_5days.pfx        - PFX/P12 format (expires in 5 days, password: test123)"
echo ""
echo -e "${YELLOW}Note: OpenSSL's -days parameter uses full day increments.${NC}"
echo -e "${YELLOW}For sub-24-hour testing, use the 1-day certificate.${NC}"
echo ""
echo "To upload these certificates to the SSL Certificate Manager:"
echo "  1. Start your Flask application"
echo "  2. Navigate to the Certificates page"
echo "  3. Upload the .crt and .key files from the ${OUTPUT_DIR}/ directory"
echo ""
