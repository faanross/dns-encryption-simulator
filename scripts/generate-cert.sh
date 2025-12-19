#!/bin/bash

# Generate self-signed certificate for localhost testing
# This creates a certificate valid for both 127.0.0.1 and localhost

CERT_DIR="./certs"
DOMAIN="timeserversync.test"

echo "Generating self-signed certificate for localhost testing..."

# Create certs directory
mkdir -p "$CERT_DIR"

# Generate private key
openssl genrsa -out "$CERT_DIR/server.key" 2048

# Create certificate signing request configuration
cat > "$CERT_DIR/cert.conf" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C=US
ST=Test
L=Test
O=DNS Simulator
OU=Testing
CN=$DOMAIN

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN
DNS.2 = localhost
DNS.3 = *.timeserversync.test
IP.1 = 127.0.0.1
EOF

# Generate certificate
openssl req -new -x509 -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -days 365 \
    -config "$CERT_DIR/cert.conf" \
    -extensions v3_req

echo ""
echo "✓ Certificate generated successfully!"
echo "  Certificate: $CERT_DIR/server.crt"
echo "  Private Key: $CERT_DIR/server.key"
echo ""
echo "Certificate details:"
openssl x509 -in "$CERT_DIR/server.crt" -noout -text | grep -A2 "Subject:"
openssl x509 -in "$CERT_DIR/server.crt" -noout -text | grep -A3 "Subject Alternative Name"