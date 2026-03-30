#!/usr/bin/env bash
# Generate self-signed CA and client certificates for EAP-TLS lab testing.
# Outputs go to ~/macforge/data/certs/ (or $CERT_DIR if set).
set -euo pipefail

CERT_DIR="${CERT_DIR:-$HOME/macforge/data/certs}"
DAYS=3650
CA_SUBJ="/C=US/ST=Lab/O=MACforge Lab/CN=MACforge Lab CA"
CLIENT_SUBJ="/C=US/ST=Lab/O=MACforge Lab/CN=macforge-client"

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

echo "[gen-lab-certs] Generating lab CA..."
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout lab-ca.key -out lab-ca.pem \
  -days "$DAYS" -subj "$CA_SUBJ" 2>/dev/null

echo "[gen-lab-certs] Generating client key + CSR..."
openssl req -newkey rsa:2048 -nodes \
  -keyout client.key -out client.csr \
  -subj "$CLIENT_SUBJ" 2>/dev/null

echo "[gen-lab-certs] Signing client cert with lab CA..."
openssl x509 -req -in client.csr \
  -CA lab-ca.pem -CAkey lab-ca.key -CAcreateserial \
  -out client.pem -days "$DAYS" 2>/dev/null

rm -f client.csr lab-ca.srl

echo "[gen-lab-certs] Done. Files in $CERT_DIR:"
ls -la "$CERT_DIR"
echo ""
echo "  CA cert:     lab-ca.pem"
echo "  Client cert: client.pem"
echo "  Client key:  client.key"
echo ""
echo "Upload these via the MACforge web UI or place them in the"
echo "~/macforge/data/certs/ volume mount for immediate use."
