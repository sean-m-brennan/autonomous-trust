#!/usr/bin/env bash
# Regenerate the operator-attended test fixtures (ethne guardian edge, D8/Q9):
# a DISTINCT operator CA + operator leaf, separate from the mission CA that
# signs the device/drone certs. Used by scenarios/identity/operator-bound-*.yaml
# to exercise operator-class classification against the distinct operator anchor.
#
#   operator-ca-bundle.pem     -- the operator trust anchor (self-signed CA)
#   certs/operator_leaf.der    -- an operator credential chaining to that CA
#
# The drone credential (certs/drone_alpha.der, mission CA) deliberately does NOT
# chain to the operator CA, which is what makes it admit-but-not-operator-class.
#
# Long validity (100y) so the committed fixtures do not expire. Run from this
# directory. Requires openssl.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tmp/operator-ca.key" \
  -out "$tmp/operator-ca.crt" -days 36500 -subj "/CN=AT Test Operator CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -newkey rsa:2048 -nodes -keyout "$tmp/operator-leaf.key" \
  -out "$tmp/operator-leaf.csr" -subj "/CN=Jane Operator (PIV test)"

openssl x509 -req -in "$tmp/operator-leaf.csr" -CA "$tmp/operator-ca.crt" \
  -CAkey "$tmp/operator-ca.key" -CAcreateserial -days 36500 \
  -out "$tmp/operator-leaf.crt" \
  -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n")

cp "$tmp/operator-ca.crt" operator-ca-bundle.pem
openssl x509 -in "$tmp/operator-leaf.crt" -outform DER -out certs/operator_leaf.der

echo "Wrote operator-ca-bundle.pem and certs/operator_leaf.der"
openssl verify -CAfile operator-ca-bundle.pem "$tmp/operator-leaf.crt"
