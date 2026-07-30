#!/usr/bin/env bash
# Regenerate the operator-attended test fixtures (ethne guardian edge, D8/Q9):
# a DISTINCT operator CA + operator leaf, separate from the mission CA that
# signs the device/drone certs. Used by scenarios/identity/operator-bound-*.yaml
# to exercise operator-class classification against the distinct operator anchor.
#
#   operator-ca-bundle.pem     -- the operator trust anchor (self-signed CA)
#   certs/operator_leaf.der    -- an operator credential chaining to that CA
#   certs/operator_leaf.key    -- that leaf's PRIVATE key (see below)
#   certs/impostor_leaf.key    -- an unrelated key, for the forgery scenario
#
# The leaf private key is kept deliberately. It stands in for the PIV/CAC token
# a real operator holds, and the operator-key scenarios need to SIGN with it at
# scenario time (both adapters do, which is how the two implementations are held
# to one signature scheme). Committing a private key is safe here and only here:
# this CA is a test anchor with no standing anywhere, and a fixture signature
# that could not be produced from the fixtures would have to be pinned as bytes
# instead, which pins one implementation's output rather than the rule.
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
cp "$tmp/operator-leaf.key" certs/operator_leaf.key

# An unrelated key of the same kind, so the forged-binding scenario differs from
# the valid one in exactly one thing: WHO signed. A forgery that also differed in
# algorithm or size would pass for the wrong reason.
openssl genrsa -out certs/impostor_leaf.key 2048 2>/dev/null

echo "Wrote operator-ca-bundle.pem, certs/operator_leaf.{der,key}, certs/impostor_leaf.key"
openssl verify -CAfile operator-ca-bundle.pem "$tmp/operator-leaf.crt"
