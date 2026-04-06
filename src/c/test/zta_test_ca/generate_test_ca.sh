#!/bin/bash
# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************
#
# Generate a test PKI for ZTA integration testing.
#
# Produces:
#   ca/              Root CA cert + key
#   intermediate/    Intermediate CA cert + key (signed by root)
#   certs/           Leaf certs (signed by intermediate):
#     command_post.pem   Valid machine cert (CN=command-post)
#     squad_leader.pem   Valid machine cert (CN=squad-leader)
#     drone_alpha.pem    Valid machine cert (CN=drone-alpha) - will be "revoked"
#     drone_bravo.pem    Valid machine cert (CN=drone-bravo)
#     expired.pem        Expired cert (for testing expiry detection)
#     unknown_ca.pem     Cert signed by a different (untrusted) CA
#   ca-bundle.pem    CA chain: root + intermediate (for verifier)
#   crl/             Certificate revocation list
#
# Usage: ./generate_test_ca.sh [output_dir]

set -euo pipefail

OUTDIR="${1:-$(dirname "$0")/output}"
DAYS_VALID=3650
DAYS_EXPIRED=0

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"/{ca,intermediate,certs,crl}

echo "=== Generating test PKI in $OUTDIR ==="

# ---- Root CA ----
echo "--- Root CA ---"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$OUTDIR/ca/root-ca.key" -out "$OUTDIR/ca/root-ca.pem" \
    -days $DAYS_VALID -nodes \
    -subj "/C=US/ST=Test/O=AT Test PKI/CN=AT Test Root CA" 2>/dev/null

# ---- Intermediate CA ----
echo "--- Intermediate CA ---"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$OUTDIR/intermediate/intermediate-ca.key" \
    -out "$OUTDIR/intermediate/intermediate-ca.csr" -nodes \
    -subj "/C=US/ST=Test/O=AT Test PKI/CN=AT Test Intermediate CA" 2>/dev/null

openssl x509 -req -in "$OUTDIR/intermediate/intermediate-ca.csr" \
    -CA "$OUTDIR/ca/root-ca.pem" -CAkey "$OUTDIR/ca/root-ca.key" \
    -CAcreateserial -out "$OUTDIR/intermediate/intermediate-ca.pem" \
    -days $DAYS_VALID \
    -extfile <(echo -e "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign") 2>/dev/null

# ---- CA Bundle ----
cat "$OUTDIR/intermediate/intermediate-ca.pem" "$OUTDIR/ca/root-ca.pem" \
    > "$OUTDIR/ca-bundle.pem"

# ---- Leaf cert helper ----
gen_leaf() {
    local name="$1" cn="$2" days="${3:-$DAYS_VALID}"
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$OUTDIR/certs/${name}.key" \
        -out "$OUTDIR/certs/${name}.csr" -nodes \
        -subj "/C=US/ST=Test/O=AT Test/CN=${cn}" 2>/dev/null
    openssl x509 -req -in "$OUTDIR/certs/${name}.csr" \
        -CA "$OUTDIR/intermediate/intermediate-ca.pem" \
        -CAkey "$OUTDIR/intermediate/intermediate-ca.key" \
        -CAcreateserial -out "$OUTDIR/certs/${name}.pem" \
        -days "$days" 2>/dev/null
    rm -f "$OUTDIR/certs/${name}.csr"
    # Also generate DER for binary tests
    openssl x509 -in "$OUTDIR/certs/${name}.pem" -outform DER \
        -out "$OUTDIR/certs/${name}.der" 2>/dev/null
    echo "  Created $name (CN=$cn, days=$days)"
}

# ---- Leaf certs ----
echo "--- Leaf certificates ---"
gen_leaf "command_post" "command-post"
gen_leaf "squad_leader" "squad-leader"
gen_leaf "drone_alpha"  "drone-alpha"
gen_leaf "drone_bravo"  "drone-bravo"

# ---- Expired cert ----
echo "--- Expired certificate ---"
# Create a cert that expired yesterday
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$OUTDIR/certs/expired.key" \
    -out "$OUTDIR/certs/expired.csr" -nodes \
    -subj "/C=US/ST=Test/O=AT Test/CN=expired-node" 2>/dev/null
# Use faketime-like approach: create with 1-day validity, backdate
openssl x509 -req -in "$OUTDIR/certs/expired.csr" \
    -CA "$OUTDIR/intermediate/intermediate-ca.pem" \
    -CAkey "$OUTDIR/intermediate/intermediate-ca.key" \
    -CAcreateserial -out "$OUTDIR/certs/expired.pem" \
    -days 0 2>/dev/null
rm -f "$OUTDIR/certs/expired.csr"
openssl x509 -in "$OUTDIR/certs/expired.pem" -outform DER \
    -out "$OUTDIR/certs/expired.der" 2>/dev/null
echo "  Created expired (CN=expired-node)"

# ---- Unknown CA cert ----
echo "--- Unknown CA certificate ---"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$OUTDIR/certs/unknown_ca_root.key" \
    -out "$OUTDIR/certs/unknown_ca_root.pem" \
    -days $DAYS_VALID -nodes \
    -subj "/C=XX/O=Unknown CA/CN=Unknown Root" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$OUTDIR/certs/unknown_ca.key" \
    -out "$OUTDIR/certs/unknown_ca.csr" -nodes \
    -subj "/C=XX/O=Unknown/CN=unknown-node" 2>/dev/null
openssl x509 -req -in "$OUTDIR/certs/unknown_ca.csr" \
    -CA "$OUTDIR/certs/unknown_ca_root.pem" \
    -CAkey "$OUTDIR/certs/unknown_ca_root.key" \
    -CAcreateserial -out "$OUTDIR/certs/unknown_ca.pem" \
    -days $DAYS_VALID 2>/dev/null
rm -f "$OUTDIR/certs/unknown_ca.csr"
openssl x509 -in "$OUTDIR/certs/unknown_ca.pem" -outform DER \
    -out "$OUTDIR/certs/unknown_ca.der" 2>/dev/null
echo "  Created unknown_ca (signed by untrusted CA)"

# ---- CRL (empty initially; drone_alpha will be revoked during demo) ----
echo "--- CRL ---"
# Create OpenSSL CA database files
touch "$OUTDIR/intermediate/index.txt"
echo "01" > "$OUTDIR/intermediate/crlnumber"
cat > "$OUTDIR/intermediate/openssl-intermediate.cnf" <<CNFEOF
[ca]
default_ca = CA_intermediate

[CA_intermediate]
dir              = $OUTDIR/intermediate
certificate      = \$dir/intermediate-ca.pem
private_key      = \$dir/intermediate-ca.key
database         = \$dir/index.txt
crlnumber        = \$dir/crlnumber
default_md       = sha256
default_crl_days = 3650

[crl_ext]
authorityKeyIdentifier = keyid:always
CNFEOF

openssl ca -gencrl -config "$OUTDIR/intermediate/openssl-intermediate.cnf" \
    -out "$OUTDIR/crl/intermediate.crl.pem" 2>/dev/null
echo "  Created empty CRL"

# ---- Revoke drone_alpha for testing ----
echo "--- Revoking drone_alpha ---"
openssl ca -revoke "$OUTDIR/certs/drone_alpha.pem" \
    -config "$OUTDIR/intermediate/openssl-intermediate.cnf" 2>/dev/null
openssl ca -gencrl -config "$OUTDIR/intermediate/openssl-intermediate.cnf" \
    -out "$OUTDIR/crl/intermediate-revoked.crl.pem" 2>/dev/null
echo "  drone_alpha revoked; CRL with revocation saved"

echo ""
echo "=== Test PKI generated in $OUTDIR ==="
echo "  CA bundle:       $OUTDIR/ca-bundle.pem"
echo "  Valid certs:     command_post, squad_leader, drone_alpha, drone_bravo"
echo "  Expired cert:    expired"
echo "  Unknown CA cert: unknown_ca"
echo "  Empty CRL:       $OUTDIR/crl/intermediate.crl.pem"
echo "  Revoked CRL:     $OUTDIR/crl/intermediate-revoked.crl.pem"
