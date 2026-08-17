# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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
"""CLI operator activation (no TUI; the Textual console is the separate
``autonomous-trust-operator`` package).

    python -m autonomous_trust.core._python.operator \
        --module /usr/lib/opensc-pkcs11.so --ca-bundle /etc/at/agency-ca.pem \
        --cfg-dir /etc/at

(The concrete ``_python`` path is used because the backend-redirector's import
alias does not support ``runpy``/``-m`` on a redirected submodule; ordinary
imports of ``autonomous_trust.core.operator`` work normally.)

PIN is prompted interactively (getpass) and never stored. Starting the
discovery-capable ``OperatorNode`` lands in P3; P1 performs activation +
credential binding + policy write.
"""
from __future__ import annotations

import argparse
import logging
import sys

from .activate import activate
from ..identity.zta import ZtaStatus
from ..processes import LOG_FORMAT, LOG_DATEFMT


def _build_token(args):
    """Open a PivToken: a real PKCS#11 card, or a SoftwareToken for dev/test."""
    if args.software_cert and args.software_key:
        # Dev/CI path: a software token from a PEM cert + private key.
        from cryptography.hazmat.primitives.serialization import (
            Encoding, load_pem_private_key)
        from cryptography.x509 import load_pem_x509_certificate
        from ..identity.zta.piv.pkcs11 import SoftwareToken
        with open(args.software_cert, 'rb') as fp:
            cert_der = load_pem_x509_certificate(fp.read()).public_bytes(Encoding.DER)
        with open(args.software_key, 'rb') as fp:
            key = load_pem_private_key(fp.read(), password=None)
        return SoftwareToken(cert_der, key)
    import getpass
    from ..identity.zta.piv.pkcs11 import PyKcs11Token
    pin = getpass.getpass('PIV PIN: ')
    return PyKcs11Token(args.module, pin, slot=args.slot)


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format=LOG_FORMAT, datefmt=LOG_DATEFMT)
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--module',
                    help='PKCS#11 module path (default: autodetected '
                         'opensc-pkcs11.so, or $AUTONOMOUS_TRUST_PKCS11_MODULE)')
    ap.add_argument('--slot', type=int, default=None, help='PKCS#11 slot index')
    # Not `required=True`: the co-signing verbs below touch only the operator
    # keystore, so demanding a CA bundle for them would be a lie about what they need.
    # Activation still refuses to proceed without one.
    ap.add_argument('--ca-bundle', default=None,
                    help='agency root/intermediate CA bundle (PEM)')
    ap.add_argument('--cfg-dir', default=None,
                    help='config dir to bind the credential + write the policy')
    ap.add_argument('--identity-id', default='',
                    help='AT identity id to bind the challenge to')
    ap.add_argument('--crl-path', default='', help='CRL path (PEM)')
    ap.add_argument('--ocsp-url', default='', help='OCSP responder URL')
    # TOTP second factor (RFC 6238).
    ap.add_argument('--enroll-totp', action='store_true',
                    help='first-activation: generate + enroll a new TOTP secret')
    ap.add_argument('--totp-code', default=None,
                    help='TOTP code (prompted if omitted when a factor is enrolled)')
    # The guardian identity (ethne D15) — OFF unless asked for. Binding publishes
    # one key per operator across that operator's nodes, which links them; AT must
    # never require that, so the flag exists and the default is anonymous.
    ap.add_argument('--bind-operator-key', action='store_true',
                    help='also bind your ed25519 operator key to this node, so it '
                         'can name WHICH human guards it (opt-in; links the nodes '
                         'you guard to one another)')
    ap.add_argument('--operator-keystore', default='',
                    help='directory holding your operator key '
                         '(default $AT_OPERATOR_KEYSTORE, else '
                         '~/.config/at-operator). Never the node config dir.')
    # Dev/CI software-token path (no card).
    ap.add_argument('--software-cert', default=None,
                    help='dev only: PEM cert for a SoftwareToken')
    ap.add_argument('--software-key', default=None,
                    help='dev only: PEM private key for a SoftwareToken')
    ap.add_argument('--sign-file', default=None, metavar='PATH',
                    help='co-sign a governance record instead of activating: sign the '
                         'bytes in PATH with this operator ed25519 key and print the '
                         'signature as hex. Needs no PIV token — the key is already '
                         'bound. Use "-" to read stdin.')
    ap.add_argument('--print-operator-key', action='store_true',
                    help='print this operator ed25519 public key as hex and exit')
    args = ap.parse_args(argv)

    # The co-signing verbs touch only the operator keystore, so they run without a
    # card and without the CA bundle's activation machinery.
    if args.print_operator_key or args.sign_file:
        from .activate import operator_public_key, sign_with_operator_key
        try:
            if args.print_operator_key:
                print(operator_public_key(args.operator_keystore).hex())
                return 0
            payload = (sys.stdin.buffer.read() if args.sign_file == '-'
                       else open(args.sign_file, 'rb').read())
        except (FileNotFoundError, OSError) as err:
            print('ERROR: %s' % err, file=sys.stderr)
            return 2
        # Say what is being signed. A seam that asks a human to sign opaque bytes has
        # taught them to sign anything; the tier that exported these bytes should have
        # shipped a readable description alongside, and this at least pins the size and
        # digest so the two can be compared.
        import hashlib
        print('signing %d bytes, sha256=%s'
              % (len(payload), hashlib.sha256(payload).hexdigest()), file=sys.stderr)
        try:
            print(sign_with_operator_key(payload, args.operator_keystore).hex())
        except FileNotFoundError as err:
            print('ERROR: %s' % err, file=sys.stderr)
            return 2
        return 0

    if not args.ca_bundle:
        ap.error('--ca-bundle is required to activate (not needed by --sign-file '
                 'or --print-operator-key)')
    if not (args.software_cert and args.software_key) and not args.module:
        ap.error('one of --module (real card) or --software-cert/--software-key '
                 '(dev) is required')

    # Resolve the TOTP second factor: enroll a fresh secret, or load the one
    # already in the operator policy.
    from .activate import enroll_totp, load_totp_secret
    totp_secret = ''
    if args.enroll_totp:
        totp_secret, uri = enroll_totp(args.identity_id or 'operator')
        print('TOTP enrollment -- add this to your authenticator, then enter a '
              'code:\n  %s' % uri)
    elif args.cfg_dir:
        totp_secret = load_totp_secret(args.cfg_dir)
    totp_code = args.totp_code
    if totp_secret and totp_code is None:
        import getpass
        totp_code = getpass.getpass('TOTP code: ')

    try:
        token = _build_token(args)
    except Exception as err:
        print('ERROR: could not open PIV token: %s' % err, file=sys.stderr)
        return 2
    try:
        result = activate(token, args.ca_bundle, cfg_dir=args.cfg_dir,
                          identity_id=args.identity_id,
                          crl_path=args.crl_path, ocsp_url=args.ocsp_url,
                          totp_secret=totp_secret, totp_code=totp_code or '',
                          bind_operator_key=args.bind_operator_key,
                          operator_keystore=args.operator_keystore)
    finally:
        token.close()

    if result.status is ZtaStatus.VERIFIED:
        print('ACTIVATED: %s (cred sha256=%s)'
              % (result.issuer, result.credential_hash.hex()[:16]))
        if args.bind_operator_key and args.cfg_dir:
            from .activate import operator_key_path
            print('GUARDIAN KEY bound for this node; your key stays at %s '
                  '(back it up — a lost key means re-binding every node you '
                  'guard, a stolen one impersonates you on all of them)'
                  % operator_key_path(args.operator_keystore))
        return 0
    print('DENIED [%s]: %s' % (result.status.value, result.reason), file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
