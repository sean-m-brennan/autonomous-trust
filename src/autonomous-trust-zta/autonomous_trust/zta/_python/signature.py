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
"""A signature by a certificate's key over some bytes: the one check every
holder-asserted binding needs (a credential binding, an operator-key binding,
a PIV challenge-response). RSA PKCS#1 v1.5 or ECDSA, both with SHA-256.

It lived on the PIV verifier, which is now the operator distribution's
(FEATURE_SPLIT_PLAN Phase 6); the binding checks here use it without PIV, and
``PivVerifier`` delegates to it.
"""


def verify_cert_signature(cert_der: bytes, data: bytes, signature: bytes) -> bool:
    """Whether ``signature`` over ``data`` verifies under the public key of
    the DER certificate ``cert_der``. False (never raises) on anything else:
    an unreadable certificate, another key type, a bad signature."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.x509 import load_der_x509_certificate
    try:
        pub = load_der_x509_certificate(cert_der).public_key()
    except Exception:
        return False
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        else:
            return False
    except InvalidSignature:
        return False
    except Exception:
        return False
    return True
