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
"""No-hardware, no-network mocks for the operator console (PIV_MFA_OPERATOR_
ACCESS_PLAN.md §7.1): a self-minted test PKI + ``SoftwareToken`` that stands in
for a PKCS#11 PIV card (stage 1-2 of §7.1), and a ``DemoNode`` that serves a
seeded directory and answers submitted ``Task``s with synthetic ``TaskResult``s.

Together these let ``python -m autonomous_trust.operator --demo`` exercise the
whole flow -- real PIV challenge-response activation, then request -> result ->
proof badge -- with zero card, cohort, or network. The live card is later just a
swap of the PKCS#11 module path + slot (the software token implements the same
``PivToken`` interface)."""
from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from queue import Empty
from typing import Any, Tuple


def demo_directory() -> Any:
    """A small, self-describing ResourceDirectory for the no-node demo."""
    from autonomous_trust.core.operator.resource_directory import (
        build_directory, CapabilityDescriptor, PeerInfo)
    descriptors = {
        'analyze': CapabilityDescriptor(
            'analyze', kind='service', description='run analysis on a blob',
            required_tier=1, arg_schema={'blob': 'str', 'mode': 'str'}),
        'airquality_stream': CapabilityDescriptor(
            'airquality_stream', kind='data_stream',
            description='live air-quality telemetry', required_tier=2,
            arg_schema={'rate_hz': 'int'}),
        'strike': CapabilityDescriptor(
            'strike', kind='service', description='privileged action',
            required_tier=4),
    }
    providers = {'analyze': ['drone-1'],
                 'airquality_stream': ['drone-1', 'drone-2'],
                 'strike': ['command-1']}
    peers = {
        'drone-1': PeerInfo('drone-1', name='alpha', tier=3, reputation=0.82),
        'drone-2': PeerInfo('drone-2', name='bravo', tier=2, reputation=0.61),
        'command-1': PeerInfo('command-1', name='cmd', tier=5, reputation=0.95),
    }
    return build_directory(descriptors, providers, peers, my_tier=2)


# -- §7.1 software-token PKI mock ------------------------------------------

#: filenames mint_demo_pki writes into its cfg_dir (also usable as the operator
#: console's --software-cert / --software-key / --ca-bundle for a dev run).
DEMO_CA_BUNDLE = 'demo_ca_bundle.pem'
DEMO_LEAF_CERT = 'demo_leaf.crt'
DEMO_LEAF_KEY = 'demo_leaf.key'


def mint_demo_pki(cfg_dir: str, common_name: str = 'operator',
                  org: str = 'AT Demo') -> Tuple[Any, str]:
    """Mint an in-memory EC CA + leaf, load the leaf into a ``SoftwareToken``,
    and write the CA bundle + leaf cert/key (PEM) into ``cfg_dir`` (plan §7.1
    stage 1-2). Returns ``(SoftwareToken, ca_bundle_path)`` -- everything
    ``activate`` needs to run a real PIV challenge-response with no hardware. The
    written leaf files double as the console's ``--software-cert/-key`` inputs."""
    import os
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from autonomous_trust.core.identity.zta.piv.pkcs11 import SoftwareToken

    not_before = datetime.now(timezone.utc) - timedelta(days=1)
    not_after = datetime.now(timezone.utc) + timedelta(days=365)

    def _mint(subject_cn, issuer_name, signer_key, is_ca):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
                          x509.NameAttribute(NameOID.ORGANIZATION_NAME, org)])
        cert = (x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(issuer_name if issuer_name is not None else name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(not_before)
                .not_valid_after(not_after)
                .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None),
                               critical=True)
                .sign(signer_key or key, hashes.SHA256()))
        return key, cert

    ca_key, ca_cert = _mint(f'{org} CA', None, None, is_ca=True)
    leaf_key, leaf_cert = _mint(common_name, ca_cert.subject, ca_key, is_ca=False)

    enc = serialization.Encoding
    ca_bundle_path = os.path.join(cfg_dir, DEMO_CA_BUNDLE)
    with open(ca_bundle_path, 'wb') as fp:
        fp.write(ca_cert.public_bytes(enc.PEM))
    with open(os.path.join(cfg_dir, DEMO_LEAF_CERT), 'wb') as fp:
        fp.write(leaf_cert.public_bytes(enc.PEM))
    with open(os.path.join(cfg_dir, DEMO_LEAF_KEY), 'wb') as fp:
        fp.write(leaf_key.private_bytes(
            enc.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    token = SoftwareToken(leaf_cert.public_bytes(enc.DER), leaf_key)
    return token, ca_bundle_path


def software_activator(token: Any, ca_bundle_path: str, totp_secret: str = ''):
    """An ``activator(pin, mfa)`` that runs the **real** operator-core
    ``activate`` against a ``SoftwareToken``. ``pin`` is unused (the software
    token needs no PIN to unlock); ``mfa`` is the TOTP code, required only when
    ``totp_secret`` is set."""
    def activate(pin: str, mfa: str):  # noqa: ARG001
        from autonomous_trust.core.operator.activate import activate as core
        return core(token, ca_bundle_path,
                    totp_secret=totp_secret, totp_code=mfa or '')
    return activate


def software_activator_from_files(cert_path: str, key_path: str,
                                  ca_bundle_path: str, totp_secret: str = ''):
    """Dev/CI activator from on-disk cert+key files (operator console
    ``--software-cert/-key/--ca-bundle``)."""
    from autonomous_trust.core.identity.zta.piv.pkcs11 import SoftwareToken
    token = SoftwareToken.from_files(cert_path, key_path)
    return software_activator(token, ca_bundle_path, totp_secret=totp_secret)


# -- demo node (answers requests) -----------------------------------------

class DemoNode:
    """A no-network mock AT node: emits a directory snapshot then echoes each
    submitted ``Task`` back as a ``TaskResult`` (with a best-effort proof), so
    the operator's request -> result -> proof-badge path works without a cohort.
    Implements the ``run_forever(q_in, q_out)`` seam the bridge expects."""

    def __init__(self, directory: Any) -> None:
        self._directory = directory
        self._stop = threading.Event()

    def run_forever(self, q_in: Any, q_out: Any) -> None:
        q_out.put(self._directory)
        while not self._stop.is_set():
            try:
                task = q_in.get(timeout=0.2)
            except Empty:
                continue
            q_out.put(self._make_result(task))

    def stop(self) -> None:
        self._stop.set()

    @staticmethod
    def _make_result(task: Any) -> Any:
        from autonomous_trust.core.negotiation.negotiation import TaskResult
        cap = getattr(task, 'capability', '?')
        params = getattr(task, 'parameters', None)
        kwargs = getattr(params, 'kwargs', {}) or {}
        result = TaskResult(task=task, result=f'demo-executed {cap}({kwargs})')
        try:
            result.generate_proof()  # no-op when ZKP unavailable
        except Exception:
            pass
        return result
