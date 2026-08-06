# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""End-to-end proof that the dod_mission forged-identity fix is real.

Exercises the WHOLE chain in-process — mission-CA provisioning
(tools/provision_zta_certs.py) -> the credential a forged sensor presents ->
the real X509Verifier -> the real IdentityProcess admission gate
(welcoming_committee._zta_admit) — and asserts a CA-signed (legitimate) sensor
is admitted while the "unsigned" and "self_signed" hacked sensors are rejected
at the identity layer (not merely floored on the dashboard).

Run:  pytest examples/dod_mission/test_zta_forged_admission.py
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("cryptography")

_REPO = Path(__file__).resolve().parents[2]
# Set up import paths WITHOUT shadowing the repo-root ``tools`` package: there
# is ALSO a src/autonomous-trust/tools package, so inserting AT's src at the
# FRONT of sys.path makes ``import tools`` resolve there instead -- which breaks
# ``tools.*`` imports (e.g. tools.seed_dod_cohort) for other tests later in the
# same pytest run. Keep the repo root ahead of AT's src, and import the cert
# tool via its package path rather than as a bare top-level module.
_AT_SRC = str(_REPO / "src" / "autonomous-trust")
if _AT_SRC not in sys.path:
    sys.path.append(_AT_SRC)
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from tools.provision_zta_certs import (  # noqa: E402
    make_ca, make_leaf_cert, make_leaf_keypair, cert_der, ca_bundle_pem,
    forged_credential)
from autonomous_trust.core.identity.idprocess import IdentityProcess  # noqa: E402
from autonomous_trust.core.identity.zta import (  # noqa: E402
    ZtaPolicy, BINDING_MODE_OFF, BINDING_MODE_REQUIRE)


class _Gate:
    """Minimal carrier of the real ZTA admission-gate methods.

    The method list has to track what `_zta_admit` actually calls; it had fallen
    behind the operator-attended work (which added the operator classification and
    guardian-key steps) and then the multi-credential work, so these tests were
    erroring on a missing attribute rather than exercising the gate.
    """
    _zta_policy = IdentityProcess._zta_policy
    _zta_verifier = IdentityProcess._zta_verifier
    _zta_operator_verifier = IdentityProcess._zta_operator_verifier
    _zta_anchor_verifiers = IdentityProcess._zta_anchor_verifiers
    _zta_credentials = IdentityProcess._zta_credentials
    _zta_match_anchors = IdentityProcess._zta_match_anchors
    _zta_credential_replayed = IdentityProcess._zta_credential_replayed
    _is_operator_credential = IdentityProcess._is_operator_credential
    _mark_operator_bound = staticmethod(IdentityProcess._mark_operator_bound)
    _verify_operator_key = IdentityProcess._verify_operator_key
    _zta_admit = IdentityProcess._zta_admit

    def __init__(self, policy: ZtaPolicy):
        self.configs = {ZtaPolicy.CONFIG_KEY: policy}
        self._zta_policy_cache = None
        self._zta_verifier_cache = None
        self._zta_operator_verifier_cache = None
        self._zta_anchor_cache = None
        self._zta_capped = set()
        self._operator_verified = set()
        self.logger = logging.getLogger("test.dod.zta")
        self.peers = SimpleNamespace(all=[])
        self.identity = None


def _peer(cred: bytes, nick: str):
    return SimpleNamespace(zta_credential=cred, nickname=nick, uuid="uuid-" + nick)


@pytest.fixture()
def mission(tmp_path):
    """A provisioned mission: CA bundle on disk + a shared rogue CA."""
    ca_key, ca_cert = make_ca("AT Mission Root CA")
    bundle = tmp_path / "zta-ca-bundle.pem"
    bundle.write_bytes(ca_bundle_pem(ca_cert))
    rogue = make_ca("AT Rogue Root", org="Rogue CA")
    # `binding_mode: off` for these three: they are about a forged CHAIN (no
    # credential, or one from a rogue CA), and `_peer` below is a stand-in with no
    # signing key, so it could not carry a credential->identity binding at all.
    # The binding cases live in test_zta_multi_credential.py, and the dod-side proof
    # that an unbound credential is refused is `test_unbound_credential_rejected`.
    policy = ZtaPolicy(enabled=True, require_at_admission=True,
                       verifier_type="x509", ca_bundle_path=str(bundle),
                       binding_mode=BINDING_MODE_OFF)
    return SimpleNamespace(ca=(ca_key, ca_cert), rogue=rogue, bundle=bundle,
                           policy=policy)


def test_legitimate_sensor_admitted(mission):
    ca_key, ca_cert = mission.ca
    cred = cert_der(make_leaf_cert("sensor-3", ca_key, ca_cert))
    gate = _Gate(mission.policy)
    assert gate._zta_admit(_peer(cred, "sensor-3")) == "admit"


def test_unsigned_hacked_sensor_rejected(mission):
    # forgery_mode == "unsigned": no credential at all.
    cred = forged_credential("unsigned", "sensor-1")
    assert cred == b""
    gate = _Gate(mission.policy)
    assert gate._zta_admit(_peer(cred, "sensor-1")) == "reject"


def test_self_signed_hacked_sensor_rejected(mission):
    # forgery_mode == "self_signed": a cert signed by a rogue CA, not the
    # mission CA — the realistic "leave-behind sensor can't prove who it is".
    cred = forged_credential("self_signed", "sensor-2", rogue_ca=mission.rogue)
    assert cred  # a real cert, just untrusted issuer
    gate = _Gate(mission.policy)
    assert gate._zta_admit(_peer(cred, "sensor-2")) == "reject"


def test_provision_roster_round_trips(tmp_path):
    # The CLI-level provisioner writes legit creds that verify and forged ones
    # that don't, under a realistic per-peer layout.
    from tools.provision_zta_certs import provision
    from autonomous_trust.core.identity.zta import X509Verifier, ZtaStatus
    peers = {"squad-captain": None, "sensor-1": "unsigned", "sensor-2": "self_signed"}
    provision(tmp_path, peers)
    bundle = tmp_path / "squad-captain" / "etc" / "at" / "zta-ca-bundle.pem"
    v = X509Verifier(str(bundle))
    legit = (tmp_path / "squad-captain" / "etc" / "at" / "zta_credential.der").read_bytes()
    assert v.verify_credential(legit).status is ZtaStatus.VERIFIED
    # unsigned: no credential file written at all
    assert not (tmp_path / "sensor-1" / "etc" / "at" / "zta_credential.der").exists()
    # self_signed: a cert present, but rejected by the mission bundle
    forged = (tmp_path / "sensor-2" / "etc" / "at" / "zta_credential.der").read_bytes()
    assert v.verify_credential(forged).status is ZtaStatus.REJECTED


def _real_identity(nick: str):
    """A real Identity, not the `_peer` stand-in: a credential->identity binding
    covers the node's uuid AND its signing key, so there has to be a key to cover."""
    import uuid as uuid_mod
    from autonomous_trust.core.identity import Identity
    from autonomous_trust.core._python.identity.sign import Signature
    from autonomous_trust.core._python.identity.encrypt import Encryptor
    return Identity(uuid_mod.uuid4(), "10.0.0.3", nick,
                    Signature.generate(), Encryptor.generate(), nick, False)


def _bind(leaf_key, ident, cred: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from autonomous_trust.core.identity.zta_binding import zta_binding_preimage
    return leaf_key.sign(zta_binding_preimage(ident, cred), ec.ECDSA(hashes.SHA256()))


def _require_policy(mission):
    return ZtaPolicy(enabled=True, require_at_admission=True, verifier_type="x509",
                     ca_bundle_path=str(mission.bundle),
                     binding_mode=BINDING_MODE_REQUIRE)


def test_bound_sensor_admitted(mission):
    """The provisioned happy path: tools/provision_zta_certs.py writes the leaf key
    beside the cert, and participant._attach_zta_credential signs the binding on first
    run. Here that is done inline."""
    ca_key, ca_cert = mission.ca
    leaf_key, leaf_cert = make_leaf_keypair("sensor-3", ca_key, ca_cert)
    cred = cert_der(leaf_cert)
    ident = _real_identity("sensor-3")
    ident.zta_credential = cred
    ident.zta_credential_binding = _bind(leaf_key, ident, cred)
    assert _Gate(_require_policy(mission))._zta_admit(ident) == "admit"


def test_unbound_credential_rejected(mission):
    """A mission-CA-signed credential with no proof that THIS node may present it.
    Chain-valid, and refused anyway -- the hole ISSUES §1.5 describes, closed. A
    forged leave-behind sensor is provisioned WITHOUT a private key precisely so it
    lands here."""
    ca_key, ca_cert = mission.ca
    cred = cert_der(make_leaf_cert("sensor-4", ca_key, ca_cert))
    ident = _real_identity("sensor-4")
    ident.zta_credential = cred
    assert _Gate(_require_policy(mission))._zta_admit(ident) == "reject"


def test_harvested_credential_and_binding_rejected(mission):
    """The full replay: the attacker lifts BOTH the credential and its binding from a
    clear-text announce. The binding names the victim, so it cannot verify here, and
    the attacker has no way to mint a fresh one."""
    ca_key, ca_cert = mission.ca
    leaf_key, leaf_cert = make_leaf_keypair("sensor-3", ca_key, ca_cert)
    cred = cert_der(leaf_cert)
    victim = _real_identity("sensor-3")
    harvested = _bind(leaf_key, victim, cred)
    attacker = _real_identity("sensor-3-clone")
    attacker.zta_credential = cred
    attacker.zta_credential_binding = harvested
    assert _Gate(_require_policy(mission))._zta_admit(attacker) == "reject"
