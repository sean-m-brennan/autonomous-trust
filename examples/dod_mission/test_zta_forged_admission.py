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
    make_ca, make_leaf_cert, cert_der, ca_bundle_pem, forged_credential)
from autonomous_trust.core.identity.idprocess import IdentityProcess  # noqa: E402
from autonomous_trust.core.identity.zta import ZtaPolicy  # noqa: E402


class _Gate:
    """Minimal carrier of the real ZTA admission-gate methods."""
    _zta_policy = IdentityProcess._zta_policy
    _zta_verifier = IdentityProcess._zta_verifier
    _zta_admit = IdentityProcess._zta_admit

    def __init__(self, policy: ZtaPolicy):
        self.configs = {ZtaPolicy.CONFIG_KEY: policy}
        self._zta_policy_cache = None
        self._zta_verifier_cache = None
        self._zta_capped = set()
        self.logger = logging.getLogger("test.dod.zta")


def _peer(cred: bytes, nick: str):
    return SimpleNamespace(zta_credential=cred, nickname=nick, uuid="uuid-" + nick)


@pytest.fixture()
def mission(tmp_path):
    """A provisioned mission: CA bundle on disk + a shared rogue CA."""
    ca_key, ca_cert = make_ca("AT Mission Root CA")
    bundle = tmp_path / "zta-ca-bundle.pem"
    bundle.write_bytes(ca_bundle_pem(ca_cert))
    rogue = make_ca("AT Rogue Root", org="Rogue CA")
    policy = ZtaPolicy(enabled=True, require_at_admission=True,
                       verifier_type="x509", ca_bundle_path=str(bundle))
    return SimpleNamespace(ca=(ca_key, ca_cert), rogue=rogue, policy=policy)


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
