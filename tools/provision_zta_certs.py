#!/usr/bin/env python3
# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Provision a mission X.509 trust root + per-peer ZTA credentials for the
dod_mission demo.

This is what makes the forged-identity ("hacked") sensors actually rejectable:
legitimate peers carry a certificate signed by the *mission CA*; a forged
sensor either carries no credential ("unsigned") or one signed by a *rogue* CA
not in the mission bundle ("self_signed"). The AT identity layer's ZTA
admission gate (idprocess.welcoming_committee, mirror of the C
handle_welcoming_committee) verifies the credential against the mission CA
bundle and rejects the forged ones before they enter the trust graph.

Layout written under <out_root> (default .demo-state/dod-mission):

    _shared/zta-ca-bundle.pem           mission CA bundle (PEM)
    <peer>/etc/at/zta-ca-bundle.pem     per-peer copy of the bundle
    <peer>/etc/at/zta_credential.der    the peer's credential (omitted if unsigned)
    <peer>/etc/at/zta_policy.cfg.json    enabled x509 policy pointing at the bundle

The minting helpers (make_ca / make_leaf_cert / forged_credential) are importable
so tests can exercise the real chain in-process without touching the filesystem.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
from pathlib import Path
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# Long-lived so the demo doesn't expire mid-exercise; the C test CA uses 2036.
_NOT_BEFORE = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
_NOT_AFTER = datetime.datetime(2036, 1, 1, tzinfo=datetime.timezone.utc)


def _name(cn: str, org: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def make_ca(common_name: str, org: str = "AT Mission PKI"
            ) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Create a self-signed CA (key, cert)."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = _name(common_name, org)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_leaf_cert(common_name: str,
                   ca_key: ec.EllipticCurvePrivateKey,
                   ca_cert: x509.Certificate,
                   org: str = "AT Mission") -> x509.Certificate:
    """Mint a leaf certificate for ``common_name`` signed by the given CA."""
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name, org))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return cert


def cert_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def ca_bundle_pem(*ca_certs: x509.Certificate) -> bytes:
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in ca_certs)


def forged_credential(mode: str, peer_name: str,
                      rogue_ca: Optional[Tuple[ec.EllipticCurvePrivateKey,
                                               x509.Certificate]] = None) -> bytes:
    """Return the DER credential a forged sensor presents for ``mode``.

      * "unsigned"    -> b'' (no credential at all)
      * "self_signed" -> a cert signed by a rogue CA NOT in the mission bundle
                         (i.e. "self-signed / not chained to the mission roster")
      * "sybil"       -> handled by uuid-collision, not the cert gate; returns b''

    The rogue CA may be supplied for determinism; otherwise a fresh one is made.
    """
    if mode in ("unsigned", "sybil"):
        return b""
    if mode == "self_signed":
        if rogue_ca is None:
            rogue_ca = make_ca("AT Rogue Root", org="Rogue CA")
        rkey, rcert = rogue_ca
        return cert_der(make_leaf_cert(peer_name, rkey, rcert, org="Rogue"))
    raise ValueError("unknown forgery mode: %r" % mode)


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def provision(out_root: Path, peers: dict) -> None:
    """Provision certs + policy for a roster.

    ``peers`` maps peer_name -> forgery_mode-or-None (None = legitimate).
    """
    ca_key, ca_cert = make_ca("AT Mission Root CA")
    bundle = ca_bundle_pem(ca_cert)
    rogue_ca = make_ca("AT Rogue Root", org="Rogue CA")  # shared rogue for self_signed

    shared = out_root / "_shared" / "zta-ca-bundle.pem"
    _write(shared, bundle)

    for peer, forgery in peers.items():
        cfg = out_root / peer / "etc" / "at"
        _write(cfg / "zta-ca-bundle.pem", bundle)
        if forgery:
            cred = forged_credential(forgery, peer, rogue_ca=rogue_ca)
        else:
            cred = cert_der(make_leaf_cert(peer, ca_key, ca_cert))
        if cred:
            _write(cfg / "zta_credential.der", cred)
        policy = {
            "__type__": "autonomous_trust.core._python.identity.zta.zta_policy.ZtaPolicy",
            "enabled": True,
            "require_at_admission": True,
            "verifier_type": "x509",
            "ca_bundle_path": str(cfg / "zta-ca-bundle.pem"),
            "allow_ddil_fallback": True,
            "ddil_fallback_reputation_cap": 0.5,
        }
        (cfg / "zta_policy.cfg.json").write_text(json.dumps(policy, indent=2) + "\n")


def _roster_from_scenario() -> dict:
    """Best-effort roster from the dod_mission scenario (forged sensors tagged)."""
    import sys
    repo = Path(__file__).resolve().parent.parent
    here = repo / "examples" / "dod_mission"
    sys.path.insert(0, str(here))
    # Source-checkout fallback so the CLI works without an installed package.
    # autonomous_trust is a namespace package spanning two sibling src trees.
    for sub in ("src/autonomous-trust", "src/autonomous-trust-evaluation"):
        p = repo / sub
        if p.is_dir():
            sys.path.insert(0, str(p))
    from scenario import DoDMissionScenario  # noqa: E402
    sc = DoDMissionScenario(
        squad_size=int(os.environ.get("AT_SQUAD_SIZE", "4")),
        swarm_size=int(os.environ.get("AT_SWARM_SIZE", "4")),
        sensor_count=int(os.environ.get("AT_SENSOR_COUNT", "3")),
        hacked_sensors=int(os.environ.get("AT_HACKED_SENSORS", "2")),
    )
    peers = {}
    forgery_default = os.environ.get("AT_FORGERY_MODE", "self_signed")
    for role in sc.peers.values():
        forged = bool((getattr(role, "metadata", None) or {}).get("forged_identity"))
        peers[role.name] = forgery_default if forged else None
    return peers


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out-root", default=".demo-state/dod-mission",
                    help="provisioning root (default: .demo-state/dod-mission)")
    args = ap.parse_args()
    try:
        peers = _roster_from_scenario()
    except Exception as err:  # pragma: no cover - environment-dependent import
        print("ERROR: could not load the dod_mission roster (%s: %s).\n"
              "Run where the autonomous_trust + autonomous_trust.evaluation "
              "packages are importable (the demo container, or `pip install -e` "
              "both src trees)." % (type(err).__name__, err), file=sys.stderr)
        return 2
    provision(Path(args.out_root), peers)
    n_forged = sum(1 for v in peers.values() if v)
    print(f"Provisioned {len(peers)} peers ({n_forged} forged) under {args.out_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
