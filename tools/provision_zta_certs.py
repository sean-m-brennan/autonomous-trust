#!/usr/bin/env python3
# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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
from typing import Optional, Sequence, Tuple

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


def make_leaf_keypair(common_name: str,
                      ca_key: ec.EllipticCurvePrivateKey,
                      ca_cert: x509.Certificate,
                      org: str = "AT Mission",
                      not_before: Optional[datetime.datetime] = None,
                      not_after: Optional[datetime.datetime] = None,
                      san_uris: Optional[Sequence[str]] = None
                      ) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Mint a leaf cert for ``common_name`` and return ``(leaf_key, cert)``.

    The private key is required for PIV challenge-response (the operator console
    signs a nonce with it); `make_leaf_cert` drops it for the X.509-only path.
    Pass ``not_after`` in the past to mint an expired leaf.

    ``san_uris`` adds URI subjectAltNames. Passing ``at://<uuid>`` is the
    CA-asserted form of the credential->identity binding (SPIFFE-style): the issuer
    vouches for which node may present the certificate, so no holder-signed binding
    blob is needed. See `identity/zta_binding.py::san_binds_identity`. Only
    meaningful for a CA whose issuance AT controls; a foreign agency CA will not
    mint these, which is why the holder-asserted signature exists.
    """
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name, org))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or _NOT_BEFORE)
        .not_valid_after(not_after or _NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if san_uris:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(u) for u in san_uris]),
            critical=False)
    return leaf_key, builder.sign(ca_key, hashes.SHA256())


def make_leaf_cert(common_name: str,
                   ca_key: ec.EllipticCurvePrivateKey,
                   ca_cert: x509.Certificate,
                   org: str = "AT Mission") -> x509.Certificate:
    """Mint a leaf certificate for ``common_name`` signed by the given CA."""
    return make_leaf_keypair(common_name, ca_key, ca_cert, org)[1]


def make_crl(ca_key: ec.EllipticCurvePrivateKey,
             ca_cert: x509.Certificate,
             revoked_serials,
             this_update: Optional[datetime.datetime] = None,
             next_update: Optional[datetime.datetime] = None) -> bytes:
    """Build a CRL (PEM) signed by the CA revoking ``revoked_serials``.

    `X509Verifier.check_revocation` loads PEM CRLs and matches **by serial
    number** against certs already in its cache (i.e. ones that passed
    `verify_credential` first), so this is the producer side of that path
    (PIV_MFA_OPERATOR_ACCESS_PLAN.md §7.1 -- no CRL-minting helper existed
    before).
    """
    this_update = this_update or _NOT_BEFORE
    next_update = next_update or _NOT_AFTER
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(this_update)
        .next_update(next_update)
    )
    for serial in revoked_serials:
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(serial))
            .revocation_date(this_update)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM)


def cert_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def ca_bundle_pem(*ca_certs: x509.Certificate) -> bytes:
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in ca_certs)


def forged_credential(mode: str, peer_name: str,
                      rogue_ca: Optional[Tuple[ec.EllipticCurvePrivateKey,
                                               x509.Certificate]] = None,
                      mission_ca: Optional[Tuple[ec.EllipticCurvePrivateKey,
                                                 x509.Certificate]] = None) -> bytes:
    """Return the DER credential a forged sensor presents for ``mode``.

      * "unsigned"    -> b'' (no credential at all)
      * "self_signed" -> a cert signed by a rogue CA NOT in the mission bundle
                         (i.e. "self-signed / not chained to the mission roster")
      * "expired"     -> a cert signed by the *mission* CA but past its validity
                         window (requires ``mission_ca``); EXPIRED, not REJECTED
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
    if mode == "expired":
        if mission_ca is None:
            raise ValueError("expired mode requires mission_ca=(key, cert)")
        mkey, mcert = mission_ca
        past_before = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
        past_after = datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc)
        _, cert = make_leaf_keypair(peer_name, mkey, mcert,
                                    not_before=past_before, not_after=past_after)
        return cert_der(cert)
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
            # No private key is written for a forged credential, and that is the
            # point: without it the peer cannot produce a credential->identity
            # binding, so under `binding_mode: require` it is refused at the
            # identity layer rather than merely flooring its reputation.
            cred = forged_credential(forgery, peer, rogue_ca=rogue_ca)
            leaf_key = None
        else:
            leaf_key, leaf_cert = make_leaf_keypair(peer, ca_key, ca_cert)
            cred = cert_der(leaf_cert)
        if cred:
            _write(cfg / "zta_credential.der", cred)
        if leaf_key is not None:
            # The credential's PRIVATE key, which the node needs to sign its own
            # binding once it has an identity. The binding cannot be produced here:
            # its pre-image names the node's uuid and signing key, and neither exists
            # until the node first runs (see participant._attach_zta_credential).
            # This is also why a machine credential can self-bind and a PIV one
            # cannot -- a card never surrenders its key.
            _write(cfg / "zta_credential.key.pem", leaf_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()))
        policy = {
            "__type__": "autonomous_trust.core._python.identity.zta.zta_policy.ZtaPolicy",
            "enabled": True,
            "require_at_admission": True,
            "verifier_type": "x509",
            "ca_bundle_path": str(cfg / "zta-ca-bundle.pem"),
            "allow_ddil_fallback": True,
            "ddil_fallback_reputation_cap": 0.5,
            # Explicit rather than relying on the default, because it is the
            # consequential setting here: a chain-valid credential with no proof that
            # THIS node may present it is refused (ISSUES §1.5). Legitimate peers get
            # a private key above and self-bind on first run; the forged ones cannot,
            # so they are rejected at the identity layer. Set "prefer" to admit
            # unbound credentials with a reputation cap during a migration.
            "binding_mode": "require",
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
