"""Emit a C-runtime-format ``identity.cfg.json`` for a pre-seeded C ``at_demo`` node.

The C and Python implementations write identity to disk in *different* JSON
schemas, and they derive the encryptor keypair from its stored secret
differently:

  * **Python** (``identity.py`` / ``sign.py`` / ``encrypt.py``): ``ConfigJSONEncoder``
    output with ``_uuid`` / ``__type__`` wrappers; the encryptor stores the *raw*
    Curve25519 private key (``PrivateKey(hex)`` uses the bytes directly).
  * **C** (``identity.c:248-286``): flat jansson object — ``typename`` / ``uuid`` /
    ``fullname`` + ``signature.hex_seed`` / ``encryptor.hex_seed``; the reader
    (``identity_from_json`` -> ``signature_init`` / ``encryptor_init``) treats
    ``hex_seed`` as a 32-byte **seed** and runs ``crypto_sign_seed_keypair`` /
    ``crypto_box_seed_keypair``.

So a pre-seeded C node must be handed a *seed* (not a raw private key), and the
rest of the (Python) cohort must store the **public** keys derived from that same
seed the way C derives them. Verified equivalence (fixed seed 00..1f):

    C  crypto_sign_seed_keypair(seed) == Py SigningKey(seed).verify_key
    C  crypto_box_seed_keypair(seed)  == Py PrivateKey.from_seed(seed).public_key

This module generates that seed-based identity, returns:
  * ``c_json``  — the dict to write verbatim (``json.dump``, *not* ConfigJSONEncoder)
    into the C node's ``etc/at/identity.cfg.json``; the C node loads it via the
    ``preserve`` path (``config/generate.c:311``) so its UUID + pubkeys are stable.
  * ``public_identity`` — a public-only Python ``Identity`` (pubkeys derived with
    C's convention) for the cohort's ``peers.cfg.json`` / reputation / group views.

Because the C node skips interface discovery when preserving a stored identity,
the seeded identity must carry the node's real runtime ``address`` (its compose
IP); the announce envelope's ``from_address`` derives from it. Callers pass that
address in.
"""

from __future__ import annotations

from typing import Optional
from uuid import uuid4

from nacl.encoding import HexEncoder
from nacl.public import PrivateKey
from nacl.signing import SigningKey
from nacl.utils import random as nacl_random

from autonomous_trust.core._python.identity import Identity
from autonomous_trust.core._python.identity.sign import Signature
from autonomous_trust.core._python.identity.encrypt import Encryptor


def make_c_node_identity(peer_name: str, address: str, *,
                         nickname: Optional[str] = None,
                         petname: Optional[str] = None,
                         rank: int = 0) -> tuple[dict, Identity]:
    """Build a fresh seed-based identity for a C ``at_demo`` node.

    Returns ``(c_json, public_identity)``:
      * ``c_json`` — C-runtime ``identity.cfg.json`` content (seeds in ``hex_seed``).
      * ``public_identity`` — public-only Python ``Identity`` with the matching
        derived pubkeys, for the cohort's peer/reputation/group views.

    ``address`` must be the node's real runtime IP (its compose-assigned address);
    the C node preserves the stored identity and does not re-discover it.
    """
    # Zooko: nickname is the ONLINE name (carried on the wire); petname is the
    # LOCAL short/bare name (what the coordinator roster matches on).
    nickname = nickname or f"{peer_name}@dod-demo"
    petname = petname or peer_name

    # Signature: ed25519. SigningKey.encode() IS the 32-byte seed (sign.py:57),
    # which is exactly what C's signature_init expects (crypto_sign_SEEDBYTES*2).
    sign_key = SigningKey.generate()
    sig_seed_hex = sign_key.encode(encoder=HexEncoder).decode("ascii")
    sig_pub_hex = sign_key.verify_key.encode(encoder=HexEncoder).decode("ascii")

    # Encryptor: Curve25519 *seed* (NOT a raw private key). C's encryptor_init
    # runs crypto_box_seed_keypair(seed); PyNaCl's PrivateKey.from_seed(seed)
    # is the same primitive, so the public keys agree.
    enc_seed = nacl_random(32)
    enc_seed_hex = enc_seed.hex()
    enc_pub_hex = PrivateKey.from_seed(enc_seed).public_key.encode(
        encoder=HexEncoder).decode("ascii")

    uuid_str = str(uuid4())

    # C on-disk schema — mirror identity_to_json (identity.c:256-283) exactly.
    c_json = {
        "typename": "identity",
        "uuid": uuid_str,
        "rank": rank,
        "address": address,
        "nickname": nickname,
        "petname": petname,
        "signature": {"hex_seed": sig_seed_hex},
        "encryptor": {"hex_seed": enc_seed_hex},
    }

    return c_json, _public_identity_from_parts(
        uuid_str, address, nickname, petname, rank,
        sig_pub_hex, enc_pub_hex)


def _public_identity_from_parts(uuid_str, address, nickname, petname,
                                rank, sig_pub_hex, enc_pub_hex) -> Identity:
    """Public-only Identity (pubkeys only) for the cohort's peer views."""
    return Identity(
        uuid_str, address, nickname,
        Signature(sig_pub_hex.encode("ascii"), True),
        Encryptor(enc_pub_hex.encode("ascii"), True),
        petname, True, _rank=rank,
    )


def public_identity_from_c_json(c_json: dict) -> Identity:
    """Rebuild the cohort's public-only view from a stored C ``identity.cfg.json``.

    Derives the public keys from the stored *seeds* using C's convention, so a
    re-run of the seed tool (idempotent, no ``--force``) reproduces the same
    cohort view the C node will actually present on announce.
    """
    sig_seed = bytes.fromhex(c_json["signature"]["hex_seed"])
    enc_seed = bytes.fromhex(c_json["encryptor"]["hex_seed"])
    sig_pub_hex = SigningKey(sig_seed).verify_key.encode(
        encoder=HexEncoder).decode("ascii")
    enc_pub_hex = PrivateKey.from_seed(enc_seed).public_key.encode(
        encoder=HexEncoder).decode("ascii")
    return _public_identity_from_parts(
        c_json["uuid"], c_json["address"], c_json["fullname"],
        c_json["nickname"], c_json.get("petname", "me"),
        int(c_json.get("rank", 0)), sig_pub_hex, enc_pub_hex)
