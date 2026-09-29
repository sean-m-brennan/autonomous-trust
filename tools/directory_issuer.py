#!/usr/bin/env python3
# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Sign directory attestations: an issuer's word that a handle belongs to a key
(FIRST_CONTACT_PLAN Phase 3, contacts/directory.py).

This is the signing half of an issuer only. Checking that the person really
controls the handle (an email round trip, an SMS code, an operator's own
records) is the issuer's job and happens before this is run.

    directory_issuer.py keygen                         # new issuer keypair; keep the seed secret
    directory_issuer.py attest --seed-file F --handle alice@example.org \\
        --key <node's hex signing key> [--days 365]    > attestation.json
    directory_issuer.py verify attestation.json [--issuer HEX]
    directory_issuer.py node-key                       # this node's signing key ($AUTONOMOUS_TRUST_ROOT)

A registry trusts an issuer by listing its public key in
<cfg_dir>/registry_issuers.cfg.json: {"issuers": ["<hex>", ...]}. The node hands
the attestation to its app, which passes it to the node with
``app_directory_publish``.
"""
import argparse
import json
import sys
import time

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from autonomous_trust.core._python.contacts import directory as d
from autonomous_trust.core._python.network import relay_seeds


def _keygen(_args):
    key = SigningKey.generate()
    print('seed   %s' % HexEncoder.encode(bytes(key)).decode())
    print('public %s' % key.verify_key.encode(HexEncoder).decode())


def _attest(args):
    with open(args.seed_file) as f:
        issuer = SigningKey(HexEncoder.decode(f.read().strip().encode()))
    att = d.attest(issuer, args.handle, args.key.lower(),
                   int(time.time()) + int(args.days * 86400))
    print(json.dumps(att.to_wire()))


def _verify(args):
    with open(args.file) as f:
        att = d.Attestation.from_wire(f.read())
    att.verify({args.issuer.lower()} if args.issuer else None)
    print('%s -> %s (issuer %s, expires %s)' % (
        att.handle, att.key, att.issuer,
        time.strftime('%Y-%m-%d', time.gmtime(att.expiry))))


def _node_key(_args):
    seed = relay_seeds.node_seed_hex()
    if not seed:
        sys.exit('no identity.cfg.json under $AUTONOMOUS_TRUST_ROOT')
    print(SigningKey(HexEncoder.decode(seed.encode())).verify_key.encode(HexEncoder).decode())


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('keygen').set_defaults(func=_keygen)
    p = sub.add_parser('attest')
    p.add_argument('--seed-file', required=True)
    p.add_argument('--handle', required=True)
    p.add_argument('--key', required=True)
    p.add_argument('--days', type=float, default=365)
    p.set_defaults(func=_attest)
    p = sub.add_parser('verify')
    p.add_argument('file')
    p.add_argument('--issuer')
    p.set_defaults(func=_verify)
    sub.add_parser('node-key').set_defaults(func=_node_key)
    args = ap.parse_args(argv)
    try:
        args.func(args)
    except d.InvalidEntry as exc:
        sys.exit('refused (%s): %s' % (exc.reason, exc))


if __name__ == '__main__':
    main()
