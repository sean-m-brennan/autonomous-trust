#!/usr/bin/env python3
# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Issue a device cert: the operator's word that a node is one of their
devices (FIRST_CONTACT_PLAN Phase 4, contacts/device.py).

Signed with the operator key in the operator's keystore
($AT_OPERATOR_KEYSTORE, else ~/.config/at-operator; created on first use), so
the key never enters a node:

    device_cert.py issue                  # this node ($AUTONOMOUS_TRUST_ROOT): writes
                                          #   <cfg_dir>/device_cert.cfg.json
    device_cert.py issue --uuid U --key HEX [--out FILE]   # any node, by its public half
    device_cert.py verify [FILE]          # default: this node's installed cert
    device_cert.py operator-key           # the operator's public key

A node with a cert installed pushes it to its contacts, and announces itself
at startup to every contact in its store, which files it under the matching
verified contact.
"""
import argparse
import json
import os
import sys
from types import SimpleNamespace

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from autonomous_trust.core._python.config.configuration import Configuration, atomic_write
from autonomous_trust.core._python.contacts import device as dv
from autonomous_trust.core._python.identity import device_contact
from autonomous_trust.core._python.network import relay_seeds
from autonomous_trust.core._python.identity.operator_keystore import load_or_create_operator_key


def _this_node():
    """(uuid, public signing key hex) of the node under $AUTONOMOUS_TRUST_ROOT."""
    path = os.path.join(Configuration.get_cfg_dir(), 'identity' + Configuration.file_ext)
    try:
        with open(path) as f:
            ident = json.load(f)
    except (OSError, ValueError):
        sys.exit('no identity.cfg.json under $AUTONOMOUS_TRUST_ROOT')
    uuid = ident.get('uuid') or ident.get('_uuid')
    if isinstance(uuid, dict):          # Python's tagged {"__type__": "UUID", ...}
        uuid = uuid.get('__value__')
    seed = relay_seeds.node_seed_hex()
    if not isinstance(uuid, str) or not seed:
        sys.exit('identity.cfg.json has no uuid or signing key')
    return uuid, SigningKey(HexEncoder.decode(seed.encode())).verify_key.encode(HexEncoder).decode()


def _issue(args):
    if args.uuid or args.key:
        if not (args.uuid and args.key):
            sys.exit('--uuid and --key go together')
        uuid, key = args.uuid, args.key.lower()
        out = args.out
    else:
        uuid, key = _this_node()
        out = args.out or device_contact.device_cert_path()
    seed_hex, _pub = load_or_create_operator_key(args.keystore or '')
    node = SimpleNamespace(uuid=uuid, signature=SimpleNamespace(public=bytes.fromhex(key)))
    cert = dv.create_device_cert(SigningKey(HexEncoder.decode(seed_hex)), node)
    text = json.dumps(cert.to_wire())
    if not out:
        print(text)
        return
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with atomic_write(out) as fh:
        fh.write(text)
    print('%s -> %s (operator %s)' % (uuid, out, cert.operator))


def _verify(args):
    path = args.file or device_contact.device_cert_path()
    with open(path) as f:
        cert = dv.DeviceCert.from_wire(json.load(f)).verify()
    print('%s key %s, operator %s' % (cert.uuid, cert.key, cert.operator))


def _operator_key(args):
    _seed, pub = load_or_create_operator_key(args.keystore or '')
    print(pub.hex())


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--keystore', help='operator keystore directory')
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('issue')
    p.add_argument('--uuid')
    p.add_argument('--key')
    p.add_argument('--out')
    p.set_defaults(func=_issue)
    p = sub.add_parser('verify')
    p.add_argument('file', nargs='?')
    p.set_defaults(func=_verify)
    sub.add_parser('operator-key').set_defaults(func=_operator_key)
    args = ap.parse_args(argv)
    try:
        args.func(args)
    except dv.InvalidDevice as exc:
        sys.exit('refused (%s): %s' % (exc.reason, exc))


if __name__ == '__main__':
    main()
