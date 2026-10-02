#!/usr/bin/env python3
# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Pin community relay rosters on a node, and sign one (FIRST_CONTACT_PLAN §4.2 / §4.5).

Operator, on the node (uses $AUTONOMOUS_TRUST_ROOT):

    relay_rosters.py pin HEXKEY               # trust rosters from this community
    relay_rosters.py unpin HEXKEY
    relay_rosters.py install roster.cfg.json  # copy a roster into <cfg_dir>/relay_rosters/
    relay_rosters.py show                     # the pinned issuers and the relays the node will use

A community that is not an Ethne polity (a polity emits its roster from
en_uplift::rendezvous_roster) signs its own, offline, where its seed lives:

    relay_rosters.py keygen
    relay_rosters.py sign --seed-file F --seq N relay://uuid:fp@host:port ... > roster.cfg.json
    relay_rosters.py verify roster.cfg.json --issuer HEXKEY
"""
import argparse
import json
import os
import shutil
import sys

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from autonomous_trust.core._python.config.configuration import atomic_write
from autonomous_trust.rendezvous._python import relay, relay_rosters as rosters


def _keygen(_args):
    key = SigningKey.generate()
    print('seed   %s' % HexEncoder.encode(bytes(key)).decode())
    print('public %s' % key.verify_key.encode(HexEncoder).decode())


def _sign(args):
    with open(args.seed_file) as f:
        seed = f.read().strip()
    print(rosters.sign_roster(seed, args.seq, args.relays))


def _verify(args):
    with open(args.file) as f:
        issuer, seq, hints = rosters.verify_roster(f.read(), [args.issuer.lower()])
    print('issuer %s seq %d' % (issuer, seq))
    for endpoint, pin in hints:
        print('  ' + relay.hint_for(endpoint, pin))


def _file_issuers():
    try:
        with open(rosters.issuers_path()) as f:
            listed = json.load(f).get('issuers', [])
        return [str(k).lower() for k in listed] if isinstance(listed, list) else []
    except FileNotFoundError:
        return []


def _save_issuers(keys):
    os.makedirs(os.path.dirname(rosters.issuers_path()), exist_ok=True)
    with atomic_write(rosters.issuers_path()) as f:
        json.dump({'issuers': keys}, f, indent=2)
    print(json.dumps({'issuers': keys}, indent=2))


def _pin(args):
    key = args.key.strip().lower()
    if not rosters._is_key_hex(key):
        sys.exit('not a hex ed25519 key: %s' % args.key)
    keys = _file_issuers()
    _save_issuers(keys if key in keys else keys + [key])


def _unpin(args):
    key = args.key.strip().lower()
    _save_issuers([k for k in _file_issuers() if k != key])


def _install(args):
    with open(args.file) as f:
        text = f.read()
    issuer, seq, _hints = rosters.verify_roster(text, rosters.pinned_issuers())
    os.makedirs(rosters.rosters_dir(), exist_ok=True)
    dest = os.path.join(rosters.rosters_dir(), '%s.cfg.json' % issuer[:16])
    shutil.copyfile(args.file, dest)
    print('installed seq %d from %s… as %s' % (seq, issuer[:16], dest))


def _show(_args):
    print('issuers:')
    for key in rosters.pinned_issuers():
        print('  ' + key)
    print('relays:')
    for endpoint, pin in rosters.load():
        print('  ' + relay.hint_for(endpoint, pin))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('keygen').set_defaults(func=_keygen)
    p = sub.add_parser('sign')
    p.add_argument('--seed-file', required=True)
    p.add_argument('--seq', type=int, required=True)
    p.add_argument('relays', nargs='*')
    p.set_defaults(func=_sign)
    p = sub.add_parser('verify')
    p.add_argument('file')
    p.add_argument('--issuer', required=True)
    p.set_defaults(func=_verify)
    for name, func in (('pin', _pin), ('unpin', _unpin)):
        p = sub.add_parser(name)
        p.add_argument('key')
        p.set_defaults(func=func)
    p = sub.add_parser('install')
    p.add_argument('file')
    p.set_defaults(func=_install)
    sub.add_parser('show').set_defaults(func=_show)
    args = ap.parse_args(argv)
    try:
        args.func(args)
    except rosters.InvalidRoster as exc:
        sys.exit('refused: %s' % exc)


if __name__ == '__main__':
    main()
