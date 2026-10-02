#!/usr/bin/env python3
# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Mint, sign and edit the relay seed list (FIRST_CONTACT_PLAN §10.1).

Release signer (run offline, where the release seed lives):

    relay_seeds.py keygen                      # new release keypair; keep the seed secret
    relay_seeds.py sign --seed-file F --seq N relay://[uuid:fp@]host:port ...  > relay_seeds.cfg.json
    relay_seeds.py verify relay_seeds.cfg.json [--key HEX]

The public key goes into RELEASE_KEY in
src/autonomous-trust-rendezvous/autonomous_trust/rendezvous/_python/relay_seeds.py
and into AT_RELAY_SEEDS_RELEASE_KEY in src/c/extensions/rendezvous/net_relay_seeds.h;
the signed file ships as <cfg_dir>/relay_seeds.cfg.json.

Operator, on the node (uses $AUTONOMOUS_TRUST_ROOT, signs with the node's own identity key):

    relay_seeds.py local add relay://host:port ...
    relay_seeds.py local remove host:port ...
    relay_seeds.py local clear
    relay_seeds.py show                        # the relays the node will use
"""
import argparse
import json
import os
import sys

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from autonomous_trust.core._python.config.configuration import Configuration, atomic_write
from autonomous_trust.rendezvous._python import relay, relay_seeds as seeds


def _keygen(_args):
    key = SigningKey.generate()
    print('seed   %s' % HexEncoder.encode(bytes(key)).decode())
    print('public %s' % key.verify_key.encode(HexEncoder).decode())


def _sign(args):
    with open(args.seed_file) as f:
        seed = f.read().strip()
    print(seeds.sign_seeds(seed, args.seq, args.relays))


def _verify(args):
    with open(args.file) as f:
        seq, hints = seeds.verify_seeds(f.read(), args.key or seeds.RELEASE_KEY)
    print('seq %d' % seq)
    for endpoint, pin in hints:
        print('  ' + relay.hint_for(endpoint, pin))


def _local_path():
    return os.path.join(Configuration.get_data_dir(), seeds.LOCAL_FILE)


def _local(args):
    seed = seeds.node_seed_hex()
    if not seed:
        sys.exit('no identity.cfg.json under %s' % Configuration.get_cfg_dir())
    add, remove = [], []
    try:
        with open(_local_path()) as f:
            pub = SigningKey(HexEncoder.decode(seed.encode())).verify_key \
                .encode(HexEncoder).decode()
            a, r = seeds.verify_local(f.read(), pub)
            add = [relay.hint_for(ep, pin) for ep, pin in a]
            remove = [relay.hint_for(ep, pin) for ep, pin in r]
    except FileNotFoundError:
        pass
    new = [relay.hint_for(*relay.parse_hint(h)) for h in args.hints
           if relay.parse_hint(h)[0] is not None]
    if len(new) != len(args.hints):
        sys.exit('not a relay hint: %s' % [h for h in args.hints
                                           if relay.parse_hint(h)[0] is None])
    eps = {relay.parse_hint(h)[0] for h in new}
    add = [h for h in add if relay.parse_hint(h)[0] not in eps]
    remove = [h for h in remove if relay.parse_hint(h)[0] not in eps]
    if args.action == 'add':
        add += new
    elif args.action == 'remove':
        remove += new
    else:
        add, remove = [], []
    os.makedirs(Configuration.get_data_dir(), exist_ok=True)
    with atomic_write(_local_path()) as f:
        f.write(seeds.sign_local(seed, add, remove))
    print(json.dumps({'add': add, 'remove': remove}, indent=2))


def _show(_args):
    for endpoint, pin in seeds.load():
        print(relay.hint_for(endpoint, pin))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('keygen').set_defaults(func=_keygen)
    p = sub.add_parser('sign')
    p.add_argument('--seed-file', required=True)
    p.add_argument('--seq', type=int, required=True)
    p.add_argument('relays', nargs='+')
    p.set_defaults(func=_sign)
    p = sub.add_parser('verify')
    p.add_argument('file')
    p.add_argument('--key')
    p.set_defaults(func=_verify)
    p = sub.add_parser('local')
    p.add_argument('action', choices=('add', 'remove', 'clear'))
    p.add_argument('hints', nargs='*')
    p.set_defaults(func=_local)
    sub.add_parser('show').set_defaults(func=_show)
    args = ap.parse_args(argv)
    try:
        args.func(args)
    except seeds.InvalidSeeds as exc:
        sys.exit('refused: %s' % exc)


if __name__ == '__main__':
    main()
