#!/usr/bin/env python3
# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Make, inspect and restore an encrypted backup of a node's address book
(FIRST_CONTACT_PLAN Phase 4, recovery; contacts/backup.py).

The operator side of the backup, and the only thing that ever puts the
operator key in one or takes it back out. A node's own app verbs
(app_backup_export / app_backup_import) never touch the key.

    backup.py export --out FILE [--with-operator-key] [--generate]
                                   # this node ($AUTONOMOUS_TRUST_ROOT)
    backup.py inspect FILE         # what is in it (needs the passphrase)
    backup.py restore-key FILE     # the operator key back into the keystore
    backup.py import FILE          # merge into this node's book, node STOPPED

The passphrase is read from $AT_BACKUP_PASSPHRASE, else asked for (twice on
export). With --generate the tool makes one and prints it, once.

Replacing a lost phone whose operator key lived on it:

    backup.py restore-key alice.atbackup    # keystore has the key again
    device_cert.py issue                    # the new phone's device cert
    backup.py import alice.atbackup         # or app_backup_import, node running

then start the node: it announces itself to every contact, and each files it
under the matching verified contact.
"""
import argparse
import getpass
import json
import os
import sys

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from autonomous_trust.core._python.config.configuration import Configuration, atomic_write
from autonomous_trust.core._python.contacts import backup as bk
from autonomous_trust.core._python.contacts import device as dv
from autonomous_trust.core._python.contacts.siblings import Siblings
from autonomous_trust.core._python.contacts.store import Contacts
from autonomous_trust.core._python.identity import device_contact
from autonomous_trust.core._python.identity.operator_keystore import (
    load_or_create_operator_key, operator_key_path)


def _passphrase(confirm=False):
    env = os.environ.get('AT_BACKUP_PASSPHRASE')
    if env:
        return env
    first = getpass.getpass('backup passphrase: ')
    if confirm and getpass.getpass('again: ') != first:
        sys.exit('the passphrases differ')
    return first


def _open(path):
    try:
        with open(path) as fh:
            return bk.open_contents(fh.read(), _passphrase())
    except OSError as err:
        sys.exit('cannot read %s (%s)' % (path, err))


def _own_cert():
    path = device_contact.device_cert_path()
    try:
        with open(path) as fh:
            return dv.DeviceCert.from_wire(json.load(fh)).verify()
    except (OSError, ValueError, dv.InvalidDevice):
        return None


def _export(args):
    store, sib = Contacts.load(), Siblings.load()
    key = ''
    if args.with_operator_key:
        if not os.path.isfile(operator_key_path(args.keystore or '')):
            sys.exit('no operator key in the keystore to include')
        key, _pub = load_or_create_operator_key(args.keystore or '')
        key = key.decode() if isinstance(key, bytes) else key
    passphrase = bk.generate_passphrase() if args.generate else _passphrase(confirm=True)
    text = bk.seal(bk.build_contents(store, sib, operator_key=key), passphrase)
    out = os.path.abspath(args.out)
    with atomic_write(out) as fh:
        fh.write(text)
    os.chmod(out, 0o600)
    print('%d contact(s), %d sibling(s)%s -> %s' % (
        len(store), len(sib), ', operator key' if key else '', out))
    if args.generate:
        print('passphrase (write it down; it is not stored): %s' % passphrase)


def _inspect(args):
    c = _open(args.file)
    book = c['contacts']
    print('made %s: %d contact(s), %d removal(s), %d sibling(s), operator key %s' % (
        c.get('created_at'), len(book.get('contacts', {})), len(book.get('tombstones', {})),
        len((c.get('siblings') or {}).get('devices', [])),
        'included' if c.get('operator_key') else 'not included'))


def _restore_key(args):
    c = _open(args.file)
    seed = c.get('operator_key')
    if not isinstance(seed, str) or not seed:
        sys.exit('this backup holds no operator key')
    try:
        pub = SigningKey(HexEncoder.decode(seed.encode())).verify_key.encode().hex()
    except Exception:  # noqa: BLE001 -- any decoding failure is the same answer
        sys.exit('the operator key in this backup is unusable')
    path = operator_key_path(args.keystore or '')
    if os.path.isfile(path):
        with open(path, 'rb') as fh:
            have = fh.read().strip().decode()
        if have.lower() != seed.lower():
            sys.exit('%s already holds a different operator key; not replaced' % path)
        print('operator key %s already in %s' % (pub, path))
        return
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    with atomic_write(path) as fh:
        fh.write(seed.lower())
    os.chmod(path, 0o600)
    print('operator key %s -> %s' % (pub, path))


def _this_uuid():
    path = os.path.join(Configuration.get_cfg_dir(), 'identity' + Configuration.file_ext)
    try:
        with open(path) as f:
            ident = json.load(f)
    except (OSError, ValueError):
        return ''
    uuid = ident.get('uuid') or ident.get('_uuid')
    if isinstance(uuid, dict):
        uuid = uuid.get('__value__')
    return uuid if isinstance(uuid, str) else ''


def _import(args):
    c = _open(args.file)
    store, sib = Contacts.load(), Siblings.load()
    try:
        changes, paired = bk.restore(store, sib, c, own_cert=_own_cert(),
                                     own_uuid=_this_uuid())
    except bk.BackupError as err:
        sys.exit('refused (%s): %s' % (err.reason, err))
    if changes:
        store.save()
    if paired:
        sib.save()
    count = {a: sum(1 for _u, act in changes if act == a)
             for a in ('added', 'updated', 'removed')}
    print('%(added)d added, %(updated)d updated, %(removed)d removed' % count
          + ', %d sibling(s) (pair again to sync with them)' % len(paired))
    if c.get('operator_key'):
        print('this backup also holds the operator key: see restore-key')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--keystore', help='operator keystore directory')
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('export')
    p.add_argument('--out', required=True)
    p.add_argument('--with-operator-key', action='store_true')
    p.add_argument('--generate', action='store_true', help='make the passphrase')
    p.set_defaults(func=_export)
    for name, func in (('inspect', _inspect), ('restore-key', _restore_key),
                       ('import', _import)):
        p = sub.add_parser(name)
        p.add_argument('file')
        p.set_defaults(func=func)
    args = ap.parse_args(argv)
    try:
        args.func(args)
    except bk.BackupError as err:
        sys.exit('refused (%s): %s' % (err.reason, err))


if __name__ == '__main__':
    main()
