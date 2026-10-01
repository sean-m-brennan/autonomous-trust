# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************
"""An encrypted backup of the address book, through the node
(FIRST_CONTACT_PLAN Phase 4, recovery). Part of first contact: registered by
:func:`.first_contact.register`, so off unless ``AT_FIRST_CONTACT`` is on.

Two local app verbs, the format being contacts/backup.py's:

  - ``app_backup_export {ref, path, passphrase}`` seals the address book and
    the sibling list into the file ``path`` (absolute; written atomically,
    mode 0600). With ``generate: true`` instead of a passphrase the node
    makes one, and the ``backup_written`` event carries it: the only time it
    is ever shown. Where the file goes from there is the app's business.
  - ``app_backup_import {ref, path, passphrase}`` opens the file and merges
    it in (contacts/backup.restore): the same rules and the same side effects
    as an address book from a sibling -- a contact new here is admitted,
    routed and told about this device, and the app hears ``contact`` /
    ``removed`` with ``origin: "backup"`` -- then ``backup_restored`` with
    the counts. Siblings from the backup join this node's list when its own
    device cert names the same operator; they have not met this device, so
    the user pairs again to resume syncing.

Anything refused is a ``backup_refused`` with a reason from
:data:`REASONS`. The node holds the passphrase only for the call, and never
the operator key: a backup carrying one (tools/backup.py) restores the
address book here and leaves the key to that tool.

Deriving the key is deliberately slow (Argon2id, 256 MiB): the identity
process is busy for about a second per call. Same verbs, events and reasons
as C's ``identity/backup_contact.{h,c}``.
"""
import os
from dataclasses import dataclass

from ..app_verbs import AppEvent, is_local_app_verb, refuse_remote_app_verb
from ..config.configuration import atomic_write
from ..contacts import backup as _backup

#: App verbs (local IPC only). Same strings as C's AT_APP_BACKUP_*.
APP_BACKUP_EXPORT = 'app_backup_export'
APP_BACKUP_IMPORT = 'app_backup_import'
APP_VERBS = (APP_BACKUP_EXPORT, APP_BACKUP_IMPORT)

#: BackupEvent.kind values. C's AT_APP_EVENT_BACKUP_* carry the same outcomes.
EVENT_WRITTEN = 'backup_written'     # ``path``, ``contacts``, ``siblings``; ``passphrase`` if generated
EVENT_RESTORED = 'backup_restored'   # ``added``, ``updated``, ``removed``, ``siblings``
EVENT_REFUSED = 'backup_refused'     # see ``reason``

#: BackupEvent.reason values. Index = C's at_backup_reason_t: the format's
#: own (contacts/backup.REASONS), then the request's.
REASONS = _backup.REASONS + ('bad_request', 'io')

#: Where a restored change came from, on the app's contact events.
ORIGIN_BACKUP = 'backup'

#: Longest ``path`` a request may name (C's PATH_MAX less the NUL).
PATH_MAX = 4095


@dataclass
class BackupEvent(AppEvent):
    """One backup outcome, reported to the app. ``ref`` echoes the request."""
    kind: str
    ref: str = ''
    path: str = ''
    #: ``backup_written`` with ``generate: true`` only: the code to write down.
    passphrase: str = ''
    reason: str = ''
    contacts: int = 0
    siblings: int = 0
    added: int = 0
    updated: int = 0
    removed: int = 0


def _fc():
    from . import first_contact
    return first_contact


def register(proc) -> None:
    """Wire the handlers into an IdentityProcess (from first_contact.register)."""
    import functools
    proc.protocol.register_handler(APP_BACKUP_EXPORT,
                                   functools.partial(handle_app_backup_export, proc))
    proc.protocol.register_handler(APP_BACKUP_IMPORT,
                                   functools.partial(handle_app_backup_import, proc))


def _refuse(proc, queues, ref, reason, path=''):
    _fc()._emit(proc, queues, BackupEvent(EVENT_REFUSED, ref=ref, path=path,
                                          reason=reason))
    return True


def _request(proc, queues, message, verb):
    """The shared front half: local-only, a usable ref, an absolute path.
    Returns (req, ref, path), or None once it has refused."""
    fc = _fc()
    if not is_local_app_verb(proc, message):
        refuse_remote_app_verb(proc, message, verb)
        return None
    req = fc._app_payload(message)
    ref = fc._app_ref(req)
    if ref is None:
        _refuse(proc, queues, '', 'bad_request')
        return None
    path = req.get('path')
    if not isinstance(path, str) or not os.path.isabs(path) \
            or len(path.encode('utf-8')) > PATH_MAX or '\0' in path:
        _refuse(proc, queues, ref, 'bad_request')
        return None
    return req, ref, path


def handle_app_backup_export(proc, queues, message) -> bool:
    """Seal the address book and siblings into ``path``. Answers
    ``backup_written`` or ``backup_refused``."""
    got = _request(proc, queues, message, APP_BACKUP_EXPORT)
    if got is None:
        return True
    req, ref, path = got
    generate = req.get('generate') is True
    passphrase = req.get('passphrase')
    if generate == (passphrase is not None):
        # Exactly one of the two.
        return _refuse(proc, queues, ref, 'bad_request', path)
    if generate:
        passphrase = _backup.generate_passphrase()
    elif not isinstance(passphrase, str):
        return _refuse(proc, queues, ref, 'bad_request', path)
    from . import sibling_sync
    store = _fc()._contacts_store(proc)
    sib = sibling_sync.siblings(proc)
    try:
        text = _backup.seal(_backup.build_contents(store, sib), passphrase)
    except _backup.BackupError as err:
        return _refuse(proc, queues, ref, err.reason, path)
    try:
        with atomic_write(path) as fh:
            fh.write(text)
        os.chmod(path, 0o600)
    except OSError as err:
        proc.logger.warning('first contact: backup not written to %s (%s)', path, err)
        return _refuse(proc, queues, ref, 'io', path)
    proc.logger.info('first contact: backup of %d contact(s), %d sibling(s) written',
                     len(store), len(sib))
    _fc()._emit(proc, queues, BackupEvent(
        EVENT_WRITTEN, ref=ref, path=path,
        passphrase=passphrase if generate else '',
        contacts=len(store), siblings=len(sib)))
    return True


def handle_app_backup_import(proc, queues, message) -> bool:
    """Open the backup at ``path`` and merge it in. Answers the contact
    events of what changed, then ``backup_restored``; or ``backup_refused``."""
    got = _request(proc, queues, message, APP_BACKUP_IMPORT)
    if got is None:
        return True
    req, ref, path = got
    passphrase = req.get('passphrase')
    if not isinstance(passphrase, str):
        return _refuse(proc, queues, ref, 'bad_request', path)
    try:
        with open(path, 'rb') as fh:
            text = fh.read(2 * _backup.CT_MAX + 1)
    except OSError as err:
        proc.logger.warning('first contact: backup at %s unreadable (%s)', path, err)
        return _refuse(proc, queues, ref, 'io', path)
    if len(text) > 2 * _backup.CT_MAX:
        return _refuse(proc, queues, ref, 'malformed', path)
    from . import device_contact, sibling_sync
    fc = _fc()
    store = fc._contacts_store(proc)
    sib = sibling_sync.siblings(proc)
    before = dict(store.contacts)
    try:
        contents = _backup.open_contents(text, passphrase)
        changes, paired = _backup.restore(store, sib, contents,
                                          own_cert=device_contact.own_cert(proc),
                                          own_uuid=str(proc.identity.uuid))
    except _backup.BackupError as err:
        proc.logger.info('first contact: backup at %s refused (%s)', path, err.reason)
        return _refuse(proc, queues, ref, err.reason, path)
    if paired:
        sibling_sync._save_siblings(proc, sib)
    if changes:
        # A local edit as far as our current siblings are concerned: pushed.
        fc._save_book(proc, store, queues)
        sibling_sync._apply(proc, queues, store, before, changes, origin=ORIGIN_BACKUP)
    count = {a: sum(1 for _u, act in changes if act == a)
             for a in ('added', 'updated', 'removed')}
    proc.logger.info('first contact: backup restored (%d added, %d updated, '
                     '%d removed, %d sibling(s))', count['added'], count['updated'],
                     count['removed'], len(paired))
    fc._emit(proc, queues, BackupEvent(
        EVENT_RESTORED, ref=ref, path=path, contacts=len(store),
        siblings=len(paired), **count))
    return True
