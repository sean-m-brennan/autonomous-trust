*Previous: [Traffic over the open internet](at-internet-traffic.md)*

# AutonomousTrust API: Integrating with an Application

You integrate AutonomousTrust by embedding a node in your program. A node is a
subclass of `AutonomousTrust`. You attach the capabilities the node offers and
the workers it runs, then start it. The node handles identity, peer discovery,
group formation, reputation, and messaging; your code decides what the node does
and what it exposes to peers.

There are four things you will touch, in rough order of how deep you go:

1. The node class, `AutonomousTrust`: construct it, run it.
2. Override hooks: where your logic plugs into the node lifecycle.
3. Capabilities and workers: what the node offers to peers and the concurrency it runs.
4. Messaging and trust state: sending to peers and reading the trust picture.

All imports resolve through the backend redirector, so `autonomous_trust.core.X`
works regardless of whether the Python or C backend is active. See [Backend
selection](#backend-selection).

## The node: `AutonomousTrust`

```python
from autonomous_trust.core import AutonomousTrust, LogLevel

class MyNode(AutonomousTrust):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # register workers here (see below)

MyNode(log_level=LogLevel.INFO).run_forever()   # blocks; runs as the lead process
```

`run_forever()` starts the four core subsystems (network, identity, negotiation,
reputation) plus any workers you added, then runs the main loop until it
receives a quit signal. It installs a SIGTERM handler so `kubectl delete`,
`docker stop`, and Tilt teardown shut the subprocesses down cleanly.

Constructor parameters:


| Parameter     | Default            | Purpose                                                                                                  |
| ------------- | ------------------ | -------------------------------------------------------------------------------------------------------- |
| `multiproc`   | `True`             | `True` runs each subsystem in its own OS process; `False` uses threads (useful for embedding and tests). |
| `log_level`   | `LogLevel.WARNING` | Log verbosity.`LogLevel` has `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`.                            |
| `logfile`     | data dir           | Path for the rotating log, or`Configuration.log_stdout` to log only to stdout.                           |
| `log_classes` | all subsystems     | Restrict logging to specific subsystem names.                                                            |
| `syslog`      | `False`            | Also emit to`/dev/log`.                                                                                  |
| `context`     | `Ctx.DEFAULT`      | Multiprocessing start method. Use`Ctx.FORKSERVER` where fork safety matters.                             |
| `testing`     | `False`            | Registers demo abilities and random tasking. Leave off in real integrations.                             |
| `silent`      | `False`            | Suppress the stdout handler. Coordinators that own a UI usually set this.                                |

To run the stock node without subclassing:

```bash
python -m autonomous_trust.core [ident] [--test] [--live] [--log-level info]
```

## Identity and configuration bootstrap

Each node needs a root directory for its keys and config. Point
`AUTONOMOUS_TRUST_ROOT` at a per-node directory before constructing the node;
the node derives `etc/at` and `var/at` under it.

```python
import os
from autonomous_trust.core import Configuration
from autonomous_trust.core.config.generate import generate_identity, generate_worker_config

os.environ[Configuration.ROOT_VARIABLE_NAME] = "/path/to/node-root"
cfg_dir = Configuration.get_cfg_dir()
os.makedirs(cfg_dir, exist_ok=True)

# Create the node's cryptographic identity (Ed25519 signing key, X25519
# key-agreement key, UUID) if it does not already exist. preserve=True
# keeps existing keys across restarts.
generate_identity(cfg_dir, preserve=True, defaults=True)

# Optional: write a default config for a worker that needs one.
generate_worker_config(cfg_dir, DataProcess.name, DataConfig, True)
```

Private keys are written under the node root and never travel the wire. Reusing
the same root across restarts gives the node a persistent identity and warm
reputation state (see [Persistent cohort](architecture/persistent-cohort.md)).

## First contact: finding and adding a specific person

The first thing a new user does is add a specific human they already know. AT's
peer discovery is **LAN-only** — UDP broadcast/multicast finds peers on the same
local network — so it is *not* the answer for a friend across town, behind NAT, or
not currently on your Wi-Fi. Adding that person is a separate, one-to-one
primitive, distinct from the cohort vote that admits a newcomer to a group. It
lives in `autonomous_trust.core.contacts`; the concept is in
[First contact](architecture/first-contact.md).

The trust root is always the cryptographic identity, never the identifier that
led to it. The default path is an out-of-band **invitation** carrying the inviter's
public key, so no directory is involved and there is nothing to spoof.

| Call | Role |
|---|---|
| `create_invitation(identity, rendezvous=…, ttl_seconds=…) -> Invitation` | Mint a signed OOB token from your own identity. `.encode()` / `.to_uri()` render it as a QR blob or `at+contact:` link. |
| `redeem_invitation(blob, in_person=False) -> Contact` | Ingest a friend's token, verifying its signature; produce a `Contact`. |
| `safety_number(id_a, id_b) -> str` | The symmetric digit string the two humans compare over a trusted channel. |
| `verify_contact(contact, presented, my_identity) -> Contact` | Confirm the safety number and promote the contact to verified. |
| `Contacts.load(data_dir)` / `.save(data_dir)` / `.add` / `.get` | The durable, user-owned address book (`<data_dir>/contacts.cfg.json`). |

Your first five minutes, end to end — Alice shares a link, Bob adds her. Each
`*_identity` is that node's own generated `Identity`; they live on different
machines, shown together only to make the values explicit:

```python
from autonomous_trust.core.contacts import (create_invitation, redeem_invitation,
                                             safety_number, verify_contact, Contacts)

# On Alice's node: mint an invitation from her own identity and share the link.
invite = create_invitation(alice_identity, rendezvous=["relay-hint"], ttl_seconds=3600)
link = invite.to_uri()          # "at+contact:eyJib2R5..."; send over SMS/Signal/QR

# On Bob's node: ingest the link and store the contact.
contact = redeem_invitation(link)          # signature verified; remote => unverified
store = Contacts.load(data_dir)
store.add(contact); store.save(data_dir)   # durable; survives restarts and networks

# Verify out of band (the MITM defense): Alice reads her safety number to Bob
# over a trusted channel. The number is symmetric, so Bob confirms the match.
presented = safety_number(alice_identity, bob_identity)   # what Alice reads aloud
verify_contact(contact, presented, bob_identity)          # flips verified on match
store.save(data_dir)
```

A QR code scanned in person is stronger still: pass `in_person=True` to
`redeem_invitation` and the contact is verified on the spot, because the key
arrived over a channel with no man in the middle. A contact added from a remote
link is usable while **unverified** — you may message it — but it reads as
unverified until the safety number is confirmed, and higher-trust actions should
gate on `contact.verified`. Rendezvous relays (reaching a contact across NAT) and
an optional find-by-handle directory are later phases; the invitation path above
needs neither.

### Going live: the 1:1 handshake (opt-in)

Everything above is offline — Bob now holds Alice's key and remembers her, but
the two nodes have not spoken. The handshake makes the pair live. It is **off by
default**: set `AT_FIRST_CONTACT=1` on both nodes, and a node that has not opted
in registers no handlers for it.

Your application drives it through two requests on the node's control queue,
the `q_in` you passed to `run_forever`, and reads the answers from `q_out`. The
app holds no private key, so the node mints the invitation for it:

```python
import json
from autonomous_trust.core.app_verbs import AppRequest
from autonomous_trust.core.identity.first_contact import (
    APP_INVITE, APP_INITIATE, FirstContactEvent)

# Alice's app: ask her node for a link to share.
control_queue.put(AppRequest(APP_INVITE, json.dumps({
    'ref': 'for-bob',            # echoed on the answer
    'ttl_seconds': 24 * 3600,    # 0 = never expires; omit for a week
})))

# Bob's app, holding the link Alice sent him:
control_queue.put(AppRequest(APP_INITIATE, json.dumps({
    'ref': 'add-alice',
    'invitation': link,
    'in_person': False,          # True ONLY for a QR scanned face to face
    'petname': 'Alice',
})))

# Either app, reading answers from q_out:
event = feedback_queue.get()
if isinstance(event, FirstContactEvent):
    if event.kind == 'invitation':
        share(event.blob)                    # an at+contact: link
    elif event.kind == 'established':
        print(event.nickname, 'is now a contact', event.role)
    elif event.kind == 'refused':
        print('could not add:', event.reason)
```

| Event `kind` | Means | Fields worth reading |
|---|---|---|
| `invitation` | the node minted your link | `blob`, `expiry` |
| `hello_sent` | your node said hello to the inviter | `peer_uuid`, `nickname` |
| `established` | both nodes now hold each other | `peer_uuid`, `nickname`, `role` |
| `refused` | a request, or a hello to one of *your* links, failed | `reason` |

Every event carries the `ref` of the request it answers. Two silences are by
design. The initiator is never told a hello was refused, because the inviter
sends nothing back (a probe learns nothing from a bad ticket), so `hello_sent`
followed by nothing for two minutes means refused or unreachable. The inviter is
told about a refusal only for a link it minted, one that came back expired or
already used, never about strangers' garbage.

The requests are honored only from the local app, never from the wire, and only
while `AT_FIRST_CONTACT` is on. From C, the same two requests and four events are
[`at_first_contact.h`](../src/c/autonomous_trust/at_first_contact.h):
`at_app_first_contact_invite` / `at_app_first_contact_initiate`, and
`at_first_contact_event()` on a polled `at_app_event_t`.

#### The address book, through the node

Once a node is running, let it own `contacts.cfg.json`: ask it rather than
editing the file from the app, or the app and the node race to rewrite it.
Every request names the contact by uuid (`peer`), echoes `ref`, and answers with
a `ContactEvent` (or a `FirstContactEvent` of kind `refused`):

| Request (`APP_...`) | Payload | Answer |
|---|---|---|
| `SAFETY_NUMBER` | `{ref, peer}` | `safety_number` event: the 60 digits to show |
| `VERIFY` | `{ref, peer, presented}` or `{ref, peer, confirmed: true}` | `verified` (`method` says which), or `refused` / `mismatch` |
| `LIST` | `{ref}` | one `contact` per record, oldest first, then `contacts_done` with `count` |
| `RENAME` | `{ref, peer, petname}` | `contact` with the new name |
| `REMOVE` | `{ref, peer}` | `removed`; `peer_dropped` says whether a direct peer was let go |

Verifying has two honest forms. `presented` is the number as the user typed it
from the *other* person's screen, and the node compares it. `confirmed` is the
user saying they compared the two screens by eye, the usual flow, and the node
takes their word for it as it does for `in_person`. Echoing back the number the
node itself handed out would compare it with itself, so there is no third form.

Removing a contact deletes the record and drops the direct peer at once, so
the node stops attributing and encrypting to it; adding them back takes a fresh
invitation. A contact who is also in your cohort keeps its place there, because
that place belongs to the group, and `peer_dropped` is `False`.

The C calls are `at_app_first_contact_safety_number` / `_verify` / `_list` /
`_rename` / `_remove`, answered by events read with
`at_first_contact_contact_event()`.

Inside the identity process, the call underneath is:

```python
from autonomous_trust.core.identity import first_contact
inviter = first_contact.initiate(proc, queues, link, ref='add-alice')
```

Alice's node validates the ticket — her signature, not expired, nonce not
already spent (an invitation is **single-use**, and the spent nonce survives a
restart) — admits Bob, and acknowledges; Bob's node admits Alice on the ack.
Both messages ride the open channel by necessity: the first hello arrives before
either side is a known peer. Bob's node honors only the ack it is waiting for:
from the inviter it said hello to, signed by the key the invitation carried,
echoing the ticket's nonce, within two minutes. An ack out of nowhere admits
nobody.

Until a contact is verified, this node serves it at most **tier 1**
(communication) when it asks for a capability, however much reputation it has
earned: a tier-2 or higher capability is refused. Verifying lifts that at once.
Members of your cohort are not affected.

**Behind NAT.** A node a friend cannot reach directly can use a rendezvous
relay: set `AT_USE_RELAY=host:port` (or several, comma-separated, in order of
preference, up to 4) and every link it mints names them, so the friend's node
says hello through them and the two stay reachable that way. When a relay is
down, or cannot reach the friend, traffic moves to the next one. Saved contacts
reconnect on their own after a restart: the node re-admits everyone in its
address book and routes each through its recorded relays, then its own. Any
node can serve as a relay with `AT_RELAY=1` (TCP port `AT_RELAY_PORT`, default
27790). A relay forwards sealed frames and can neither read nor forge them. It
proves who it is when a node registers, and once it has, the links that node
mints pin it (`relay://<uuid>:<fp>@host:port`, uuid plus a fingerprint of its
key), so nothing else answering at that address is accepted. A node never uses a
relay whose reputation has fallen below the cut-off, and a relay never serves
such a node; unknown and neutral nodes are served. A node keeps its contacts
told where it is: whenever its relays or address change it signs a new
reachability record, pushes it to its contacts and files it at its relays, and a
contact that has lost it looks the record up there.

With no `AT_USE_RELAY` set, a node with first contact on falls back on the
**signed seed list**: `<cfg_dir>/relay_seeds.cfg.json` (or `$AT_RELAY_SEEDS`),
shipped with the build and signed by the project's release key, plus the
operator's own additions and removals in `<data_dir>/relay_seeds_local.cfg.json`
(signed by the node's key). `tools/relay_seeds.py local add|remove|clear` edits
them and `show` prints the relays the node will use. An explicit `AT_USE_RELAY`
always wins, and with first contact off the list is never read.

Ahead of the seed list come the relays of any **community** the operator pinned:
signed rosters in `<cfg_dir>/relay_rosters/` from the issuers in
`$AT_RELAY_ROSTER_ISSUERS` or `<cfg_dir>/relay_roster_issuers.cfg.json`. An Ethne
polity publishes one for the relays it runs (`en_uplift::rendezvous_roster`); any
other community signs one with `tools/relay_rosters.py`, which also pins, installs
and shows them. A newer roster from an issuer replaces its older one whole.

What admission means here is narrower than joining a group, and worth being
explicit about if you are building on it: each side gains the other as a
**direct peer** — reachable, attributable on the encrypted point-to-point
channel, and scorable by reputation — and **not** a group member. The group key
is not propagated, so an invitation can never be used as a back door into the
cohort. The contact also stays `verified=False` until the safety-number
comparison above; the handshake proves reachability, not identity.

The C twin is `at_first_contact_initiate` /
`handle_first_contact_hello` (`identity/first_contact.h`), gated on the same
`AT_FIRST_CONTACT` flag, with the same three gates, the same durable single-use
guard, and the same pending-hello gate on the ack.

#### Finding someone by handle (opt-in directory)

A link is the strongest way to add someone, but it has to travel between the
two people first. The directory is the alternative for someone you know only by
a handle, such as an email address or phone number. It is opt-in on both ends:
Alice is findable only if she publishes, and a registry lists her only on an
issuer's word that the handle is hers. Finding her does not add her. Bob asks,
and **Alice's app has to accept** before the two nodes meet.

A registry is a relay that also sets `AT_REGISTRY=1`, and it trusts the issuers
listed in `<cfg_dir>/registry_issuers.cfg.json` (`{"issuers": ["<hex key>"]}`).
An issuer is whoever checked that Alice controls the handle (an email round
trip, an SMS code, an organization's own records) and signed an attestation
binding the handle to her node's key (`tools/directory_issuer.py attest`). Alice
and Bob each register with the registry as their relay (`AT_USE_RELAY`).

```python
from autonomous_trust.core._python.identity.directory_contact import (
    APP_DIR_PUBLISH, APP_DIR_LOOKUP, APP_REQUEST, APP_ACCEPT, APP_DECLINE,
    DirectoryEvent)

# Alice's app: publish the handle an issuer attested.
control_queue.put(AppRequest(APP_DIR_PUBLISH, json.dumps({
    'ref': 'pub', 'attestation': attestation,   # {body, sig} from the issuer
    'visibility': 'anyone',                      # or 'published': only findable
})))                                             # by others who publish too

# Bob's app: look her up, then ask.
control_queue.put(AppRequest(APP_DIR_LOOKUP, json.dumps(
    {'ref': 'look', 'handle': 'alice@example.org'})))
# ... a DirectoryEvent 'found' arrives, then:
control_queue.put(AppRequest(APP_REQUEST, json.dumps(
    {'ref': 'ask', 'handle': 'alice@example.org'})))

# Alice's app, on a DirectoryEvent 'contact_request':
control_queue.put(AppRequest(APP_ACCEPT, json.dumps({'ref': event.ref})))
# (or APP_DECLINE; either way nothing is said to Bob unless she accepts)
```

| `DirectoryEvent` kind | Means | Fields worth reading |
|---|---|---|
| `published` / `withdrawn` | a registry filed (or dropped) your entry | `handle`, `relay`, `seq` |
| `found` | a lookup found the handle | `peer_uuid`, `nickname`, `relay` |
| `not_found` | it did not | `reason`: `''`, `limited` (asked too often), `invalid` |
| `request_sent` | your request left for the holder | `peer_uuid` |
| `contact_request` | someone asks to become your contact | `ref` (answer with it), `peer_uuid`, `nickname`, `handle` |
| `accepted` / `declined` | your app answered a request | `peer_uuid` |
| `refused` | a request failed | `reason` |

After an accept, the ordinary handshake runs and each app sees a
`FirstContactEvent` `established`, under the `ref` of its request. Both sides
record an **unverified** contact with provenance `directory`, capped at tier 1
until the safety numbers match. The directory helps you find the person;
verification is still what makes them trusted. `APP_DIR_WITHDRAW` (`{ref,
handle}`) takes an entry back.

What bounds harvesting is that a lookup names one handle, and each registry
allows each client a limited number a minute (`AT_REGISTRY_RATE`, default 10).
An entry with visibility `published` is shown only to clients that publish
themselves. The answer for a handle nobody filed is the same as for one you may
not see. Bob's node checks every entry itself (the holder's signature, the
issuer's attestation, the handle it asked for) rather than take the registry's
word.

From C, the requests are in
[`at_first_contact.h`](../src/c/autonomous_trust/at_first_contact.h):
`at_app_directory_publish` / `_withdraw` / `_lookup`, then
`at_app_first_contact_request` and, on the holder's side,
`at_app_first_contact_accept` / `_decline` with the request's `ref`. The events
are the `AT_APP_EVENT_DIR_*` kinds, read with `at_first_contact_directory_event()`;
the `established` that follows an accept is an ordinary
`AT_APP_EVENT_FC_ESTABLISHED`. A C registry is a relay with `AT_REGISTRY=1`,
reading the same `registry_issuers.cfg.json`.

#### Your own devices: pairing and one address book

Each of your devices is its own node, with its own keys. What ties them
together is your **operator key**. Run `tools/device_cert.py issue` where your
operator keystore is, once per device; it writes
`<cfg_dir>/device_cert.cfg.json`, which must name that very node. A contact who
has verified you then files your other devices under your record without you
doing anything: a device with a cert tells your contacts about itself when it
starts, and each contact's app gets a `ContactEvent` `device_linked`.

To give a new device your address book, **pair** it with one you already have.
On the old device, ask for a pairing link, and redeem it on the new one:

```python
from autonomous_trust.core._python.identity.sibling_sync import (
    APP_SIBLING_LIST, APP_SIBLING_REMOVE)

# Old device: a pairing link (needs a device cert; `refused` / not_sibling otherwise).
control_queue.put(AppRequest(APP_INVITE, json.dumps({'ref': 'pair', 'pair': True})))
# New device: redeem it, as any link.
control_queue.put(AppRequest(APP_INITIATE, json.dumps(
    {'ref': 'pair', 'invitation': link})))
```

The two nodes run the ordinary handshake, then each checks that the other's
device cert names the same operator key. If it does, both apps see a
`FirstContactEvent` `sibling_paired`, and neither records the other as a
contact. If it does not (a device with no cert, another person's device, or no
cert within two minutes), both see `refused` with reason `not_sibling`, and the
direct peer is dropped. A pairing link never becomes a contact.

Paired devices, **siblings**, keep one address book. The new device gets the
whole book at once, verified contacts included, and each sibling then gets
every rename, removal, verification or device link as it happens. At startup
the books are swapped again. The app hears these changes as the usual
`contact` and `removed` events with `origin == 'sibling'`. A contact that
arrives this way is reached from this device too, and is told this device is
yours. Siblings are never tier-capped. The newer edit wins, a removal
propagates, and a verification made on one device is never undone by an edit
made on another (see `first-contact.md`, *Your own devices, one address book*).

| Request | Payload | Answer |
|---|---|---|
| `APP_SIBLING_LIST` | `{ref}` | one `ContactEvent` `sibling` per device (`peer_uuid`, `nickname`, `added_at`), then `siblings_done` with `count` |
| `APP_SIBLING_REMOVE` | `{ref, peer}` | `sibling_removed` (`peer_dropped`); only on this device, as unpairing is not synced |

From C: `at_app_first_contact_pair_invite`, then `at_app_first_contact_initiate`
on the new device; `at_app_sibling_list` / `at_app_sibling_remove`. The events
are `AT_APP_EVENT_FC_SIBLING_PAIRED` (read with `at_first_contact_event()`) and
`AT_APP_EVENT_FC_SIBLING` / `_SIBLINGS_DONE` / `_SIBLING_REMOVED` (read with
`at_first_contact_contact_event()`); a synced change carries
`origin == AT_FC_ORIGIN_SIBLING`.

#### A lost device: the encrypted backup

Pairing needs the old device in your hand. For the day it is gone, have the
node seal your address book and sibling list into a file, under a passphrase,
and keep that file anywhere you like:

```python
from autonomous_trust.core._python.identity.backup_contact import (
    APP_BACKUP_EXPORT, APP_BACKUP_IMPORT)

# Your passphrase (12 characters or more), or `'generate': True` for the node to make one.
control_queue.put(AppRequest(APP_BACKUP_EXPORT, json.dumps(
    {'ref': 'b', 'path': '/home/alice/alice.atbackup', 'passphrase': passphrase})))
# On the replacement device, once it has its own device cert:
control_queue.put(AppRequest(APP_BACKUP_IMPORT, json.dumps(
    {'ref': 'r', 'path': '/media/usb/alice.atbackup', 'passphrase': passphrase})))
```

The node writes the file atomically, readable only by you (mode 0600), and
never keeps the passphrase. The key is Argon2id over the passphrase (256 MiB,
so expect about a second), and the file is XChaCha20-Poly1305. A generated
passphrase is 24 characters in groups of four, shown once in the
`backup_written` event; it can be typed back in lower case or with spaces.

An import merges into the address book on this device. It never replaces it.
The rules are those of a sibling's sync: the newer edit wins, a removal stays
removed, and a verified contact stays verified, filed with provenance `backup`.
Every contact that arrives is reached from this device and told that the
device is yours, so a contact who verified you files the new device under your
record, as long as it has a cert from your operator key. The app hears the
usual `contact` / `removed` events with `origin == 'backup'`, then
`backup_restored`. The siblings in the backup join this device's list when its
cert names the same operator key. They have never met this device, though, so
pair again with each one to resume syncing.

| Request | Payload | Answer |
|---|---|---|
| `APP_BACKUP_EXPORT` | `{ref, path, passphrase}` or `{ref, path, generate: true}` | `BackupEvent` `backup_written` (`path`, `contacts`, `siblings`; `passphrase` when generated) |
| `APP_BACKUP_IMPORT` | `{ref, path, passphrase}` | `contact` / `removed` events, then `backup_restored` (`added`, `updated`, `removed`, `siblings`, `contacts`) |

Either one can answer `backup_refused` with a `reason`. `bad_request` means no
absolute `path`, or not exactly one of `passphrase` / `generate`.
`weak_passphrase` means fewer than 12 characters. `bad_passphrase` means the
open failed, either a wrong passphrase or a file changed since it was made,
and the two cannot be told apart. `malformed` means not a backup.
`unsupported` means another version, or Argon2id settings outside what an
open accepts. `io` means the file could not be written or read.

The node never puts your **operator key** in a backup. If that key lived on
the lost phone, contacts cannot link a replacement, so keep a copy of the key
with `tools/backup.py`, the operator-side tool and the only thing that reads
or writes the key:

```sh
tools/backup.py export --out alice.atbackup --with-operator-key   # the book, siblings and key
tools/backup.py restore-key alice.atbackup    # on the replacement: the key back in the keystore
tools/device_cert.py issue                    # the new device's cert
tools/backup.py import alice.atbackup         # or APP_BACKUP_IMPORT with the node running
```

`restore-key` never replaces a different key already in the keystore, and
`inspect` shows what a backup holds.

From C: `at_app_backup_export` (a NULL passphrase asks for a generated one) and
`at_app_backup_import`. The events are `AT_APP_EVENT_BACKUP_WRITTEN` /
`_RESTORED` / `_REFUSED`, read with `at_first_contact_backup_event()`, and a
restored change carries `origin == AT_FC_ORIGIN_BACKUP`.

## Override hooks

Your integration logic lives in methods you override on your subclass. Each
receives `queues`, the dictionary of interprocess queues keyed by subsystem
name.


| Method                                      | When it runs          | Use it to                                                                                    |
| ------------------------------------------- | --------------------- | -------------------------------------------------------------------------------------------- |
| `autonomous_ability(queues)`                | Once, before the loop | Register the capabilities this node offers and broadcast them to the workers.                |
| `init_tasking(queues)`                      | Once, before the loop | One-time setup that needs the queues.                                                        |
| `autonomous_tasking(queues)`                | Every tick            | Drive work: send messages, kick off tasks, poll state.                                       |
| `cleanup()`                                 | On shutdown           | Release resources.                                                                           |
| `autonomous_loop(results, queues, signals)` | Replaces the loop     | Full control. You must replicate process monitoring and message handling yourself. Advanced. |

`add_worker(...)` is the exception: it must be called from `__init__`, not from
a hook, because workers are launched when the node starts.

## Capabilities: what the node offers

A capability is a named service a node advertises to its peers. Register
capabilities in `autonomous_ability`, then broadcast the populated
`Capabilities` object to the worker queues so the other subsystems learn what
this node offers.

```python
from autonomous_trust.core.system import queue_cadence

def autonomous_ability(self, queues):
    self.capabilities.register_ability(
        "weather",                 # capability name
        self.read_weather,         # callable, or None if a worker serves it
        required_tier=1,           # minimum peer tier allowed to invoke it
        transaction_weight=2,      # reputation weight of one invocation
        description="Hourly weather observation",
    )
    for q_name in queues:
        if q_name != self.proc_name:
            queues[q_name].put(self.capabilities, block=True, timeout=queue_cadence)
```

`register_ability(name, function, arg_names=None, keywords=None,
required_tier=0, transaction_weight=1, description="", kind="",
arg_schema=None)`. `required_tier` gates access: a peer must have earned at
least that trust tier to invoke the capability (0 means any admitted peer).
`transaction_weight` sets how much a single use counts toward reputation. See
[Trust tiers](architecture/trust-tiers.md).

The node auto-registers a small bootstrap corpus (`at.handshake`,
`at.time-attest`, `at.echo-challenge`) so new peers have low-stakes interactions
to earn initial trust. Set `AT_BOOTSTRAP_DISABLED=1` to suppress it.

## Workers: attaching concurrency

A worker is a `Process` subclass that runs alongside the core subsystems,
typically to serve or consume a capability. Register workers in `__init__`:

```python
def __init__(self, **kwargs):
    super().__init__(**kwargs)
    self.add_worker(NetStatsSource)                                  # no deps
    self.add_worker(DataProcess, self.system_dependencies)           # start after core subsystems
```

`add_worker(process: type[Process], dependencies: list[str] = None, **kwargs)`.
`dependencies` is a list of process names that must start first;
`self.system_dependencies` gives you the core subsystem names, which is the
common case. Extra `kwargs` are passed to the worker.

Prebuilt workers live in the `autonomous_trust.services` package:


| Import                                             | Role                                                                                                   |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `services.data.server.DataProcess`                 | Serves a stream of readings (capability`data`). Config: `DataConfig`.                                  |
| `services.data.client.DataRcvr`                    | Subscribes to peers offering`data` and receives their readings.                                        |
| `services.network_statistics.NetStatsSource`       | Publishes per-node network statistics.                                                                 |
| `services.peer.position`, `services.peer.metadata` | Peer position and metadata sources.                                                                    |
| `services.video.server`, `services.video.client`   | Video stream server and client.                                                                        |
| `services.envdata.*`                               | Environmental data sources used by the disaster-response demo (weather, seismic, air quality, fusion). |

To write your own worker, subclass `Process` with the `ProcMeta` metaclass,
declare a `capability_name` if it serves one, register handlers for the message
verbs it answers, and implement `process(self, queues, signal)` as its run loop.
`services/data/server.py` (`DataProcess`) and `services/data/client.py`
(`DataRcvr`) are compact worked examples. See [Process
Architecture](architecture/process-architecture.md).

## Messaging and trust state

Workers and hooks talk to peers by putting `Message` objects on the queue of the
subsystem that should route them.

```python
from autonomous_trust.core.network import Message
from autonomous_trust.core import CfgIds

msg = Message(DataProcess.name, DataProtocol.request, payload, to_peer, from_whom=self.identity)
queues[CfgIds.network].put(msg, block=True, timeout=queue_cadence)
```

A receiving worker registers a handler (for example `DataRcvr.handle_data`) that
the framework calls when a matching message arrives. `DataRcvr.process` shows
the pattern: it watches `self.protocol.peer_capabilities` for peers that
advertise a capability, subscribes, and handles inbound data.

The node exposes the live trust picture as attributes you can read from
`autonomous_tasking` or from a worker:


| Attribute                      | Contents                                                                  |
| ------------------------------ | ------------------------------------------------------------------------- |
| `self.identity`                | This node's`Identity` (UUID, keys, nickname, address).                    |
| `self.peers`                   | Known peers.                                                              |
| `self.peer_count`              | Current peer count.                                                       |
| `self.latest_reputation`       | `{subject_uuid: Reputation}`, overwritten per response.                   |
| `self.latest_reputation_pairs` | `{(observer_uuid, subject_uuid): Reputation}`, the full bilateral matrix. |

To request a reputation value explicitly, send a `rep_req` to the reputation
subsystem:

```python
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.config import to_json_string

query = Message(CfgIds.reputation, ReputationProtocol.rep_req,
                to_json_string((peer, self.proc_name)), self.identity, from_whom=self.identity)
queues[CfgIds.reputation].put(query, block=True, timeout=queue_cadence)
```

The response lands in `latest_reputation` / `latest_reputation_pairs`. Trust
changes are agreed by the reputation subsystem's Paxos rounds, so a value you
read is a consensus result, not a local guess. See [Reputation
Consensus](architecture/reputation.md).

## Embedding AT inside a larger process

When AT is one component of a bigger application (a dashboard, a coordinator, a
mission controller), pass external queues to `run_forever` so your outer process
can feed the node and read from it without subclassing the loop:

```python
node.run_forever(q_in=control_queue, q_out=feedback_queue)
```

`q_in` is watched by the main loop (external control in); `q_out` is where the
loop publishes (feedback out). The inspector package uses this shape: a
coordinator subclasses `AutonomousTrust`, builds a `Cohort` over the
`queue_pool`, and adds a `CohortTracker` worker that drains peer state into the
cohort for a Dash UI.

```python
from autonomous_trust.inspector.peer.daq import Cohort, CohortTracker

class MyCoordinator(AutonomousTrust):
    def __init__(self, **kwargs):
        super().__init__(silent=True, **kwargs)
        self.cohort = Cohort(self.queue_pool)
        self.add_worker(CohortTracker, self.system_dependencies, cohort=self.cohort)
```

## Backend selection

The core ships two interoperable implementations. Choose one with the
`AUTONOMOUS_TRUST_BACKEND` environment variable:

- `auto` (default): use the native C backend if its library is present, otherwise Python.
- `python`: force the pure-Python core.
- `native`: force the C core via CFFI.

The public API is identical across backends. See [Native/FFI Dual
Implementation](architecture/native-ffi-dual-implementation.md).

## Worked examples

- [`examples/multi_agency/participant.py`](../examples/multi_agency/participant.py): a data-producing node. Subclasses `AutonomousTrust`, adds `NetStatsSource` and `DataProcess`, and advertises its capabilities in `autonomous_ability`.
- [`examples/multi_agency/coordinator.py`](../examples/multi_agency/coordinator.py): a consuming node. Adds `CohortTracker` and a `DataRcvr` and drives a dashboard.
- [`examples/README.md`](../examples/README.md): the example suite and how to add a scenario.

## See also

- [Concept](concept.md): the model behind the API.
- [Architecture](architecture/README.md): how the subsystems the API drives are built.
- [Example application](example-application.md): these entrypoints in a full scenario.

---

*Next: [AutonomousTrust whitepaper](whitepaper/AutonomousTrust.md)*
