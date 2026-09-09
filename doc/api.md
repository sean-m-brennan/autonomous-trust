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
reputation state (see [Persistent Cohort](architecture/persistent-cohort.md)).

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
[Trust Tiers](architecture/trust-tiers.md).

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
