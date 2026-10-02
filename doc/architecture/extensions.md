*Previous: [App-facing peer carrier](app-peer-carrier.md)*

# Extensions: how a feature attaches to the core

## Context

Social (Agora) and ZTA used to reach the IPC layer and the app ABI through
`#ifdef`s in the core: `generic_msg_t.info` was a tagged union with one arm per
feature payload, `message_type_t` had a block of values per flag, and
`at_app_event_t` carried eleven social arms in its union. That had two costs.
A separately linked feature library could not add a type at all, which blocked
moving any feature out of the core (FEATURE_SPLIT_PLAN.md §3.1/§3.2). And the
structs changed size with the build flags: `at_app_event_t` was 104 B in a core
build and several KB in a social one, so a foreign mirror of it (the ethne
`en-at` crate) was correct for exactly one build.

Runtime registries replace both. A feature reaches the IPC layer and the app ABI
only through registration, so moving it into its own library is a code move
rather than an ABI change. Social made that move in Phase 5, and in Phase 5b
left this repository for Agora (see "External extensions and conformance
plug-ins"); ZTA still lives in the core tree and compiles under its flag.

## Ordinals are not on any wire

Every IPC hop is a Unix datagram carrying a `google.protobuf.Any` whose
`type_url` is the type's **name** (`message_type_to_string`). The receiver maps
the name back with `string_to_message_type`. Peer traffic is the separate
`NetMessage` proto and never carries a `message_type_t`. The Python runtime
dispatches pickled objects by class and never sees a type number. The
conformance corpus names no message types.

So message-type **ids are process-local**. The reserved ranges below exist so
that two features never collide, not for compatibility. The **name** is the
stable identifier and must never change once a type has shipped. (Several
in-source comments used to say "these values are serialized"; they were
wrong, and are gone.)

App-event **kinds** are different: they cross the flat ABI into foreign
consumers as numbers, so they are frozen and only ever appended.

## Message types (`utilities/msg_registry.h`)

`generic_msg_t.info` keeps a named arm for every core type and gains one opaque
arm:

```c
_Alignas(max_align_t) uint8_t payload[AT_MSG_PAYLOAD_MAX];   /* 8192 */
```

`info` is exactly `AT_MSG_PAYLOAD_MAX` bytes in every build (static-asserted).
The core has to size it for payloads it cannot see. 8 KiB clears the widest
today, `peer_cosign_request_msg_t` at 6,384 B, with headroom. It is a fixed cap
rather than a pointer so messages stay copy-by-value through the queue with no
allocation on the hot path.

A feature registers each type from a constructor:

```c
AT_MSG_ASSERT_FITS(peer_post_msg_t);
static const at_msg_vtable_t post_vt = {
    .name = "PEER_POST_OBSERVED", .size = sizeof(peer_post_msg_t),
    .app_bound = true };
AT_MSG_TYPE_REGISTER(post, PEER_POST_OBSERVED, &post_vt)
```

and reads or writes the payload through `AT_MSG_EXT(msg, T)`.

| Range | Owner |
|---|---|
| 1–999 | core (`message_type_t`); never registrable |
| 1000–1999 | social (Agora's `at-social/c/social/social_msg_types.h`, 1000–1011 used) |
| 2000–2099 | ZTA (`zta/zta_msg_types.h`, 2000–2001 used) |
| 2100–2199 | fleet (reserved) |
| 2200–2219 | first contact (`identity/first_contact.h`, 2200–2201 used: `FIRST_CONTACT_EVENT`, `FIRST_CONTACT_CONTACT_EVENT`) |
| 2300–2309 | stele (Stele's `at-stele/c/stele/stele_msg_types.h`) |

Registration refuses an id outside the extension ranges, a duplicate id, a
duplicate name, a name the core already uses, a zero or oversized payload, and
a half-set proto pair. A refusal is printed to stderr, because it happens
before `main()` where nothing else would see it.

What the registry drives:

- `message_size`, `message_type_to_string` and `string_to_message_type` fall
  through to it for any id or name the core does not own.
- `generic_msg_to_proto` / `proto_to_generic_msg` serialize a registered
  payload with its own `to_proto`/`from_proto`, or by default as a raw copy of
  `size` bytes. The decoder refuses a value shorter than `size`, for the reason
  `COPY_FIXED_PAYLOAD` does: the sender picks the `type_url`, so it would
  otherwise pick how far past the buffer the copy reads.
- The main process's app drain forwards a registered type to the app queue iff
  it registered `app_bound`. This replaces the hand-kept case list, which is
  how app events used to go missing.
- `run_message_handlers` reads `info.net_msg` only for a `NET_MESSAGE`. It used
  to treat every non-core type as one, comparing payload bytes against the
  process name.

**App verbs.** The app→AT direction has an allowlist too:
`at_route_extern_msg` forwards a `NET_MESSAGE` only when its `function` is a
known verb, each to one fixed process. The core's own verbs are hard-wired
there. A feature adds its verbs with `AT_APP_VERB_REGISTER(tag, verb, target)`.
The social feature registers its 18 verbs, all to `identity`; first contact
registers seven (`app_first_contact_invite`, `_initiate`, and the address book's
`_safety_number`, `_verify`, `_list`, `_rename`, `_remove`), also to `identity`. A registered verb reaches its process, but that says nothing about
who sent it. An app verb and a peer's message are both `NET_MESSAGE`s
dispatched by name, so each handler must still refuse a frame from the wire
with `identity_is_local_app_verb`, or an admitted peer could make this node act
on its behalf.

Python has the same allowlist in `app_verbs.py`. An app puts an `AppRequest`
on the node's control queue; the main loop forwards it only when an ENABLED
extension lists its verb in `Extension.app_verbs`, and only to the process
named there, rebuilt with no `from_whom` so the handler's `is_local_app_verb`
reads it as local. The other direction is `AppEvent`: any instance a process
puts on `CfgIds.main` is forwarded to the app's feedback queue, the Python
counterpart of registering a type `app_bound`. The core's
`app_roster_request` predates both and stays hard-wired, because it fans out to
more than one process.

## App events (`app_events.h`, `at_agora.h`, `app_events_registry.h`)

`app_events.h` is the core's surface and is **the same in every build** (app
ABI v2, `AT_APP_ABI_VERSION`):

```c
typedef struct {
    int32_t kind;
    union {
        at_app_peer_t       peer;
        at_app_reputation_t reputation;
        at_app_rtt_t        rtt;
        _Alignas(8) uint8_t payload[AT_APP_EVENT_PAYLOAD_MAX];   /* 8192 */
    } data;
} at_app_event_t;          /* 8200 B, data at offset 8, in every build */
```

`kind` is a plain `int32_t` because a feature's kinds are not members of the
core enum. `at_app_peer_t.in_group` and `.blocked`, once social-only, are
always present and read false without the feature. `at_app_abi_version()`
returns the version the library was built with, and a consumer compiled
against a different header must refuse to read events: a stride mismatch
misaligns every event after the first. The Agora shim and `en-at` both check it
at open. `test/app_abi_test.c` pins the size and every core-arm offset in all
four build configs. Those are the numbers the foreign mirrors assert.

| Kinds | Owner |
|---|---|
| 0–3 | core |
| 4–15 | Agora (`at_agora.h`), grandfathered; Agora appends into 16–99 |
| 100–199 | future core kinds |
| 1000–1099 | first contact (`at_first_contact.h`, 1000–1008 used) |
| 1100– | further features, one block each |

A feature's public header (`at_agora.h`, installed only by a build with social)
carries its kinds, flat payload structs and **kind-checked accessors**:

```c
const at_app_post_t *post = at_agora_event_post(&batch[i]);   /* NULL unless a POST */
```

so a consumer never reinterprets one payload as another. The same header
declares the feature's app→AT senders.

On the core side, `at_app_events_poll` translates its three core types itself
and asks `app_events_registry.h` for a decoder for anything else it drains. A
feature registers one per app-bound message type with
`AT_APP_EVENT_DECODER_REGISTER`, writing into the payload with
`AT_APP_EVENT_EXT`. The poll zeroes the slot before calling, as each inline
case always did. `app_events_registry.h` is internal: it is for a feature built
against the core, never for an app.

## Process handlers (`processes/extension.h`)

A feature that answers protocol verbs registers one `at_extension_t` from a
constructor:

```c
static const at_extension_t first_contact_extension = {
    .name = "first_contact",
    .enabled = at_first_contact_enabled,          /* read on EVERY register */
    .register_handlers = _fc_extension_register,  /* (proc, proc_name) */
    .reset = at_first_contact_reset,              /* conformance / tests */
};
AT_EXTENSION_REGISTER(first_contact, &first_contact_extension)
```

Each core process ends its handler registration with
`at_extensions_register_handlers(proc, "<name>")`: `identity`, `reputation` and
`negotiation` at the end of `*_register_handlers`, and `network` in
`network_run` before its receivers start. Every **enabled** extension is given
the process and its name and registers only where it belongs, so the core names
no feature and a node that enables none registers nothing extra.

`enabled()` is read on every call, never cached, because the conformance
adapter flips `AT_FIRST_CONTACT` between scenarios. `at_extensions_reset()`
runs each extension's `reset`, and the adapter calls it before every scenario.
The table holds 16 and is filled before `main()`, so it is unlocked. It refuses
a NULL or unnamed extension, a duplicate name and a full table, each with a line
on stderr.

There is no `init` hook. Message types, verbs, decoders and transports have
registries of their own, and they cover everything an `init` would have done.

First contact is the first client. It stays in the core tree, so the core calls
its anchor, `at_first_contact_link()`, from `identity_register_handlers`.

A feature's handlers reach identity's state only through the services
`identity/id_proc_priv.h` exports for them: `identity_self_identity`,
`identity_find_peer_pub`, `identity_send_to_network`,
`identity_freshness_stamp` and `identity_freshness_accept`. Each takes
identity's lock for itself, and a feature keeps its own state behind its own
lock.

## Transports and processes

**Transports** (`network/net_transport.h`). The five core transports stay in
the static table in `net_transport_registry.c`. An extension library adds its
own with

```c
NET_TRANSPORT_REGISTER(dtn_bp, &dtn_bp_transport)
```

and `net_transport_find` searches the core table first, then the registered
ones. Registration refuses a NULL or unnamed transport, any name already
taken, core or registered, and a table past `NET_TRANSPORT_EXT_MAX` (8).

**Processes** (`processes/process_tracker.h`). The generator scans only
`src/c/autonomous_trust/`, and `process_table[]` used to be exactly as long as
what it found. The template now sizes it
`[LIST_COUNT__DECLARE_PROCESS + AT_PROCESS_EXT_MAX]`: `preprocess.py`
substitutes its entry count for the `LIST_COUNT__<macro>` token, which leaves 8
free slots. An extension fills one with

```c
DEFINE_PROCESS(network, dtn_bp, network_dtn_bp_run)
```

which now calls the bounds-checked `process_table_append`. It refuses a missing
name or runner, a name already in the table and a full table, where it once
wrote past the end of the array. Its constructor is `static`, because
`__COUNTER__` restarts in every translation unit and two extensions would
otherwise both define `register_process_0`.

**DTN is the first extension library.** It lives in `src/c/extensions/dtn/`,
outside the generator's scan root, and builds when `AT_NET_DTN=ON`:

| Target | Consumer |
|---|---|
| `at_dtn` (`libat_dtn.so`) | the shared core. Links `libautonomous_trust.so` by file (see below). |
| `at_dtn_static` (`libat_dtn.a`) | static links: tests, `examples/`. Link it with `--whole-archive`, or call `at_dtn_link()`. |

The extension's `CMakeLists.txt` owns the backend choice
(`AT_NET_DTN_BACKEND`: `stub`, `ion`, `ud3tn`, `ud3tnv2`), the ION
ExternalProject and the `aap2.proto` codegen. It sets their include
directories on its own targets, not globally. It is added with
`add_subdirectory` after the core targets, because DTN includes core-private
headers (`net_proc_priv.h`, `process_t`) and must be built with the same
flags. The core no longer defines `AT_NET_DTN`, and nothing in the core names
DTN.

`at_dtn` links the core as `$<TARGET_LINKER_FILE:autonomous_trust>`, not as
the target. The core declares `target_sources(autonomous_trust PUBLIC
${libsrc})`, so linking the target compiles a second copy of the whole core
into the consumer, with its own process and transport tables. Any future
extension library has to follow the same rule.

The Python native loader (`_native/_ffi.py`) dlopens every `libat_*.so` beside
`libautonomous_trust.so`, and under `extensions/*/` in a build tree, right
after the core. Loading is all it takes: the constructors register the
transport and runner. With no extension present, this does nothing.

## Network filters (`network/net_filter.h`)

A feature that changes what goes on the wire, rather than adding a transport
or a verb, sits between the wire and the network handlers as a **filter**. A
filter has three optional hooks:

| Hook | Runs | May |
|---|---|---|
| `inbound` | at the top of each `handle_inbound_*`, before any decryption | drop the frame, consume it (it forwarded it itself), or let it continue, narrowing the slice the core decodes |
| `outbound` | just before each transport send in `net_encrypt_and_send` | wrap the frame, or refuse the send |
| `after_deliver` | after the core routed the frame to its process | re-emit it (deliver-and-forward) |

Filters are ordered by `order`, lower nearer the wire: `inbound` and
`after_deliver` run ascending, `outbound` descending, so the header nearest
the wire goes on last and comes off first. The first `DROP` or `CONSUMED`
stops the chain. A filter tells the core what it learned through
`net_inbound_meta_t`:

- `inner` / `inner_len`: the slice the core decodes;
- `has_src_uuid` / `src_uuid`: the originator, used for the peer lookup and
  the defer key instead of the transport address, which may be a gateway's;
- `forwarded`: the frame came through a gateway;
- `keep_reported_addr`: keep a broadcast sender's self-reported address
  rather than overwrite it with the transport address.

An extension installs its filter from `register_handlers(proc, "network")`,
which `network_run` calls before the receiver threads start. After that the
chain is read-only, so it is unlocked, as the other registries are.
`net_filter_install` refuses a NULL or unnamed filter, a name already
installed, and a chain past `NET_FILTER_MAX` (8). **An empty chain changes
nothing on any path**: conformance is case-for-case identical with the chain
empty.

**The config gate.** Right after the extensions register, `network_run` calls
`net_filters_check_config` and refuses to start the network process, with an
ERROR, when the network config asks for something no installed filter
provides:

- `"envelope": true` with no `"envelope"` filter installed, because
  libat_gateway is absent;
- `"group_forward"` or `"cross_cluster"` without `"envelope"`. This invariant
  used to be enforced by CMake.

The three switches live in `network_config_t` and are written to JSON only
when true, so a default node's config file is unchanged.

**The gateway relay is the second extension library** (`src/c/extensions/gateway/`,
FEATURE_SPLIT_PLAN Phase 2). It holds the routing envelope codec
(`net_envelope.{c,h}`) and one filter, `"envelope"` (order 0), which does the
following:

- wraps every frame in the 36-byte plaintext routing header;
- on the way in, classifies each frame. It forwards a PEER frame for another
  node when this node is a gateway, and forwards a GROUP frame for another
  group on its routed leg when `group_forward` is set. Otherwise it narrows the
  slice and names the originator;
- after delivery, relays broadcasts to the other legs, with a dedup ring and
  a token bucket.

Unlike DTN it is **built by default** (`AT_NET_GATEWAY`, ON), because building
it turns nothing on. Its extension is always enabled, and it installs the
filter only when the node's network config sets `"envelope": true`. That
matters because the envelope changes the wire format for the whole cohort,
and the Python loader dlopens every `libat_*.so` it finds. Its targets
follow DTN's shape: `at_gateway` links the core `.so` by file, and
`at_gateway_static` serves tests and `examples/`.

## Oracle layers (`negotiation/neg_oracle.h`, `core/_python/oracles.py`)

The verification layers of R+D.md §12 are five extension libraries
(FEATURE_SPLIT_PLAN Phase 3), `src/c/extensions/<layer>/`, each built by
`AT_ORACLE_<LAYER>` (all ON by default):

| Library | Layer | Declared by | Registers |
|---|---|---|---|
| `libat_physics` | physical consistency (§12.2) | `$AT_PHYSICS` | arm `physics.check` (100, verdict); the capability → reported-quantity provider |
| `libat_calibration` | coverage audit (§12.4) | `$AT_CALIBRATION` | arms `calibration.settle` (200, observe) and `calibration.assess` (400, verdict) |
| `libat_prequential` | prequential competence (§12.5) | `$AT_PREQUENTIAL` | arm `prequential.observe` (210, observe); the competence provider |
| `libat_certificates` | certificate-carrying interfaces (§12.3) | `$AT_CERTIFICATES` | arm `certificates.check` (300, verdict) |
| `libat_replication` | replicated execution (§12.6) | — | its declaration only; nothing scores through it yet |

`AT_ORACLE_REPLICATION` requires `AT_ORACLE_CERTIFICATES`, whose SplitMix64 it
samples with; `libat_replication` links `libat_certificates`.

**The registry.** A layer registers from load-time constructors: it
*declares* itself (`NEG_ORACLE_REGISTER`, carrying its reset), adds its *arms*
(`NEG_ORACLE_ARM_REGISTER`), and may *provide* one of two services. A verdict
arm returns a score and channel or falls through; an observe arm only records.
`negotiation_score_task_result` runs the known-answer probe, then the arms in
ascending order, and the first verdict ends scoring. The completion arm comes
last. The orders reproduce the scorer's sequence from before the split, so
every conformance case scores as it did. An empty registry scores exactly as
the probe and completion arms alone.

**The providers.** Calibration and prequential settle a forecast against the
quantity a later result reports. That mapping lives in the physics
declaration, so physics provides `neg_oracle_reported_quantity`, and the other
two ask the registry rather than link physics. Prequential provides
`neg_oracle_competence`, the weight multiplier the negotiation process submits
with each score; with no provider it is 1.0, the authored weight verbatim.

**The refusal.** The core keeps the table of declarations and the layer each
needs: names only, never behavior. A layer that is absent cannot declare
itself, so the table has to live in the core. `negotiation_run` calls
`neg_oracles_check_env` and refuses to start, with an ERROR naming the
library, when `$AT_PHYSICS`, `$AT_CALIBRATION`, `$AT_PREQUENTIAL` or
`$AT_CERTIFICATES` is set and non-empty and its layer is not loaded. A node
declared to check physics that silently did not would accept results physics
refutes. Refusing is the only safe answer.

**What stayed in the core.** The certified-result wire helpers
(`negotiation/neg_certified.{h,c}`: the challenge seed, and the
`{"at_certified": …}` split a worker applies before a reply goes on the wire)
are negotiation wire format, used whether or not this node can check a
witness. The EMA weight rounding (`at_tx_weight_round`, `floor(x + 0.5)`) is
reputation's, so the reputation process needs nothing from prequential.

**Building one.** `extensions/at_extension.cmake` gives each library the shape
DTN's and the gateway's have: `at_extension_library(<layer> SOURCES …
[DEPENDS …])` makes `at_<layer>` (shared, linking the core `.so` by file) and
`at_<layer>_static`; `at_extension_tests` links a test with the static library
whole-archived. Each layer's registration is `<layer>_oracle.c` and its anchor
header `at_<layer>.h`.

**Python.** `core/_python/oracles.py` is the same registry: `declare`,
`register_arm`, `provide_quantity`/`reported_quantity`,
`provide_competence`/`competence`, `check_env` (raises `OracleMissingError`
after an ERROR per missing layer) and `reset`, with the same orders and the same
declarations table. The five layers are a separate distribution,
`src/autonomous-trust-oracle/` (`autonomous_trust.oracle.<layer>`, laid out
`_python`/`_native` behind the redirector prefix `autonomous_trust.oracle.`).
Each layer's `oracle.py` registers when its package is imported.
`AutonomousTrust.__init__` calls `oracles.load()`, which imports whatever
`all_extensions()` finds (below), then `oracles.check_env()`, so the Python
node refuses as the C one does. The layers score in the main process, where
`score_task_result` runs; the extension attaches no process handlers.

## Identity hooks (`identity/id_ext.h`, `IdentityHooks`)

A feature that follows the identity process, as Agora's social does, attaches
through hooks rather than being named by the process. `identity_ext_t`
(`identity/id_ext.h`, at most `IDENTITY_EXT_MAX` = 4, registered by
`IDENTITY_EXT_REGISTER`) is the C half. Every member may be NULL, and with
nothing registered every dispatcher is a no-op and every query false, which is
exactly a node without the feature. `id_proc.c` calls each through its
dispatcher:

| Hook | Called from (`id_proc.c`) | Agora's social uses it for |
|---|---|---|
| `init` | identity's own init | its state; seeds `$AT_OWN_*` |
| `reset` | `identity_reset_state`, after the final unlock | dropping all state |
| `run_start` | `identity_run`, after the handlers register | restoring the blocks from `social.cfg.json` before traffic |
| `peer_confirmed` | `handle_confirm_peer` | the position and profile queries |
| `group_update_seen` | `handle_group_update`, before any adopt | recording the peer's group |
| `periodic_resync` | `identity_periodic_caps_resync`, after the core sweep | re-asking position- and profile-less peers |
| `roster_replay` | `handle_peer_roster_request` | replaying its own events; says whether it logged |
| `peer_in_group` | `identity_emit_peer_observed` | PEER_OBSERVED's `in_group` |
| `peer_blocked` | `identity_emit_peer_observed`; `identity_get_peer_tier` | `blocked`, and a blocked peer's tier reads 0 |

**The C lock rule.** A feature keeps its state behind its own leaf lock
(social's is `social_state.lock`). The order is peers rwlock → identity lock →
feature lock. The core dispatches every hook **with no lock held**, not the
identity lock and not a peers lock, so a hook may call back into exported
identity functions. The converse binds the feature: while it holds its own lock
it calls only map, string, its own store's and log functions, never anything
that locks or dispatches. `identity_get_peer_tier` reads the tier under the
identity lock, unlocks, and only then asks `peer_blocked`, so a tier and a block
are two snapshots rather than one. What a feature needs from identity it calls
through exports in `identity/id_proc_priv.h`; social's are
`identity_state_ensure_init`, the freshness pair, `identity_find_peer_pub`,
`identity_send_to_network`, `identity_emit_peer_observed`,
`identity_request_attestation`, `identity_is_local_app_verb` and
`identity_refuse_remote_app_verb`.

**What stayed in the core.** Peer standing and the tier read are identity's:
a governance standing is not an Agora idea, and `get_peer_tier` asks the
extension only whether a peer is blocked. `net_msg_t.group_multicast` and
`RECIPIENT_GROUP` are unconditional core. The JSON key is still written only
when true, so the IPC bytes did not change. The local-app-verb guard
(`identity_is_local_app_verb`) is core, because core verbs use it too.

**The refusal.** The core keeps the names-only table beside the oracle table.
`identity_run` refuses, with an ERROR naming the library, when
`$AT_OWN_GEOHASH` or `$AT_OWN_PROFILE` is set and non-empty and no identity
extension named "social" is registered (`identity_ext_check_env`). A node told
to publish its position that silently published nothing would look healthy
while failing its operator.

**Python.** A Python feature's handlers register as `functools.partial(fn,
proc)`, so the process still pickles. The core's identity process calls the
feature through `IdentityHooks` on `Extension.identity`, fewer hooks than C
has, because Python has no app-event carrier:

| Hook | Called from (`idprocess.py`) | Lock |
|---|---|---|
| `on_peer_confirmed(proc, queues, peer)` | `handle_confirm_peer` | not held |
| `periodic_resync(proc, queues)` | `_periodic_caps_resync`, inside its `try` | not held |
| `is_blocked_locked(proc, uuid_str)` | `get_peer_tier` | **held**: must not take `proc.lock` |

`Extension.post_fork` is Python's `run_start`; social's restores its blocks
before the process takes traffic. `load_extensions` records a loaded name on
every process it runs for, so a hook must act only where its state exists
(social's checks `proc.social`, which only the identity process has). **Python
keeps the single `proc.lock`**, where C has a second lock: social's accrual runs
under it, and a second lock would buy Python nothing it can use.
`AutonomousTrust.__init__` calls `extensions.check_env` after
`oracles.check_env` and raises `ExtensionMissingError` when any
`$AT_OWN_GEOHASH`/`$AT_OWN_EXACT`/`$AT_OWN_PROFILE` is set without social. It
logs the loaded extensions at INFO.

## ZTA (`libat_zta`, `autonomous_trust.zta`)

Zero Trust credential integration left both cores in FEATURE_SPLIT_PLAN Phase
6. What the core keeps is what every identity carries: the credential fields
of `public_identity_t` / `Identity`, now unconditional in C as the operator
fields already were (D3), their bounds, and the binding pre-image
(`identity.c::zta_binding_preimage`, `core/_python/identity/zta_fields.py`). A
node without ZTA carries and relays a peer's credentials and verifies none.
The C struct no longer depends on a build flag, so the FFI auditor resolves
conditionals against nothing and probes without `-DAT_ZTA_ENABLED`.

**C.** `src/c/extensions/zta/` builds `libat_zta` when `AT_ZTA` is ON (still OFF
by default) and takes OpenSSL with it; `libautonomous_trust` no longer links
it. It registers, from constructors: the identity extension `"zta"`
(`zta_identity.c`, the logic that used to sit under `#ifdef AT_ZTA_ENABLED` in
`id_proc.c` and `rep_proc.c`, moved verbatim), the `zta_policy`
configuration section (`DEFINE_CONFIGURATION`), the `zta_verify` process
(`DEFINE_PROCESS`), its message types and its errors (`DEFINE_ERROR`). The
configuration and error tables gained the bounds-checked appends the process
table had (§3.3): `configuration_table_append` with `AT_CONFIG_EXT_MAX` free
slots, and `error_table_append`, where the same error twice is one error and
two errors on one number are refused. Turning that check on found four real
collisions, now renumbered: `EGEN_NOIF` 226, `ENET_INVALID_MASK` 234,
`ENET_ADDR_TOO_LONG` 235, `EUPDATE` 300, `ECONFIG` 301 (the DAG errors keep
220/221, which their ACSL contracts pin).

**The admission-authority hooks.** `identity_ext_t` gained five members, each
phrased so that no extension at all is a node with no such authority:

| Hook | Called from | Without an authority |
|---|---|---|
| `admission_gate` | the welcoming committee, before the vote | admit |
| `join_refused` | `_join_authorized` (a targeted join) | not refused |
| `gateway_refused` | child-gateway discovery, parent derivation, a hierarchy claim | not refused |
| `operator_credential` | an attestation re-verify | not operator-class |
| `credential_anchored` | reputation's check of an evidence co-signer it never admitted | not anchored |

`admission_gate` answers the most restrictive verdict (`ADMIT`,
`ADMIT_CAPPED`, `REJECT`); ZTA's publishes its standing to reputation before
the vote, as the core did. Python's `IdentityHooks` has the same five plus
`on_tick(proc, queues, tick)`, which carries the background re-verification
off the identity loop (C has its own `zta_verify` process for that).

**Python.** `src/autonomous-trust-zta/` (`autonomous_trust.zta`, D2's shape with
an empty `_native`) holds the verifiers, `ZtaPolicy`, MFA and TOTP, binding
verification and `admission.py`, the former `IdentityProcess._zta_*` methods as
functions over the process. Their state keeps its old names on the process
(`proc._zta_policy_cache`, `proc._zta_capped`, ...), set up when the extension
registers on identity and reputation. The core's `pyproject.toml` no longer
needs `cryptography`. Policy files written before the move name the class at
its old path; `register_config_alias` lets them decode as the class they are
now.

**Present plus policy.** Linking or installing ZTA changes nothing until a
node's `zta_policy.cfg.json` enables it. Three refusals keep that honest, in
both runtimes. A node whose policy enables ZTA without the extension refuses to
start (`identity_ext_check_config` in C, `extensions.check_config` in Python,
names only, as the social one is). An enabled policy naming a `verifier_type`
this runtime does not implement fails to load (C implements `x509`, `oidc`,
`null`, and `mfa` as chain-only X.509 on the policy's anchors, which is what
Python's MFA chain checks of a bare peer certificate). And an MFA factor type
nothing provides fails it too. All three used to fall back to a verifier that
admits everyone.

**Operator.** PIV/CAC (`piv/`, PKCS#11) and the node-side operator package
(`operator/node/`: activation, session, DDIL, the operator node) moved into the
existing `autonomous-trust-operator` distribution, which depends on ZTA. Its
`_at_extension.py` registers the `piv` MFA factor with ZTA's factor registry.
The operator keystore (`identity/operator_keystore.py`) stayed in the core,
because first contact's device certs and backups use it with no PIV involved.
The core asks a live operator session whether it is attended through the
session's own `is_attended()`, so it imports nothing from the distribution.

**Corpus.** The ZTA scenarios stay in the `identity` and `reputation`
protocols, gated on their `zta_policy` fixture: both adapters skip them without
ZTA (C without `libat_zta`, Python without `autonomous_trust.zta`), and the two
skip sets are the same 21 cases.

## External extensions and conformance plug-ins

An extension need not live in this repository. Agora's social
(`apps/agora/at-social/` in muudd) is one: it was in-tree until FEATURE_SPLIT_PLAN
Phase 5b and left because Agora is its only consumer. Five seams let an outside
directory build, register and test as an in-tree extension does, and AT names
none of what plugs into them.

1. **C build.** `AT_EXTERNAL_EXTENSIONS` (`src/c/CMakeLists.txt`) is a cache
   list of directories, each holding an extension's `CMakeLists.txt`. Each is
   `add_subdirectory`'d inside AT's scope, after the in-tree extensions, with
   binary dir `extensions/<basename>`. It therefore sees what an in-tree
   extension does: `lib_compile_flags`, `AT_EXT_DIR`, `AT_TEST_LIBS`, the
   directory-scoped include dirs and `test/test_setup.h`.
   `at_extension_library` adds the parent of the calling directory as a PUBLIC
   include root, so `"social/x.h"` resolves wherever the extension lives. A
   consumer that adds AT as a subdirectory (Agora's `native/CMakeLists.txt`)
   sets the list before it does.
2. **C conformance adapter.** `at_conformance_adapter(PROTOCOL <p> RUN <fn>
   SOURCES … LIBS … CORPUS <dir>)` (`extensions/at_extension.cmake`) records
   its arguments as global properties. `src/c/conformance/CMakeLists.txt`,
   added after the extensions, compiles the sources, links the libraries
   whole-archive and generates `conformance_registry.c`, a `{protocol,
   run_fn}` table. `runner.c`'s dispatch falls through to it before "no C
   adapter".
3. **Corpus.** `tools/corpus_to_json.py` takes `--in` more than once. The first
   root supplies `schema/`; the rest add `scenarios/`, `vectors/` and
   `testdata/`. One `index.json` is written, pruning covers every root, and a
   duplicate case id, mirror path or testdata file is an error.
4. **Python harness.** `$AT_CONFORMANCE_PLUGINS` is an os.pathsep list of
   plug-in directories, each with `scenarios/<protocol>/` and a
   `conformance_plugin.py` (`SYS_PATH`, `adapters()`). The runner loads each by
   path; `scenario_loader.discover` takes the extra roots and refuses a
   duplicate case id.
5. **Script.** `scripts/test-conformance.sh` turns `AT_EXTERNAL_EXTENSIONS`
   (':'-separated) into `-DAT_EXTERNAL_EXTENSIONS=…` for its C build and
   exports `AT_CONFORMANCE_PLUGINS` to the Python run. Results land in AT's
   `results/` as before, so the freshness check and the diff are unchanged.

What an identity-riding adapter builds on is the identity adapters' published
hooks: C `ic_ext_t` / `at_identity_run_ext`
(`src/c/conformance/adapters/identity_priv.h`: fixtures, inbound, dispatch,
check_key, on_send, impl_free), and Python `IdentityAdapter`'s
`FIXTURE_HOOKS`, `TRIGGERS`, `INBOUND_BUILDERS` and `STATE_CHECKS`.

An external extension builds in AT's scope, so it can include every
`*_priv.h`, as an in-tree one could. The ones it may rely on are the extension
headers named in this document, `identity/id_ext.h`,
`identity/id_proc_priv.h` (the exports listed under "Identity hooks") and, for
an adapter, `adapters/identity_priv.h`. Anything else can change without
notice. Two-repo skew is the normal submodule pin: the seams add no ABI of
their own.

## Python: `load_extensions` (`core/_python/extensions.py`)

The Python processes do the same thing with an `Extension` dataclass
(`name, enabled, register_handlers, post_fork=None, reset=None,
identity=None`; `identity` is the feature's `IdentityHooks`, see "Identity
hooks"). Each of
`IdentityProcess`, `NetworkProcess`, `ReputationProcess` and
`NegotiationProcess` ends its handler block with `load_extensions(self,
self.name)`, and each `process()` starts with `run_post_fork(self)`, which runs
in the worker.

Extensions come from three places:

1. a built-in list (first contact). It is a built-in list, not the package's
   own entry points, because the package usually runs from a source tree where
   its `pyproject.toml` entry points are invisible;
2. the `autonomous_trust.extensions` entry-point group, for an installed
   distribution (`autonomous-trust-oracle` declares `oracle`; Agora's
   `autonomous-trust-social` declares `social`);
3. for a source tree, a marker scan. Every subpackage of the `autonomous_trust`
   namespace that holds `_at_extension.py` is found by a filesystem check, and
   only that module is imported, so a heavy sibling without one
   (`-services`, `-simulator`) is never imported. Putting
   `src/autonomous-trust-oracle` (or Agora's `at-social/python`) on
   `PYTHONPATH` beside `src/autonomous-trust` is all a checkout needs.

The same extension found by both the entry point and the scan counts once.

Only extension **names** are kept on the process. Multiproc mode pickles the
process to its worker, so a handler must pickle too: use a bound method or a
`functools.partial` of a module function, never a lambda. First contact's
lambdas broke exactly this whenever `AT_FIRST_CONTACT=1` with `multiproc=True`.
`tests/a_unit/test_extensions.py` pins the round-trip on a real
`IdentityProcess`.

A feature package that ships both backends beside the core calls
`autonomous_trust.core.register_backend_prefix('<pkg>.')`. The import
redirector then serves `<pkg>.X` from `<pkg>._native.X` or `<pkg>._python.X`,
as it does the core. The longest matching prefix wins.

## Static links: the anchor rule

Registration runs from `__attribute__((constructor))`, the same pattern as
`DEFINE_PROCESS`. A **static** link keeps a constructor only if something
references its object file, and a dropped registration is silent at run time:
the types simply fail to serialize, and the events never reach the app.

Each feature therefore exports a no-op anchor, and every core entry point that
depends on the feature calls it:

| Anchor | Called from |
|---|---|
| `at_social_link()` (Agora's `libat_social`) | nothing in the core: the Agora shim (`agora_events_open`), `agorad`'s `main` and en-at's `EmbeddedAtNode` call it. It calls `at_agora_link()`, which calls `at_social_msg_types_link()` |
| `at_zta_link()` (`libat_zta`) | nothing in the core: ZTA's consumers own its link (the conformance runner and the tests with a ZTA half link it whole; `examples/` adds it to every demo). It keeps the identity extension, the process, the configuration section and the message types |
| `at_first_contact_link()` | `identity_register_handlers` |
| `at_dtn_link()` | nothing in the core: DTN's consumers own its link |
| `at_gateway_link()` | nothing in the core: the gateway's consumers own its link |
| `at_physics_link()`, `at_calibration_link()`, `at_certificates_link()`, `at_prequential_link()`, `at_replication_link()` | nothing in the core. en-at's `EmbeddedAtNode` calls each one its build found (see below) |

A consumer that links `at_social_static` must call `at_social_link()` or link
it with `-Wl,--whole-archive`; a shared `libat_social.so` has the
`--as-needed` trap below. Once a feature is its own library, the core's calls
into its anchor go away and the feature's consumers own the link, per
FEATURE_SPLIT_PLAN.md §5.3, as social's now do.
`msg_types3_test`'s `test_feature_types_are_registered` is the per-build
assertion that the registrations survived the link.

**Shared links have the same trap.** A consumer that names `libat_<layer>.so`
but never calls into it loses the library's `DT_NEEDED` under `--as-needed`,
the default for Ubuntu's gcc and for rustc, and the layer goes with it, just as
silently. Agora's CMake links the five under `-Wl,--no-as-needed` and leaves it
on for the rest of the link line: CMake moves a layer another layer links
(certificates, under replication) after its dependent, past any point where
`--as-needed` would be switched back on. rustc's `-as-needed` link modifier is
nightly-only, so en-at's `build.rs` sets an `at_ext_<name>` cfg for each
library it finds and `EmbeddedAtNode` calls that library's anchor; the
reference is real, so the `DT_NEEDED` survives into any binary that embeds a
node. Check a consumer with `readelf -d <binary> | grep NEEDED`, not by
whether it built.

## Verification

- `test/msg_types3_test.c`: every core and registered type's name round-trips
  and its size fits; a registered type round-trips through the real serializer
  (not the conformance hook); short payloads are refused; bad registrations are
  refused; the ZTA types are registered in a ZTA build.
- `test/app_abi_test.c`: the event layout, identical in every config.
- `test/extension_test.c`: extension registration refusals; `enabled()` is
  re-read and dispatch is per process; first contact registers exactly when
  enabled; transport and process registration and their refusals. It links
  the core alone, so it also asserts `dtn_bp` is absent.
- `extensions/dtn/test/dtn_link_test.c`: with `at_dtn_static` linked,
  `net_transport_find("dtn_bp")` and `find_process("dtn_bp")` resolve
  (FEATURE_SPLIT_PLAN.md §5.3).
- `test/net_filter_test.c`: chain order, verdicts that stop it, narrowing,
  `after_deliver` slices, install refusals, reset, an empty chain passing
  frames through byte-identical, and the config gate refusing the envelope
  in a core-only binary; the three switches' JSON round-trip.
- `extensions/gateway/test/`: the envelope codec and its eight relay tests,
  which now switch the gateway on through a network config as a node does.
  They include a switch-off case each for `group_forward` and
  `cross_cluster`. `gateway_link_test.c` pins that linking installs nothing
  until the config sets `"envelope"`, that the filter wraps, and that a send
  with no identity yet is refused rather than dereferenced.
- `test/neg_oracle_test.c`: arm order, the first verdict ending scoring, observe
  arms, an empty registry scoring as probe + completion, the providers'
  neutral fallback, the refusals, `neg_oracles_check_env` and the reset.
- `extensions/<layer>/test/<layer>_link_test.c` (physics, calibration,
  certificates, prequential): with the static library linked, the layer is
  declared and its arm scores through `negotiation_score_task_result` once its
  declaration names a model. Muting the physics or the certificates arm fails
  its test.
- `b-oracles-off` (all five `AT_ORACLE_*` OFF): the core builds and passes, the
  eight oracle conformance cases skip rather than fail, and with
  `$AT_PHYSICS` set `neg_oracles_check_env` (what `negotiation_run` refuses on)
  returns -1 with its ERROR.
- `tests/a_unit/test_extensions.py`: the Python half, including pickling and a
  second redirector prefix.
- `test/extension_test.c` also pins the core-only half of social: no social
  verb, and the `$AT_OWN_*` declarations refused; `b-core` has no social symbol
  in `libautonomous_trust.so`. `tests/a_unit/test_identity_without_social.py`
  is the Python half: a core-only node has none of the 17 verb strings, no
  `proc.social` and no block hook, and refuses each `$AT_OWN_*`. Social's own
  tests (the 17 ctest in `at-social/c/social/test/`, `social_link_test` among
  them, and the Python distribution's) are Agora's; `at-social/README.md` runs
  them.
- `tests/a_unit/test_oracles.py`: the Python registry, as `neg_oracle_test`, and
  a node that declares a layer it lacks refusing to start.
  `autonomous-trust-oracle`'s `test_oracle_registration.py`: discovery finds the
  distribution once, the five are declared, and the arms keep the scorer's
  order.
- Conformance: all 306 cases per build config are unchanged against the
  pre-registry baseline, case by case. After Phase 5 moved the 56 social
  scenarios to protocol `social`, each was compared **by name** with its
  earlier `identity/` result, in both runtimes and in all six C configs:
  identical, except that the four `proximity-*` cases now skip instead of
  fail in a C build without social.
  After Phase 5b moved social to Agora, AT alone runs 250 cases in each config,
  identical to the same 250 before the move (by name: three `peer-standing-*`
  descriptions were reworded, which changes their ids), and the 306 through
  `at-social/test-conformance.sh` match the pre-move run the same way, with 0
  asymmetric.
- Downstream: the Agora shim builds and `test/abi_lockstep_test.dart` passes
  (`agora_event_t` is unchanged at 22,168 B, so Dart and the cohort ctypes are
  untouched). `en-at` passes `cargo test --features at-ffi` against both a core
  and a social+ZTA `libautonomous_trust.so`; since Phase 5b the Agora native
  build links `libat_social` from `at-social/c/social` through
  `AT_EXTERNAL_EXTENSIONS`.

## Honest limits

- The anchors mean the core still references its in-tree features by name
  (ZTA, first contact). That is the price of keeping the static archive correct
  until the features are separate libraries. DTN, the gateway, the five oracle
  layers and Agora's social are the ones that are not referenced.
- Social's locking differs between the runtimes: C has a leaf lock of its own,
  and Python keeps the one `proc.lock`. In C a tier and a block are therefore
  two snapshots. Conformance is deterministic and cannot show a timing
  difference; only live cohorts can, and those run on the host, not in the
  development sandbox.
- Most `app_*` social verbs still accept an admitted peer's frame (ISSUES.md
  §2.17). The move carried that behavior as it was.
- `src/c/conformance/CMakeLists.txt` finds the Python tree as
  `CMAKE_SOURCE_DIR/../autonomous-trust`, which is wrong when AT is not the
  top-level project. Agora's build never enables AT's conformance, and
  `at-social/test-conformance.sh` runs AT top-level, so it is recorded rather
  than fixed.
- `find_process` matches by prefix (`strncmp` over the query's length), so a
  query that is a prefix of another entry's name returns that entry. No current
  name collides, `dtn_bp` included, so it is left as is.
- The gateway's `group_forward` still violates invariant G when turned on
  (ISSUES.md §2.12). The move changed only how it is switched on, from a build
  option to a config switch.
- A C program that links the core but not libat_gateway, such as Agora's
  `agorad`, cannot use the envelope. A config that asks for it is refused at
  network start rather than joining the cohort in the wrong format.
- The oracle layers are opt-in modules for `scripts/verify-contracts.sh`
  (`--module physics`, …), not part of its default run. They were never in the
  verified set before the split, and Frama-C is not installed in the
  development sandbox, so none has been run.
- The Python calibration and prequential layers still take a `physics_model=`
  argument. It is fed `oracles.ReportedQuantities()`, the registry's quantity
  provider in the shape of a physics model, so neither imports physics, but the
  parameter name outlived the design.
- The ION backend is not built in the development sandbox. Its CMake moved
  unchanged except for paths, but only `stub` and `ud3tnv2` have been built
  since the move.

---

*Next: [The dual implementation](native-ffi-dual-implementation.md)*
