*Previous: [First contact](first-contact.md)*

# Rendezvous

Rendezvous is how one AT node reaches another across NAT. It began as part of
[first contact](first-contact.md), which still uses it most, and is now an
extension of its own (FEATURE_SPLIT_PLAN Phase 7b): a node that never meets
strangers can leave it out, and one that does can use it without first contact,
since any peer can be reached through it.

A friend's node behind a home router cannot be reached at its address at all:
the router forwards nothing it did not see go out. So an invitation can name a
**rendezvous relay**, any AT node that opted in with `AT_RELAY=1`, which both
sides reach by holding one outbound TCP connection to it, the one kind of flow
a NAT keeps open. Alice's node registers with its own relays (`AT_USE_RELAY=
host:port[,host:port...]`, up to four, in order of preference) and puts every
one in each link it mints as a `relay://host:port` hint. Bob's node, seeing
those hints, sends its hello through the first, and the ack comes back the same
way. From then on each network process routes that peer through its relays, a
per-peer route beside the ordinary transport, so nothing else about the two
nodes' traffic changes.

The rest of this chapter is the relay itself. What first contact does with it
(the hints in the links it mints, pushing and applying a contact's reachability
record, re-admitting contacts at restart) is in
[First contact](first-contact.md#reaching-a-contact-behind-nat).

## Several relays, one at a time

A peer's route is an ordered list, and one relay on it carries the peer's
traffic at a time. A relay that cannot be reached is skipped at once, and the
next takes over. A relay that is up but does not have the peer registered
answers "unreachable" (the only thing a relay ever says about delivery: it
acknowledges nothing), and the sender resends that frame through the next
relay. Each frame is tried at most once per relay. If every relay refuses it,
the frame is walked down the route again every few seconds, three times, since
the peer may register moments later; a newer frame to the same peer cancels
that. A frame arriving through a relay makes that relay the active one, so
replies go back the way traffic came. A node stays registered with every relay
it might be reached through: its own and each one its peers' routes name.

## Who a relay is, and whom it serves

A relay proves who it is in the same exchange that proves the client: the
client's hello carries a fresh nonce, and the relay signs its challenge over
that nonce, its own, and both uuids with its AT key. A uuid alone is only a
label, so a link names a relay by uuid AND key: `relay://<uuid>:<fp>@host:port`,
where `fp` is the first 16 bytes of SHA-256 over the relay's signing key. A
node that has registered with its own relay learns who it is and pins it in
every link it mints from then on. A client holding a pinned hint refuses
anything else that answers at that address, and refuses a relay that offers no
proof at all; an unpinned `relay://host:port` hint still works, unauthenticated.

Reputation gates both ends. A relay refuses to register a client its node
distrusts, and drops one the moment it becomes distrusted; a client refuses a
relay it distrusts, and hangs up on one that becomes distrusted, so that peer's
traffic fails over to its next relay. "Distrusted" means below the reputation
cut-off -- the same cut-off that already drops a peer's traffic -- matched by
uuid and by key: the uuid is excluded, or the proven key belongs to an identity
that is, or the uuid is a peer this node knows under a different key. Unknown
and neutral pass, because meeting strangers is what first contact is for, and
relaying itself earns or costs nothing: the gate reads the relay's ordinary AT
reputation.

## Where a node is now: signed reachability records

A link names the relays its minter used that day. Relays change, so each node
also keeps a **reachability record**: its own signed statement of how to reach
it now -- its relays (pinned hints) and its direct address -- with a sequence
number and an expiry (a week), signed by its identity key over
`at-reach-v1|` plus the exact body bytes transmitted (Python `reach.py`, C
`rendezvous/reach.{h,c}`). A node issues a new record
whenever what it states changes, and at half its life; the sequence is
persisted, so it only ever rises.

A node files its record at each of its relays under the fingerprint of its key:
a relay files only its registrant's own record (the key must be the one it
registered with) and only a newer one. A node that has lost a peer through every
relay it knows asks each relay it is registered at for that peer's record, and
the answer goes to identity. Who may use a record, and what it changes, is first
contact's: see
[where a contact is now](first-contact.md#where-a-contact-is-now).

A relay can read the records it holds (they list relay addresses and
endpoints), but it files them under key fingerprints, so it cannot list whose
they are without already knowing the keys.

## Where a fresh install finds relays: the seed list

A node learns relays from an invitation first. A node whose operator named none
(`AT_USE_RELAY` unset) and that has `AT_RELAY_SEED_FALLBACK` on falls back on a
**seed list**: the community-run relays a fresh install registers with (Python
`relay_seeds.py`, C `rendezvous/net_relay_seeds.{h,c}`). It is a default
mirror list, not a root of trust. A seed relay still proves itself and is still
gated by reputation like any other, so all the signature decides is who chose
the defaults. An explicit `AT_USE_RELAY` always wins, and with the switch off the
list is never read. The switch is rendezvous's own; first contact being on does
not turn it on.

The list ships with the build as `<cfg_dir>/relay_seeds.cfg.json`
(`$AT_RELAY_SEEDS` names another path), signed by the project's **release key**
over `at-seeds-v1|` plus the exact body bytes, which carry a version, a sequence
number and the relay hints (pinned or not). It changes only with a new build;
nothing is fetched at runtime. The node remembers the highest sequence it has
accepted (`<data_dir>/relay_seeds_seen.cfg.json`) and refuses a lower one, so
reinstalling an older build's list cannot roll the defaults back.

The operator edits the list locally in `<data_dir>/relay_seeds_local.cfg.json`,
signed by the node's own identity key over `at-seeds-local-v1|` plus the body:
additions come first (the operator's choice beats the default), and removals
drop a shipped entry by address. `tools/relay_seeds.py` (in
`src/autonomous-trust-rendezvous`) writes both files
(`keygen`, `sign`, `verify` for the release signer; `local add|remove|clear`
and `show` on the node). A file that fails its check is ignored with a warning,
never half-applied; one unparseable entry refuses the whole file, since that is
a signing mistake rather than a relay to skip. The release public key is a
constant in both runtimes (`RELEASE_KEY`, `AT_RELAY_SEEDS_RELEASE_KEY`) and is
empty until the release keypair is minted. Until then no shipped list is
trusted, and only the local additions apply.

## Relays a community stands behind: rosters

Between the operator's explicit choice and the project's defaults sits a third
source: the relays a **community** the operator trusts has published (Python
`relay_rosters.py`, C `rendezvous/net_relay_rosters.{h,c}`). The case it was
built for is an Ethne polity running rendezvous relays as a governed service,
which confers an office on each operator and publishes the result
(`en_uplift::rendezvous_roster`, Ethne design D36). Nothing here knows what a polity
is: any community with a key can publish a roster, and `tools/relay_rosters.py`
signs one for a community that is not a polity.

A roster is the same kind of file as the seed list, verified by the same code:
`{"body", "sig"}`, signed by the community's key over `at-relay-roster-v1|` plus the
exact body, which names that key as its `issuer` and carries a version, a
sequence number and the relays. Rosters live in `<cfg_dir>/relay_rosters/`
(`$AT_RELAY_ROSTERS` names another directory), and a roster counts only when its
issuer is **pinned**, in `$AT_RELAY_ROSTER_ISSUERS` (comma-separated keys) or in
`<cfg_dir>/relay_roster_issuers.cfg.json`. `tools/relay_rosters.py pin`, `install`
and `show` manage both, and an application does the same through the app verbs
`app_relay_roster_install` and `app_relay_roster_remove`
([`at_rendezvous.h`](../../src/c/extensions/rendezvous/at_rendezvous.h)),
answered by the roster events (kinds 1028–1030). Three rules differ from the
seed list's:

- **Every entry is pinned.** A community vouches for a relay by its key, so an
  entry without `<uuid>:<fp>@` refuses the whole roster.
- **A higher sequence replaces the issuer's previous roster whole.** That is how a
  community retires a relay, by publishing without it, and an empty roster is how
  it says it runs none. The node keeps the highest sequence it has accepted per
  issuer (`<data_dir>/relay_rosters_seen.cfg.json`) and refuses a lower one; of two
  files from one issuer, the higher sequence wins.
- **The issuer list is plain configuration**, like the rest of `<cfg_dir>`, which
  already holds the node's own key.

The order is fixed: `AT_USE_RELAY` if set, otherwise the pinned communities'
relays in pin order, then the seed list's entries they lack, at most four. With
`AT_RELAY_SEED_FALLBACK` off, neither rosters nor seeds are read. A roster relay proves
itself and is gated by reputation exactly as any other, so a roster decides where
a node looks, never whom it trusts. The format is pinned across three
implementations: AT's own signer, fed Ethne's inputs, reproduces the roster
Ethne emits byte for byte, and both runtimes accept that file and refuse the
same five variations (conformance `network/relay-roster-*`).

## What a relay can and cannot do

The relay is deliberately powerless. It forwards frames that are the ordinary
AT envelope, sealed end to end between the two peers (bar the plaintext hello
and ack, exactly as on UDP), so it cannot read them. It cannot forge who sent
one either: a node registers by signing the relay's challenge with its own key,
so nobody can register someone else's uuid and receive their traffic, and the
relay stamps each delivery's sender from that registration rather than from the
frame. A receiving node goes one step further and drops a relayed frame whose
envelope names anyone but the sender the relay vouched for.

Both runtimes implement it (Python `relay.py`, C `rendezvous/net_relay.{h,c}`)
and each relays for the other. It is tested
in-sandbox with nodes that have no direct path (different addresses and ports,
so a direct hello lands where nobody listens), with controls proving they never
meet without the relay and never reconnect without the address book;
[`tools/relay_nat/run.sh`](../../tools/relay_nat/run.sh) builds two real
masquerading NATs with network namespaces for the same check on a Linux host,
and has passed there.

## Services that ride the relays

A relay carries more than frames. A feature can plug a family of operations
into it, and first contact plugs in two: the directory registry (`dir_` ops,
see [finding someone by handle](first-contact.md#finding-someone-by-handle-the-directory))
and the area hub (`hub_` ops). The relay server dispatches an op to the family
whose prefix it starts with, and answers one that no family claims as
`<family>_refused` with the reason `unknown_op`, so a relay without first
contact still answers a lookup and the finder counts it as answered. A client
sends an op with `net_relay_client_request` / `RelayClient.request` and gets
the answers to its family through `net_relay_client_on_op` /
`RelayClient.on_op`; [Extensions](extensions.md#rendezvous-libat_rendezvous-autonomous_trustrendezvous)
has the four calls side by side.

## Where it lives

In C rendezvous is `libat_rendezvous`, built from `src/c/extensions/rendezvous/`
by default (the CMake option `AT_RENDEZVOUS_LIB`); first contact links it and
cannot be built without it. In Python it is the `autonomous_trust.rendezvous`
distribution in `src/autonomous-trust-rendezvous`, which also carries the seed
and roster tools. The core reaches it only through the network hooks and the
identity handlers it registers. Having it changes nothing by itself:
`AT_USE_RELAY` registers with relays, `AT_RELAY` serves as one, and
`AT_RELAY_SEED_FALLBACK` lets the rosters and the seed list stand in for
`AT_USE_RELAY`. A node with any of the three set but without rendezvous refuses
to start rather than quietly stay on its LAN.

---

*Next: [Getting work done](negotiation.md)*
