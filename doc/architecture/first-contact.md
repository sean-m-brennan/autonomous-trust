*Previous: [Becoming a peer](identity-protocol.md)*

# First contact

The [identity protocol](identity-protocol.md) admits a newcomer to a *group* by
majority vote. That is the right primitive for a permissionless population
deciding who may join it, and it is not the primitive a person reaches for
first. The first thing a new user does is different and smaller: *here is a
specific human I already know, connect us.* That is a two-party act rather than
a cohort decision, and until first contact it had no home in the framework.

Two gaps stood in the way, and both are structural rather than missing
convenience. Discovery is LAN-only, since the open channel is UDP broadcast and
multicast (see [Networking](networking.md)), so it finds peers on the same local
network and nobody else, and a friend across town, behind NAT, is unreachable by
any shipped mechanism. Admission is that cohort vote, where "I want to connect
to exactly Alice" is a different shape the vote cannot express. First contact
adds the missing shape, being a durable, user-owned contact and a one-to-one
introduction that binds a *verified key* to a memorable name.

## The rule that governs everything

A phone number feels effortless because it quietly does four jobs at once. It is
a memorable identifier, a proof you control it, a directory entry and a
rendezvous address, and it fakes a fifth, verification, by asking you to trust
the server. Bundling those four into one identifier owned by one company is
exactly what makes such systems centralized. We refuse the bundle, under one
rule:

> The human-memorable identifier, whether a QR code, an invite link or later a
> handle, is a **hint for finding and reaching** a peer. It is **never** the root
> of trust. The root of trust is always the cryptographic identity, confirmed at
> first contact. The [petname](identity-protocol.md) is the memorable name,
> assigned locally the moment the key is verified.

That is what keeps the identifier disposable. It can be squatted, spoofed or
served by a hostile directory, and none of that grants trust, because trust
attaches to the key the two humans actually confirmed.

## The contact record

A contact is user-owned durable state, and deliberately not cohort state. Where
`Peers` is the live group membership a node rebuilds each session and prunes on
restart, a contact is a personal address-book entry meant to survive across
networks, restarts, and eventually a user's own devices. It carries the public
identity, being the trust root, a locally-assigned petname never transmitted,
reachability hints, a verification flag, the provenance of how it was acquired,
and the reputation seed applied once it is verified.

## The out-of-band invitation

The default path, and the strongest, needs no directory and no relay. Alice's
node mints a signed **invitation** carrying her *public* identity, a rendezvous
hint, a nonce and an expiry:

```
Invitation := sign_Alice{ published_identity, rendezvous_hint, nonce, expiry }
```

She hands it to Bob over a channel she already trusts, whether a QR code in
person or an invite link over SMS, Signal or email. Because the public key
travels *inside* the invitation, there is nothing for a directory to lie about,
and Bob's node holds Alice's real key before a single packet crosses the
network. We compute the signature over the exact bytes transmitted, in a
canonical sorted-key encoding, and those exact bytes are what a redeemer
verifies. Nothing re-serializes, so there is no canonicalization ambiguity, and
the signature is a detached Ed25519 signature, deterministic and reproducible
byte-for-byte by the C twin.

What the signature proves depends on the channel, and that distinction is the
whole point. It proves the invitation was minted by the holder of the embedded
key. Over an in-person or QR exchange that is conclusive, since there was no man
in the middle, so the contact is verified on the spot. Over a remote link a
man-in-the-middle could substitute its own self-consistent invitation, so a
remote contact stays **unverified** until the safety number is confirmed.

## Safety-number verification

Verification is the fifth job the phone number faked, made explicit here. Before
a remote contact is promoted to verified, the two humans compare a **safety
number** over a channel they trust, which is the Signal model. It is a
deterministic, order-independent function of both public identities, being an
iterated hash over the public keys with the two per-identity fingerprints
concatenated in sorted order, so both parties read the same twelve groups of
digits regardless of who calls which identity "mine". Only when they match does
`verified` flip and the trust edge seed apply, and the reputation process picks
that seed up from the store (see [The seed reaches
reputation](#the-seed-reaches-reputation)).

An unverified contact is usable and visibly unverified. A node may message it,
and higher-trust actions gate on verification, so a user is never silently
talking to a peer a hostile channel inserted. A verified contact is seeded
slightly above the reputation cold-start neutral, in recognition of the
deliberate human confirmation rather than as a grant of standing, which must
still be earned by interaction.

## The durable store

Contacts persist as `<data_dir>/contacts.cfg.json`, keyed by the peer's UUID,
being the stable cryptographic identifier rather than the mutable petname or the
non-unique nickname. A missing file is the normal first-run state rather than an
error, and writes are atomic. The on-disk form is the same DRY canonical shape
both runtimes speak, so a store written by the Python implementation loads in
the C twin and the reverse, and the identity inside it is the flat cross-runtime
public form, never the Python-only config encoding the C side cannot parse.

## The live handshake

The invitation and the contact record are offline, letting Bob learn Alice's key
and remember her while neither node has spoken to the other. The handshake is
the step that turns a redeemed invitation into a live, mutually-known pair. It
is **optional and off by default**, so a node opts in with the
`AT_FIRST_CONTACT` environment flag, and a default deployment registers no
handlers for it at all, which means the feature adds no surface to a node that
has not asked for it.

It is two messages, hosted in the identity process beside the cohort protocol it
deliberately is not:

1. Bob calls `initiate` with the invitation blob. His node sends
   `first_contact_hello` to the endpoint the invitation names, carrying his
   identity on the envelope and the invitation itself as his ticket.
2. Alice validates the ticket, admits Bob, and replies
   `first_contact_hello_ack`. Bob's node admits Alice in turn.

Both ride the **open, unencrypted channel**, and that is forced rather than
chosen, since the first hello arrives from somebody who is not yet a peer and
there is no shared key it could have been encrypted under. This is the same
reason `access_granted` is plaintext. They are correspondingly *not* bootstrap
verbs, conferring no membership and handing over no group key, so a gateway
boundary must keep carrying them (see [the wire
format](network-wire-format.md)).

Alice's side applies three gates, and each closes a distinct hole:

- **The ticket must be one Alice signed.** A valid invitation minted by anyone
  else, even a fellow cohort member, is not authority over Alice's peer list.
  Verifying the signature and checking who signed it are two separate tests, and
  a runtime conflating them would admit anybody holding any signed blob.
- **It must not have expired.** The point of setting an expiry is that a link
  shared into a channel the sender does not control stops working on its own.
- **The nonce must not already be spent.** An invitation is **single-use**.
  Because the ticket travels out of band it is exactly the kind of bearer token
  that gets forwarded and screenshotted, and an invitation with no expiry, the
  convenient default for "come find me", would otherwise be replayable forever.
  We write the spent nonce through to
  `<data_dir>/first_contact_nonces.cfg.json` before the acknowledgement goes out,
  atomically, and reload it on the next start, because an in-memory-only guard
  would be defeated by waiting for the inviter to restart. A nonce is stored with
  its invitation's expiry so the record can be pruned once the ticket would be
  refused as expired anyway, and an expiry of zero is kept forever, because
  single use is then the only thing bounding replay.

Bob's side applies a gate of its own, and it is the one that was missing at
first. An ack is plaintext for the same reason the hello is, and a plaintext
frame from an unknown sender is parsed and routed with no verb filter, since
that is how bootstrap traffic gets in at all. The envelope is verified only
against the identity it carries. So nothing upstream stops a stranger's ack
from reaching the handler, and a handler that admitted whoever the envelope
named made any stranger on the LAN Bob's direct peer, with no ticket at all.

`initiate` therefore records the hello as **pending**, and an ack is honored
only when it answers one:

- **From an inviter Bob sent a hello to.** An ack out of nowhere admits nobody.
- **Signed by the key the invitation carried.** The uuid alone is not enough: a
  forger can name the inviter's uuid and still sign its envelope correctly,
  with its own key. The invitation is where Bob learned the real key, so it is
  what the ack is compared against.
- **Echoing the nonce of the ticket presented.** Otherwise one outstanding hello
  would be a blank cheque for any ack under the inviter's name.
- **Within the handshake window**, 120 seconds (`PENDING_TTL_SECONDS` /
  `AT_FC_PENDING_TTL_SECONDS`).

The entry is consumed by the ack that matches it, so an ack is honored once, and
a refused one does not burn it, so a forgery arriving first cannot block the real
answer. Pending hellos live in memory only. A restart forgets them, and the user
redeems the link again.

### Direct peer, not group member

Admission here adds the peer to `Peers`, so the encrypted point-to-point channel
can attribute its frames and reputation can score it, and stops there. It does
**not** propagate the group key, and does not insert into the group identity
history. A first-contact peer is *directly reachable* rather than a member of
the inviter's cohort.

That distinction is the security property rather than a labelling nicety. Were
the group key to follow a direct peer in, one out-of-band invitation would
become unilateral group admission: anybody Alice ever invited would hold the
cohort's shared private key, and the majority vote the identity protocol exists
to enforce would be bypassed by a QR code. The two runtimes reach the property
by different mechanisms, Python by calling `peers.add` and deliberately not
`_confirm_group_membership`, C by admitting through
`identity_admit_direct_peer`, which is the provisional half of `_add_peer`, so
it is a corpus case rather than a comment that keeps them agreeing.

A contact admitted this way is still **unverified**, since the handshake proves
reachability and possession of the ticket rather than that the human on the
other end is who Bob thinks. Only the out-of-band safety-number comparison flips
that.

### What an unverified contact may do

A direct peer is put to work at once. Negotiation sends it bootstrap probe tasks
the moment it is admitted, each success raises its reputation, and it is asked
for its capabilities straight away (as confirming a cohort member does, rather
than waiting for the periodic caps sweep). Left alone, that means anyone holding
one forwarded invitation link climbs to full trust in minutes, verified or not.

So negotiation holds an **unverified contact at tier 1**, communication, when
it asks this node to run a capability, whatever it has earned: it may message,
and services, reading shared data and writing it wait for verification
(FIRST_CONTACT_PLAN §10.3). Reputation still records what it earns, so verifying
it later unlocks that at once. Who counts as unverified:

- **Own-group members are never capped**: this node's group voted them in.
- **A child-group member is capped while it is on record as an unverified
  contact.** The child group's vote does not vouch for what first contact
  introduced. A child member with no contact record at all never went through
  first contact, so it is not capped.
- **Any other peer is capped unless it is a *verified* contact.** Here a
  missing record counts as unverified, so losing `contacts.cfg.json` cannot
  lift the cap.

Nothing is capped while first contact is off. The
rule is one function in each runtime, Python `first_contact.capped_tier` and C
`at_first_contact_capped_tier`, and the only caller is negotiation's acceptance
gate.

### What the handshake records

Admission is the live half and the address book is the durable one. `Peers` is
cohort-shaped state a node rebuilds every session, so a handshake that admitted
a peer and wrote nothing would leave the user re-adding the same friend on every
restart. Both handlers therefore write a Contact to the durable store, the
accepter when it honors a ticket and the initiator when the ack lands.

A NEW record is always `token` provenance and **unverified**, with no trust
seed. The accepter cannot know how its own invitation travelled, because
`create_invitation` carries no in-person flag, since in-person-ness is the
*redeemer's* local knowledge. A key that arrived over the wire has had no
out-of-band confirmation, and recording it as verified would hand
safety-number-grade posture, and with it the reputation seed, to anyone
presenting a ticket.

An EXISTING record keeps everything the user or an earlier verification
established, meaning verified state, petname, provenance, trust seed, and the
time it was added. Only reachability and the originating nonce are refreshed,
newest hint first, the previous ones behind it, capped at four, the same cap in
both runtimes because both write the same file. Rewriting the record instead
would mean that re-presenting a ticket, something anyone who obtained one can
do, strips the verified flag off a confirmed contact and drops its reputation
prior with it. That is a downgrade an attacker drives rather than a refresh.

### The seed reaches reputation

The seed a verified contact carries is a **cold-start prior**, and reputation
reads it from the store rather than being pushed it. `contacts.cfg.json` is
already shared byte-for-byte between the runtimes, so the trust-seed decision
stays in one file instead of introducing an identity-to-reputation message. The
reputation process applies it at boot and, guarded by the file's mtime, once per
pass afterwards, so a contact verified while the node is running is picked up
without a restart.

We write it **only where the node has no reputation for that peer at all**. It
can never overwrite an earned score, a warm-started one, or a slashed one, since
a contact cannot be verified back into good standing, or safety-number
confirmation would become an attack on reputation rather than a convenience.
Both halves of the record are checked, verified *and* a seed above zero, because
the store is plain JSON in the user's data dir and honoring a hand-written
`trust_seed` on an unverified record would turn one editable float into a
reputation prior.

### Adding a friend from an application

An application reaches the handshake through two **app verbs**, sent on the local
app queue and answered with events. The app holds no private key, so it cannot
sign an invitation, and it is not the identity process, so it cannot call
`initiate`. The node does both on the app's behalf:

- `app_first_contact_invite` asks the node to mint an invitation. The answer is
  an `invitation` event carrying the `at+contact:` link to share.
- `app_first_contact_initiate` hands the node a friend's link. The node records
  the contact, verified at once if the app says the link came in person, sends
  the hello, and answers `hello_sent`. `established` follows when the ack lands.

Every event echoes the `ref` the app put on its request. A refused request says
why (`malformed`, `bad_signature`, `expired`, `bad_request`, and so on), because
"it didn't work" is not something a person can act on.

Two things the app is deliberately **not** told. A refused hello is not reported
to the initiator, because the inviter sends nothing back, so a probe learns
nothing from a bad ticket. The initiator sees `hello_sent` and then either
`established` or silence, and silence past the handshake window means refused or
unreachable, on purpose indistinguishable. And the inviter's app hears about a
refusal only when the ticket is provably its own, one it minted that came back
expired or already used. A stranger's garbage stays in the log, because
reporting it would let anyone on the LAN flood the app with events.

Both verbs are **local-only**. An app verb and a peer's message are the same
kind of object, both dispatched by name, so a verb that did not check would let
an admitted peer make this node mint links or say hello on its behalf. Each
handler refuses a request that carries a sender other than itself. The main
loop, for its part, forwards only the verbs an enabled feature declared, each to
the one process that declared it: C through `AT_APP_VERB_REGISTER`, Python
through `Extension.app_verbs` (`app_verbs.py`), which is also the first general
app-verb dispatch Python has had.

The address book goes through the node too, once it is running:
`app_first_contact_safety_number`, `_verify`, `_list`, `_rename` and `_remove`.
That makes the identity process the only writer of `contacts.cfg.json`, where an
app editing the file itself would race the handshake's own writes. Verifying
takes one of two honest forms: `presented`, the digits typed from the *other*
screen, which the node compares, or `confirmed`, the user's word that the two
screens matched, trusted as `in_person` is. A list always ends with
`contacts_done` and a count, so an empty address book is an answer rather than
a silence.

**Removing a contact drops the direct peer at once**, not just the record, so the
node stops attributing and encrypting to it. That needed a way out of the peer
list, which neither runtime had: C's `peers[]` was filled from `PEER` messages
and nothing ever took an entry out, so removal added `processes_remove_peer` and
a `PEER_REMOVED` broadcast that every sibling process applies; Python's
`Peers.delete` cleared the nickname slots but left the address listing lookups
read, so removal added `Peers.remove`. A contact who is also a cohort member is
the exception, keeping its peer entry, because that place belongs to the group
the vote admitted it to.

The events cross the flat app ABI as kinds 1000–1008
([`at_first_contact.h`](../../src/c/autonomous_trust/at_first_contact.h)) and
reach a Python app as `FirstContactEvent` objects on `external_feedback`. See
[the API](../api.md#going-live-the-11-handshake-opt-in) for the calls.

### Resolving the endpoint

`initiate` reduces the invitation's rendezvous hint to a bare host, preferring
the hint over the address the inviter's identity advertises. The advertised
address is where the inviter *was* when it published, where the hint is where it
says to reach it *now*, so reading them in the other order works on a LAN and
never reaches a remote friend.

Reducing the hint is not the two-line job it looks like, because a **bracketless
IPv6 literal cannot express a port**, since its colons are part of the address.
Only a single colon (`10.5.5.5:7000`) or a bracketed literal
(`[2001:db8::1]:9000`) carries one, and only those two are split, so `fe80::1`
is passed through entire. A path tail is dropped first. Both runtimes implement
the same table, being Python `endpoint_host` and C
`at_first_contact_endpoint_host`, and the C side treats a host too long for its
fixed `ADDR_LEN` as a **failure** rather than truncating it, on the same
reasoning as [`cidr_split`](../../src/c/autonomous_trust/network/network.c),
that half an address still looks like an address, so clipping it turns a local
mistake into an apparently-unreachable peer.

`ADDR_LEN` is 45, so the buffer behind every C address, `char address[ADDR_LEN +
1]`, is exactly `INET6_ADDRSTRLEN`, and any numeric address of either family
fits whole. It was 32 until this work, which silently clipped a long IPv6
literal in three places at once: a node's own discovered address at config
generation, the self-filter that lets a node recognize its own traffic, and this
endpoint. Python bounds `Identity.address` not at all, so the old width was also
a C-only divergence the corpus never exercised. The refusal branch now triggers
only for what genuinely does not fit, being a scoped literal (`fe80::1%eth0`,
which the transport's `inet_pton` rejects regardless) or a DNS name, neither of
which this field is meant to hold.

## Reaching a contact behind NAT

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

### Several relays, one at a time

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

### Who a relay is, and whom it serves

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

### Where a contact is now: signed reachability records

A link names the relays its minter used that day. Relays change, so each node
also keeps a **reachability record**: its own signed statement of how to reach
it now -- its relays (pinned hints) and its direct address -- with a sequence
number and an expiry (a week), signed by its identity key over
`at-reach-v1|` plus the exact body bytes transmitted (Python
`contacts/reach.py`, C `contacts/reach.{h,c}`). A node issues a new record
whenever what it states changes, and at half its life; the sequence is
persisted, so it only ever rises.

A record travels two ways. It is **pushed** to every contact that is a peer
at the time, over the sealed channel, and to a new contact the moment the
handshake completes (which is how the inviter learns the initiator's own
relays -- the hello carries none). And it is **filed at each of the node's
relays** under the fingerprint of its key: a relay files only its registrant's
own record (the key must be the one it registered with) and only a newer one.
When a node has lost a contact through every relay it knows, it asks each relay
it is registered at for that contact's record; the answer goes to identity like
a pushed one.

Whichever way it arrives, a record is applied only if it verifies, is
unexpired, carries a sequence above the one last applied (`reach_seq` on the
contact, so a replay loses), and -- the part a uuid cannot provide -- is signed
by the key already on record for that contact. Pushed on the wire, it must also
come from the contact itself. A record for someone who is not a contact is
ignored: it updates an address book, never creates one. Applied, its relays and
endpoints go to the head of the contact's hints, and the network process is
told the new route.

A relay can read the records it holds (they list relay addresses and
endpoints), but it files them under key fingerprints, so it cannot list whose
they are without already knowing the keys.

### Where a fresh install finds relays: the seed list

A node learns relays from an invitation first. A node whose operator named none
(`AT_USE_RELAY` unset) and that has first contact on falls back on a **seed
list**: the community-run relays a fresh install registers with (Python
`network/relay_seeds.py`, C `network/net_relay_seeds.{h,c}`). It is a default
mirror list, not a root of trust. A seed relay still proves itself and is still
gated by reputation like any other, so all the signature decides is who chose
the defaults. An explicit `AT_USE_RELAY` always wins, and with first contact off
the list is never read.

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
drop a shipped entry by address. `tools/relay_seeds.py` writes both files
(`keygen`, `sign`, `verify` for the release signer; `local add|remove|clear`
and `show` on the node). A file that fails its check is ignored with a warning,
never half-applied; one unparseable entry refuses the whole file, since that is
a signing mistake rather than a relay to skip. The release public key is a
constant in both runtimes (`RELEASE_KEY`, `AT_RELAY_SEEDS_RELEASE_KEY`) and is
empty until the release keypair is minted. Until then no shipped list is
trusted, and only the local additions apply.

### Relays a community stands behind: rosters

Between the operator's explicit choice and the project's defaults sits a third
source: the relays a **community** the operator trusts has published (Python
`network/relay_rosters.py`, C `network/net_relay_rosters.{h,c}`). The case it was
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
and `show` manage both. Three rules differ from the seed list's:

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
first contact off, neither rosters nor seeds are read. A roster relay proves
itself and is gated by reputation exactly as any other, so a roster decides where
a node looks, never whom it trusts. The format is pinned across three
implementations: AT's own signer, fed Ethne's inputs, reproduces the roster
Ethne emits byte for byte, and both runtimes accept that file and refuse the
same five variations (conformance `network/relay-roster-*`).

### Reconnecting after a restart

`Peers` is rebuilt every session and keeps no direct peer, so a restarted node
would otherwise forget everyone it met through first contact. At startup it
re-admits every contact in its address book as a direct peer (an unverified one
still under the tier cap) and routes each through the relays its record names,
then through its own. The initiator's record keeps the relays the link named;
the inviter reaches its contacts through its own relays, where they registered
in order to reach it. Each side also learns the other's own relays from the
reachability record pushed at the handshake, and later ones keep that current.

The relay is deliberately powerless. It forwards frames that are the ordinary
AT envelope, sealed end to end between the two peers (bar the plaintext hello
and ack, exactly as on UDP), so it cannot read them. It cannot forge who sent
one either: a node registers by signing the relay's challenge with its own key,
so nobody can register someone else's uuid and receive their traffic, and the
relay stamps each delivery's sender from that registration rather than from the
frame. A receiving node goes one step further and drops a relayed frame whose
envelope names anyone but the sender the relay vouched for.

Both runtimes implement it (Python `network/relay.py`, C
`network/net_relay.{h,c}`) and each relays for the other. It is tested
in-sandbox with nodes that have no direct path (different addresses and ports,
so a direct hello lands where nobody listens), with controls proving they never
meet without the relay and never reconnect without the address book;
[`tools/relay_nat/run.sh`](../../tools/relay_nat/run.sh) builds two real
masquerading NATs with network namespaces for the same check on a Linux host,
and has passed there.

## Finding someone by handle: the directory

An invitation has to reach the other person before anything else can happen.
The directory is for the case where all you know is a handle, such as an email
address or phone number. This is the layer where centralization, squatting and
contact harvesting live, so everything about it is opt-in and bounded, and it
grants no trust.

**Who may be found.** Only someone who publishes. An entry
(`contacts/directory.py`, C `contacts/directory.{h,c}`) is the holder's own
signed statement: this handle, this uuid, this key, found by whom, a sequence
number and an expiry. It carries the holder's public identity with the address
left blank, since whoever finds it reaches the holder through the registry's
relay. It must also carry an **issuer's attestation**, an issuer's signature
binding the handle to the holder's KEY. That makes it useless on anyone else's
entry. An issuer is whoever checked that the person controls the handle, such
as an email or SMS verification service or an organization's own records. A
handle is ASCII `[a-z0-9._@+-]`, 1 to 128 bytes, folded to lower case. Unicode
folding is left out because the two runtimes could not agree on it byte for
byte.

**Where entries live.** A registry is a relay that also sets `AT_REGISTRY=1`
(Python `network/registry.py`, C `network/net_registry.{h,c}`), serving the
directory over the same TCP link. The relay's two-way signed registration
already proves who each client is, so a registry files an entry only from the
registered holder of its key. It also needs an attestation from an issuer this
registry trusts (`registry_issuers.cfg.json`), an unexpired one, and a higher
sequence than any it holds. A handle already held under another key is
`taken` until that entry expires. Entries live in memory; a node refiles its
own at every registration, and after a restart from its saved state
(`directory.cfg.json`, which also keeps the sequence rising).

**Who may look.** A lookup names one handle, never a list, and costs one token
from a bucket each client uuid has at each registry (`AT_REGISTRY_RATE` a
minute, default 10). Past it the answer is `dir_limited`. An entry published
with visibility `published` is shown only to a client that has an entry at
that registry itself. For anyone else, and for a holder the registry's node
has come to distrust, the answer is the same `null` a handle nobody filed
gets. A node asks every relay it is registered at and takes the first entry
found. It checks that entry itself (the holder's signature, the attestation,
that it answers the handle asked) and never takes the registry's word.

**Finding is not adding.** Bob sends Alice a signed **contact request**
(`first_contact_request`, plaintext for the same reason a hello is). It names
her uuid, so it cannot be replayed at anyone else, and it names the handle he
found her by, which must be one she publishes. It also lists his relays, so she
can answer. Alice's node checks that it is signed by the sender the envelope
names, addressed to her, and for one of her handles. It then holds the
request, at most 32 at a time and one per sender, and shows it to **her app**.
Nothing else happens until the app accepts. A decline, or silence, sends
nothing back, so Bob learns no more than he would from an unreachable node.

On accept, Alice's node mints an ordinary single-use invitation and sends it
to Bob in a `first_contact_accept` that echoes his request's nonce. Bob's node
takes it only for a request it has outstanding to that uuid, and only if the
invitation is signed by the key the entry named. A request stays outstanding
until its own expiry, an hour by default, so Alice has that long to answer.
Then Bob's node runs the ordinary hello, so every guarantee above (the
single-use ticket, the ack gate, the direct-peer admission) applies unchanged. Both sides record an **unverified**
contact with provenance `directory`, capped at tier 1 until the safety numbers
match. The directory is how you found the person; the safety number is still
what verifies them.

It is tested with three real nodes: a registry, a publisher and a finder that
share no direct path. A control shows that without the publisher's accept the
two never become peers.

## Finding people nearby: area hubs

A handle is for someone you already know of. An area hub is for someone near you
whom you do not know yet, which is harder to do well: the directory's own
lesson, that finding is where harvesting lives, applies with more force when the
key is a place. So a hub knows only what people tell it about themselves, shows
it only to people in the same position, and still grants no trust.

**Who may be found.** Only someone who lists themself. A listing is an **area
card** (`contacts/area_card.py`, C `contacts/area_card.{h,c}`), the holder's own
signed statement over `at-area-card-v1|`: this uuid and key, this area (a
geohash prefix of 2 to 5 characters, which is what a hub serves), a bucket inside
it of at most five characters (about 5 km, as fine as a card gets), an optional
name, a sequence number, and an expiry, an hour by default. It carries the
holder's public identity, with the address left blank, so a finder can address a
contact request to it. Nearness is not attestable, so there is no issuer. The
card is only its holder's word, and what bounds it is the hub.

**Where cards live.** A hub is a relay that also sets `AT_HUB=1`
(`network/hub.py`, C `network/net_hub.{h,c}`) and serves the areas in
`AT_HUB_AREAS`, over the same TCP link as the relay's other ops (`hub_publish`,
`hub_withdraw`, `hub_lookup`). It files a card only from the registered holder
of its key, only for an area it serves, only over a lower sequence, never for
longer than a day, and one per holder per area. Cards live in memory; a listed
node refiles its own at every registration and issues a fresh one while its
current card is past half its life, from `area.cfg.json`, which also keeps the
sequence rising.

**Who may look.** A lookup names one area and is **reciprocal**: only a client
with a live card in that area is shown the area's cards. Anyone else gets the
same empty list a quiet area gets, so a hub cannot be read from outside the area
it serves. An answer holds at most 32 cards, the freshest first, never the
asker's own and never a holder this node has come to distrust, and each lookup
costs one token of a per-client bucket (`AT_HUB_RATE` a minute, default 6). A
node asks every relay it is registered at, and checks every card itself
(signature, holder, the area asked) rather than taking the hub's word.

**Finding is not adding.** A card leads to the directory's own contact request,
unchanged except that it names the **area** in place of a handle, exactly one of
the two. The holder's node shows it to its app only for an area it is listed in
now, and from there the flow is the directory's: the app accepts or declines,
an accept is an ordinary single-use invitation, and both sides record an
unverified contact, of provenance `area`, capped at tier 1 until the safety
numbers match.

**Which hubs.** A community's relay roster may name which of its relays are hubs,
in an optional `areas` object keyed by each hub's own entry. It is left out
when a roster names no hub, so every roster keeps its bytes, and a roster whose
`areas` names a relay it does not list, or anything that is not an area, is
refused whole. A node registers first with a hub whose area holds one of its own
listed buckets. An app may install a roster it trusts (`app_relay_roster_install`,
which pins the roster's issuer) and remove it again; Agora does so for the
communities its reader follows, whose policy carries the roster.

It is tested with three real nodes, a hub and two people with no direct path
between them. A control shows that someone who is not listed in the area finds
nobody, though both of the others are listed.

## One person, several devices

A person's phone and laptop are two nodes, each with its own uuid and keys,
and the keys never leave the device they were made on. What says the two
belong to one person is that person's **operator key**, the ed25519 key in
their operator keystore (never in a node's config), which signs a **device
cert** for each of their devices:

```
DeviceCert := sign_Operator{ "at-device-v1|" + body }
body       := { v, typename: "at-device-cert", operator, uuid, key, issued_at }
```

`key` is the device node's signing key, so a cert cannot be lifted onto
another node. Checking one needs no PIV card, X.509 chain or CA; the operator
key is trusted for one reason only. Bob's record of Alice learned it from a
cert naming the device Bob **verified**, and learns it once: it never
changes, and one operator key belongs to one contact. From then on, a further
device with a cert under the same key is filed under that same contact as
verified, because the safety number Bob compared vouched for Alice, and Alice
vouches for the device. Its uuid resolves to her record, the tier cap treats
it as her, and it gets the contact's trust seed as a cold-start prior of its
own. **Earned reputation does not move**: each device is its own node and
earns its own standing.

Four refusals keep the link from being a way in. A cert must name the very
node presenting it. An unverified contact gains no devices, since there is no
verification to carry over. A device that is already a contact of its own is
not folded into another, because merging two records is the user's call. And
a contact lists at most eight further devices. The store is plain JSON in the
user's data dir, so on load a device survives only if its cert still
verifies, names it, and is under the contact's own operator key.

A node gets its own cert from `tools/device_cert.py`, run where the operator
keystore is, and keeps it in `<cfg_dir>/device_cert.cfg.json`; on load the cert
must name that very node. The invitation format does not change. After a
handshake each side pushes its cert to the other, sealed, as `device_cert`,
which is how Bob's record of Alice learns her operator key. A new device then
sends a plaintext `device_announce` to every contact when it starts. Bob files
it under Alice's record if the rules above allow, and his app gets a
`device_linked` event; a refusal is silent, and nothing is sent back.

### Your own devices, one address book

The devices that carry certs under **your** operator key are your
**siblings**. They are kept in `<data_dir>/siblings.cfg.json`, apart from the
address book, so they never show up as contacts:

```
{ typename: "siblings", version: 1, operator: <hex>,
  devices: [ { identity, cert, added_at } ] }
```

A node pairs with a sibling only if its own cert verifies and both certs name
the same operator key. A node is not its own sibling, there are at most eight,
and a node re-certified under a new operator key starts the list over. As
with contact devices, a sibling in the file loads only if its cert still
verifies, names it, and is under the stored key.

Siblings keep one address book between them by swapping a sync payload:

```
{ v: 1, typename: "at-contacts-sync",
  contacts:   { uuid: <contact record> },
  tombstones: { uuid: removed_at } }
```

Each side folds what it receives into its own store one contact at a time,
and the newer edit wins. A record's version is the latest of when it was
added, when it was verified, and `updated_at`, which only renames and device
or operator links set. Reachability refreshes do not count as edits, because
each device hears those from the contact itself. On a merge the higher
`reach_seq` is kept and both hint lists are merged.

A removal leaves a **tombstone** that is kept for good, so a sibling that was
away for months cannot bring the contact back. A tombstone beats any record
of that uuid that is no newer than it, ties included. Adding the contact
again later is newer, and wins. A time from a sibling more than five minutes
ahead of ours is taken as now, so a fast clock cannot pin its edits as the
winner. When two versions are equal, the tie goes to the larger of (verified,
trust seed, petname, operator key, device uuids, nonce), which both runtimes
compare the same way, so siblings converge whichever copy each saw first.

Nothing ever unverifies a contact, unlinks a device, or unlearns an operator
key, so none of those is lost to a newer edit. The losing copy's
verification, operator key and devices are folded into the winner, and a
rename on one phone cannot undo a verification the other made in the
meantime. A contact new on this device arrives with provenance `sibling` and
its verification intact, since the device that verified it belongs to the
same operator. A contact already here keeps its own provenance. A record
that would file a device or an operator key twice, or that names this node
or a sibling, is refused.

**Pairing** is how two of your devices become siblings. The old device mints
an ordinary invitation whose signed body also carries `purpose: "pair"`, usually
shown as a QR code, and the new device redeems it. The two run the ordinary
hello and ack, but neither records a contact. Each pushes its device cert,
sealed, and on receiving the other's checks the rule above. A match writes both
sibling files. Anything else (a device with no cert, another operator's device,
or no cert within two minutes) drops the direct peer and refuses with
`not_sibling`, so a pairing link can never become a contact.

Siblings then keep the book in step with sealed `contacts_sync` messages, each
carrying a sync payload. Right after pairing, each sends the other its whole
book. After each local edit, a node sends every sibling the contacts that
changed. At startup, a node sends each sibling its whole book with `reply:
true`, and the sibling answers once with its own, so both converge and nothing
loops. A node takes a payload only from a sibling under the key it holds, and a
synced change has the effect the same local edit would. A contact added this
way is admitted as a direct peer, routed, and told this device is one of ours,
so it links it. A removed contact's peers are dropped. The app hears `contact` or
`removed` with origin `sibling`.

Siblings are reached like contacts: re-admitted and routed at startup from the
hints in their file, sent our reachability record, and moved when theirs
changes. They are never tier-capped. Unpairing (`app_sibling_remove`) is not
synced, because each device decides whom it syncs with.

Still ahead is an encrypted backup for a lost phone.

## What is built, and what is not

This chapter describes the primitive as it stands, covering the contact record,
the signed invitation in its QR and invite-link encodings, safety-number
verification, the durable store, the opt-in live handshake, and the app verbs
that let an application drive it, which together are the no-directory, no-relay
path. It is complete on both runtimes and pinned
by conformance, and a node behind NAT is reachable through a relay the
invitation names. Two roles still have loose ends:

- **Rendezvous relays, beyond what is built.** Relays are built (see
  *Reaching a contact behind NAT*, above): several relays per node, named in
  the invitation, with failover and reconnection after a restart, and a
  signed seed list a fresh install falls back on, and the rosters of the
  communities an operator pins, which is how an Ethne polity offers
  rendezvous as a service. Still ahead is the release keypair that signs the
  shipped list.
- **The directory, beyond what is built.** Finding someone by handle is built
  (see *Finding someone by handle*, above): opt-in entries backed by an
  issuer's attestation, registries on relays, one-handle, rate-limited lookups,
  and a contact request the holder's app must accept. The issuer services
  themselves (the email or SMS check behind an attestation) are outside AT;
  `tools/directory_issuer.py` is only the signing half.
- **Several devices, beyond what is built.** The device cert, the contact
  record that lists devices, the rules that link them, and the messages that
  carry a cert to a contact are built. So are pairing and keeping siblings'
  address books in step (see *One person, several devices*, above). Still
  ahead is the encrypted backup.

First contact is an **AT** primitive, so it must complete without the compact
tier present. Its rendezvous and directory *roles* may optionally be served by
an Ethne polity, and the protocol, the record and verification stay at AT, so
first contact never requires a governed community to exist before two people can
connect.

## Pinned scenarios

The conformance corpus pins the behavior on both runtimes, the Python and C
adapters assert the same values, and the cross-language diff reports zero
asymmetry.

| Behavior | Scenario |
|---|---|
| Remote redeem is unverified | [`redeem-remote-unverified.yaml`](../../src/autonomous-trust/conformance/scenarios/contacts/redeem-remote-unverified.yaml) |
| In-person redeem is verified + seeded | [`redeem-in-person-verified.yaml`](../../src/autonomous-trust/conformance/scenarios/contacts/redeem-in-person-verified.yaml) |
| Tampered invitation refused | [`invitation-tampered-rejected.yaml`](../../src/autonomous-trust/conformance/scenarios/contacts/invitation-tampered-rejected.yaml) |
| Expired invitation refused | [`invitation-expired-rejected.yaml`](../../src/autonomous-trust/conformance/scenarios/contacts/invitation-expired-rejected.yaml) |
| Safety number is symmetric + pinned | [`safety-number-pinned.yaml`](../../src/autonomous-trust/conformance/scenarios/contacts/safety-number-pinned.yaml) |
| Safety-number match promotes the contact | [`verify-contact-match.yaml`](../../src/autonomous-trust/conformance/scenarios/contacts/verify-contact-match.yaml) |
| Safety-number mismatch leaves it unverified | [`verify-contact-mismatch.yaml`](../../src/autonomous-trust/conformance/scenarios/contacts/verify-contact-mismatch.yaml) |
| Store round-trips across runtimes | [`store-roundtrip.yaml`](../../src/autonomous-trust/conformance/scenarios/contacts/store-roundtrip.yaml) |
| A device cert verifies and names only its node | [`device-cert-verifies.yaml`](../../src/autonomous-trust/conformance/scenarios/contacts/device-cert-verifies.yaml) |
| A contact learns its operator key only from its own cert | [`device-adopt-another-devices-cert.yaml`](../../src/autonomous-trust/conformance/scenarios/contacts/device-adopt-another-devices-cert.yaml) |
| A further device joins a verified contact | [`device-link-verified-contact.yaml`](../../src/autonomous-trust/conformance/scenarios/contacts/device-link-verified-contact.yaml) |
| An unverified contact gains no devices | [`device-link-unverified-contact.yaml`](../../src/autonomous-trust/conformance/scenarios/contacts/device-link-unverified-contact.yaml) |
| A cert lifted onto another node links nothing | [`device-link-lifted-cert.yaml`](../../src/autonomous-trust/conformance/scenarios/contacts/device-link-lifted-cert.yaml) |
| A hand-added device does not load | [`device-store-drops-hand-added.yaml`](../../src/autonomous-trust/conformance/scenarios/contacts/device-store-drops-hand-added.yaml) |
| A contact synced from a sibling arrives verified, as `sibling` | [`sync-new-contact-arrives-as-sibling.yaml`](../../src/autonomous-trust/conformance/scenarios/contacts/sync-new-contact-arrives-as-sibling.yaml) |
| A rename elsewhere does not undo a verification | [`sync-rename-does-not-undo-verification.yaml`](../../src/autonomous-trust/conformance/scenarios/contacts/sync-rename-does-not-undo-verification.yaml) |
| Equal versions converge on the larger tie key | [`sync-tie-goes-to-the-larger-key.yaml`](../../src/autonomous-trust/conformance/scenarios/contacts/sync-tie-goes-to-the-larger-key.yaml) |
| A removed contact does not come back | [`sync-removed-contact-does-not-come-back.yaml`](../../src/autonomous-trust/conformance/scenarios/contacts/sync-removed-contact-does-not-come-back.yaml) |
| A sibling's clock running ahead is taken as now | [`sync-future-time-taken-as-now.yaml`](../../src/autonomous-trust/conformance/scenarios/contacts/sync-future-time-taken-as-now.yaml) |
| Only a device under our own operator is a sibling | [`siblings-another-operators-device.yaml`](../../src/autonomous-trust/conformance/scenarios/contacts/siblings-another-operators-device.yaml) |
| A linked device is not tier-capped; an unlinked one is | [`invite-verified-contacts-linked-device-uses-earned-tier.yaml`](../../src/autonomous-trust/conformance/scenarios/negotiation/invite-verified-contacts-linked-device-uses-earned-tier.yaml) |
| Handshake admits a DIRECT peer, not a group member | [`first-contact-hello-admits-direct-peer.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/first-contact-hello-admits-direct-peer.yaml) |
| An invitation is single-use | [`first-contact-invitation-single-use.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/first-contact-invitation-single-use.yaml) |
| Single use survives a restart | [`first-contact-nonce-survives-restart.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/first-contact-nonce-survives-restart.yaml) |
| A ticket we did not sign is refused | [`first-contact-foreign-invitation-ignored.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/first-contact-foreign-invitation-ignored.yaml) |
| An expired ticket is refused | [`first-contact-invitation-expired-ignored.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/first-contact-invitation-expired-ignored.yaml) |
| `initiate` prefers the rendezvous hint | [`first-contact-initiate-reaches-the-hint.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/first-contact-initiate-reaches-the-hint.yaml) |
| IPv4/port, bare IPv6 and bracketed IPv6 hints all resolve | [`first-contact-initiate-endpoint-forms.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/first-contact-initiate-endpoint-forms.yaml) |
| A handshake records an unverified contact | [`first-contact-hello-records-a-contact.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/first-contact-hello-records-a-contact.yaml) |
| A re-handshake never downgrades a verified one | [`first-contact-rehandshake-preserves-verification.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/first-contact-rehandshake-preserves-verification.yaml) |
| An ack nobody asked for admits nobody | [`first-contact-unsolicited-ack-ignored.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/first-contact-unsolicited-ack-ignored.yaml) |
| An ack for a different ticket admits nobody | [`first-contact-ack-wrong-nonce-ignored.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/first-contact-ack-wrong-nonce-ignored.yaml) |
| Removing a contact drops the direct peer | [`first-contact-remove-drops-the-direct-peer.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/first-contact-remove-drops-the-direct-peer.yaml) |
| An unverified contact is held at tier 1 | [`invite-unverified-contact-held-at-communication.yaml`](../../src/autonomous-trust/conformance/scenarios/negotiation/invite-unverified-contact-held-at-communication.yaml) |
| A verified contact uses what it earned | [`invite-verified-contact-uses-earned-tier.yaml`](../../src/autonomous-trust/conformance/scenarios/negotiation/invite-verified-contact-uses-earned-tier.yaml) |
| A child-group member with no contact record uses what it earned | [`invite-child-group-member-uses-earned-tier.yaml`](../../src/autonomous-trust/conformance/scenarios/negotiation/invite-child-group-member-uses-earned-tier.yaml) |
| A child-group member who is an unverified contact is held at tier 1 | [`invite-child-group-unverified-contact-held-at-communication.yaml`](../../src/autonomous-trust/conformance/scenarios/negotiation/invite-child-group-unverified-contact-held-at-communication.yaml) |
| A child-group member who is a verified contact uses what it earned | [`invite-child-group-verified-contact-uses-earned-tier.yaml`](../../src/autonomous-trust/conformance/scenarios/negotiation/invite-child-group-verified-contact-uses-earned-tier.yaml) |
| An own-group member is never capped, even as an unverified contact | [`invite-group-member-unverified-contact-uses-earned-tier.yaml`](../../src/autonomous-trust/conformance/scenarios/negotiation/invite-group-member-unverified-contact-uses-earned-tier.yaml) |
| A contact's newer reachability record updates its hints | [`reach-record-updates-the-contact.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/reach-record-updates-the-contact.yaml) |
| A record not newer than the one applied is refused | [`reach-record-stale-is-refused.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/reach-record-stale-is-refused.yaml) |
| A record for a contact signed by another key is refused | [`reach-record-wrong-key-is-refused.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/reach-record-wrong-key-is-refused.yaml) |
| A contact's record pushed by someone else is refused | [`reach-record-pushed-by-someone-else-is-refused.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/reach-record-pushed-by-someone-else-is-refused.yaml) |
| A relay lookup's answer (no sender) is applied on its merits | [`reach-record-from-a-relay-lookup-is-applied.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/reach-record-from-a-relay-lookup-is-applied.yaml) |
| An expired record is refused | [`reach-record-expired-is-refused.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/reach-record-expired-is-refused.yaml) |
| A record from a non-contact is ignored | [`reach-record-from-a-stranger-is-ignored.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/reach-record-from-a-stranger-is-ignored.yaml) |
| Both handshake verbs are plaintext-allowlisted, neither is bootstrap | [`unencrypted-verbs.yaml`](../../src/autonomous-trust/conformance/scenarios/network/unencrypted-verbs.yaml) |

The ack's signing-key check and the app verbs are local behavior a corpus
fixture cannot express (a fixture cannot mint a second key for a participant's
uuid, and app verbs have no wire form), so they are pinned by unit tests on each
runtime instead: `test_first_contact_handshake.py` and
`test_first_contact_app_verbs.py` in Python,
[`first_contact_app_test.c`](../../src/c/test/first_contact_app_test.c) in C.

One level up,
[`test_first_contact_two_node.py`](../../src/autonomous-trust/tests/b_integration/test_first_contact_two_node.py)
runs two real Python nodes on separate loopback addresses that cannot discover
each other, and has their apps add each other: the request crosses the main
loop, the hello and ack arrive on the network process's unknown-sender path,
and the events come back out to both apps.
[`first_contact_live_test.c`](../../src/c/test/first_contact_live_test.c) is the
same test for two real C daemons, each started through `at_app_node_start` and
driven only through the flat app ABI, so it is what a foreign consumer sees;
it also lists and removes, checking the removal inside a running daemon. Skip
both live tests in a quick C run with `ctest -LE live`.

## Further reading

- [Becoming a peer](identity-protocol.md): the cohort analog of this two-party
  flow, the nickname/petname distinction, and amnesia readmission (re-adding a
  known UUID skips the vote).
- [Networking](networking.md): why discovery is LAN-only, which is the gap first
  contact fills.
- [The API](../api.md): the calls a hosting application uses to mint, redeem, and
  verify a contact.

---

*Next: [Getting work done](negotiation.md)*
