*Previous: [Becoming a peer](identity-protocol.md)*

# First contact

The [identity protocol](identity-protocol.md) admits a newcomer to a *group* by
majority vote. That is the right primitive for a permissionless population
deciding who may join it, but it is not the primitive a person reaches for first.
The first thing a new user does is different and smaller: *here is a specific
human I already know — connect us.* That is a two-party act, not a cohort
decision, and until first contact it had no home in the framework.

Two gaps stood in the way, and both are structural rather than missing
convenience. Discovery is LAN-only: the open channel is UDP broadcast and
multicast (see [Networking](networking.md)), so it finds peers on the same local
network and nobody else — a friend across town, behind NAT, is unreachable by any
shipped mechanism. And admission is that cohort vote — "I want to connect to
exactly Alice" is a different shape the vote cannot express. First contact adds
the missing shape: a durable, user-owned contact and a one-to-one introduction
that binds a *verified key* to a memorable name.

## The rule that governs everything

A phone number feels effortless because it quietly does four jobs at once — it is
a memorable identifier, a proof you control it, a directory entry, and a
rendezvous address — and fakes a fifth, verification, by asking you to trust the
server. Bundling those four into one identifier owned by one company is exactly
what makes such systems centralized. First contact refuses the bundle. The one
rule underneath it:

> The human-memorable identifier — a QR code, an invite link, later a handle — is
> a **hint for finding and reaching** a peer. It is **never** the root of trust.
> The root of trust is always the cryptographic identity, confirmed at first
> contact. The [petname](identity-protocol.md) is the memorable name, assigned
> locally the moment the key is verified.

This is what keeps the identifier disposable: it can be squatted, spoofed, or
served by a hostile directory, and none of that grants trust, because trust
attaches to the key the two humans actually confirmed.

## The contact record

A contact is user-owned durable state, deliberately not cohort state. Where
`Peers` is the live group membership a node rebuilds each session and prunes on
restart, a contact is a personal address-book entry meant to survive across
networks, restarts, and — eventually — a user's own devices. It carries the
public identity (the trust root), a locally-assigned petname (never transmitted),
reachability hints, a verification flag, the provenance of how it was acquired,
and the reputation seed applied once it is verified.

## The out-of-band invitation

The default path, and the strongest, needs no directory and no relay. Alice's
node mints a signed **invitation** carrying her *public* identity, a rendezvous
hint, a nonce, and an expiry:

```
Invitation := sign_Alice{ published_identity, rendezvous_hint, nonce, expiry }
```

She hands it to Bob over a channel she already trusts — a QR code in person, or
an invite link over SMS, Signal, or email. Because the public key travels *inside*
the invitation, there is nothing for a directory to lie about: Bob's node holds
Alice's real key before a single packet crosses the network. The signature is
computed over the exact bytes transmitted (a canonical, sorted-key encoding), and
those exact bytes are what a redeemer verifies — no re-serialization, so there is
no canonicalization ambiguity, and the signature is a detached Ed25519 signature,
deterministic and reproducible byte-for-byte by the C twin.

What the signature proves depends on the channel, and that distinction is the
whole point. It proves the invitation was minted by the holder of the embedded
key. Over an in-person/QR exchange that is conclusive — there was no man in the
middle — so the contact is verified on the spot. Over a remote link a
man-in-the-middle could substitute its own self-consistent invitation, so a
remote contact stays **unverified** until the safety number is confirmed.

## Safety-number verification

Verification is the fifth job the phone number faked, made explicit here. Before
a remote contact is promoted to verified, the two humans compare a **safety
number** over a channel they trust — the Signal model. It is a deterministic,
order-independent function of both public identities (an iterated hash over the
public keys, the two per-identity fingerprints concatenated in sorted order), so
both parties read the same twelve groups of digits regardless of who calls which
identity "mine". Only when they match does `verified` flip and the trust edge
seed apply.

An unverified contact is usable but visibly unverified: a node may message it, but
higher-trust actions gate on verification, so a user is never silently talking to
a peer a hostile channel inserted. A verified contact is seeded slightly above the
reputation cold-start neutral — recognition of the deliberate human confirmation,
not a grant of standing, which must still be earned by interaction.

## The durable store

Contacts persist as `<data_dir>/contacts.cfg.json`, keyed by the peer's UUID (the
stable cryptographic identifier, not the mutable petname or the non-unique
nickname). A missing file is the normal first-run state, not an error, and writes
are atomic. The on-disk form is the same DRY canonical shape both runtimes speak,
so a store written by the Python implementation loads in the C twin and vice
versa; the identity inside it is the flat cross-runtime public form, never the
Python-only config encoding the C side cannot parse.

## The live handshake

The invitation and the contact record are offline: they let Bob learn Alice's key
and remember her, but neither node has spoken to the other. The handshake is the
step that turns a redeemed invitation into a live, mutually-known pair. It is
**optional and off by default** — a node opts in with the `AT_FIRST_CONTACT`
environment flag, and a default deployment registers no handlers for it at all,
so the feature adds no surface to a node that has not asked for it.

It is two messages, hosted in the identity process beside the cohort protocol it
deliberately is not:

1. Bob calls `initiate` with the invitation blob. His node sends
   `first_contact_hello` to the endpoint the invitation names, carrying his
   identity on the envelope and the invitation itself as his ticket.
2. Alice validates the ticket, admits Bob, and replies
   `first_contact_hello_ack`. Bob's node admits Alice in turn.

Both ride the **open, unencrypted channel**, and that is forced rather than
chosen: the first hello arrives from somebody who is not yet a peer, so there is
no shared key it could have been encrypted under — the same reason
`access_granted` is plaintext. They are correspondingly *not* bootstrap verbs:
they confer no membership and hand over no group key, so a gateway boundary must
keep carrying them (see [the wire format](network-wire-format.md)).

Alice's side applies three gates, and each closes a distinct hole:

- **The ticket must be one Alice signed.** A valid invitation minted by anyone
  else — even a fellow cohort member — is not authority over Alice's peer list.
  Verifying the signature and checking who signed it are two separate tests, and
  a runtime that conflated them would admit anybody holding any signed blob.
- **It must not have expired.** The point of setting an expiry is that a link
  shared into a channel the sender does not control stops working on its own.
- **The nonce must not already be spent.** An invitation is **single-use**.
  Because the ticket travels out of band it is exactly the kind of bearer token
  that gets forwarded and screenshotted, and an invitation with no expiry (the
  convenient default for "come find me") would otherwise be replayable forever.
  The spent nonce is written through to
  `<data_dir>/first_contact_nonces.cfg.json` before the acknowledgement goes out,
  atomically, and reloaded on the next start — an in-memory-only guard would be
  defeated by waiting for the inviter to restart. A nonce is stored with its
  invitation's expiry so the record can be pruned once the ticket would be
  refused as expired anyway; an expiry of zero is kept forever, because single
  use is then the only thing bounding replay.

### Direct peer, not group member

Admission here adds the peer to `Peers` — so the encrypted point-to-point channel
can attribute its frames and reputation can score it — and stops there. It does
**not** propagate the group key, and does not insert into the group identity
history. A first-contact peer is *directly reachable*, not a member of the
inviter's cohort.

That distinction is the security property, not a labelling nicety. Were the group
key to follow a direct peer in, one out-of-band invitation would become
unilateral group admission: anybody Alice ever invited would hold the cohort's
shared private key, and the majority vote the identity protocol exists to enforce
would be bypassed by a QR code. The two runtimes reach the property by different
mechanisms — Python by calling `peers.add` and deliberately not
`_confirm_group_membership`, C by admitting through `identity_admit_direct_peer`,
which is the provisional half of `_add_peer` — so it is a corpus case, not a
comment, that keeps them agreeing.

A contact admitted this way is still **unverified**: the handshake proves
reachability and possession of the ticket, not that the human on the other end is
who Bob thinks. Only the out-of-band safety-number comparison flips that.

### Resolving the endpoint

`initiate` reduces the invitation's rendezvous hint to a bare host, preferring
the hint over the address the inviter's identity advertises — the advertised
address is where the inviter *was* when it published, while the hint is where it
says to reach it *now*, so reading them in the other order works on a LAN and
never reaches a remote friend.

Reducing the hint is not the two-line job it looks like, because a **bracketless
IPv6 literal cannot express a port**: its colons are part of the address. Only a
single colon (`10.5.5.5:7000`) or a bracketed literal (`[2001:db8::1]:9000`)
carries one, and only those two are split; `fe80::1` is passed through entire. A
path tail is dropped first. Both runtimes implement the same table (Python
`endpoint_host`, C `at_first_contact_endpoint_host`), and the C side treats a
host too long for its fixed `ADDR_LEN` as a **failure** rather than truncating
it, on the same reasoning as
[`cidr_split`](../../src/c/autonomous_trust/network/network.c): half an address
still looks like an address, so clipping it turns a local mistake into an
apparently-unreachable peer.

`ADDR_LEN` is 45, so the buffer behind every C address —
`char address[ADDR_LEN + 1]` — is exactly `INET6_ADDRSTRLEN`, and any numeric
address of either family fits whole. It was 32 until this work, which silently
clipped a long IPv6 literal in three places at once: a node's own discovered
address at config generation, the self-filter that lets a node recognise its own
traffic, and this endpoint. Python bounds `Identity.address` not at all, so the
old width was also a C-only divergence the corpus never exercised; the refusal
branch now triggers only for what genuinely does not fit — a scoped literal
(`fe80::1%eth0`, which the transport's `inet_pton` rejects regardless) or a DNS
name, neither of which this field is meant to hold.

## What is built, and what is not

This chapter describes the primitive as it stands: the contact record, the signed
invitation (QR and invite-link encodings), safety-number verification, the
durable store, and the opt-in live handshake — the no-directory, no-relay path.
It is complete on both runtimes and pinned by conformance. Two roles the
invitation names are still ahead:

- **Rendezvous relays** — reaching a contact across NAT and changing networks via
  content-blind, signed reachability records addressed by identity-hash. The
  invitation already carries a rendezvous hint, and the handshake will use it as
  a direct endpoint on the shared comm port; the relay layer that resolves a hint
  into a route across NAT, and across ports, is not yet built.
- **An optional, opt-in directory** — the "type a handle to find a friend"
  convenience, tightly bounded against squatting and harvesting. The strongest,
  most private paths need no directory at all, which is why it is last.

First contact is an **AT** primitive: it must complete without the compact tier
present. Its rendezvous and directory *roles* may optionally be served by an
Ethne polity, but the protocol, the record, and verification stay at AT, so first
contact never requires a governed community to exist before two people can
connect.

## Pinned scenarios

The conformance corpus pins the behavior on both runtimes; the Python and C
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
| Handshake admits a DIRECT peer, not a group member | [`first-contact-hello-admits-direct-peer.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/first-contact-hello-admits-direct-peer.yaml) |
| An invitation is single-use | [`first-contact-invitation-single-use.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/first-contact-invitation-single-use.yaml) |
| Single use survives a restart | [`first-contact-nonce-survives-restart.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/first-contact-nonce-survives-restart.yaml) |
| A ticket we did not sign is refused | [`first-contact-foreign-invitation-ignored.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/first-contact-foreign-invitation-ignored.yaml) |
| An expired ticket is refused | [`first-contact-invitation-expired-ignored.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/first-contact-invitation-expired-ignored.yaml) |
| `initiate` prefers the rendezvous hint | [`first-contact-initiate-reaches-the-hint.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/first-contact-initiate-reaches-the-hint.yaml) |
| IPv4/port, bare IPv6 and bracketed IPv6 hints all resolve | [`first-contact-initiate-endpoint-forms.yaml`](../../src/autonomous-trust/conformance/scenarios/identity/first-contact-initiate-endpoint-forms.yaml) |
| Both handshake verbs are plaintext-allowlisted, neither is bootstrap | [`unencrypted-verbs.yaml`](../../src/autonomous-trust/conformance/scenarios/network/unencrypted-verbs.yaml) |

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
