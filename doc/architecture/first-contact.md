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

## What is built, and what is not

This chapter describes the primitive as it stands: the contact record, the signed
invitation (QR and invite-link encodings), safety-number verification, and the
durable store — the offline, no-directory, no-relay path. It is complete on both
runtimes and pinned by conformance. Two roles the invitation names are still
ahead:

- **Rendezvous relays** — reaching a contact across NAT and changing networks via
  content-blind, signed reachability records addressed by identity-hash. The
  invitation already carries a rendezvous hint; the relay layer that resolves it
  is not yet built.
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
