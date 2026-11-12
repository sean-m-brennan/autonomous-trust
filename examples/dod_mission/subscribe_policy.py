# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Roster-subscription rules shared by the coordinator's data receiver and the
gateway relay: which roster peers still need a data subscribe, and when a peer
that has not answered is due another."""


def roster_name_of(peer):
    """Bare roster name for a peer == the local-part of its ONLINE nickname.

    The online nickname (e.g. ``mq800@tekfive.com``) is the only globally-
    consistent, wire-carried name; the local petname is deliberately arbitrary
    (a random suffix is minted on receipt -- see
    identity.derive_local_petname) and must NOT be used to match a peer to its
    scenario roster role. We strip the ``@domain`` to recover the deployment-set
    AT_PEER_NAME (``mq800``) the scenario keys on.

    Accepts either a raw ``Identity`` (``.nickname``) or a peer wrapper that
    exposes ``.identity`` (the inspector's ``PeerDataAcq``), and tolerates a
    nickname with no ``@`` (returned as-is)."""
    ident = getattr(peer, "identity", None) or peer
    nn = (getattr(ident, "nickname", None)
          or getattr(peer, "nickname", None) or "")
    return str(nn).split('@', 1)[0].strip()


def pending_roster_subscriptions(peers_all, already, data_producers):
    """Roster peers that produce data but aren't satisfied yet.

    Pure decision half of the late-joiner fallback (see
    _patched_process): given the admitted roster, the set of peers
    already satisfied, and the set of data-producer roster names,
    return the peers to (re)subscribe to now. ``already`` may hold
    Identity objects (the cap path's servicers) OR bare uuid strings
    (the retry path's _received_data_uuids) — both reduce to a uuid
    string. Dedups by uuid string so a peer already serviced / already
    delivering data is skipped, and the same peer isn't returned twice
    within one pass.
    """
    subscribed = {str(getattr(s, "uuid", s)) for s in already}
    pending = []
    for p in peers_all:
        # Match on the ONLINE nickname's local-part, NOT the petname:
        # the petname is local-only and arbitrary on the receiver side
        # (random suffix), so it never equals a roster name like
        # "mq800". See roster_name_of / identity.derive_local_petname.
        if roster_name_of(p) not in data_producers:
            continue
        uid = str(getattr(p, "uuid", ""))
        if not uid or uid in subscribed:
            continue
        subscribed.add(uid)
        pending.append(p)
    return pending

def resub_due(schedule, uid, tick, base, cap):
    """True when peer ``uid`` is due another subscribe at ``tick``.

    Pure backoff half of the retry path: the first attempt is
    immediate, then the gap doubles from ``base`` ticks up to ``cap``.
    ``schedule`` maps uid -> (next due tick, current gap) and is
    updated in place whenever an attempt is due.
    """
    entry = schedule.get(uid)
    if entry is None:
        schedule[uid] = (tick + base, min(base * 2, cap))
        return True
    due_at, gap = entry
    if tick < due_at:
        return False
    schedule[uid] = (tick + gap, min(gap * 2, cap))
    return True
