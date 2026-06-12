# ******************
#  Copyright 2026 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Tests for the data-sink late-joiner subscription fallback.

The coordinator's DiagDataRcvr normally subscribes to a peer's data stream
when that peer advertises the ``data`` capability. A late joiner (the MQ-800
at T+4:00) can drop that advertisement under UDP loss, after which the
cap-driven path never lists it and its readings never arrive — so it is never
detected (and, downstream, the anomaly-gated jet never flies). The roster
fallback subscribes to known data-producing peers directly. This pins the pure
decision half of that fallback.

Imports the coordinator, which pulls in the dashboard stack (dash/plotly); the
whole module skips cleanly where those aren't installed.

Run from the repo root:
    pytest examples/dod_mission/test_data_subscription.py
"""

from __future__ import annotations

import pytest

coord = pytest.importorskip(
    "examples.dod_mission.coordinator",
    reason="coordinator needs the dashboard stack (dash/plotly) + services.data",
)

if not getattr(coord, "HAS_DATA", False):
    pytest.skip("autonomous_trust.services.data unavailable",
                allow_module_level=True)

_pending = coord.DiagDataRcvr._pending_roster_subscriptions


class _Peer:
    def __init__(self, uuid, nickname):
        self.uuid = uuid
        self.nickname = nickname


PRODUCERS = {"mq800", "rq86-1", "rq86-2", "microdrone-1"}


def _nicks(peers):
    return [p.nickname for p in peers]


def test_subscribes_late_producer_not_yet_serviced():
    roster = [_Peer("u-rq", "rq86-1"), _Peer("u-mq", "mq800")]
    servicers = [_Peer("u-rq", "rq86-1")]   # rq86-1 already via the cap path
    assert _nicks(_pending(roster, servicers, PRODUCERS)) == ["mq800"]


def test_excludes_non_producers():
    roster = [_Peer("u-sq", "squad-captain"), _Peer("u-cmd", "command")]
    assert _pending(roster, [], PRODUCERS) == []


def test_dedups_duplicate_roster_entries():
    roster = [_Peer("u-mq", "mq800"), _Peer("u-mq", "mq800")]
    assert _nicks(_pending(roster, [], PRODUCERS)) == ["mq800"]


def test_idempotent_once_subscribed():
    roster = [_Peer("u-mq", "mq800"), _Peer("u-md", "microdrone-1")]
    first = _pending(roster, [], PRODUCERS)
    assert set(_nicks(first)) == {"mq800", "microdrone-1"}
    # Feeding the result back as servicers yields nothing more.
    assert _pending(roster, first, PRODUCERS) == []


def test_retries_until_data_received():
    """Retry path: keyed on readings actually received, not on a prior send.

    The producer-side subscribe is fire-and-forget (server.handle_requests
    registers a client only if the request lands, no ack), so a single
    lost/early request strands a late joiner at clients=0. The caller now
    passes _received_data_uuids (uuid strings of peers that have delivered a
    reading) as the 'already-satisfied' set, so an un-heard producer stays
    pending on every pass and is dropped only once its data arrives."""
    roster = [_Peer("u-mq", "mq800")]
    received: set = set()
    # No reading yet -> still pending on repeated passes (NOT one-shot).
    assert _nicks(_pending(roster, received, PRODUCERS)) == ["mq800"]
    assert _nicks(_pending(roster, received, PRODUCERS)) == ["mq800"]
    # A reading arrives (uuid recorded) -> stop re-subscribing.
    received.add("u-mq")
    assert _pending(roster, received, PRODUCERS) == []


def test_empty_producer_set_is_noop():
    roster = [_Peer("u-mq", "mq800")]
    assert _pending(roster, [], set()) == []


def test_skips_peers_without_uuid():
    roster = [_Peer("", "mq800")]   # not yet a resolvable identity
    assert _pending(roster, [], PRODUCERS) == []
