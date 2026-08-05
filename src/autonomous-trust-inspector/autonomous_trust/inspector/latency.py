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
"""Turn a ``PingATStats`` reply into numbers the display can use.

Both consumers of a PingAT reply used to mishandle the object: the bridge did
``float(stats)``, which raises TypeError and was caught and skipped, and the
inspector forwarded the object itself into a channel whose handler requires a
2-tuple and silently ignores anything else. Neither had a test fed a real
PingATStats, so both failures were invisible. The conversion lives here, once,
with both consumers going through it.

PingAT answers a different question from ICMP: it confirms an AT peer is
present and answering on AT's ports via a cooperating responder, where ping(8)
only asks whether a host is reachable. It stays non-load-bearing -- a missed
reply changes no AT behaviour, it only leaves the display without a sample.
"""

from __future__ import annotations

from typing import NamedTuple, Optional


class LatencySample(NamedTuple):
    """A PingAT round summarized for display."""
    rtt_ms: float
    loss_pct: float
    count: int


def summarize(stats) -> Optional[LatencySample]:
    """Summarize a ``PingATStats``, or return None if it is not one.

    Latency alone hides a peer answering one ping in five, so loss and count
    come along with it.
    """
    avg = getattr(stats, 'avg', None)
    total_seconds = getattr(avg, 'total_seconds', None)
    if total_seconds is None:
        return None                      # not a PingATStats; caller skips
    try:
        rtt_ms = total_seconds() * 1000.0
        loss_pct = float(stats.loss)
        count = int(stats.count)
    except (AttributeError, TypeError, ValueError, ZeroDivisionError):
        # An empty times mapping makes `loss` divide by zero. A round that
        # recorded nothing is not a sample.
        return None
    return LatencySample(rtt_ms=rtt_ms, loss_pct=loss_pct, count=count)
