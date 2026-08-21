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
"""Per-verb message freshness: a monotonic sender sequence plus a receiver-side
high-water mark.

A signed AT message binds its content and nothing about when it was said (see
``Message._signable_content``), so a verb whose payload carries no freshness
token can be captured and re-presented, to its own recipient or to a different
one. Verbs that already carry such a token -- a Paxos ballot id, a group key
epoch, a chain index, an attestation nonce, a relayed query id -- are unaffected
and must NOT be given a second one. This module is for the verbs that carried
nothing. See ``doc/architecture/security-hardening.md``, "Replay resistance,
per verb".

The shape, and why this one:

* The SENDER stamps a monotonically increasing ``seq`` into the payload, which
  the message signature already covers because the pre-image includes
  ``base64(data)``. So a stripped or edited ``seq`` is an invalid message
  rather than an unstamped one -- no separate integrity story is needed, and no
  change to the pre-image, which is what would have made this a wire break for
  the C twin and the byte-pinned corpus.
* The RECEIVER keeps, per (sender, verb), the highest ``seq`` it has accepted,
  and refuses anything at or below it. Not a timestamp: a clock-based window
  would make the deliberately advisory cohort-clock subsystem
  (``network/clock.py``, ``doc/architecture/cohort-clock-skew.md``)
  load-bearing, and would still leave replay free inside the window.
* ONE counter per process, shared across the verbs that process emits, rather
  than one counter per verb. The marks are keyed per (sender, verb), so a
  shared counter is still strictly increasing within any single verb -- the
  gaps a verb sees are just the other verbs' sends. One counter means one
  number to persist and one place for it to go wrong.

Both halves are persisted, and both have to be. A sender that rewound its
counter after a restart would have its next messages refused as replays by
peers whose marks it cannot see -- the same trap the checkpoint and slash epoch
counters document. A receiver that forgot its marks would accept one replay per
(sender, verb) on every restart, which for an admission verb is one
re-admission of a peer that was removed.

There is no lenient mode for an unstamped message. That is the standing rule
for this kind of change here (``doc/architecture/reputation.md``, "Quorum
attestation"): a receiver that accepts unstamped messages is a receiver an
attacker selects by simply not stamping.
"""

import json
import os

from .config import Configuration, atomic_write

#: Base name of the per-process freshness file; the process name is appended so
#: two processes on one node never write the same file, and so a counter is
#: only ever advanced by the single process that owns it.
FRESHNESS_FILE = 'freshness'

#: Coalescing window for mark writes, seconds. A mark advance is one small
#: atomic write, and on a busy verb that is per accepted message; bursts inside
#: this window are written once. The residual is bounded and stated: an unclean
#: stop can lose up to this much of the mark state, which costs at most one
#: replay per (sender, verb) whose mark had not yet reached disk. The sender
#: counter is NOT throttled -- it is written before the message it stamps goes
#: out, because a rewound counter breaks liveness rather than merely narrowing
#: a window.
FLUSH_INTERVAL_SECS = float(os.environ.get('AT_FRESHNESS_FLUSH_SECS', '1.0'))


class Freshness(object):
    """One process's freshness state: its own send counter, and its marks.

    ``clock`` is injected (defaulting to the module's monotonic source) so a
    test can drive the flush window without sleeping.
    """

    def __init__(self, proc_name: str, logger=None, clock=None):
        self.proc_name = proc_name
        self.logger = logger
        self._clock = clock if clock is not None else _monotonic
        self._seq = 0
        self._marks: dict[tuple, int] = {}
        # Per-verb count of messages this process REFUSED as stale. Not
        # persisted and not part of the guard's decision: the marks are the
        # security state, this is only the evidence that they fired. A refusal
        # is otherwise invisible from outside — the pre-existing per-sender
        # cooldowns suppress a second delivery on their own, so "no second
        # response" cannot tell the mark from the cooldown. Read by the
        # conformance `freshness_refusals` observable; C mirrors it in
        # freshness_refusals().
        self._refusals: dict[str, int] = {}
        self._dirty = False
        self._last_flush = 0.0
        # Resolved ONCE, here: the config root is established before the
        # process is built (the conformance harness sets it per scenario), and
        # re-resolving on every write would let the file move under a running
        # process -- which for replay marks means silently starting over.
        self._path = os.path.join(
            Configuration.get_cfg_dir(),
            '%s-%s%s' % (FRESHNESS_FILE, self.proc_name,
                         Configuration.file_ext))
        self._load()

    # --- paths ---------------------------------------------------------

    def path(self):
        return self._path

    # --- sender side ---------------------------------------------------

    def stamp(self) -> int:
        """The next sequence number to put on an outgoing payload.

        Persisted before it is returned: the caller is about to put this number
        on the wire, and a number that reaches a peer but not the disk is
        exactly the one that gets reused after a restart and refused.
        """
        self._seq += 1
        self._flush(force=True)
        return self._seq

    # --- receiver side -------------------------------------------------

    def accept(self, sender, verb, seq) -> bool:
        """True iff ``seq`` is fresh for this (sender, verb), advancing the
        mark when it is.

        A missing, non-integer or non-positive ``seq`` is refused: sequences
        start at 1, so 0 is the never-seen floor and anything that cannot be
        read as a number above it is either an unstamped sender or a stripped
        field, both of which are refusals rather than exceptions.
        """
        if sender is None or seq is None:
            self._refused(verb)
            return False
        try:
            seq = int(seq)
        except (TypeError, ValueError):
            self._refused(verb)
            return False
        key = (str(sender), str(verb))
        if seq <= self._marks.get(key, 0):
            self._refused(verb)
            return False
        self._marks[key] = seq
        self._dirty = True
        self._flush()
        return True

    def mark(self, sender, verb) -> int:
        """The current high-water mark, for logging and tests."""
        return self._marks.get((str(sender), str(verb)), 0)

    def _refused(self, verb) -> None:
        """Tally one refusal against ``verb``.

        Keyed by verb alone, not by (sender, verb) like the marks: the sender
        detail is already in the caller's log line and its ``_probes`` counter,
        and a per-verb total is what an observer outside the process can
        assert. Both refusal shapes land here — a sequence at or below the mark
        (a replay) and one that is missing, unreadable or non-positive (an
        unstamped sender, or a stripped field) — because to the guard they are
        one decision. Which of the two a case induces is stated by the case.
        """
        key = str(verb)
        self._refusals[key] = self._refusals.get(key, 0) + 1

    def refusals(self, verb=None) -> int:
        """Messages refused as stale, for ``verb`` or across every verb."""
        if verb is None:
            return sum(self._refusals.values())
        return self._refusals.get(str(verb), 0)

    # --- persistence ---------------------------------------------------

    def _flush(self, force=False):
        if not force and not self._dirty:
            return
        nowish = self._clock()
        if not force and (nowish - self._last_flush) < FLUSH_INTERVAL_SECS:
            return
        doc = {
            'seq': int(self._seq),
            'marks': {'%s|%s' % (s, v): int(n)
                      for (s, v), n in self._marks.items()},
        }
        try:
            with atomic_write(self.path()) as f:
                json.dump(doc, f, indent=2)
            self._dirty = False
            self._last_flush = nowish
        except (OSError, IOError, ValueError, TypeError) as e:
            # Swallowed, like the other snapshot writers: the alternative is
            # taking a process down over a full disk. Logged at warning rather
            # than debug because the cost is a reopened replay window, not a
            # slower warm start.
            if self.logger is not None:
                self.logger.warning('Could not persist freshness state: %s', e)

    def flush(self):
        """Force any pending marks to disk (shutdown, or a test)."""
        self._flush(force=True)

    def _load(self):
        path = self.path()
        if not os.path.exists(path):
            return  # cold start: no counter, no marks, first message accepted
        try:
            with open(path) as f:
                doc = json.load(f)
            if not isinstance(doc, dict):
                raise ValueError('not an object')
            seq = int(doc.get('seq', 0))
            marks = {}
            for flat, n in (doc.get('marks') or {}).items():
                sender, _, verb = str(flat).partition('|')
                if not sender or not verb:
                    raise ValueError('malformed mark key %r' % flat)
                marks[(sender, verb)] = int(n)
        except (OSError, IOError, ValueError, TypeError) as e:
            # Refused loudly and left in place rather than silently treated as
            # empty: "no marks" is the state an attacker would want to induce,
            # and an operator needs to see that the file, not the protocol,
            # is what needs fixing.
            if self.logger is not None:
                self.logger.error(
                    'Freshness state unreadable (%s); replay protection for '
                    '%s starts from empty this boot', e, self.proc_name)
            return
        self._seq = seq
        self._marks = marks
        if self.logger is not None:
            self.logger.debug(
                'Freshness restored for %s: seq=%d, %d mark(s)',
                self.proc_name, self._seq, len(self._marks))


def _monotonic():
    import time
    return time.monotonic()
