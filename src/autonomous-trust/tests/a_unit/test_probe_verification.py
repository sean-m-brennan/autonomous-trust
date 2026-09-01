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
"""Honeypot probe verification (R+D.md §12.7).

The bootstrap corpus was described from the start as a known-answer check —
"a misbehaving B can drop, tamper, or refuse, and A scores 0.1 in any of
those cases" (bootstrap_capabilities.py). It did not do that. Every
``verify_*`` function and the ``BOOTSTRAP_VERIFIERS`` registry were dead
outside their unit tests, and the reason was structural rather than a
forgotten call: ``TaskResult`` carries no ``parameters``, so the requestor's
scorer knew neither which capability produced a result nor what challenge had
been sent. A peer that tampered with an echo scored 0.8, exactly like one that
echoed faithfully.

These tests pin the wiring and, more importantly, the integrity property that
makes it worth anything: the expected value comes from the requestor's own
record, never from the reply.
"""

import os

import pytest

from autonomous_trust.core._python.bootstrap_capabilities import (
    at_echo_challenge, at_handshake, at_time_attest, is_probe_capability,
    register_bootstrap_capabilities, time_attest_tolerance,
    verify_bootstrap_result, DEFAULT_TIME_ATTEST_TOLERANCE_SEC,
)
from autonomous_trust.core._python.capabilities import Capabilities
from autonomous_trust.core._python.negotiation.negotiation import (
    Task, TaskParameters, TaskResult, TaskTracker,
)
from autonomous_trust.core.reputation import TX_CHANNEL_PROBE


def _task(cap_name='at.handshake', **kwargs):
    caps = Capabilities()
    register_bootstrap_capabilities(caps)
    return Task(TaskParameters(caps[cap_name], args=(), kwargs=kwargs), None)


class TestProbeDispatch:
    """The dispatcher the BOOTSTRAP_VERIFIERS comment always described and
    nothing implemented."""

    def test_honest_answers_score_well(self):
        assert verify_bootstrap_result(
            'at.handshake', at_handshake(7), {'nonce': 7}) == 0.9
        assert verify_bootstrap_result(
            'at.echo-challenge', at_echo_challenge('abc'),
            {'payload': 'abc'}) == 0.9

    @pytest.mark.parametrize('result', [7, 9, 0, None, 'x'])
    def test_a_wrong_handshake_is_a_defection(self, result):
        """0.1, not 0.8. A stale nonce (7 for 7) is the interesting case: the
        peer replied, promptly, with a well-formed integer -- completion-based
        scoring cannot tell it from a correct answer."""
        assert verify_bootstrap_result(
            'at.handshake', result, {'nonce': 7}) == 0.1

    @pytest.mark.parametrize('result', ['abd', 'ab', '', 'abcd', None, 7])
    def test_a_tampered_echo_is_a_defection(self, result):
        assert verify_bootstrap_result(
            'at.echo-challenge', result, {'payload': 'abc'}) == 0.1

    def test_a_truthful_clock_passes_and_a_lying_one_does_not(self):
        assert verify_bootstrap_result('at.time-attest', at_time_attest()) == 0.9
        # Out of tolerance but parseable scores 0.5 ("could be drift"), not
        # 0.1 -- the requestor's comparison includes the round trip, so a
        # truthful distant peer must not be branded a defector.
        assert verify_bootstrap_result(
            'at.time-attest', at_time_attest() - 3600) == 0.5
        assert verify_bootstrap_result('at.time-attest', 'not-a-time') == 0.1

    def test_a_non_probe_capability_returns_none(self):
        """None, not a score -- so the caller falls through to ordinary task
        scoring rather than grading a domain task against a nonexistent
        expected value."""
        assert verify_bootstrap_result('dod.sensor-report', 1, {}) is None
        assert verify_bootstrap_result(None, 1, {}) is None
        assert is_probe_capability('at.handshake')
        assert not is_probe_capability('pi')
        assert not is_probe_capability(None)

    def test_a_missing_nonce_still_has_a_right_answer(self):
        """Defaults to 0, matching at_handshake's own default, so an
        unstamped challenge expects 1 rather than accepting anything."""
        assert verify_bootstrap_result('at.handshake', 1, {}) == 0.9
        assert verify_bootstrap_result('at.handshake', 55, {}) == 0.1


class TestTimeAttestTolerance:
    """The env override was documented at the top of the module from the
    start and never read."""

    def test_default_when_unset(self):
        os.environ.pop('AT_TIME_ATTEST_TOLERANCE_SEC', None)
        assert time_attest_tolerance() == DEFAULT_TIME_ATTEST_TOLERANCE_SEC

    def test_env_override_is_honored(self):
        os.environ['AT_TIME_ATTEST_TOLERANCE_SEC'] = '5.0'
        try:
            assert time_attest_tolerance() == 5.0
            # A peer 1s away is now within tolerance rather than "drifting".
            assert verify_bootstrap_result(
                'at.time-attest', at_time_attest() - 1.0) == 0.9
        finally:
            os.environ.pop('AT_TIME_ATTEST_TOLERANCE_SEC', None)

    @pytest.mark.parametrize('bad', ['', 'abc', '0', '-1'])
    def test_garbage_and_nonpositive_fall_back_to_the_default(self, bad):
        os.environ['AT_TIME_ATTEST_TOLERANCE_SEC'] = bad
        try:
            assert time_attest_tolerance() == DEFAULT_TIME_ATTEST_TOLERANCE_SEC
        finally:
            os.environ.pop('AT_TIME_ATTEST_TOLERANCE_SEC', None)


class TestRequestedParameterIntegrity:
    """The property the whole feature rests on."""

    def test_the_requestor_record_overrides_what_the_peer_claims(self):
        """A peer that computed the wrong answer must not be able to report
        the challenge its answer would have been right for. Reading the
        challenge off the reply verifies nothing: result=99 with a claimed
        nonce of 98 is a perfect increment."""
        task = _task(nonce=7)
        reply = TaskResult(task, result=99,
                           requested_capability_name='at.handshake',
                           requested_kwargs={'nonce': 98})
        # Taken at face value, the peer's story checks out.
        assert verify_bootstrap_result(
            'at.handshake', reply.result, {'nonce': 98}) == 0.9
        # Stamped from our own retained Task, it does not.
        reply.attach_requested_parameters(TaskTracker(task))
        assert reply.requested_kwargs == {'nonce': 7}
        assert verify_bootstrap_result(
            reply.requested_capability_name, reply.result,
            reply.requested_kwargs) == 0.1

    def test_no_local_record_clears_rather_than_trusts(self):
        """When we have nothing of our own, the answer is "unknown", not
        "whatever the peer said" -- otherwise the attacker-chosen values
        survive exactly where they are least checked. Downstream reads an
        absent capability name as "not a probe"."""
        class NoParams:
            pass
        reply = TaskResult(_task(nonce=7), result=99,
                           requested_capability_name='at.handshake',
                           requested_kwargs={'nonce': 98})
        assert reply.attach_requested_parameters(NoParams()) is False
        assert reply.requested_capability_name is None
        assert reply.requested_kwargs == {}
        assert not is_probe_capability(reply.requested_capability_name)

    def test_defaults_are_empty_so_an_executor_asserts_nothing(self):
        reply = TaskResult(_task(nonce=7), result=8)
        assert reply.requested_capability_name is None
        assert reply.requested_args == ()
        assert reply.requested_kwargs == {}

    def test_attached_parameters_survive_the_wire(self):
        from autonomous_trust.core import from_json_string, to_json_string
        task = _task(nonce=7)
        reply = TaskResult(task, result=8)
        reply.attach_requested_parameters(TaskTracker(task))
        back = from_json_string(to_json_string(reply))
        assert back.requested_capability_name == 'at.handshake'
        assert back.requested_kwargs == {'nonce': 7}

    def test_echo_challenge_round_trip(self):
        task = _task('at.echo-challenge', payload='echo:deadbeef')
        reply = TaskResult(task, result='echo:deadbe')     # truncated
        reply.attach_requested_parameters(TaskTracker(task))
        assert verify_bootstrap_result(
            reply.requested_capability_name, reply.result,
            reply.requested_kwargs) == 0.1


class TestProbeChannelIsTheAnchor:
    def test_probe_is_in_the_closed_channel_set(self):
        from autonomous_trust.core.reputation import TX_CHANNELS
        assert TX_CHANNEL_PROBE in TX_CHANNELS

    def test_a_probe_score_is_distinguishable_from_a_task_outcome(self):
        """The point of the channel: 0.1 from "failed a known-answer
        challenge" must not read as 0.1 from "the task went badly"."""
        from autonomous_trust.core.reputation import (
            TransactionScore, TX_CHANNEL_TASK_OUTCOME)
        probe = TransactionScore(_task().uuid, 0.1, channel=TX_CHANNEL_PROBE)
        plain = TransactionScore(_task().uuid, 0.1,
                                 channel=TX_CHANNEL_TASK_OUTCOME)
        assert probe.score == plain.score
        assert probe.channel != plain.channel

class TestRequestorSideScoring:
    """``automate.score_task_result``: the requestor's whole verdict on a
    returned result, score and channel together.

    Extracted out of ``Automate._handle_messages`` so the C twin's
    ``negotiation_score_task_result`` can be pinned against the same rules
    from the conformance corpus (``bootstrap/probe-result-scored``). The two
    runtimes cannot share a call site — C scores in its negotiation process,
    because that is where it keeps the requestor's record of the task — so the
    rules are what parity means here.
    """

    @staticmethod
    def _reply(cap_name, result, **kwargs):
        """A reply as the requestor's negotiation process hands it on: the
        requested capability and challenge stamped from OUR record.

        `requestor` is only passed when there is no originating task to copy
        it from -- TaskInfo takes it positionally, and `task.to_dict()`
        already carries it."""
        if cap_name.startswith('at.'):
            task = _task(cap_name, **kwargs)
            return TaskResult(task, result=result,
                              requested_capability_name=cap_name,
                              requested_kwargs=kwargs)
        return TaskResult(None, result=result, requestor=None,
                          requested_capability_name=cap_name,
                          requested_kwargs=kwargs)

    def test_an_honest_probe_answer_scores_well_on_the_probe_channel(self):
        from autonomous_trust.core._python.automate import score_task_result
        score, channel = score_task_result(
            self._reply('at.handshake', 42, nonce=41))
        assert (score, channel) == (0.9, TX_CHANNEL_PROBE)

    def test_the_same_answer_against_a_different_challenge_is_a_defection(self):
        """The integrity property, stated as a test: a peer that computed the
        wrong answer would report the challenge its answer satisfies, so the
        expected value has to come from the requestor's record."""
        from autonomous_trust.core._python.automate import score_task_result
        assert score_task_result(
            self._reply('at.handshake', 42, nonce=41))[0] == 0.9
        assert score_task_result(
            self._reply('at.handshake', 42, nonce=77))[0] == 0.1

    def test_an_unparseable_probe_answer_is_not_an_answer(self):
        """`soon` is not a clock. It has to land on 0.1 rather than on
        at.time-attest's 0.5 "forgivable drift" band, which is where a finite
        zero would land — the C twin parses to NaN for the same reason."""
        from autonomous_trust.core._python.automate import score_task_result
        assert score_task_result(
            self._reply('at.time-attest', 0))[0] == 0.5
        assert score_task_result(
            self._reply('at.time-attest', 'soon'))[0] == 0.1

    def test_a_non_probe_result_is_scored_on_completion(self, monkeypatch):
        """Which arm a non-probe result takes depends on whether the ZKP
        extension is BUILT, so the test says which arm it means.

        ``ZKP_AVAILABLE`` is an ambient fact about the installation, not about
        the result: with the extension absent, a missing proof cannot attest
        anything and completion is the honest score; with it present, a missing
        proof is suspicious. Asserting the first without pinning the flag is a
        test that passes only where the extension is unbuilt -- which is how
        this pair passed here and failed on a machine that has it.
        """
        from autonomous_trust.core._python.automate import score_task_result
        from autonomous_trust.core.reputation import TX_CHANNEL_TASK_OUTCOME
        monkeypatch.setattr(
            'autonomous_trust.core._python.automate.ZKP_AVAILABLE', False)
        assert score_task_result(self._reply('data_fetch', 'done')) == (
            0.8, TX_CHANNEL_TASK_OUTCOME)
        assert score_task_result(self._reply('data_fetch', None)) == (
            0.3, TX_CHANNEL_TASK_OUTCOME)

    def test_a_missing_proof_is_suspicious_where_zkp_is_available(
            self, monkeypatch):
        """The other arm, and the reason the channel is not `task_outcome`:
        a certificate-carrying interface was expected here and nothing was
        presented, which is a fact about the proof rather than about the work.
        Same 0.3 as an INVALID proof -- the algebra does not distinguish them,
        the channel is what carries the reason."""
        from autonomous_trust.core._python.automate import score_task_result
        from autonomous_trust.core.reputation import TX_CHANNEL_CERTIFICATE
        monkeypatch.setattr(
            'autonomous_trust.core._python.automate.ZKP_AVAILABLE', True)
        assert score_task_result(self._reply('data_fetch', 'done')) == (
            0.3, TX_CHANNEL_CERTIFICATE)

    def test_no_retained_capability_falls_through_to_completion(self, monkeypatch):
        """A result for a task we have no record of, or one stamped by a
        pre-§12.7 requestor: scored on completion, never graded against a
        challenge we do not have."""
        from autonomous_trust.core._python.automate import score_task_result
        from autonomous_trust.core.reputation import TX_CHANNEL_TASK_OUTCOME
        monkeypatch.setattr(
            'autonomous_trust.core._python.automate.ZKP_AVAILABLE', False)
        reply = TaskResult(None, result='done', requestor=None)
        assert score_task_result(reply) == (0.8, TX_CHANNEL_TASK_OUTCOME)
