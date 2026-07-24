# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ******************

"""Unit tests for the log-harvest reputation reconstruction.

Pure-logic coverage (no container runtime): parsing AT_REPDUMP lines,
authoritative observer->subject name resolution, matrix construction, the
emitted bridge-tuple stream, push-delta gating, and CTFT-input readout.
Run: ``pytest examples/multi_agency/test_log_harvest.py`` or directly.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from log_harvest import (  # noqa: E402
    parse_repdump, RepMatrix, docker_logs_cmd, k8s_logs_cmd, REPDUMP_TOKEN,
    format_triage_table,
)

U1 = "11111111-1111-1111-1111-111111111111"
U2 = "22222222-2222-2222-2222-222222222222"
U3 = "33333333-3333-3333-3333-333333333333"


def _dump_line(self_uuid, view, t=1.0, prefix=True):
    rec = {"t": t, "self": self_uuid, "view": view}
    body = REPDUMP_TOKEN + json.dumps(rec)
    if prefix:
        # Simulate a real docker-logs line with timestamp + level prefix.
        return "2026-07-23 12:00:00 INFO ReputationProcess: " + body
    return body


def _view(subj, con, nick=None, n=0, coop=0, dfct=0, tier=0, exc=False,
          rep=None):
    return {"s": subj, "nick": nick, "con": con, "rep": rep,
            "n": n, "coop": coop, "def": dfct, "tier": tier, "exc": exc}


# --- parse_repdump ----------------------------------------------------

def test_parse_valid_with_log_prefix():
    line = _dump_line(U1, [_view(U2, 0.8)])
    rec = parse_repdump(line)
    assert rec is not None
    assert rec["self"] == U1
    assert rec["view"][0]["s"] == U2


def test_parse_non_dump_line_is_none():
    assert parse_repdump("2026-07-23 INFO some other log line") is None
    assert parse_repdump("") is None


def test_parse_malformed_json_is_none():
    assert parse_repdump(REPDUMP_TOKEN + "{not valid json") is None
    # token present but no object / missing 'self'
    assert parse_repdump(REPDUMP_TOKEN + "[1,2,3]") is None
    assert parse_repdump(REPDUMP_TOKEN + '{"view":[]}') is None


# --- RepMatrix name resolution + edge emission ------------------------

def test_edge_deferred_until_subject_self_reports():
    m = RepMatrix()
    # Observer noaa-1 reports its view of U2 before U2 has self-reported.
    out = m.ingest("noaa-sensor-1", parse_repdump(
        _dump_line(U1, [_view(U2, 0.8, nick="whatever-nick")])))
    # Observer announced; edge withheld (subject not yet authoritative).
    assert ("peer_seen", "noaa-sensor-1", U1, "") in out
    assert not any(t[0] == "rep_pair" for t in out), \
        "edge must wait for the subject's own self-report"

    # Now U2 self-reports as container noaa-sensor-2.
    out2 = m.ingest("noaa-sensor-2", parse_repdump(
        _dump_line(U2, [_view(U1, 0.75)])))
    assert ("peer_seen", "noaa-sensor-2", U2, "") in out2
    reps = [t for t in out2 if t[0] == "rep_pair"]
    # Both directions resolve to authoritative names (nick is ignored).
    assert ("rep_pair", "noaa-sensor-1", "noaa-sensor-2", 0.8) in reps
    assert ("rep_pair", "noaa-sensor-2", "noaa-sensor-1", 0.75) in reps
    # The identity nickname must never leak into an emitted name.
    assert all("whatever-nick" not in t[1] and "whatever-nick" not in t[2]
               for t in reps)


def test_self_edge_skipped():
    m = RepMatrix()
    out = m.ingest("noaa-sensor-1", parse_repdump(
        _dump_line(U1, [_view(U1, 1.0), _view(U2, 0.5)])))
    m.ingest("noaa-sensor-2", parse_repdump(_dump_line(U2, [])))
    out += m.ingest("noaa-sensor-1", parse_repdump(
        _dump_line(U1, [_view(U2, 0.5)], t=2.0)))
    assert not any(t[0] == "rep_pair" and t[1] == t[2] for t in out)


def test_push_delta_gating():
    m = RepMatrix(push_delta=0.01)
    m.ingest("a", parse_repdump(_dump_line(U1, [_view(U2, 0.80)])))
    m.ingest("b", parse_repdump(_dump_line(U2, [_view(U1, 0.5)])))
    # Sub-threshold change: no re-emit.
    out = m.ingest("a", parse_repdump(_dump_line(U1, [_view(U2, 0.805)], t=2)))
    assert not any(t[0] == "rep_pair" and t[1] == "a" and t[2] == "b"
                   for t in out)
    # Supra-threshold change: re-emit with the new score.
    out = m.ingest("a", parse_repdump(_dump_line(U1, [_view(U2, 0.83)], t=3)))
    assert ("rep_pair", "a", "b", 0.83) in out


def test_none_consensus_skipped():
    m = RepMatrix()
    m.ingest("a", parse_repdump(_dump_line(U1, [_view(U2, None)])))
    out = m.ingest("b", parse_repdump(_dump_line(U2, [_view(U1, None)])))
    assert not any(t[0] == "rep_pair" for t in out)


def test_full_matrix_three_nodes():
    m = RepMatrix()
    names = {U1: "n1", U2: "n2", U3: "n3"}
    # Each node reports its own view of the other two.
    m.ingest("n1", parse_repdump(_dump_line(U1, [_view(U2, 0.7), _view(U3, 0.6)])))
    m.ingest("n2", parse_repdump(_dump_line(U2, [_view(U1, 0.9), _view(U3, 0.4)])))
    out = m.ingest("n3", parse_repdump(_dump_line(U3, [_view(U1, 0.8), _view(U2, 0.55)])))
    # After all three self-report, the matrix holds 6 directed edges.
    assert len(m.matrix) == 6
    for uid, nm in names.items():
        assert m.uuid_to_name[uid] == nm
    # The final ingest flushes every now-resolvable edge at least once.
    all_edges = {(t[1], t[2]): t[3] for t in out if t[0] == "rep_pair"}
    assert all_edges.get(("n3", "n1")) == 0.8
    assert all_edges.get(("n3", "n2")) == 0.55


def test_ctft_inputs_snapshot():
    m = RepMatrix()
    m.ingest("n1", parse_repdump(_dump_line(
        U1, [_view(U2, 0.3, n=5, coop=1, dfct=4, tier=1, exc=True, rep=0.28)])))
    m.ingest("n2", parse_repdump(_dump_line(U2, [])))
    snap = m.ctft_inputs()
    assert snap[("n1", "n2")]["n"] == 5
    assert snap[("n1", "n2")]["coop"] == 1
    assert snap[("n1", "n2")]["def"] == 4
    assert snap[("n1", "n2")]["exc"] is True


# --- command builders -------------------------------------------------

def test_docker_cmd():
    assert docker_logs_cmd("noaa-sensor-1") == \
        ["docker", "logs", "-f", "--tail", "0", "noaa-sensor-1"]


def test_docker_cmd_oneshot():
    # follow=False, bounded history
    assert docker_logs_cmd("c", tail=2000, follow=False) == \
        ["docker", "logs", "--tail", "2000", "c"]
    # follow=False, all history (no --tail)
    assert docker_logs_cmd("c", tail=0, follow=False) == \
        ["docker", "logs", "c"]


def test_k8s_cmd_with_namespace():
    assert k8s_logs_cmd("pod-x", "demo") == \
        ["kubectl", "logs", "-f", "--tail=0", "pod-x", "-n", "demo"]
    assert k8s_logs_cmd("pod-x") == \
        ["kubectl", "logs", "-f", "--tail=0", "pod-x"]


def test_k8s_cmd_oneshot():
    assert k8s_logs_cmd("pod-x", "demo", tail=500, follow=False) == \
        ["kubectl", "logs", "--tail=500", "pod-x", "-n", "demo"]
    assert k8s_logs_cmd("pod-x", follow=False) == \
        ["kubectl", "logs", "pod-x"]


# --- exclusion triage --------------------------------------------------

UA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
UB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
UC = "cccccccc-cccc-cccc-cccc-cccccccccccc"
UD = "dddddddd-dddd-dddd-dddd-dddddddddddd"
UO1 = "01010101-0101-0101-0101-010101010101"
UO2 = "02020202-0202-0202-0202-020202020202"


def _run_triage_ingests():
    """Ingest a fixed 4-subject / 2-observer scene; return (matrix, emitted).

      a: cold-start baseline (0.2, 0 committed txs)  -> forming / MISLABELED
      b: healthy (0.8+, real history)                -> active / ok
      c: real exclusion (exc=true on both observers) -> excluded / REAL
      d: earned decline (0.3, def >> coop)           -> active / DECLINED
    """
    m = RepMatrix()
    emitted = []
    # Subjects self-report (empty view) so uuid->name resolves authoritatively.
    for uid, nm in ((UA, "a"), (UB, "b"), (UC, "c"), (UD, "d")):
        emitted += m.ingest(nm, parse_repdump(_dump_line(uid, [])))
    emitted += m.ingest("o1", parse_repdump(_dump_line(UO1, [
        _view(UA, 0.20, n=0),
        _view(UB, 0.80, n=5, coop=5),
        _view(UC, 0.05, n=3, coop=0, dfct=3, exc=True),
        _view(UD, 0.30, n=4, coop=1, dfct=3),
    ])))
    emitted += m.ingest("o2", parse_repdump(_dump_line(UO2, [
        _view(UA, 0.20, n=0),
        _view(UB, 0.82, n=6, coop=6),
        _view(UC, 0.04, n=2, coop=0, dfct=2, exc=True),
        _view(UD, 0.28, n=5, coop=1, dfct=4),
    ])))
    return m, emitted


def _triage_matrix():
    return _run_triage_ingests()[0]


def test_triage_verdicts():
    rows = {r["subject"]: r for r in _triage_matrix().triage_table()}
    assert rows["a"]["with_history"] == 0
    assert rows["a"]["excluded_by"] == 0
    assert rows["a"]["dash_excluded"] is True
    assert "MISLABELED" in rows["a"]["verdict"]

    assert rows["b"]["dash_excluded"] is False
    assert rows["b"]["verdict"] == "ok"

    assert rows["c"]["excluded_by"] == 2
    assert "REAL" in rows["c"]["verdict"]

    assert rows["d"]["excluded_by"] == 0
    assert rows["d"]["dash_excluded"] is True
    assert "DECLINED" in rows["d"]["verdict"]


def test_triage_sorted_most_excluded_first():
    subjects = [r["subject"] for r in _triage_matrix().triage_table()]
    # c (~0.045) < a (0.20) < d (~0.29) < b (~0.81)
    assert subjects == ["c", "a", "d", "b"]


def test_triage_table_render_and_summary():
    text = format_triage_table(_triage_matrix().triage_table())
    assert "SUBJECT" in text and "VERDICT" in text
    assert "MISLABELED" in text and "REAL" in text and "DECLINED" in text
    # 3 dashboard-excluded (a, c, d); 1 real; 1 baseline; 1 declined.
    assert ("3 subject(s) render 'excluded'" in text)
    assert "1 truly excluded by AT" in text
    assert "1 cold-start baseline" in text
    assert "1 earned decline" in text


def test_triage_empty():
    text = format_triage_table(RepMatrix().triage_table())
    assert "no reputation dumps parsed" in text


# --- authoritative rep_status emission (feeds dashboard status) --------

def test_rep_status_tuples_emitted():
    _m, emitted = _run_triage_ingests()
    status = {t[1]: (t[2], t[3]) for t in emitted if t[0] == "rep_status"}
    # (excluded, forming)
    assert status["a"] == (False, True)    # cold start -> forming, NOT excluded
    assert status["b"] == (False, False)   # active
    assert status["c"] == (True, False)    # real exclusion (majority)
    assert status["d"] == (False, False)   # declined but not excluded yet


def test_rep_status_not_reemitted_when_unchanged():
    m = RepMatrix()
    m.ingest("b", parse_repdump(_dump_line(UB, [])))
    m.ingest("o1", parse_repdump(_dump_line(UO1, [_view(UB, 0.8, n=5, coop=5)])))
    # A second identical observation must not re-emit a status tuple.
    again = m.ingest("o1", parse_repdump(
        _dump_line(UO1, [_view(UB, 0.8, n=5, coop=5)], t=2.0)))
    assert not any(t[0] == "rep_status" for t in again)


def test_exclusion_needs_majority():
    # One of two observers excluding is NOT a majority -> not excluded.
    m = RepMatrix()
    for uid, nm in ((UC, "c"), (UO1, "o1"), (UO2, "o2")):
        m.ingest(nm, parse_repdump(_dump_line(uid, [])))
    m.ingest("o1", parse_repdump(_dump_line(UO1, [_view(UC, 0.05, n=2, dfct=2, exc=True)])))
    emitted = m.ingest("o2", parse_repdump(_dump_line(UO2, [_view(UC, 0.6, n=2, coop=2)])))
    status = {t[1]: (t[2], t[3]) for t in emitted if t[0] == "rep_status"}
    # excluded_by=1 of observers=2 -> 1*2 > 2 is False -> not excluded.
    assert status.get("c", (True, False))[0] is False


if __name__ == "__main__":
    import types
    mod = sys.modules[__name__]
    failures = 0
    for name in sorted(dir(mod)):
        if not name.startswith("test_"):
            continue
        fn = getattr(mod, name)
        if not isinstance(fn, types.FunctionType):
            continue
        try:
            fn()
            print("PASS", name)
        except AssertionError as e:
            failures += 1
            print("FAIL", name, "-", e)
        except Exception as e:  # noqa: BLE001
            failures += 1
            print("ERROR", name, "-", repr(e))
    print("\n%d failure(s)" % failures)
    sys.exit(1 if failures else 0)
