# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ******************

"""Host-side reputation log harvester for the multi-agency demo.

DEBUG INSTRUMENT — deliberately NOT production-realistic. Instead of
relaying bilateral reputation peer-to-peer over the mesh (and viewing
whatever survives the network round-trip), this reconstructs the full
observer->subject trust matrix out-of-band from container/pod logs:

  1. Each AT node, run with ``AT_REP_DUMP_SEC=<sec>``, emits one
     ``AT_REPDUMP {json}`` line per interval carrying ITS OWN view of
     every peer it scores plus the CTFT inputs behind each score
     (see repprocess.ReputationProcess._dump_reputation_trace).
  2. This harvester tails ``docker logs -f`` (or ``kubectl logs -f``)
     for every node, parses those lines, and unions each node's
     self-report into a global matrix. Observer identity is the
     container/pod the line came from — authoritative, needs no trust
     in what the node claims about itself.
  3. It pushes the same ``peer_seen`` / ``rep_pair`` bridge tuples the
     dashboard already drains, so ``MultiAgencyDemo`` renders the
     reconstructed matrix with no UI changes. Each observer's own-view
     score becomes one directed edge; the demo averages them per
     subject for the Trust-Dynamics line and takes min() per undirected
     pair for the Trust-Network edge.

The parser and matrix (``RepMatrix``) are pure and unit-tested; only
``LogHarvester`` touches subprocesses, so the reconstruction logic runs
without any container runtime present.
"""

from __future__ import annotations

import json
import logging
import subprocess
import threading
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# Line marker written by ReputationProcess._dump_reputation_trace. The
# JSON record follows the token on the same line.
REPDUMP_TOKEN = "AT_REPDUMP "

# Minimum change in an edge's score before we re-emit it downstream.
# Mirrors the coordinator's REPUTATION_PUSH_DELTA so the harvested feed
# is no chattier than the live bridge it replaces.
REP_PUSH_DELTA = 0.01

# Display exclusion threshold the dashboard paints against (demo.py
# _EXCLUSION_THRESHOLD). NOT AT's real exclusion — that is COMM_CUTOFF
# (0.1) / the reputation process's `_excluded` set, surfaced per-observer
# as the dump's `exc` flag. Triage compares the two so a peer sitting at
# the 0.2 cold-start baseline (below 0.5, but nowhere near 0.1) is called
# out as "mislabeled", not genuinely excluded.
DASH_EXCLUSION_THRESHOLD = 0.5


def parse_repdump(line: str) -> Optional[dict]:
    """Extract the JSON record from one ``AT_REPDUMP`` log line.

    Returns the decoded dict, or None when the line is not a dump line
    or its JSON is malformed (log lines carry timestamps / level
    prefixes, so we locate the token and decode everything after it).
    """
    idx = line.find(REPDUMP_TOKEN)
    if idx < 0:
        return None
    payload = line[idx + len(REPDUMP_TOKEN):].strip()
    if not payload:
        return None
    try:
        rec = json.loads(payload)
    except (ValueError, TypeError):
        return None
    if not isinstance(rec, dict) or "self" not in rec:
        return None
    return rec


class RepMatrix:
    """Global observer->subject reputation matrix reconstructed from
    per-node self-reports. Pure state machine — no I/O.

    ``ingest(observer_name, rec)`` folds one parsed ``AT_REPDUMP`` record
    (emitted by the container ``observer_name``) into the matrix and
    returns the list of bridge tuples that should be pushed downstream as
    a result (``peer_seen`` for newly-named nodes, ``rep_pair`` for edges
    whose score moved past ``REP_PUSH_DELTA``).
    """

    def __init__(self, push_delta: float = REP_PUSH_DELTA):
        self._push_delta = push_delta
        # subject-uuid -> authoritative container/pod name (from that
        # node's own self-report; observer identity is never guessed).
        self.uuid_to_name: dict[str, str] = {}
        # (observer_uuid, subject_uuid) -> latest view entry dict.
        self.matrix: dict[tuple[str, str], dict] = {}
        # Names we've already announced via peer_seen.
        self._seen: set[str] = set()
        # (observer_name, subject_name) -> last-emitted score.
        self._last_edge: dict[tuple[str, str], float] = {}
        # subject_name -> last-emitted (excluded, forming) status.
        self._last_status: dict[str, tuple[bool, bool]] = {}

    def _subject_name(self, subj_uuid: str, entry: dict) -> str:
        """Resolve a subject uuid to a display name: authoritative
        self-report first, then the observer-supplied nickname, then a
        short uuid so an as-yet-unheard node is still visible."""
        name = self.uuid_to_name.get(subj_uuid)
        if name:
            return name
        nick = entry.get("nick")
        if nick:
            return str(nick)
        return subj_uuid[:8]

    def ingest(self, observer_name: str, rec: dict) -> list[tuple]:
        out: list[tuple] = []
        obs_uuid = str(rec.get("self", ""))
        if not obs_uuid:
            return out
        # The container an AT_REPDUMP line came from IS the observer, so
        # its self-uuid -> name binding is authoritative.
        if self.uuid_to_name.get(obs_uuid) != observer_name:
            self.uuid_to_name[obs_uuid] = observer_name
        if observer_name not in self._seen:
            self._seen.add(observer_name)
            out.append(("peer_seen", observer_name, obs_uuid, ""))

        for entry in rec.get("view", []) or []:
            try:
                subj_uuid = str(entry["s"])
            except (KeyError, TypeError):
                continue
            if subj_uuid == obs_uuid:
                continue
            self.matrix[(obs_uuid, subj_uuid)] = entry

        # Re-resolve every edge: a self-report that just landed gives a
        # subject its authoritative name, unblocking edges other observers
        # referenced only by uuid, so a single ingest can flush a batch.
        out.extend(self._flush())
        # Authoritative per-subject status (excluded / forming) for the
        # dashboard, so it stops inferring exclusion from a score threshold.
        out.extend(self._status_updates())
        return out

    def _status_updates(self) -> list[tuple]:
        """Yield ``("rep_status", subject, excluded, forming)`` for subjects
        whose status changed. Authoritative, from the CTFT inputs — NOT a
        score threshold:

          forming  = no observer has committed bilateral history (n>0) with
                     the subject yet — the honest cold-start state, whatever
                     the 0.2 baseline score looks like.
          excluded = a MAJORITY of reporting observers hold the subject in
                     their `_excluded` set (real AT exclusion, below
                     COMM_CUTOFF). Majority (not any) so one node's premature
                     drop doesn't flip the graph.
        """
        out: list[tuple] = []
        by_subject: dict[str, list[dict]] = {}
        for (_obs_uuid, subj_uuid), entry in self.matrix.items():
            name = self.uuid_to_name.get(subj_uuid)
            if not name:
                continue  # only subjects with an authoritative name
            by_subject.setdefault(name, []).append(entry)
        for name, entries in by_subject.items():
            observers = len(entries)
            with_history = sum(1 for e in entries if (e.get("n") or 0) > 0)
            excluded_by = sum(1 for e in entries if bool(e.get("exc")))
            forming = with_history == 0
            excluded = (not forming) and (excluded_by * 2 > observers)
            status = (excluded, forming)
            if self._last_status.get(name) != status:
                self._last_status[name] = status
                out.append(("rep_status", name, excluded, forming))
        return out

    def _flush(self) -> list[tuple]:
        out: list[tuple] = []
        for (obs_uuid, subj_uuid), entry in self.matrix.items():
            # Emit an edge only when BOTH endpoints have self-reported, so
            # every name is the authoritative container/pod name the
            # dashboard keys on — never an identity nickname that might not
            # match the scenario roster. Endpoints resolve within one
            # AT_REP_DUMP_SEC interval, so this only defers, never drops.
            obs_name = self.uuid_to_name.get(obs_uuid)
            subj_name = self.uuid_to_name.get(subj_uuid)
            if not obs_name or not subj_name:
                continue
            score = entry.get("con")
            if score is None:
                continue
            try:
                score = float(score)
            except (TypeError, ValueError):
                continue
            edge = (obs_name, subj_name)
            prev = self._last_edge.get(edge)
            if prev is not None and abs(prev - score) < self._push_delta:
                continue
            self._last_edge[edge] = score
            out.append(("rep_pair", obs_name, subj_name, score))
        return out

    def triage_table(self) -> list[dict]:
        """Per-SUBJECT aggregation across all observers, for exclusion triage.

        Answers "why does the graph paint this node excluded?" by separating
        the dashboard's display verdict (mean consensus <= 0.5) from AT's
        real one (any observer holds the subject in its `_excluded` set) and
        from the cold-start case (no observer has committed bilateral txs, so
        the score is just the 0.2 baseline). Rows sorted most-excluded-looking
        first. Each row:

          subject       display name
          observers     how many peers reported a view of it
          with_history  observers with n>0 committed bilateral txs
          mean_con/min/max   consensus stats (mean mirrors the dashboard)
          excluded_by   observers holding it in `_excluded` (real exclusion)
          coop/def      summed CTFT tallies across observers
          dash_excluded mean_con <= DASH_EXCLUSION_THRESHOLD (what you SEE)
          verdict       one-line interpretation
        """
        by_subject: dict[str, list[dict]] = {}
        for (obs_uuid, subj_uuid), entry in self.matrix.items():
            name = (self.uuid_to_name.get(subj_uuid)
                    or self._subject_name(subj_uuid, entry))
            by_subject.setdefault(name, []).append(entry)

        rows: list[dict] = []
        for name, entries in by_subject.items():
            cons = [float(e["con"]) for e in entries if e.get("con") is not None]
            with_history = sum(1 for e in entries if (e.get("n") or 0) > 0)
            excluded_by = sum(1 for e in entries if bool(e.get("exc")))
            coop = sum(int(e.get("coop") or 0) for e in entries)
            defect = sum(int(e.get("def") or 0) for e in entries)
            mean_con = (sum(cons) / len(cons)) if cons else None
            dash_excluded = (mean_con is not None
                             and mean_con <= DASH_EXCLUSION_THRESHOLD)
            if excluded_by > 0:
                verdict = "REAL: below COMM_CUTOFF on %d observer(s)" % excluded_by
            elif dash_excluded and with_history == 0:
                verdict = "MISLABELED: cold-start baseline, 0 committed txs"
            elif dash_excluded:
                verdict = "DECLINED: earned drop (check def vs coop)"
            else:
                verdict = "ok"
            rows.append({
                "subject": name,
                "observers": len(entries),
                "with_history": with_history,
                "mean_con": mean_con,
                "min_con": min(cons) if cons else None,
                "max_con": max(cons) if cons else None,
                "excluded_by": excluded_by,
                "coop": coop,
                "def": defect,
                "dash_excluded": dash_excluded,
                "verdict": verdict,
            })
        rows.sort(key=lambda r: (r["mean_con"] if r["mean_con"] is not None
                                 else float("inf")))
        return rows

    def ctft_inputs(self) -> dict[tuple[str, str], dict]:
        """Name-keyed snapshot of the CTFT inputs behind each edge
        (n/coop/def/tier/exc), for callers that want to surface WHY a
        score is what it is. Not consumed by the current dashboard."""
        snap: dict[tuple[str, str], dict] = {}
        for (obs_uuid, subj_uuid), entry in self.matrix.items():
            obs_name = self.uuid_to_name.get(obs_uuid, obs_uuid[:8])
            subj_name = self._subject_name(subj_uuid, entry)
            snap[(obs_name, subj_name)] = {
                k: entry.get(k) for k in ("n", "coop", "def", "tier", "exc",
                                          "rep", "con")
            }
        return snap


def docker_logs_cmd(container: str, tail: int = 0,
                    follow: bool = True) -> list[str]:
    """`docker logs` argv for one container.

    ``follow`` streams (`-f`) for the live lens; ``follow=False`` is a
    one-shot read for triage. ``tail`` > 0 bounds history; with follow it
    otherwise means "only new lines" (``--tail 0``); one-shot it means
    "all" (``--tail`` omitted)."""
    cmd = ["docker", "logs"]
    if follow:
        cmd.append("-f")
    if tail > 0:
        cmd += ["--tail", str(tail)]
    elif follow:
        cmd += ["--tail", "0"]
    cmd.append(container)
    return cmd


def k8s_logs_cmd(pod: str, namespace: Optional[str] = None,
                 tail: int = 0, follow: bool = True) -> list[str]:
    """`kubectl logs` argv for one pod (minikube / any cluster). See
    ``docker_logs_cmd`` for the ``follow``/``tail`` semantics."""
    cmd = ["kubectl", "logs"]
    if follow:
        cmd.append("-f")
    if tail > 0:
        cmd.append("--tail=%d" % tail)
    elif follow:
        cmd.append("--tail=0")
    cmd.append(pod)
    if namespace:
        cmd += ["-n", namespace]
    return cmd


def collect_once(nodes: list[str], *, runtime: str = "docker",
                 namespace: Optional[str] = None, tail: int = 0,
                 timeout: float = 30.0) -> "RepMatrix":
    """One-shot (non-following) log read across ``nodes`` → a populated
    ``RepMatrix``. Reads the current log buffer of each container/pod,
    folds every ``AT_REPDUMP`` line found, and returns the matrix. Used by
    the ``--triage`` command; no live tail, no bridge queue.

    ``tail`` == 0 reads all available history (bounded per-container by the
    runtime's own log retention); pass a positive value to cap it.
    """
    matrix = RepMatrix()
    for node in nodes:
        if runtime == "k8s":
            cmd = k8s_logs_cmd(node, namespace, tail, follow=False)
        else:
            cmd = docker_logs_cmd(node, tail, follow=False)
        try:
            # Merge stderr into stdout — AT logging lands on the container's
            # stderr, which `docker logs` echoes to its own stderr.
            proc = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=timeout)
        except FileNotFoundError:
            logger.error("triage: '%s' not found on PATH", cmd[0])
            continue
        except Exception:
            logger.warning("triage: log read failed for %s", node,
                           exc_info=True)
            continue
        found = 0
        for line in (proc.stdout or "").splitlines():
            rec = parse_repdump(line)
            if rec is not None:
                matrix.ingest(node, rec)
                found += 1
        if found == 0:
            logger.warning("triage: no AT_REPDUMP lines from %s — is "
                           "AT_REP_DUMP_SEC set on the mesh?", node)
    return matrix


def format_triage_table(rows: list[dict]) -> str:
    """Render ``RepMatrix.triage_table()`` rows as a fixed-width table with
    a one-line summary. Pure string builder (no I/O) so it's testable."""
    header = ("SUBJECT", "OBS", "n>0", "MEAN", "MIN", "MAX",
              "EXC", "COOP", "DEF", "VERDICT")
    def _f(x):
        return "--" if x is None else ("%.2f" % x)
    body = [(
        r["subject"], str(r["observers"]), str(r["with_history"]),
        _f(r["mean_con"]), _f(r["min_con"]), _f(r["max_con"]),
        str(r["excluded_by"]), str(r["coop"]), str(r["def"]), r["verdict"],
    ) for r in rows]
    widths = [len(h) for h in header]
    for row in body:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    def _line(cells):
        return "  ".join(c.ljust(widths[i]) for i, c in enumerate(cells))
    out = [_line(header), _line(tuple("-" * w for w in widths))]
    out += [_line(r) for r in body]

    dash = sum(1 for r in rows if r["dash_excluded"])
    real = sum(1 for r in rows if r["excluded_by"] > 0)
    baseline = sum(1 for r in rows
                   if r["dash_excluded"] and r["excluded_by"] == 0
                   and r["with_history"] == 0)
    declined = dash - real - baseline
    out.append("")
    out.append(
        "%d subject(s) render 'excluded' on the dashboard (mean <= %.1f): "
        "%d truly excluded by AT, %d cold-start baseline (0 committed txs, "
        "MISLABELED), %d earned decline."
        % (dash, DASH_EXCLUSION_THRESHOLD, real, baseline, declined))
    if not rows:
        out.append("(no reputation dumps parsed — is AT_REP_DUMP_SEC set on "
                   "the mesh, and are these the right container/pod names?)")
    return "\n".join(out)


class LogHarvester:
    """Tail every node's logs, reconstruct the matrix, and push bridge
    tuples onto ``bridge_queue`` (a thread-safe ``queue.Queue``).

    ``nodes`` are container names (docker) or pod names (k8s). One reader
    thread per node runs ``docker/kubectl logs -f`` and feeds lines
    through the shared ``RepMatrix`` under a lock.
    """

    def __init__(self, bridge_queue, nodes: list[str], *,
                 runtime: str = "docker",
                 namespace: Optional[str] = None,
                 tail: int = 0,
                 matrix: Optional[RepMatrix] = None):
        self._queue = bridge_queue
        self._nodes = list(nodes)
        self._runtime = runtime
        self._namespace = namespace
        self._tail = tail
        self._matrix = matrix or RepMatrix()
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        self._procs: list[subprocess.Popen] = []
        self._stop = threading.Event()

    def _cmd(self, node: str) -> list[str]:
        if self._runtime == "k8s":
            return k8s_logs_cmd(node, self._namespace, self._tail)
        return docker_logs_cmd(node, self._tail)

    def _emit(self, tuples: list[tuple]) -> None:
        for t in tuples:
            try:
                self._queue.put_nowait(t)
            except Exception:
                logger.debug("bridge_queue put failed for %r", t,
                             exc_info=True)

    def _ingest_line(self, node: str, line: str) -> None:
        rec = parse_repdump(line)
        if rec is None:
            return
        with self._lock:
            tuples = self._matrix.ingest(node, rec)
        if tuples:
            self._emit(tuples)

    def _reader(self, node: str) -> None:
        cmd = self._cmd(node)
        logger.info("harvest: tailing %s (%s)", node, " ".join(cmd))
        while not self._stop.is_set():
            try:
                # AT logging goes to the container's STDERR, which
                # `docker logs` replicates onto ITS stderr — so merge it
                # into the stdout pipe we read, or the AT_REPDUMP lines
                # never arrive. (kubectl already merges the two streams.)
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1)
            except FileNotFoundError:
                logger.error("harvest: '%s' not found — is the %s runtime "
                             "on PATH?", cmd[0], self._runtime)
                return
            except Exception:
                logger.exception("harvest: failed to spawn tail for %s", node)
                return
            self._procs.append(proc)
            try:
                assert proc.stdout is not None
                for line in proc.stdout:
                    if self._stop.is_set():
                        break
                    self._ingest_line(node, line)
            except Exception:
                logger.exception("harvest: reader error for %s", node)
            finally:
                try:
                    proc.terminate()
                except Exception:
                    pass
            if self._stop.is_set():
                break
            # `logs -f` exits when a container restarts; re-attach after a
            # short backoff so the lens survives node churn.
            logger.warning("harvest: log stream for %s ended; re-attaching",
                           node)
            self._stop.wait(2.0)

    def start(self) -> None:
        for node in self._nodes:
            th = threading.Thread(target=self._reader, args=(node,),
                                  name="harvest-%s" % node, daemon=True)
            th.start()
            self._threads.append(th)
        logger.info("harvest: started %d log reader(s) [%s]",
                    len(self._threads), self._runtime)

    def stop(self) -> None:
        self._stop.set()
        for proc in list(self._procs):
            try:
                proc.terminate()
            except Exception:
                pass

    @property
    def matrix(self) -> RepMatrix:
        return self._matrix
