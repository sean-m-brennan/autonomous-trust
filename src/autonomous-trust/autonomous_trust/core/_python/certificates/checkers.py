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
"""The certificate checkers (R+D.md §12.3; certifying algorithms, McConnell,
Mehlhorn, Naeher and Schweitzer 2011).

One function per row of the oracle doc's table. Each takes the problem
*inputs*, the peer's *answer*, and the peer's *certificate*, and returns an
exact verdict.

**Inputs come from the requestor's own retained task parameters, never from the
reply.** This is the same integrity property that makes a honeypot probe worth
issuing (R+D.md §12.7), and it matters more here, not less: a checker that read
the matrices out of the peer's response would be verifying that the peer can
multiply two matrices of its own choosing, which every peer can. The answer and
the certificate are the only things the peer supplies.

Three verdicts, and the third is not a euphemism for either of the others:

``VALID``
    The witness checks out. The answer is *right*, not merely plausible.
``INVALID``
    The witness does not check out. The answer is *wrong*, or the certificate
    does not certify it. Either way it is evidence about the peer.
``INDETERMINATE``
    We cannot run the check --- our own retained inputs are missing or
    malformed, or the problem is degenerate. Never scored against the peer,
    because the fault is on this side.

A note on floating point that applies to every numeric checker here: sums run
in index order and comparisons are against the declaration's ``tolerance``.
Both are load-bearing for the two-runtime port, since addition is not
associative and a checker that summed in a different order could land on the
other side of a bound. The C twin is
``src/c/autonomous_trust/certificates/checkers.c``.
"""

from __future__ import annotations

import math
from typing import Any, Mapping, Optional, Sequence

from .drat import DratError, check_refutation
from .rng import SplitMix64

VALID = 'valid'
INVALID = 'invalid'
INDETERMINATE = 'indeterminate'

#: Largest problem dimension a checker will accept. The inputs are ours, but
#: the certificate is the peer's, and a witness claiming a million-row dual is
#: a denial of service rather than a proof.
MAX_DIM = 4096

#: Largest total element count in any one matrix. Capping each DIMENSION is not
#: enough -- 4096 x 4096 is 134 MB of doubles -- and the C twin has to
#: materialise the same matrix, so the bound belongs on the area rather than on
#: the sides.
MAX_ELEMENTS = 1 << 20


class _Malformed(Exception):
    """Our own inputs will not coerce -- an INDETERMINATE, not a defection."""


def _vec(obj: Any, what: str) -> list[float]:
    if not isinstance(obj, (list, tuple)) or not obj:
        raise _Malformed(f'{what} must be a non-empty list of numbers')
    if len(obj) > MAX_DIM:
        raise _Malformed(f'{what} exceeds {MAX_DIM} entries')
    out: list[float] = []
    for item in obj:
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise _Malformed(f'{what} must contain only numbers')
        val = float(item)
        if not math.isfinite(val):
            raise _Malformed(f'{what} contains a non-finite value')
        out.append(val)
    return out


def _mat(obj: Any, what: str) -> list[list[float]]:
    if not isinstance(obj, (list, tuple)) or not obj:
        raise _Malformed(f'{what} must be a non-empty list of rows')
    if len(obj) > MAX_DIM:
        raise _Malformed(f'{what} exceeds {MAX_DIM} rows')
    rows = [_vec(row, f'{what} row') for row in obj]
    width = len(rows[0])
    for row in rows:
        if len(row) != width:
            raise _Malformed(f'{what} is ragged')
    if len(rows) * width > MAX_ELEMENTS:
        raise _Malformed(f'{what} exceeds {MAX_ELEMENTS} elements')
    return rows


def _dot(a: Sequence[float], b: Sequence[float]) -> float:
    total = 0.0
    for i in range(len(a)):
        total += a[i] * b[i]
    return total


def _peer_value(answer: Any, key: str) -> Any:
    """Pull a named field out of the peer's answer, tolerating a bare value."""
    if isinstance(answer, Mapping):
        return answer.get(key)
    return answer


# --------------------------------------------------------------------------
# Linear algebra
# --------------------------------------------------------------------------

def check_matrix_product(inputs, answer, certificate, decl, seed):
    """Freivalds' check: ``A(Br) == Cr`` for a random ``r``, in O(n^2).

    The one row of the table that needs no witness from the peer at all --- the
    certificate is the *verifier's* randomness, not the prover's data, which is
    why the seed must come from the requestor and must not be derivable from
    the matrices. See :mod:`.rng`.

    One-sided: a correct product passes every round, and a wrong one survives a
    round with probability at most 1/2, so ``repetitions`` rounds bound the
    false-accept rate at 2^-k. It is the only checker here that is
    probabilistic rather than exact, and it is the one whose exact alternative
    (recomputing the product) costs more than the work being verified.
    """
    try:
        a = _mat(inputs.get('a'), 'input a')
        b = _mat(inputs.get('b'), 'input b')
    except _Malformed as exc:
        return INDETERMINATE, str(exc)
    if len(a[0]) != len(b):
        return INDETERMINATE, 'input a columns do not match input b rows'
    try:
        c = _mat(_peer_value(answer, 'c'), 'the answer')
    except _Malformed as exc:
        return INVALID, f'answer is not a matrix: {exc}'
    if len(c) != len(a) or len(c[0]) != len(b[0]):
        return INVALID, ('answer is %dx%d but A*B is %dx%d'
                         % (len(c), len(c[0]), len(a), len(b[0])))

    rng = SplitMix64(seed)
    for round_no in range(decl.repetitions):
        r = [rng.next_pm1() for _ in range(len(b[0]))]
        br = [_dot(row, r) for row in b]          # B r   (n-vector)
        abr = [_dot(row, br) for row in a]        # A(Br) (m-vector)
        cr = [_dot(row, r) for row in c]          # C r   (m-vector)
        for i in range(len(abr)):
            if abs(abr[i] - cr[i]) > decl.tolerance:
                return INVALID, ('Freivalds round %d: row %d differs by %g'
                                 % (round_no, i, abs(abr[i] - cr[i])))
    return VALID, ''


def check_linear_solve(inputs, answer, certificate, decl, seed):
    """Residual check: ``||A x - b||_inf <= tolerance``.

    One matrix-vector product against a solve. No witness is needed beyond the
    solution itself, which is the point --- the answer certifies itself, and
    the interface only had to promise to return ``x`` rather than a claim
    about ``x``.
    """
    try:
        a = _mat(inputs.get('a'), 'input a')
        b = _vec(inputs.get('b'), 'input b')
    except _Malformed as exc:
        return INDETERMINATE, str(exc)
    if len(a) != len(b):
        return INDETERMINATE, 'input a rows do not match input b'
    try:
        x = _vec(_peer_value(answer, 'x'), 'the answer')
    except _Malformed as exc:
        return INVALID, f'answer is not a vector: {exc}'
    if len(x) != len(a[0]):
        return INVALID, ('answer has %d entries, A has %d columns'
                         % (len(x), len(a[0])))
    worst = 0.0
    for i, row in enumerate(a):
        residual = abs(_dot(row, x) - b[i])
        if residual > worst:
            worst = residual
    if worst > decl.tolerance:
        return INVALID, ('residual norm %g exceeds the declared tolerance %g'
                         % (worst, decl.tolerance))
    return VALID, ''


def check_lp(inputs, answer, certificate, decl, seed):
    """Linear programming, in the canonical primal form::

        minimise  c.x   subject to   A x >= b,  x >= 0

    Two things can be certified, and the certificate says which:

    ``{"dual": y}``
        Optimality. Weak duality gives ``c.x >= b.y`` for any feasible pair, so
        exhibiting a feasible ``x`` and a dual-feasible ``y`` whose objectives
        MEET proves both are optimal. That is the whole proof --- no
        re-solving, no trusting the solver, linear in the size of the problem.
    ``{"farkas": y}``
        Infeasibility. By Farkas' lemma the system has no solution exactly when
        some ``y >= 0`` has ``A' y <= 0`` and ``b.y > 0``. A peer that answers
        "infeasible" is otherwise making the one claim that cannot be checked
        by inspecting an answer, because there is no answer to inspect.

    The duality gap is compared against the declared tolerance; every
    inequality is slackened by the same tolerance, so a solver returning a
    solution at the limit of its own precision is not called a liar for it.
    """
    try:
        a = _mat(inputs.get('a'), 'input a')
        b = _vec(inputs.get('b'), 'input b')
        c = _vec(inputs.get('c'), 'input c')
    except _Malformed as exc:
        return INDETERMINATE, str(exc)
    if len(a) != len(b):
        return INDETERMINATE, 'input a rows do not match input b'
    if len(a[0]) != len(c):
        return INDETERMINATE, 'input a columns do not match input c'
    tol = decl.tolerance
    cert = certificate if isinstance(certificate, Mapping) else {}

    claims_infeasible = bool(_peer_value(answer, 'infeasible')) \
        if isinstance(answer, Mapping) else False
    if claims_infeasible:
        try:
            y = _vec(cert.get('farkas'), 'the Farkas certificate')
        except _Malformed as exc:
            return INVALID, f'infeasibility claimed without a witness: {exc}'
        if len(y) != len(a):
            return INVALID, 'Farkas certificate length does not match A rows'
        for i, val in enumerate(y):
            if val < -tol:
                return INVALID, f'Farkas certificate entry {i} is negative'
        for j in range(len(a[0])):
            col = _dot([row[j] for row in a], y)
            if col > tol:
                return INVALID, (f"Farkas certificate violates (A' y)[{j}] "
                                 f'<= 0 by {col:g}')
        if _dot(b, y) <= tol:
            return INVALID, ('Farkas certificate has b.y = %g, which does not '
                             'exceed zero' % _dot(b, y))
        return VALID, ''

    try:
        x = _vec(_peer_value(answer, 'x'), 'the answer')
    except _Malformed as exc:
        return INVALID, f'answer is not a primal solution: {exc}'
    if len(x) != len(a[0]):
        return INVALID, 'answer length does not match A columns'
    for j, val in enumerate(x):
        if val < -tol:
            return INVALID, f'primal solution entry {j} is negative'
    for i, row in enumerate(a):
        if _dot(row, x) < b[i] - tol:
            return INVALID, (f'primal solution violates constraint {i} by '
                             f'{b[i] - _dot(row, x):g}')

    if not decl.require_optimal:
        return VALID, ''
    try:
        y = _vec(cert.get('dual'), 'the dual certificate')
    except _Malformed as exc:
        return INVALID, f'optimality claimed without a dual: {exc}'
    if len(y) != len(a):
        return INVALID, 'dual certificate length does not match A rows'
    for i, val in enumerate(y):
        if val < -tol:
            return INVALID, f'dual entry {i} is negative'
    for j in range(len(a[0])):
        col = _dot([row[j] for row in a], y)
        if col > c[j] + tol:
            return INVALID, (f"dual violates (A' y)[{j}] <= c[{j}] by "
                             f'{col - c[j]:g}')
    gap = abs(_dot(c, x) - _dot(b, y))
    if gap > tol:
        return INVALID, ('duality gap %g exceeds the declared tolerance %g'
                         % (gap, tol))
    return VALID, ''


# --------------------------------------------------------------------------
# Combinatorial
# --------------------------------------------------------------------------

def _edges(obj: Any, what: str):
    if not isinstance(obj, (list, tuple)) or not obj:
        raise _Malformed(f'{what} must be a non-empty list of [u, v, w]')
    if len(obj) > MAX_DIM * 4:
        raise _Malformed(f'{what} is too large')
    out = []
    for edge in obj:
        if not isinstance(edge, (list, tuple)) or len(edge) != 3:
            raise _Malformed(f'{what} entries must be [u, v, w]')
        u, v, w = edge
        if isinstance(w, bool) or not isinstance(w, (int, float)) \
                or not math.isfinite(float(w)):
            raise _Malformed(f'{what} weight must be a finite number')
        out.append((u, v, float(w)))
    return out


def check_path(inputs, answer, certificate, decl, seed):
    """A path, plus a feasible potential proving it is shortest.

    The optimality half is where a naive interface goes wrong. "The path, plus
    an admissible lower bound" is the standard phrasing, but a bound the peer
    merely *asserts* certifies nothing --- a peer returning a detour can assert
    a bound equal to its own cost and call itself optimal. What is checkable is
    the bound's own witness: a **feasible potential**, the LP dual of shortest
    path. Node prices ``pi`` with ``pi[v] - pi[u] <= w(u,v)`` on every edge make
    ``pi[target] - pi[source]`` a valid lower bound on *any* source-target
    path, verifiable in one pass over the edges. A path whose cost meets that
    bound is optimal, and no assertion is taken on trust.

    Negative weights are allowed; a feasible potential exists exactly when
    there is no negative cycle, which is itself part of what the witness
    establishes.
    """
    try:
        edges = _edges(inputs.get('edges'), 'input edges')
    except _Malformed as exc:
        return INDETERMINATE, str(exc)
    source = inputs.get('source')
    target = inputs.get('target')
    if source is None or target is None:
        return INDETERMINATE, 'inputs must name a source and a target'
    weight: dict[tuple, float] = {}
    for u, v, w in edges:
        key = (u, v)
        # Parallel edges: keep the cheapest, which is the only one a shortest
        # path would use and the only one the potential has to admit.
        if key not in weight or w < weight[key]:
            weight[key] = w

    path = _peer_value(answer, 'path')
    if not isinstance(path, (list, tuple)) or not path:
        return INVALID, 'answer is not a path'
    if len(path) > MAX_DIM * 4:
        return INVALID, 'answer path is too long'
    if path[0] != source or path[-1] != target:
        return INVALID, ('path runs %r -> %r, not %r -> %r'
                         % (path[0], path[-1], source, target))
    cost = 0.0
    for i in range(len(path) - 1):
        step = (path[i], path[i + 1])
        if step not in weight:
            return INVALID, f'path uses a non-existent edge {step!r}'
        cost += weight[step]

    if not decl.require_optimal:
        return VALID, ''
    cert = certificate if isinstance(certificate, Mapping) else {}
    potential = cert.get('potential')
    if not isinstance(potential, Mapping) or not potential:
        return INVALID, ('optimality claimed without a feasible potential; a '
                         'bare lower bound is an assertion, not a witness')
    pot: dict[Any, float] = {}
    for node, value in potential.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)) \
                or not math.isfinite(float(value)):
            return INVALID, f'potential for {node!r} is not a finite number'
        pot[node] = float(value)
    tol = decl.tolerance
    for (u, v), w in weight.items():
        pu = pot.get(u)
        pv = pot.get(v)
        if pu is None or pv is None:
            return INVALID, (f'potential omits an endpoint of edge '
                             f'{(u, v)!r}, so it bounds nothing')
        if pv - pu > w + tol:
            return INVALID, (f'potential is infeasible on edge {(u, v)!r}: '
                             f'{pv - pu:g} > {w:g}')
    lower = pot[target] - pot[source] if target in pot and source in pot else None
    if lower is None:
        return INVALID, 'potential omits the source or the target'
    if cost > lower + tol:
        return INVALID, ('path costs %g but the potential proves a lower bound '
                         'of only %g, so optimality is not established'
                         % (cost, lower))
    return VALID, ''


def check_flow(inputs, answer, certificate, decl, seed):
    """A feasible flow, plus a cut whose capacity meets its value.

    Max-flow min-cut: any s-t cut's capacity bounds any s-t flow's value, so a
    flow and a cut that agree are simultaneously maximum and minimum. Both
    halves are checked --- feasibility (capacity and conservation) and
    optimality (the cut) --- because a feasible flow alone certifies only that
    the peer returned *a* flow.
    """
    try:
        edges = _edges(inputs.get('edges'), 'input edges')
    except _Malformed as exc:
        return INDETERMINATE, str(exc)
    source = inputs.get('source')
    sink = inputs.get('sink')
    if source is None or sink is None:
        return INDETERMINATE, 'inputs must name a source and a sink'
    if source == sink:
        return INDETERMINATE, 'source and sink are the same node'
    capacity: dict[tuple, float] = {}
    for u, v, cap in edges:
        capacity[(u, v)] = capacity.get((u, v), 0.0) + cap

    raw = _peer_value(answer, 'flow')
    if not isinstance(raw, (list, tuple)):
        return INVALID, 'answer carries no flow assignment'
    tol = decl.tolerance
    flow: dict[tuple, float] = {}
    for entry in raw:
        if not isinstance(entry, (list, tuple)) or len(entry) != 3:
            return INVALID, 'flow entries must be [u, v, f]'
        u, v, f = entry
        if isinstance(f, bool) or not isinstance(f, (int, float)) \
                or not math.isfinite(float(f)):
            return INVALID, 'flow value must be a finite number'
        key = (u, v)
        if key not in capacity:
            return INVALID, f'flow on a non-existent edge {key!r}'
        f = float(f)
        if f < -tol or f > capacity[key] + tol:
            return INVALID, (f'flow {f:g} on edge {key!r} is outside '
                             f'[0, {capacity[key]:g}]')
        flow[key] = flow.get(key, 0.0) + f

    net: dict[Any, float] = {}
    for (u, v), f in flow.items():
        net[u] = net.get(u, 0.0) - f
        net[v] = net.get(v, 0.0) + f
    for node, balance in net.items():
        if node in (source, sink):
            continue
        if abs(balance) > tol:
            return INVALID, (f'flow is not conserved at {node!r}: net '
                             f'{balance:g}')
    value = -net.get(source, 0.0)
    claimed = _peer_value(answer, 'value') if isinstance(answer, Mapping) else None
    if isinstance(claimed, (int, float)) and not isinstance(claimed, bool):
        if abs(float(claimed) - value) > tol:
            return INVALID, ('claimed value %g does not match the flow out of '
                             'the source, %g' % (float(claimed), value))

    if not decl.require_optimal:
        return VALID, ''
    cert = certificate if isinstance(certificate, Mapping) else {}
    cut = cert.get('cut')
    if not isinstance(cut, (list, tuple)):
        return INVALID, 'optimality claimed without a cut witness'
    side = set(cut)
    if source not in side:
        return INVALID, 'the cut does not contain the source'
    if sink in side:
        return INVALID, 'the cut contains the sink'
    cut_capacity = 0.0
    for (u, v), cap in capacity.items():
        if u in side and v not in side:
            cut_capacity += cap
    if abs(cut_capacity - value) > tol:
        return INVALID, ('cut capacity %g does not meet the flow value %g, so '
                         'maximality is not established'
                         % (cut_capacity, value))
    return VALID, ''


def check_schedule(inputs, answer, certificate, decl, seed):
    """Start times, plus the makespan they achieve.

    Feasibility is three linear passes --- non-negative starts, precedences
    respected, and no instant with more jobs running than there are machines.
    The capacity test only has to examine job *start* times: occupancy changes
    only when something starts, so if no start instant is over capacity, no
    instant is.

    The makespan in the certificate is checked against the schedule rather than
    trusted, and against the declared deadline if the inputs carry one. A peer
    that under-reports its own makespan is claiming a better schedule than it
    produced, which is the failure mode worth catching.
    """
    jobs_in = inputs.get('jobs')
    if not isinstance(jobs_in, (list, tuple)) or not jobs_in:
        return INDETERMINATE, 'inputs must carry a non-empty job list'
    if len(jobs_in) > MAX_DIM:
        return INDETERMINATE, 'too many jobs'
    duration: dict[Any, float] = {}
    for job in jobs_in:
        if not isinstance(job, Mapping):
            return INDETERMINATE, 'each job must be an object'
        jid = job.get('id')
        dur = job.get('duration')
        if jid is None or isinstance(dur, bool) \
                or not isinstance(dur, (int, float)) \
                or not math.isfinite(float(dur)) or float(dur) < 0:
            return INDETERMINATE, f'job {jid!r} has no usable duration'
        # Keyed by the id AS TEXT. Start times arrive as a JSON object, whose
        # keys are strings by construction, so an integer job id would never
        # match its own start and every schedule would read as missing one.
        duration[str(jid)] = float(dur)
    capacity = inputs.get('capacity', 1)
    if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
        return INDETERMINATE, 'capacity must be a positive integer'
    precedences = inputs.get('precedences') or []
    if not isinstance(precedences, (list, tuple)):
        return INDETERMINATE, 'precedences must be a list of [before, after]'

    starts_raw = _peer_value(answer, 'start')
    if not isinstance(starts_raw, Mapping) or not starts_raw:
        return INVALID, 'answer carries no start times'
    starts: dict[str, float] = {}
    for jid, when in starts_raw.items():
        if isinstance(when, bool) or not isinstance(when, (int, float)) \
                or not math.isfinite(float(when)):
            return INVALID, f'start time for {jid!r} is not a finite number'
        starts[str(jid)] = float(when)
    tol = decl.tolerance
    for jid in duration:
        if jid not in starts:
            return INVALID, f'no start time for job {jid!r}'
        if starts[jid] < -tol:
            return INVALID, f'job {jid!r} starts before zero'

    for pair in precedences:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            return INDETERMINATE, 'precedences must be [before, after] pairs'
        before, after = str(pair[0]), str(pair[1])
        if before not in duration or after not in duration:
            return INDETERMINATE, f'precedence {pair!r} names an unknown job'
        if starts[after] < starts[before] + duration[before] - tol:
            return INVALID, (f'job {after!r} starts at {starts[after]:g}, '
                             f'before {before!r} finishes at '
                             f'{starts[before] + duration[before]:g}')

    for jid, when in starts.items():
        if jid not in duration:
            return INVALID, f'answer schedules an unknown job {jid!r}'
        running = 0
        for other, other_start in starts.items():
            if other not in duration:
                continue
            if other_start <= when + tol < other_start + duration[other] - tol \
                    or (duration[other] == 0.0 and abs(other_start - when) <= tol):
                running += 1
        if running > capacity:
            return INVALID, (f'{running} jobs run at t={when:g} but capacity '
                             f'is {capacity}')

    makespan = 0.0
    for jid, when in starts.items():
        end = when + duration[jid]
        if end > makespan:
            makespan = end
    cert = certificate if isinstance(certificate, Mapping) else {}
    claimed = cert.get('makespan')
    if isinstance(claimed, (int, float)) and not isinstance(claimed, bool):
        if abs(float(claimed) - makespan) > tol:
            return INVALID, ('claimed makespan %g does not match the schedule, '
                             'which finishes at %g' % (float(claimed), makespan))
    deadline = inputs.get('deadline')
    if isinstance(deadline, (int, float)) and not isinstance(deadline, bool):
        if makespan > float(deadline) + tol:
            return INVALID, ('schedule finishes at %g, past the deadline %g'
                             % (makespan, float(deadline)))
    return VALID, ''


# --------------------------------------------------------------------------
# SAT
# --------------------------------------------------------------------------

def check_sat(inputs, answer, certificate, decl, seed):
    """A satisfying assignment, or a DRAT refutation.

    The asymmetry is the reason this row is in the table. SAT is certified in
    one line --- exhibit the assignment, evaluate the clauses --- while UNSAT
    admits no such object and is exactly the answer a lying peer gives for
    free. :mod:`.drat` supplies the other half.
    """
    cnf = inputs.get('cnf')
    if not isinstance(cnf, (list, tuple)) or not cnf:
        return INDETERMINATE, 'inputs must carry a non-empty CNF'
    claim = _peer_value(answer, 'sat')
    if not isinstance(claim, bool):
        return INVALID, 'answer does not state whether the formula is satisfiable'
    cert = certificate if isinstance(certificate, Mapping) else {}

    if claim:
        assignment = cert.get('assignment')
        if not isinstance(assignment, (list, tuple)):
            return INVALID, 'satisfiability claimed without an assignment'
        true_lits = set()
        for lit in assignment:
            if isinstance(lit, bool) or not isinstance(lit, int) or lit == 0:
                return INVALID, 'assignment must be non-zero integer literals'
            if -lit in true_lits:
                return INVALID, f'assignment sets both {lit} and {-lit}'
            true_lits.add(lit)
        for idx, clause in enumerate(cnf):
            if not isinstance(clause, (list, tuple)):
                return INDETERMINATE, 'each CNF clause must be a list'
            if not any(lit in true_lits for lit in clause):
                return INVALID, f'assignment leaves clause {idx} unsatisfied'
        return VALID, ''

    proof = cert.get('proof')
    if not isinstance(proof, (list, tuple)):
        return INVALID, ('unsatisfiability claimed without a refutation; '
                         '"I searched and found nothing" is not a witness')
    try:
        ok, reason = check_refutation(cnf, proof, decl.max_proof_len)
    except DratError as exc:
        # A malformed proof is the PEER's blob, not our inputs: it is a failed
        # certificate, not something we were unable to check.
        return INVALID, f'malformed refutation: {exc}'
    return (VALID, '') if ok else (INVALID, reason)


# --------------------------------------------------------------------------
# Estimation
# --------------------------------------------------------------------------

def check_state_estimation(inputs, answer, certificate, decl, seed):
    """Whiteness of the innovation sequence.

    The one row of the table that yields a BOUND rather than a proof, and it is
    worth being plain about that. A well-behaved estimator leaves innovations
    that are serially uncorrelated; correlation at short lags means the filter
    is mis-specified or the reported sequence was not produced by the filter
    claimed. Neither is a contradiction, so this verdict is weaker in kind than
    the others here --- but it is the standard test, and an estimator that
    fails it is not delivering what it says it is.

    The normalised autocorrelation at each lag up to ``max_lag`` must stay
    within ``bound``. A constant sequence has zero variance and no
    autocorrelation to speak of, which is INDETERMINATE rather than a failure.
    """
    seq_raw = _peer_value(answer, 'innovations')
    try:
        seq = _vec(seq_raw, 'the innovation sequence')
    except _Malformed as exc:
        return INVALID, f'answer carries no innovation sequence: {exc}'
    n = len(seq)
    if n <= decl.max_lag + 1:
        return INDETERMINATE, ('sequence of %d is too short for %d lags'
                               % (n, decl.max_lag))
    mean = 0.0
    for value in seq:
        mean += value
    mean /= n
    centred = [value - mean for value in seq]
    denom = 0.0
    for value in centred:
        denom += value * value
    if denom <= 0.0:
        return INDETERMINATE, 'the sequence is constant, so it has no spectrum'
    for lag in range(1, decl.max_lag + 1):
        numer = 0.0
        for i in range(n - lag):
            numer += centred[i] * centred[i + lag]
        rho = numer / denom
        if abs(rho) > decl.bound:
            return INVALID, ('innovations correlate at lag %d (rho = %g, '
                             'bound %g), so the sequence is not white'
                             % (lag, rho, decl.bound))
    return VALID, ''


#: Dispatch table, keyed by the declaration's ``checker``. The keys are exactly
#: :data:`~.model.CHECKER_KINDS`; the module-level test asserts that, so a kind
#: added to one and not the other is caught at import rather than at the first
#: task result that needed it.
CHECKERS = {
    'lp': check_lp,
    'sat': check_sat,
    'path': check_path,
    'linear_solve': check_linear_solve,
    'matrix_product': check_matrix_product,
    'schedule': check_schedule,
    'flow': check_flow,
    'state_estimation': check_state_estimation,
}
