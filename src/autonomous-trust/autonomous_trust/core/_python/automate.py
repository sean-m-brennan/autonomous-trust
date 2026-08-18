# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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

from __future__ import annotations

import os
import random
import signal
import sys
import time
import logging
import uuid as _uuid
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler, SysLogHandler
import traceback
import queue
from enum import Enum
from typing import Any, Union
import multiprocessing as mp
from multiprocessing import Pool as ProcessPool
from multiprocessing.dummy import Pool as ThreadPool
from multiprocessing.pool import AsyncResult  # noqa
from operator import mul, pow
from decimal import Decimal, getcontext

import psutil

try:
    from autonomous_trust.core import __version__ as version
except ImportError:
    version = '?.?.?'
from .config import Configuration, to_json_string, from_json_string, ConfigMap
from .config.discover import get_cfg_type, load_configs
from .processes import Process, LogLevel, ProcessTracker, LOG_FORMAT, LOG_DATEFMT
from .identity import Peers
from .identity.protocol import IdentityProtocol
from .bootstrap_capabilities import (
    register_bootstrap_capabilities,
    BOOTSTRAP_CAPABILITY_NAMES,
)
from .capabilities import Capabilities, Capability, PeerCapabilities
from .system import CfgIds, PackageHash, queue_cadence, max_concurrency, now, preferred_proto_ver, QueueType
from .protocol import Protocol
from .negotiation import Task, TaskParameters, TaskStatus, Status, TaskResult, NegotiationProtocol
from .network import Message, require_synced_clock
from .reputation import TransactionScore, ReputationProtocol, PeerReputation
from .reputation.reputation import Reputation
from .queue_pool import QueuePool
from .._zkp import ZKP_AVAILABLE
from . import _probes

PoolType = Union[ProcessPool, ThreadPool]


def pi(precision):  # intentionally non-trivial, arbitrary precision
    getcontext().prec = precision
    return sum(1 / Decimal(16) ** k *
               (Decimal(4) / (8 * k + 1) -
                Decimal(2) / (8 * k + 4) -
                Decimal(1) / (8 * k + 5) -
                Decimal(1) / (8 * k + 6)) for k in range(precision))


class Ctx(str, Enum):
    FORK = 'fork'
    SPAWN = 'spawn'
    DEFAULT = FORKSERVER = 'forkserver'

    def __str__(self) -> str:
        return str.__str__(self)


################################################################################


class AutonomousTrust(Protocol):
    """
    Creates an AutonomousTrust machine
    """
    external_control = 'extern_out'
    external_feedback = 'extern_in'

    # Transport errors raised by a manager-proxied queue when its connection
    # drops (peer/subprocess churn) or the manager server dies — distinct from
    # queue.Empty / queue.Full. BrokenPipeError and ConnectionError are OSError
    # subclasses; EOFError is not, so both are listed.
    _MGR_CONN_ERRORS = (EOFError, OSError)
    _IPC_DROP_LOG_INTERVAL = 30.0  # min seconds between IPC-drop log lines

    # default to production values
    def __init__(self, multiproc: bool = True, log_level: int = LogLevel.WARNING,
                 logfile: str = None, log_classes: list[str] = None, syslog: bool = False,
                 context: str = Ctx.DEFAULT, testing: bool = False, silent: bool = False):
        self._stopped_procs: list[str] = []
        if multiproc:
            # Multiprocessing
            self._pool_type = ProcessPool
            ctx = mp.get_context(context)
            # Forkserver children must inherit autonomous_trust.core
            # fully loaded — otherwise the Manager server's per-client
            # threads each re-import on first unpickle, and concurrent
            # deep-chain imports race on _python.processes (intermittent
            # "ImportError: cannot import name 'ProcessTracker' from
            # partially initialized module"). Preloading hands the
            # forkserver a fully-resolved module before any fork.
            if context == Ctx.FORKSERVER:
                ctx.set_forkserver_preload(['autonomous_trust.core'])
            manager = ctx.Manager()
            # Keep the manager referenced (not just via its queue proxies) so
            # the main loop can check whether its server process is still alive
            # when a proxy connection drops — see _mq_get / _manager_alive.
            self._manager = manager
            self._queue_type = manager.Queue  # noqa
        else:
            # Threading
            self._manager = None  # no manager server in threading mode
            self._pool_type = ThreadPool
            self._queue_type = queue.Queue
        self.queue_pool: QueuePool = QueuePool(self._queue_type)

        self._log_level: int = log_level
        self.name: str = self.__class__.__name__
        if logfile is None:
            logfile = os.path.join(Configuration.get_data_dir(), 'autonomous_trust.log')
        self.classes_to_log = log_classes
        if log_classes is None:
            self.classes_to_log = list(CfgIds)
        root: logging.Logger = logging.getLogger()
        root.setLevel(logging.DEBUG)
        self._logger: logging.Logger = logging.getLogger(self.name)
        # Clear any stale handlers from prior instances (loggers are singletons)
        self._logger.handlers.clear()
        handlers = []
        if not silent:
            handlers.append(logging.StreamHandler(sys.stdout))
        if logfile == Configuration.log_stderr:
            # Explicit stderr destination, honored REGARDLESS of `silent`.
            # `silent` governs user-facing console chatter (see self.print);
            # naming a destination governs where logs go. Keeping the two
            # separate is the point of this sentinel -- without it, a caller
            # that wants a quiet console and a debug trace has no way to ask.
            handlers.append(logging.StreamHandler(sys.stderr))
        elif logfile != Configuration.log_stdout:
            os.makedirs(os.path.dirname(logfile), exist_ok=True)
            handlers.append(TimedRotatingFileHandler(logfile, when="midnight", interval=1, backupCount=5))
        if not handlers:
            # Reachable only via silent=True + logfile=log_stdout, i.e. "keep the
            # console quiet" AND "log to the console" -- a contradiction, resolved
            # by discarding. NOTE: log_level is INERT in this mode; no level makes
            # anything appear. Pass logfile=Configuration.log_stderr (or a real
            # file) if you want the logs. Many tests/a_unit/test_automate.py cases
            # rely on this staying quiet, so the discard is deliberate, not a bug.
            handlers.append(logging.NullHandler())
        for handler in handlers:
            handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATEFMT))
            handler.setLevel(log_level)
            self._logger.addHandler(handler)
        if syslog:
            syslog_handler = SysLogHandler(address='/dev/log')
            self._logger.addHandler(syslog_handler)
        super().__init__(CfgIds.main, self._logger, None)
        self.identity = None  # of type Identity (can't import)

        self.process_names: list[str] = []
        self.capabilities: Capabilities = Capabilities()
        # AT-core bootstrap corpus: register at.handshake /
        # at.time-attest / at.echo-challenge unless explicitly
        # disabled (AT_BOOTSTRAP_DISABLED=1). These are tier-0,
        # weight-1 — the baby-steps signal documented in doc/architecture/trust-tiers.md
        # §6.
        if not os.environ.get('AT_BOOTSTRAP_DISABLED'):
            register_bootstrap_capabilities(self.capabilities)
        self._output: QueueType = self.queue_type()  # subsystem logging
        # Rate-limit for IPC-drop warnings so a churn-induced connection reset
        # reconnects quietly instead of logging a traceback every tick.
        self._last_ipc_drop_log: float = 0.0
        self._subsystems: ProcessTracker = ProcessTracker()
        self._additional_workers: list[tuple[type[Process], list[str], dict[str, Any]]] = []
        # Register the BootstrapWorker alongside the bootstrap caps. It
        # rides the normal add_worker / additional_procs lifecycle (so
        # signal/quit teardown is uniform with everything else) but
        # honors AT_BOOTSTRAP_DISABLED both at registration time (here)
        # and at process-entry time (in bootstrap_worker.process), so a
        # late env change still suppresses the work.
        if not os.environ.get('AT_BOOTSTRAP_DISABLED'):
            from .bootstrap_worker import BootstrapWorker
            self._additional_workers.append((BootstrapWorker, None, {}))
        self._my_queue: QueueType = self.queue_type()
        self.testing: bool = testing
        self.silent = silent
        self.active_tasks: dict[str, Task] = {}
        self.active_pids: dict[str, int] = {}
        self.last_tick: dict[int, int] = {}
        self.tasking_start: datetime = now()
        self.latest_reputation: dict[str, Any] = {}
        # Bilateral reputation: (observer_uuid_str, subject_uuid_str) ->
        # Reputation. Populated alongside latest_reputation when a
        # rep_resp arrives. The non-pair dict above is keyed by subject
        # only and gets overwritten on every response, losing observer
        # info; consumers that want a peer-to-peer matrix (the multi-agency
        # demo's trust graph, for one) read from the pair dict.
        self.latest_reputation_pairs: dict[tuple[str, str], Any] = {}
        # Subtree member-roster enumeration (requestor-side BFS). The app
        # calls request_subtree_roster(queues, gateway) to start a walk of a
        # gateway's cohort tree; each roster_resp is merged here and, for any
        # newly-named child gateway we can route to, a follow-up roster_req is
        # sent — unrolling the recursion across message ticks WITHOUT blocking
        # a handler. `subtree_roster` maps member-uuid -> member dict; the walk
        # is complete once `_roster_pending` drains. A child gateway we cannot
        # resolve to a peer (or that never answers) leaves the roster marked
        # incomplete; a gateway that opted out (AT_ROSTER_PRIVATE) is recorded
        # in `subtree_roster_private` as an intentional boundary, NOT a failure.
        # See doc/architecture/gateway-reputation-tree.md.
        self.subtree_roster: dict[str, Any] = {}
        self.subtree_roster_complete: bool = True
        self.subtree_roster_private: list[str] = []
        self._roster_visited: set[str] = set()
        self._roster_pending: set[str] = set()
        # Operator-attended pull (ethne D8, attended-now half). The live
        # OperatorSession is created by the console app; the main loop runs in
        # a daemon thread of that same process (see the operator bridge), so
        # this is the one place in the node that can actually read it. The
        # identity subprocess asks us for the current state per pull —
        # see _answer_operator_state / operator-attended.md.
        self._operator_session = None
        # Consumer side: peer-uuid -> epoch we asked at, for pulls handed to the
        # identity process and not yet reported back. Verified answers land on
        # `peer_attestations` (peer-uuid -> attested epoch, 0 = not attended);
        # that dict is what ethne's guardian edge reads.
        self._attest_sent: dict[str, float] = {}
        self.peer_attestations: dict[str, float] = {}
        self.unhandled_messages: list[Message] = []
        self.peer_count = 0

    def print(self, string):
        if not self.silent:
            print(string)

    @property
    def queue_type(self):
        return self._queue_type

    @property
    def system_dependencies(self) -> list[str]:
        return self._subsystems.names

    def add_worker(self, process: type[Process], dependencies: list[str] = None, **kwargs) -> None:
        """
        Adds custom concurrency (Process), must be called in __init__()
        :param process: object derived from autonomous_trust.core.processes.Process
        :param dependencies: list of process names that must precede this one
        :return: None
        """
        self._additional_workers.append((process, dependencies, kwargs))

    def autonomous_ability(self, queues: dict[str, QueueType]):
        """
        Override this to register real services (Capability).
        :param queues: Interprocess communication queues to each process
        :return: None
        """
        if self.testing:
            self.capabilities.register_ability('mult', mul)
            self.capabilities.register_ability('pow', pow)
            self.capabilities.register_ability('pi', pi)

            for q_name in queues:
                if q_name != self.proc_name:
                    queues[q_name].put(self.capabilities, block=True, timeout=queue_cadence)

    def init_tasking(self, queues: dict[str, QueueType]):
        """
        Override this for pre-loop initializations
        :param queues: Interprocess communication queues to each process
        :return: None
        """
        self.tasking_start = now()
        if self.testing:
            self.peer_count = len(self.peers.all)  # noqa

    def tasking_tick(self, t_id: int, period: float = 30.0):
        mark = (now() - self.tasking_start).total_seconds() / period
        if t_id not in self.last_tick:
            self.last_tick[t_id] = 0
        if mark > self.last_tick[t_id]:
            diff = mark - self.last_tick[t_id]
            self.last_tick[t_id] = mark
            return diff
        return 0

    def autonomous_tasking(self, queues: dict[str, QueueType]):
        """
        Override this for assigning tasks
        :param queues: Interprocess communication queues to each process
        :return: None
        """
        if self.testing:
            if len(self.peers.all) > 0:
                if len(self.peers.all) > self.peer_count:
                    self.peer_count = len(self.peers.all)  # noqa
                    self._random_task(queues)
                    # check reputation for all known peers on first sighting
                    for peer in list(self.peers.all) + [self.identity]:
                        query = Message(CfgIds.reputation, ReputationProtocol.rep_req,
                                        to_json_string((peer, self.proc_name)), self.identity,
                                        from_whom=self.identity)
                        queues[CfgIds.reputation].put(query, block=True, timeout=queue_cadence)
                elif self.tasking_tick(0):
                    self._random_task(queues)
                    # check reputation for all known peers (including self)
                    for peer in list(self.peers.all) + [self.identity]:
                        query = Message(CfgIds.reputation, ReputationProtocol.rep_req,
                                        to_json_string((peer, self.proc_name)), self.identity,
                                        from_whom=self.identity)
                        queues[CfgIds.reputation].put(query, block=True, timeout=queue_cadence)
        self._report_unhandled()

    def cleanup(self):
        pass

    # --- Subtree member-roster enumeration (requestor-side BFS) --------------

    def _resolve_gateway(self, gateway_uuid):
        """Resolve a gateway node uuid to an addressable Identity via the
        requestor's own peer view (mirrors how reputation resolves peers).
        Returns the Identity, or None if this node cannot route to it — in
        which case the enumeration is marked incomplete rather than hanging."""
        key = str(gateway_uuid)
        if self.identity is not None and key == str(self.identity.uuid):
            return self.identity
        try:
            return self.peers.find_by_uuid(gateway_uuid)
        except Exception:
            return None

    def _send_roster_req(self, queues, gateway):
        """Send a roster_req to one gateway Identity and mark it pending.
        The gateway's identity process answers via handle_roster_request.

        The payload names the process the answer must come back to. Inbound
        messages are routed by ``Message.process`` alone (see
        netprocess._msg_to_queue), and the aggregation this answer feeds lives
        here in the main loop, not in the identity process — so without naming
        it the reply lands in the wrong process and the walk never completes.
        Same convention as rep_req's ``requesting_process``."""
        try:
            req = Message(CfgIds.identity, IdentityProtocol.roster_req,
                          to_json_string({'requestor': str(self.identity.uuid),
                                          'requesting_process': self.proc_name}),
                          to_whom=gateway, from_whom=self.identity)
            queues[CfgIds.network].put(req, block=True, timeout=queue_cadence)
            self._roster_pending.add(str(gateway.uuid))
            return True
        except queue.Full:
            self.logger.error('_send_roster_req: network queue full')
            self.subtree_roster_complete = False
            return False

    def request_subtree_roster(self, queues, gateway):
        """Begin enumerating a gateway's cohort tree (any depth).

        Resets the accumulator and sends the first roster_req to ``gateway``
        (an Identity, or a node-uuid resolvable via this node's peer view).
        Subsequent levels are pursued automatically as each roster_resp
        arrives (see the roster_resp branch in autonomous_loop). Read the
        result off ``subtree_roster`` / ``subtree_roster_complete`` /
        ``subtree_roster_private`` once the walk settles."""
        self.subtree_roster = {}
        self.subtree_roster_complete = True
        self.subtree_roster_private = []
        self._roster_visited = set()
        self._roster_pending = set()
        if not isinstance(gateway, str) and gateway is not None:
            target = gateway
        else:
            target = self._resolve_gateway(gateway)
        if target is None:
            self.subtree_roster_complete = False
            return
        self._roster_visited.add(str(target.uuid))
        self._send_roster_req(queues, target)

    @staticmethod
    def _reputation_entry(entry):
        """One rep_resp entry as a Reputation, or None if it is not one.

        A reply may arrive already deserialized (a `Reputation`, because the
        sender is this runtime and the payload carried its `__type__` tag) or as
        a bare mapping. The mapping case is real: a peer running the C library
        answered with plain JSON fields, and reaching for `.peer_id` on the dict
        that produced raised `AttributeError` out of the message loop — so a
        C peer's view of the cohort reached nothing, and the failure did not
        name its cause. Accepting the mapping here means one runtime's reply
        shape cannot silence the other's; C now sends the tagged form, and this
        keeps a mixed-version cohort working while it catches up.

        Both spellings of the key are read: `peer_id` is the Reputation field
        name, `peer_uuid` was the C wire name.

        The test is what an entry ANSWERS, not what class it is: anything already
        carrying a usable `peer_id` and `score` is passed through untouched. A
        stricter isinstance check would reject a stand-in that behaves like a
        Reputation for no gain — the two attributes are the entire contract the
        caller relies on.
        """
        peer_id = getattr(entry, 'peer_id', None)
        score = getattr(entry, 'score', None)
        if peer_id is not None and score is not None:
            try:
                float(score)
            except (TypeError, ValueError):
                return None     # answers the right names with the wrong value
            return entry
        if isinstance(entry, dict):
            peer_id = entry.get('peer_id', entry.get('peer_uuid'))
            score = entry.get('score')
            if peer_id is None or score is None:
                return None
            try:
                return Reputation(peer_id, float(score))
            except (TypeError, ValueError):
                return None
        # Anything else (a bare score, a string, None) is not an observation and
        # must not be guessed at.
        return None

    def _reputation_entries(self, payload, observer=None):
        """Every usable Reputation in a rep_resp payload.

        A rep_resp carries either a single Reputation (the classic rep_req /
        leaf path) or a subtree roster from a gateway, which arrives as a JSON
        array. Normalising to a list here lets the caller run its per-entry body
        once per entry; the maps it writes are keyed per-uuid, so a gateway's
        reply populates one entry for every peer in its subtree.

        Unusable entries are dropped with a warning rather than raised on. This
        loop services every message the node receives, so one malformed reply
        must not be able to stop the rest — and the warning names the sender,
        because "which peer is sending me nonsense" is the only actionable part.
        """
        if isinstance(payload, str):
            try:
                payload = from_json_string(payload)
            except Exception as err:  # noqa - malformed or foreign payload
                self.logger.warning(
                    'rep_resp from %s could not be deserialized: %s',
                    getattr(observer, 'nickname', observer), err)
                return []
        entries = payload if isinstance(payload, list) else [payload]
        usable = []
        for entry in entries:
            rep = self._reputation_entry(entry)
            if rep is None:
                self.logger.warning(
                    'rep_resp from %s carried an unusable entry (%s); ignoring '
                    'it. Expected a Reputation or a mapping with '
                    'peer_id/peer_uuid and score.',
                    getattr(observer, 'nickname', observer),
                    type(entry).__name__)
                continue
            usable.append(rep)
        return usable

    def _consume_roster_resp(self, queues, message):
        """Merge one roster_resp and pursue any newly-named child gateways —
        the per-tick unroll of the requestor-side breadth-first walk."""
        responder = getattr(message, 'from_whom', None)
        responder_uuid = getattr(responder, 'uuid', None)
        if responder_uuid is not None:
            self._roster_pending.discard(str(responder_uuid))
        payload = message.obj
        if isinstance(payload, str):
            payload = from_json_string(payload)
        if not isinstance(payload, dict):
            self.subtree_roster_complete = False
            return
        if payload.get('private'):
            # Intentional opaque boundary — do not recurse, not a failure.
            if responder_uuid is not None:
                uid = str(responder_uuid)
                if uid not in self.subtree_roster_private:
                    self.subtree_roster_private.append(uid)
            return
        for member in payload.get('members') or []:
            if isinstance(member, dict):
                key = str(member.get('uuid'))
                if key and key not in self.subtree_roster:
                    self.subtree_roster[key] = member
        for child_uuid in payload.get('child_gateways') or []:
            key = str(child_uuid)
            if key in self._roster_visited:
                continue
            self._roster_visited.add(key)
            target = self._resolve_gateway(key)
            if target is None:
                # Cannot route to this gateway — partial, not a hang.
                self.subtree_roster_complete = False
                continue
            self._send_roster_req(queues, target)

    # --- Operator-attended pull (ethne D8 guardian edge) ---------------------

    def set_operator_session(self, session):
        """Attach the live :class:`OperatorSession` so this node can answer
        attended-now pulls.

        Called by the console bridge right after it builds the node, because
        the bridge runs ``run_forever`` in a daemon thread of the app process —
        the main loop and the session share an address space. IdentityProcess
        does NOT: it runs in its own subprocess, which is exactly why the
        attended-now signal was always 0 before this. It asks us per pull
        (operator_state_query) rather than caching a mirror that could go
        stale. See doc/architecture/operator-attended.md."""
        self._operator_session = session

    def _operator_attended(self):
        """Current attended state as ``(attended, epoch, have_session)``.

        Attended is decided by :func:`operator.session.is_attended` — the one
        definition, shared with IdentityProcess so the two processes cannot
        drift apart. No session (a drone, or a node with no console attached) is
        honestly reported as have_session=False, which the puller reads as
        not-attended rather than as an error."""
        session = self._operator_session
        if session is None:
            return False, 0.0, False
        try:
            from .operator.session import is_attended  # operator pkg is optional
            return bool(is_attended(session)), time.time(), True
        except Exception:
            # Never let a session read break the loop; unknown reads as absent.
            self.logger.debug('operator session poll failed', exc_info=True)
            return False, 0.0, False

    def _answer_operator_state(self, queues, message):
        """Answer the identity subprocess's operator_state_query. Local-only
        IPC — this never touches the network queue."""
        attended, epoch, have_session = self._operator_attended()
        payload = {'attended': attended, 'epoch': epoch,
                   'have_session': have_session}
        try:
            reply = Message(CfgIds.identity,
                            IdentityProtocol.operator_state_resp,
                            to_json_string(payload),
                            from_whom=self.identity)
            queues[CfgIds.identity].put(reply, block=True,
                                        timeout=queue_cadence)
        except queue.Full:
            # The identity process ages the pull out and answers "cannot
            # confirm" — a dropped answer degrades to not-attended, never hangs.
            self.logger.error('_answer_operator_state: identity queue full')
        except Exception as err:
            self.logger.error('_answer_operator_state: %s', err)

    def request_peer_attestation(self, queues, peer):
        """Ask for a freshly-stamped operator attestation from one peer.

        Consumer-pull by design: nothing is announced on a cadence, so an idle
        network carries no attestation traffic. ``peer`` is an Identity or a node
        uuid. Read the answer off ``peer_attestations[peer_uuid]`` once it
        arrives — an epoch (a human was at that node's console when it answered)
        or 0.0 for not-attended. Returns True if the request was handed off.

        The pull itself belongs to IdentityProcess, which holds the operator
        trust anchor: an attestation is worthless until the credential in it has
        been re-verified, so the process that can verify is the process that
        asks. This is the local hand-off."""
        target = str(getattr(peer, 'uuid', peer))
        try:
            req = Message(CfgIds.identity, IdentityProtocol.attest_trigger,
                          to_json_string({'target': target}),
                          from_whom=self.identity)
            queues[CfgIds.identity].put(req, block=True, timeout=queue_cadence)
        except queue.Full:
            self.logger.error('request_peer_attestation: identity queue full')
            return False
        self._attest_sent[target] = time.time()
        return True

    def _consume_attest_resp(self, queues, message):
        """Record a peer's verified attended-now stamp for consumers to read.

        The identity process has already matched the nonce it minted and
        re-verified the operator credential; what reaches here is a verdict, so
        this only files it. An unsolicited report is still dropped: nothing
        should be able to inject an attendance claim for a peer we never asked
        about."""
        payload = message.obj
        if isinstance(payload, str):
            payload = from_json_string(payload)
        if not isinstance(payload, dict):
            return
        peer_uuid = payload.get('peer')
        if not peer_uuid:
            return
        peer_uuid = str(peer_uuid)
        if peer_uuid not in self._attest_sent:
            _probes.counter('proc.automate', 'attest_unsolicited')
            self.logger.warning('_consume_attest_resp: unsolicited report for %s', peer_uuid)
            return
        del self._attest_sent[peer_uuid]
        attested = payload.get('operator_attested_at') or 0.0
        try:
            self.peer_attestations[peer_uuid] = float(attested)
        except (TypeError, ValueError):
            self.peer_attestations[peer_uuid] = 0.0

    def autonomous_loop(self, results: dict[str, AsyncResult], queues: dict[str, QueueType],
                        signals: dict[str, QueueType]) -> None:
        """
        Override this for more control inside the main loop.
        Careful: equivalent message handling and monitoring is required.
        :param results: subprocess AsyncResults
        :param queues: Interprocess communication queues to each process
        :param signals: queues listening for a quit signal
        :return: None
        """
        self.autonomous_ability(queues)
        self.init_tasking(queues)
        with self._pool_type(max_concurrency) as pool:
            while True:
                try:
                    self._monitor_processes(results)
                    if not self._handle_messages(queues, pool, results):
                        break
                    self._handle_results(queues, results)
                    self.autonomous_tasking(queues)
                    time.sleep(Process.cadence)
                except KeyboardInterrupt:
                    for sig in signals.values():
                        sig.put_nowait(Process.sig_quit)
                    break
                except Exception as err:
                    self.logger.error('%s:  %s', self.name, ''.join(traceback.TracebackException.from_exception(err).format()))
        self.cleanup()

    def run_forever(self, q_in: QueueType = None, q_out: QueueType = None):
        """
        Start the autonomous machinery as the lead process
        :return: None
        """
        os.makedirs(Configuration.get_data_dir(), exist_ok=True)
        # Clock gate, before anything timestamps or votes. AT carries no NTP
        # client of its own: a stock daemon on the HOST disciplines the clock
        # and this reads only what it achieved. Enforcing inside AT container
        # images (they set AT_REQUIRE_SYNCED_CLOCK=1), advisory elsewhere so a
        # developer machine still runs. Mirrors the C gate in at_node_init.
        require_synced_clock(self.logger)
        configs = self._configure()
        procs: list[Process] = configs[Process.key]
        if self._log_level <= LogLevel.WARNING:
            self._banner()
        self.logger.info('%s:  Package signature %s', self.name, configs[PackageHash.key])
        self.logger.info("%s:  Configuring '%s' at %s for %s", self.name, self.identity.nickname, self.identity.address, '(unknown domain)')
        self.logger.info('%s:  Signature: %s', self.name, self.identity.signature.publish())
        self.logger.info('%s:  Public key: %s', self.name, self.identity.encryptor.publish())

        if procs is None:
            return
        queues = dict(zip(list(map(lambda x: x.name, procs)),
                          [self.queue_type() for _ in range(len(procs))]))
        queues[self.proc_name] = self._my_queue
        signals: dict[str, QueueType] = {}
        results: dict[str, AsyncResult] = {}
        # Separate system processes from additional workers so system starts first
        system_names = set(self._subsystems.names)
        system_procs = [p for p in procs if p.name in system_names]
        additional_procs = [p for p in procs if p.name not in system_names]

        with self._pool_type(len(procs)) as pool:
            for proc in system_procs:
                self.logger.info('%s:  Starting system %s ...', self.name, proc.name)
                self.process_names.append(proc.name)
                signals[proc.name] = self.queue_type()
                results[proc.name] = pool.apply_async(proc.process, (queues, signals[proc.name]))
            for proc in additional_procs:
                self.logger.info('%s:  Starting worker %s ...', self.name, proc.name)
                self.process_names.append(proc.name)
                signals[proc.name] = self.queue_type()
                results[proc.name] = pool.apply_async(proc.process, (queues, signals[proc.name]))
            if q_in is not None:
                queues[self.external_control] = q_in  # main loop must watch/process
            if q_out is not None:
                queues[self.external_feedback] = q_out  # main loop must upload to this

            # Graceful SIGTERM shutdown — pods/services hit this on
            # `kubectl delete`, `docker stop`, Tilt teardown, etc. Without
            # the handler, subprocess loops exit via os._exit and skip
            # their final-flush hooks (repprocess._persist_reputations,
            # idprocess._record_peers/group on shutdown). Propagating
            # sig_quit through the existing signal queues lets each
            # subprocess exit its `while self.keep_running(signal)` loop
            # cleanly and run its tail-of-loop persistence.
            def _graceful_shutdown(signum, _frame):
                try:
                    self.logger.info('%s:  SIGTERM received, propagating quit to subprocesses', self.name)
                except Exception:
                    pass
                for sig in signals.values():
                    try:
                        sig.put_nowait(Process.sig_quit)
                    except Exception:
                        pass
            try:
                signal.signal(signal.SIGTERM, _graceful_shutdown)
            except (ValueError, OSError):
                # Non-main-thread invocation (some test harnesses) —
                # signal.signal raises ValueError; harmless to skip.
                pass

            pool.close()  # no more system tasks (use separate pool for dynamic tasks)
            # Wait briefly for system processes to initialize before declaring ready
            _ready_wait = 0.0
            while _ready_wait < Process.cadence * 3:
                if all(not r.ready() for r in results.values()):
                    break  # all still running means they started successfully
                time.sleep(Process.cadence)
                _ready_wait += Process.cadence
            self.logger.info('%s:                                          Ready.', self.name)

            self.autonomous_loop(results, queues, signals)

        self.logger.info('%s:  Shutdown', self.name)

    ####################
    # Protected methods

    def _banner(self):
        self.print("")
        self.print("You are using\033[94m AutonomousTrust\033[00m v%s" % version)
        self.print("")

    def _configure(self, start: bool = True):
        # Pull initial state from configuration files
        required = [CfgIds.network, CfgIds.identity, CfgIds.peers, CfgIds.capabilities]
        defaultable = {CfgIds.peers: Peers, CfgIds.capabilities: PeerCapabilities, }

        configs: ConfigMap = {}
        cfg_dir = Configuration.get_cfg_dir()
        self._subsystems.from_file(cfg_dir)

        # find missing configs, set defaults
        config_files = os.listdir(cfg_dir)
        cfg_types = list(map(get_cfg_type, config_files))
        for cfg_name in required:
            if cfg_name not in cfg_types:
                if cfg_name in defaultable:
                    defaultable[cfg_name]().to_file(os.path.join(cfg_dir, cfg_name + Configuration.file_ext))
                else:
                    self.logger.error('%s:  Required %s configuration missing', self.name, cfg_name)
                    return None

        # load configs
        configs = load_configs()

        package_hash = PackageHash()
        configs[PackageHash.key] = package_hash.digest
        configs[Process.level] = self._log_level

        net_cfg = configs[CfgIds.network]
        # A config directory can outlive the address it recorded -- a container
        # restarted onto a different subnet keeps its var/at but not its IP --
        # and an address we no longer hold is one we cannot bind. The stored
        # address stays authoritative while it is still present on this host.
        try:
            if net_cfg.refresh():
                net_cfg.to_file(os.path.join(cfg_dir, CfgIds.network + Configuration.file_ext))
        except OSError as err:
            self.logger.warning('%s:  Could not re-derive the network address: %s', self.name, err)
        self.identity = configs[CfgIds.identity]
        self.identity.address = net_cfg.ip4
        if preferred_proto_ver == 6:
            self.identity.address = net_cfg.ip6
        self.peers = configs[CfgIds.peers]

        if start:
            # init configured process classes
            sub_sys_list = self._subsystems.ordered
            for sub_sys_cls in sub_sys_list:
                suppress = True
                if sub_sys_cls.cfg_name in self.classes_to_log:
                    suppress = False
                configs[Process.key].append(sub_sys_cls(configs, self._subsystems, self._output, suppress_log=suppress))
            # Note: only instantiates workers here; run_forever() starts system
            # procs before additional workers (see system_procs/additional_procs split).
            for worker_cls, deps, kwargs in self._additional_workers:
                configs[Process.key].append(worker_cls(configs, self._subsystems, self._output, deps, **kwargs))
        return configs

    @staticmethod
    def _reset_proxy_connection(proxy) -> None:
        """Drop a manager proxy's wedged thread-local connection so the next
        call on it opens a fresh one. Recovers a proxy whose remote end was
        closed (e.g. when a peer/subprocess churns) without tearing down the
        loop. No-op for plain threading-mode queues (no ``_tls``)."""
        tls = getattr(proxy, '_tls', None)
        if tls is None:
            return
        conn = getattr(tls, 'connection', None)
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001 - best-effort teardown
                pass
            try:
                del tls.connection
            except AttributeError:
                pass

    def _manager_alive(self) -> bool:
        """Whether the multiprocessing manager server process is still up.
        True in threading mode (no manager) so callers treat drops as
        recoverable there."""
        mgr = getattr(self, '_manager', None)
        proc = getattr(mgr, '_process', None) if mgr is not None else None
        return proc is None or proc.is_alive()

    def _mq_get(self, proxy, block: bool = False, timeout: float = None):
        """``queue.get`` on a manager-proxied queue that survives a dropped
        connection. On a transport error it resets the proxy (so the next
        tick reconnects) and reports the queue as empty — returning the main
        loop to a receptive state instead of spinning on a dead connection.
        Whether the manager server itself is still alive is surfaced at most
        once per _IPC_DROP_LOG_INTERVAL rather than as a per-tick traceback."""
        try:
            if block:
                return proxy.get(block=True, timeout=timeout)
            return proxy.get_nowait()
        except queue.Empty:
            raise
        except self._MGR_CONN_ERRORS as ex:
            self._reset_proxy_connection(proxy)
            alive = self._manager_alive()
            now = time.monotonic()
            if now - self._last_ipc_drop_log >= self._IPC_DROP_LOG_INTERVAL:
                self._last_ipc_drop_log = now
                if alive:
                    self.logger.warning(
                        '%s: IPC queue connection dropped (%s); reconnecting', self.name, type(ex).__name__)
                else:
                    self.logger.error(
                        '%s: manager server process is down; IPC lost, '
                        'awaiting restart', self.name)
            raise queue.Empty from ex

    def _monitor_processes(self, proc_results: dict[str, AsyncResult], show_output: bool = True):
        """
        Should be included in any main-loop override function
        :param proc_results: dict of process names to multiprocessing.pool.AsyncResults
        :return: whether to keep going or not
        """
        # record subprocess exceptions
        for name, result in proc_results.items():
            if name in self._stopped_procs:
                continue
            if result.ready():
                try:
                    self.logger.debug('Check process %s', name)
                    result.get(0)
                except mp.TimeoutError:
                    pass
                except KeyboardInterrupt:
                    pass
                except Exception as ex:
                    self.logger.error('%s:  %s', self.name, ''.join(traceback.TracebackException.from_exception(ex).format()))
                    self._stopped_procs.append(name)

        if show_output:
            # drain subprocess outputs, if any. _mq_get treats a dropped
            # manager connection as empty (after resetting it to reconnect
            # next tick), so a peer/subprocess churn no longer spins here.
            while True:
                try:
                    level, name, msg = self._mq_get(self._output)
                    self.logger.log(level, '%s: %s' % (name, msg))
                except queue.Empty:
                    break
        return True

    def _failed_task_cb(self, task: Task):
        def report_error(err: Exception):
            self.logger.error('Task %s failed: %s', task.capability.name, '\n'.join(traceback.format_exception(type(err), err)))

        return report_error

    def _handle_messages(self, queues: dict[str, QueueType], pool: PoolType, results: dict[str, AsyncResult]):
        if self.external_control in queues:
            try:
                cmd = self._mq_get(queues[self.external_control])
                if isinstance(cmd, Task):
                    message = Message(CfgIds.negotiation, NegotiationProtocol.start, cmd)
                    queues[CfgIds.negotiation].put(message, block=True, timeout=queue_cadence)
                elif cmd == ReputationProtocol.app_roster_request:
                    # The app asked for the current peer view
                    # (doc/architecture/app-peer-carrier.md). Exactly ONE verb is
                    # accepted from an app and forwarded to a fixed destination, as the
                    # C daemon does: forwarding an app-supplied message to whatever
                    # process it names would hand an app AT's whole internal verb
                    # surface. This pull is also
                    # the only path on which `rated=False` can cross.
                    query = Message(CfgIds.reputation,
                                    ReputationProtocol.app_roster_request, '',
                                    to_whom=None, from_whom=self.identity)
                    queues[CfgIds.reputation].put(query, block=True,
                                                  timeout=queue_cadence)
                elif cmd == Process.sig_quit:
                    self.logger.debug('%s: External signal to quit', self.name)
                    return False
            except queue.Empty:
                pass
            except queue.Full:
                self.logger.error('%s: Negotiation queue full', self.name)

        message = None
        try:
            message = self._mq_get(queues[self.proc_name], block=True, timeout=queue_cadence)
        except queue.Empty:
            pass

        if message is not None:
            if not self.run_message_handlers(queues, message):
                if isinstance(message, TaskStatus):
                    if message.uuid in self.active_pids:
                        pid = self.active_pids[message.uuid]
                        message.status = Status.from_ps(psutil.Process(pid).status())
                    else:
                        message.status = Status.unknown
                    queues[CfgIds.negotiation].put(message, block=True, timeout=queue_cadence)
                    self.logger.debug('Handled status: %s', message.status)
                elif isinstance(message, TaskResult):
                    task = message
                    self.logger.debug('%s: Task result recvd: %s', self.name, task.result)
                    # Requestor-side score for a returned TaskResult. verify_proof()
                    # is tri-state: True (proof verified), False (proof present but
                    # INVALID -> genuine tamper signal), or None (indeterminate: no
                    # proof attached, or ZKP unavailable in this process).
                    #
                    # None must NOT be scored as a defection. Split by cause:
                    #   * ZKP unavailable process-wide -> proofs cannot attest
                    #     anything, so score on the fact the task completed with a
                    #     result; missing infrastructure is not the peer's fault.
                    #   * ZKP available but proof absent -> suspicious; score as a
                    #     defection, like an invalid proof.
                    # Previously `0.8 if zkp_valid else 0.3` collapsed None into the
                    # defection bucket, so with the ZKP extension unshipped every
                    # requestor scored 0.3 and honest reputation cratered.
                    zkp_valid = task.verify_proof()
                    if zkp_valid is True:
                        score = 0.8
                    elif zkp_valid is False:
                        self.logger.warning(
                            '%s: ZKP verification FAILED for task %s', self.name, task.uuid)
                        score = 0.3
                    elif ZKP_AVAILABLE:
                        # Proof missing despite ZKP being available -> suspicious.
                        self.logger.warning(
                            '%s: task %s result carried no ZKP proof despite ZKP being available', self.name, task.uuid)
                        score = 0.3
                    else:
                        # ZKP unavailable: score on successful completion.
                        score = 0.8 if task.result is not None else 0.3
                    tx = TransactionScore(task.uuid, score)
                    queues[CfgIds.reputation].put(tx, block=True, timeout=queue_cadence)
                    if self.external_feedback in queues:
                        queues[self.external_feedback].put(task, block=True, timeout=queue_cadence)
                elif isinstance(message, PeerReputation):
                    # AT -> app: the outward hop the reputation process cannot
                    # make itself, mirroring the C daemon's forward off
                    # AT_MAIN_QUEUE. `rated` rides along; see PeerReputation.
                    if self.external_feedback in queues:
                        try:
                            queues[self.external_feedback].put(
                                message, block=True, timeout=queue_cadence)
                        except queue.Full:
                            self.logger.error(
                                '%s: external feedback queue full', self.name)
                elif isinstance(message, Task):
                    task = message
                    if task.capability in self.capabilities:
                        capability = self.capabilities[task.capability.name]
                        pq = self.queue_type()
                        self.logger.debug('%s: Running task', self.name)
                        self.active_tasks[str(task.uuid)] = task
                        results[task.uuid] = pool.apply_async(capability.execute, (task, pq))
                        try:
                            pid = pq.get(block=True, timeout=1)
                            self.active_pids[str(task.uuid)] = pid
                        except queue.Empty:
                            self.logger.error(
                                '%s: Process failed to start for task %s (capability=%s, task_uuid=%s). '
                                'No PID received within timeout.', self.name, task.capability.name, capability.name, task.uuid)
                elif isinstance(message, Message) and message.function == ReputationProtocol.rep_resp:
                    # A rep_resp carries either a single Reputation (the
                    # classic rep_req / leaf path) or a subtree roster
                    # from a gateway. A roster arrives as a JSON array
                    # string (a multi-element list); a bare Reputation
                    # arrives as an object. Normalise to a list and run
                    # the per-Reputation body once per entry — the maps
                    # below are keyed per-uuid, so a gateway's reply
                    # populates one entry for every peer in its subtree.
                    observer = getattr(message, "from_whom", None)
                    observer_uuid = getattr(observer, "uuid", None)
                    reps = self._reputation_entries(message.obj, observer)
                    for rep in reps:
                        if rep.peer_id == self.identity.uuid:
                            self.print('My current reputation score:\033[32m %s\033[00m' % rep.score)
                        else:
                            peer = self.peers.find_by_uuid(rep.peer_id)
                            if peer:
                                self.print("%s's current reputation score:\033[32m %s\033[00m" % (peer.nickname, rep.score))
                        # latest_reputation is THIS node's OWN view of each
                        # peer (fed to the reputations panel + Trust Dynamics
                        # timeline; see the "My/X's current reputation score"
                        # prints above). Only our own computation belongs here:
                        # a transitive peer-pair rep_req answered by a REMOTE
                        # observer (from_whom != us) is that observer's bilateral
                        # CTFT reading — cold-start PREREP_NEUTRAL (0.0) for a
                        # pair with no shared history, e.g. a consumer-only peer
                        # nobody transacts with. Writing those here overwrote the
                        # consensus value and dragged the timeline to 0; they are
                        # captured below for the Trust Network graph only.
                        own_view = (observer_uuid is None
                                    or str(observer_uuid) == str(self.identity.uuid))
                        if own_view:
                            self.latest_reputation[str(rep.peer_id)] = rep
                        # Bilateral capture: track WHO computed this score.
                        if observer_uuid is not None:
                            key = (str(observer_uuid), str(rep.peer_id))
                            self.latest_reputation_pairs[key] = rep
                elif isinstance(message, Message) and message.function == IdentityProtocol.roster_resp:
                    # One level of the requestor-side subtree-roster walk:
                    # merge this gateway's members and fan out roster_req to
                    # any child gateways it named (see _consume_roster_resp).
                    self._consume_roster_resp(queues, message)
                elif (isinstance(message, Message)
                      and message.function == IdentityProtocol.operator_state_req):
                    # Local-only IPC: the identity subprocess cannot see the
                    # console's OperatorSession, but this loop shares its
                    # address space. Answer with the current attended state.
                    self._answer_operator_state(queues, message)
                elif (isinstance(message, Message)
                      and message.function == IdentityProtocol.attest_resp):
                    # A peer answered one of our attended-now pulls.
                    self._consume_attest_resp(queues, message)
                else:
                    self.unhandled_messages.append(message)
        return True

    def _report_unhandled(self):
        while len(self.unhandled_messages) > 0:
            message = self.unhandled_messages.pop()
            if isinstance(message, Message):
                _probes.counter('proc.automate', 'unhandled', message.function)
                _probes.trace_msg(message, 'unhandled', proc='automate')
                self.logger.error('%s: Unhandled message %s', self.name, message.function)
            else:
                _probes.counter('proc.automate', 'unhandled', 'type:' + message.__class__.__name__)
                self.logger.error('%s: Unhandled message of type %s', self.name, message.__class__.__name__)  # noqa

    def _handle_results(self, queues: dict[str, QueueType], results: dict[str, AsyncResult]):
        for key in list(results.keys()):
            if results[key].ready():
                if key in list(self.process_names):
                    # A long-running process is not supposed to return at all,
                    # so this stays an error -- but report it ONCE. The entry
                    # remains ready() forever, so continuing without dropping
                    # it re-logged the same line on every main-loop pass
                    # (Process.cadence, 2 Hz) for the rest of the run.
                    # _monitor_processes runs earlier in the same iteration, so
                    # any exception traceback is already on the record; a clean
                    # return leaves no traceback and only this line.
                    self.logger.error('unexpected termination of process %s', key)
                    if key not in self._stopped_procs:
                        self._stopped_procs.append(key)
                    del results[key]
                    continue
                try:
                    self.logger.debug('%s: %s Task', self.name, key)
                    result = results[key].get()
                    self.logger.debug('%s: %s Task completed %s', self.name, key, result)
                    orig_task = self.active_tasks[str(key)]
                    tr = TaskResult(orig_task, result)
                    tr.generate_proof()
                    queues[CfgIds.negotiation].put(tr, block=True, timeout=queue_cadence)
                    # Tag the TS with the capability that produced it so the
                    # reputation process's _resolve_tx_weight applies the
                    # capability's configured transaction_weight. The executor
                    # holds the original Task (active_tasks), so the name comes
                    # "for free" off the negotiation-driven path — this is the
                    # principled producer the DoD coordinator stop-gap hand-tags
                    # by hand (see doc/NV059/work/deferred.md §1.2). A None name
                    # falls back to weight 1, the prior behavior.
                    cap_name = getattr(
                        getattr(orig_task, 'capability', None), 'name', None)
                    tx = TransactionScore(tr.uuid, 0.9, capability_name=cap_name)
                    queues[CfgIds.reputation].put(tx, block=True, timeout=queue_cadence)
                except KeyboardInterrupt:
                    pass
                except Exception:
                    self.logger.error('Task Exception - %s', traceback.format_exc())
                    try:
                        error_result = TaskResult(self.active_tasks[str(key)], None)
                        queues[CfgIds.negotiation].put(error_result, block=True, timeout=queue_cadence)
                    except Exception:
                        self.logger.error('Failed to report task error: %s', traceback.format_exc())
                del results[key]

    def _random_task(self, queues: dict[str, QueueType]):
        # Bootstrap capabilities (at.handshake / at.time-attest /
        # at.echo-challenge) are exercised exclusively by BootstrapWorker
        # via _build_task_args, which knows their per-cap kwarg shape.
        # _random_task only knows about the legacy `pi`/`pow` corpus
        # and defaults everything else to two positional ints — which
        # collides with at_handshake(nonce: int = 0). Filter the
        # bootstrap names out of the random-pick pool.
        cap_list = [n for n in self.capabilities.to_list()
                    if n not in BOOTSTRAP_CAPABILITY_NAMES]
        if not cap_list:
            return
        cap = Capability(cap_list[random.randint(0, len(cap_list) - 1)])
        args = (random.randint(2, 1000000), random.randint(2, 1000000))
        if cap.name == 'pi':
            args = (random.randint(1000, 10000),)
        elif cap.name == 'pow':
            args = (random.randint(2, 100), random.randint(2, 20))
        try:
            task = Task(TaskParameters(cap, args=args), self.identity)
            msg = Message(CfgIds.negotiation, NegotiationProtocol.start, task)
            queues[CfgIds.negotiation].put(msg, block=True, timeout=queue_cadence)
            self.logger.debug('%s: Send task to %d peers', self.name, len(self.peers.all))
        except queue.Full:
            self.logger.error('%s: Test task: negotiation queue full', self.name)
