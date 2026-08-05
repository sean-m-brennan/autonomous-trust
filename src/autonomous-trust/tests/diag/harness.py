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
"""
Minimal in-process AT harness — spawn N peers as subprocesses on
loopback aliases, watch their persisted state, drive convergence
tests without Docker.

Stage 3 of the debug-tooling subproject (see
`memory/project_debug_tooling_plan.md`). The intent is *regression*
coverage: any future change that breaks bootstrap/convergence/
unhandled-cascade fails here without needing a docker compose run.

Topology
--------
Peers can be separated on either of two axes (`separate_by`):

- `'address'` (default, the original topology): each peer binds
  `127.0.0.{base+i}` on the same `comm_port` (its `group_port` is
  `comm_port + 1`).
- `'port'`: every peer binds ONE address and gets its own base port via
  `AT_COMM_PORT`, `port_stride` apart. This is the axis `AT_COMM_PORT`
  exists for, and the only one that also separates the derived ports, so
  anything still binding a wildcard address (see ISSUES.md on ping.py's
  receive bind) stops contending. Convergence helpers that identify peers
  by address refuse to run in this mode rather than pass vacuously.

UDP broadcast goes to `127.255.255.255` (the /8 broadcast). Linux loopback
supports SO_REUSEADDR + broadcast on all of 127/8 by default; macOS does
not, hence `pytest.mark.skipif` on the smoke test.

Each peer has its own `etc/at` config dir under the harness tmp root
so identity/peer/group state is fully isolated. The harness reads
the persisted `peers.cfg.json` files from outside to track
convergence (no IPC needed — AT already saves on every accept).
"""
from __future__ import annotations

import json
import multiprocessing as mp
import os
import shutil
import socket
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


# ---------------------------------------------------------------------------
# Per-subprocess entry point — runs inside each peer
# ---------------------------------------------------------------------------

def _peer_main(peer_idx: int, addr: str, cfg_dir: str,
               transport: str, runtime_sec: float,
               log_level_name: str, ready_q,
               probes_dir: Optional[str], comm_port: Optional[int] = None):
    """Forkserver target. Top-level so it pickles cleanly."""
    # Configure environment BEFORE importing autonomous_trust.core, so
    # transport selection + config dir are visible at import time.
    os.environ['AT_TRANSPORT'] = transport
    os.environ['AT_PEER_NAME'] = f'peer-{peer_idx}'
    # Separation by port, as an alternative to separation by address. Must be
    # set before core import: system.comm_port and the ports derived from it
    # are resolved at import time.
    if comm_port is not None:
        os.environ['AT_COMM_PORT'] = str(comm_port)
    if probes_dir:
        os.environ['AT_PROBES'] = '1'
        os.environ['AT_PROBES_DIR'] = probes_dir
    from autonomous_trust.core.config import Configuration
    os.environ[Configuration.ROOT_VARIABLE_NAME] = cfg_dir

    # Patch Network.get_addresses BEFORE generate_identity runs — its
    # default implementation queries the host's primary device, which
    # would give every harness peer the same IP. The harness assigns
    # each peer a distinct loopback alias (127.0.0.{base+i}); pin
    # Network.get_addresses to return that.
    from autonomous_trust.core.network.network import Network
    fixed_addrs = {
        'ip4': addr,
        'ip6': '::1',
        'mac': '00:00:00:00:00:%02x' % peer_idx,
        'ip4_subnet': '255.0.0.0',
        'ip6_subnet': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
        'mac_bcast': 'ff:ff:ff:ff:ff:ff',
    }
    Network.get_addresses = classmethod(lambda cls: fixed_addrs)

    # Generate per-peer identity in this peer's cfg dir. Use peer_idx
    # as the seed so the identity is deterministic per-peer.
    from autonomous_trust.core.config.generate import random_config
    random_config(cfg_dir, ident=str(peer_idx))

    # Smoke signal: tell the harness this peer reached AT bootstrap.
    try:
        ready_q.put(('ready', peer_idx, addr), block=True, timeout=2)
    except Exception:
        pass

    # Run AT for the requested wall-clock window. Importing here (after
    # env+patches) avoids stale bindings.
    from autonomous_trust.core import AutonomousTrust, Process
    from autonomous_trust.core.processes import LogLevel
    log_level = getattr(LogLevel, log_level_name.upper(), LogLevel.WARNING)

    class _BoundedTrust(AutonomousTrust):
        """Run for `runtime_sec` then signal-quit. Mirrors the existing
        `tests/conftest.QuickTrust` pattern but we can't import it here
        without dragging in pytest's collection state."""

        def autonomous_loop(self, results, queues, signals):
            from datetime import datetime, timedelta, UTC
            self.autonomous_ability(queues)
            self.init_tasking(queues)
            end = datetime.now(UTC) + timedelta(seconds=runtime_sec)
            while datetime.now(UTC) < end:
                self._monitor_processes(results)
                if not self._handle_messages(queues, None, results):
                    break
                self._handle_results(queues, results)
                self.autonomous_tasking(queues)
                time.sleep(Process.cadence)
            for sig in signals.values():
                try:
                    sig.put_nowait(Process.sig_quit)
                except Exception:
                    pass

    try:
        _BoundedTrust(multiproc=True, log_level=log_level,
                      logfile=Configuration.log_stdout,
                      testing=True, silent=True).run_forever()
    except Exception as err:  # pragma: no cover — diagnostic only
        try:
            ready_q.put(('error', peer_idx, repr(err)),
                        block=True, timeout=2)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Harness facade
# ---------------------------------------------------------------------------

@dataclass
class PeerHandle:
    idx: int
    addr: str
    cfg_dir: str
    process: Optional[mp.Process] = None
    error: Optional[str] = None
    comm_port: Optional[int] = None  # None => the default base for every peer


@dataclass
class MultiPeerHarness:
    """Spawn N peers, watch their convergence, tear them down.

    Usage:
        with MultiPeerHarness(n_peers=2, runtime_sec=45) as h:
            assert h.wait_until_all_peers_grouped(timeout=40)
    """
    n_peers: int
    runtime_sec: float = 45.0
    base_octet: int = 2  # peers bind to 127.0.0.{base..base+N-1}
    transport: str = 'autonomous_trust.core.network.TCPNetworkProcess'
    log_level: str = 'warning'
    capture_probes: bool = False
    tmp_root: Optional[str] = None
    peers: list[PeerHandle] = field(default_factory=list)
    # Separation axis. 'address' is the original behaviour: every peer on the
    # shared default comm_port, distinguished by loopback alias. 'port' puts
    # every peer on ONE address and separates them by base port instead, which
    # is what AT_COMM_PORT exists for and the only axis that also separates the
    # derived ports (group, and Python's ping/ntp). Separating by address alone
    # leaves anything that binds a wildcard address contending — see ISSUES.md
    # on ping.py's receive bind.
    separate_by: str = 'address'
    port_stride: int = 100   # gap between peers' bases; > 1 leaves room for +1

    def __post_init__(self):
        if self.tmp_root is None:
            self.tmp_root = tempfile.mkdtemp(prefix='at_harness_')
        os.makedirs(self.tmp_root, exist_ok=True)

    def endpoint_for(self, i: int) -> tuple[str, Optional[int]]:
        """The (address, comm_port) peer `i` should bind.

        In 'address' mode the port is None, meaning "whatever the peer resolves
        by default" — the original topology. In 'port' mode every peer shares
        one loopback address and gets its own base.
        """
        if self.separate_by == 'port':
            from autonomous_trust.core._python.system import default_comm_port
            return (f'127.0.0.{self.base_octet}',
                    default_comm_port + (i + 1) * self.port_stride)
        if self.separate_by != 'address':
            raise ValueError(f'separate_by must be address or port, '
                             f'not {self.separate_by!r}')
        return f'127.0.0.{self.base_octet + i}', None

    # Required for `with` use
    def __enter__(self) -> 'MultiPeerHarness':
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()
        return False

    @property
    def probes_dir(self) -> Optional[str]:
        if not self.capture_probes:
            return None
        path = os.path.join(self.tmp_root, 'probes')
        os.makedirs(path, exist_ok=True)
        return path

    def start(self) -> None:
        ctx = mp.get_context('forkserver')
        try:
            ctx.set_forkserver_preload(['autonomous_trust.core'])
        except Exception:
            pass
        manager = ctx.Manager()
        self._manager = manager
        self._ready_q = manager.Queue()

        for i in range(self.n_peers):
            addr, port = self.endpoint_for(i)
            cfg_dir = os.path.join(self.tmp_root, f'peer_{i}', 'etc', 'at')
            os.makedirs(cfg_dir, exist_ok=True)
            handle = PeerHandle(idx=i, addr=addr, cfg_dir=cfg_dir,
                                comm_port=port)
            proc = ctx.Process(
                target=_peer_main,
                args=(i, addr, cfg_dir, self.transport, self.runtime_sec,
                      self.log_level, self._ready_q, self.probes_dir, port),
                daemon=False)
            proc.start()
            handle.process = proc
            self.peers.append(handle)

        # Wait for ready signals so we know each peer made it past
        # config generation. Bail out early on subprocess crashes.
        deadline = time.time() + 30
        seen_ready: set[int] = set()
        while len(seen_ready) < self.n_peers and time.time() < deadline:
            try:
                tag, idx, payload = self._ready_q.get(timeout=0.5)
            except Exception:
                continue
            if tag == 'ready':
                seen_ready.add(idx)
            elif tag == 'error':
                self.peers[idx].error = payload

    def stop(self, kill_timeout: float = 5.0) -> None:
        # Subprocesses self-quit after `runtime_sec`; if they hang past
        # that, terminate. Don't rmtree the tmp_root automatically — a
        # failing test wants the configs and probes preserved for
        # post-mortem; the caller can drop tmp_root() if desired.
        for h in self.peers:
            if h.process and h.process.is_alive():
                # Give the bounded loop a chance to exit on its own.
                h.process.join(timeout=kill_timeout)
                if h.process.is_alive():
                    h.process.terminate()
                    h.process.join(timeout=2)

    def drop_tmp_root(self) -> None:
        if self.tmp_root and os.path.isdir(self.tmp_root):
            shutil.rmtree(self.tmp_root, ignore_errors=True)

    # --- invariants / pollers --------------------------------------------

    def peers_known_by(self, peer_idx: int) -> list[str]:
        """Read the per-peer persisted Peers config; returns the list
        of *other* peer addresses currently in this peer's view. Empty
        list if the file isn't written yet."""
        cfg_dir = self.peers[peer_idx].cfg_dir
        peers_file = os.path.join(cfg_dir, 'peers.cfg.json')
        if not os.path.exists(peers_file):
            return []
        try:
            with open(peers_file, 'r') as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return []
        # Peers serializes as a Configuration with `__type__` and a
        # `_peers` (or similar) member; we don't decode the full object
        # — just count addresses by walking the JSON tree.
        return _addresses_from_peers_blob(data)

    def all_peers_grouped(self) -> bool:
        """Every peer sees every other peer in its persisted Peers."""
        if self.separate_by == 'port':
            # Refuse rather than mislead: this check identifies peers by
            # address, and in port mode every peer shares one. The expected set
            # would collapse to the peer's own address and the assertion would
            # pass vacuously. Convergence coverage needs address separation (or
            # a peer identifier that is not the address); port mode exists for
            # the bind/co-location question.
            raise NotImplementedError(
                'all_peers_grouped() identifies peers by address and cannot '
                'work in separate_by="port" mode; use separate_by="address" '
                'for convergence assertions')
        for i in range(self.n_peers):
            seen = set(self.peers_known_by(i))
            expected = {p.addr for p in self.peers if p.idx != i}
            if not expected.issubset(seen):
                return False
        return True

    def wait_until_all_peers_grouped(self, timeout: float = 60.0,
                                     poll: float = 1.0) -> bool:
        """Poll every `poll`s until convergence or timeout. Returns
        True if converged, False if timeout."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.all_peers_grouped():
                return True
            time.sleep(poll)
        return False

    def wait_until(self, predicate: Callable[['MultiPeerHarness'], bool],
                   timeout: float = 60.0, poll: float = 1.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate(self):
                return True
            time.sleep(poll)
        return False

    # --- probe inspection ------------------------------------------------

    def read_probes(self) -> list[dict]:
        """Read every JSONL line written by the AT_PROBES writer across
        all peer subprocesses. Empty if `capture_probes` was False or
        no events landed (typical of very-short runs)."""
        if not self.probes_dir or not os.path.isdir(self.probes_dir):
            return []
        events: list[dict] = []
        for entry in sorted(os.listdir(self.probes_dir)):
            if not entry.endswith('.jsonl'):
                continue
            try:
                with open(os.path.join(self.probes_dir, entry), 'r') as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            except OSError:
                continue
        return events

    def counter_total(self, layer: str, event: Optional[str] = None,
                      reason: Optional[str] = None) -> int:
        """Sum a (layer, event, reason) counter across all peers. The
        writer emits 'counters'/'snapshot' events with `items=[...]`;
        each item carries layer/event/reason/count. The bag aggregates
        in 5s windows by default, so a short run may not capture
        anything — use `wait_until_all_peers_grouped` first to ensure
        the run lasted long enough."""
        total = 0
        for ev in self.read_probes():
            if ev.get('layer') != 'counters' or ev.get('event') != 'snapshot':
                continue
            for item in ev.get('items', []):
                if item.get('layer') != layer:
                    continue
                if event is not None and item.get('event') != event:
                    continue
                if reason is not None and item.get('reason') != reason:
                    continue
                total += int(item.get('count') or 0)
        return total

    def drain_bursts(self, layer: str, min_drained: int = 2) -> int:
        """Sum, across all peers, the number of `iter_drained` counter
        snapshots whose reason (the drain count, stringified) was at
        least `min_drained`. Used to assert the drain-loop pattern is
        actually doing real burst draining, not 1-msg-per-iter pacing.
        Returns total burst count across all snapshots."""
        total = 0
        for ev in self.read_probes():
            if ev.get('layer') != 'counters' or ev.get('event') != 'snapshot':
                continue
            for item in ev.get('items', []):
                if item.get('layer') != layer:
                    continue
                if item.get('event') != 'iter_drained':
                    continue
                try:
                    drained = int(item.get('reason') or 0)
                except (TypeError, ValueError):
                    continue
                if drained >= min_drained:
                    total += int(item.get('count') or 0)
        return total

    def assert_no_unhandled_cascade(self, max_count: int = 5) -> None:
        """An 'unhandled' counter fires when a process gets a message
        type its registered handlers don't claim. A handful per run is
        normal (timing windows during bootstrap); a cascade indicates
        a regression in the dispatch table or the message protocol.
        Raises AssertionError on cascade."""
        offenders: dict[str, int] = {}
        for ev in self.read_probes():
            if ev.get('layer') != 'counters' or ev.get('event') != 'snapshot':
                continue
            for item in ev.get('items', []):
                lyr = str(item.get('layer') or '')
                if not lyr.startswith('unhandled'):
                    continue
                key = '%s/%s/%s' % (lyr, item.get('event') or '',
                                    item.get('reason') or '')
                offenders[key] = offenders.get(key, 0) + int(
                    item.get('count') or 0)
        cascade = {k: v for k, v in offenders.items() if v > max_count}
        if cascade:
            raise AssertionError(
                'unhandled cascade detected (per-key threshold=%d): %r'
                % (max_count, cascade))


def _addresses_from_peers_blob(blob) -> list[str]:
    """Walk a serialized Peers JSON blob and pull out IPv4 addresses.
    The on-disk format is a `Peers` Configuration containing a list
    of Identity entries each with an `address`. We accept either the
    object-with-__type__ form or a list/dict tree."""
    out: list[str] = []
    stack = [blob]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            addr = node.get('address')
            if isinstance(addr, str) and _looks_like_ipv4(addr):
                out.append(addr)
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return out


def _looks_like_ipv4(s: str) -> bool:
    parts = s.split('.')
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


# ---------------------------------------------------------------------------
# Environment probes (used by skip-marks on smoke tests)
# ---------------------------------------------------------------------------

def loopback_aliases_supported(addresses: list[str]) -> bool:
    """Best-effort check: bind a UDP socket to each desired loopback
    alias. On Linux this is free; on macOS only 127.0.0.1 is bound."""
    socks = []
    try:
        for a in addresses:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.bind((a, 0))
                socks.append(s)
            except OSError:
                return False
        return True
    finally:
        for s in socks:
            s.close()


def loopback_broadcast_supported() -> bool:
    """Send a broadcast packet to 127.255.255.255 and try to receive
    it from a bound listener. If this fails the harness's discovery
    path can't work."""
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.255.255.255', 0))
        port = listener.getsockname()[1]
        listener.settimeout(1.0)

        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sender.sendto(b'harness-probe', ('127.255.255.255', port))

        try:
            data, _ = listener.recvfrom(64)
            return data == b'harness-probe'
        except socket.timeout:
            return False
    except OSError:
        return False
    finally:
        for s in (locals().get('listener'), locals().get('sender')):
            try:
                s.close()
            except Exception:
                pass
