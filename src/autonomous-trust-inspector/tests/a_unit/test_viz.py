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

import asyncio
import glob
import json
import os
import subprocess
import sys
from queue import Queue
import pytest

try:
    from autonomous_trust.inspector.viz import server
    from autonomous_trust.inspector.viz import network_graph as ng
    from autonomous_trust.inspector.viz.live_graph import LiveData
    has_viz = True
except (ImportError, ModuleNotFoundError):
    server = None
    ng = None
    LiveData = None
    has_viz = False

from .. import INSIDE_DOCKER

pytestmark = pytest.mark.skipif(not has_viz,
                                reason='inspector viz dependencies not available')

# The websocket handler waits on the graph's own cadence between frames, and the
# live graph blocks on its queue for `queue_cadence` before each emit. Every
# receive is bounded so a hung handler fails as a timeout rather than hanging the
# suite -- generous enough not to flake on a loaded box.
RECV_TIMEOUT = 10.0


def _sim_dir():
    return os.path.abspath(os.path.dirname(server.__file__))


async def _recv_json(ws):
    """One frame off the socket, decoded. The server sends JSON as text (the
    handler does `websocket.send(str(graph))`), so this also asserts the frame
    IS valid JSON -- the half the old stubs left commented out."""
    raw = await asyncio.wait_for(ws.receive(), timeout=RECV_TIMEOUT)
    return json.loads(raw)


def _assert_graph_frame(payload, *, expect_type=None):
    """The force.js contract: nodes, links (never networkx 3.x's 'edges'), the
    group labels, and a change type naming what this frame is. Asserted on every
    frame because a client that receives 'edges' renders nothing and says
    nothing."""
    assert isinstance(payload, dict), payload
    for key in ('nodes', 'links', 'groups'):
        assert key in payload, f'missing {key!r}; got {sorted(payload)}'
    assert 'edges' not in payload, 'networkx edge key leaked past the rename'
    assert isinstance(payload['nodes'], list)
    assert isinstance(payload['links'], list)
    if expect_type is not None:
        assert payload.get('type') == expect_type, payload.get('type')


@pytest.mark.skipif(INSIDE_DOCKER, reason='Inside docker (not valid)')
@pytest.mark.asyncio
async def test_presentation():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))
    pres_dir = os.path.join(base_dir, 'doc', 'presentation')
    if not os.path.isdir(pres_dir):
        pytest.skip('doc/presentation directory not found')
    # Every top-level page the directory actually serves, rather than a hardcoded
    # ['/']: the server templates out of this directory, so a page added there
    # and broken here would otherwise never be requested by any test.
    pages_list = ['/'] + ['/' + os.path.basename(p)
                          for p in sorted(glob.glob(os.path.join(pres_dir, '*.html')))
                          if os.path.basename(p) != 'index.html']
    app = server.VizServer(pres_dir, 8998, False, 12).app
    for page in pages_list:
        response = await app.test_client().get(page)
        assert response.status_code == 200, f'{page} -> {response.status_code}'


@pytest.mark.asyncio
async def test_simulation():
    app = server.VizServer(_sim_dir(), 8998, False, 12).app
    response = await app.test_client().get('/')
    assert response.status_code == 200

    # The first client message SELECTS the simulation, by implementation name.
    # 'random' is the registered default network.
    async with app.test_client().websocket('/ws') as ws:
        await ws.send(ng.Graphs.Implementation.RANDOM.value)
        first = await _recv_json(ws)
        # The opening frame is the whole graph, hence 'new' and a populated
        # node set -- a client cannot diff against a graph it was never sent.
        _assert_graph_frame(first, expect_type='new')
        assert len(first['nodes']) == 12, len(first['nodes'])

        # Subsequent frames are DIFFS against that opening state. Asserting a
        # second frame arrives is what proves the stream continues; the old stub
        # closed after the handshake and so could not have noticed a handler
        # that emitted once and stopped.
        second = await _recv_json(ws)
        _assert_graph_frame(second)
        assert second.get('type') in ('add', 'remove', 'meta'), second.get('type')


@pytest.mark.asyncio
async def test_simulation_rejects_unknown_implementation():
    """The negative control for the handshake above.

    Worth its own test because the old stub sent the literal 'test', which is
    not an implementation: the handler raised `RuntimeError` into a 500 and the
    stub -- never receiving -- reported success. A selection test that passes
    for an invalid selection is testing nothing.
    """
    app = server.VizServer(_sim_dir(), 8998, False, 12).app
    with pytest.raises(Exception):
        async with app.test_client().websocket('/ws') as ws:
            await ws.send('no-such-graph')
            await _recv_json(ws)


@pytest.mark.asyncio
async def test_live_interface():
    """The live path: no handshake, and the graph is driven by the data queue.

    Feeding the queue is what the FIXME asked for, and it is the only way to
    assert the server serves LIVE data rather than a simulation that happens to
    look plausible.
    """
    data_q = Queue()
    # Peers arrive keyed by uuid; the live graph folds them into nodes.
    peers = ['11111111-1111-4111-8111-111111111111',
             '22222222-2222-4222-8222-222222222222']
    data_q.put((LiveData.peers, peers))

    app = server.VizServer(_sim_dir(), 8998, False, data_q=data_q).app
    response = await app.test_client().get('/')
    assert response.status_code == 200

    async with app.test_client().websocket('/ws') as ws:
        first = await _recv_json(ws)
        _assert_graph_frame(first, expect_type='new')

        # Keep reading until the fed peers show up. They may land on the frame
        # after the opening one, since the opening frame can be emitted before
        # the queue is drained; bounded so a graph that never ingests them fails
        # rather than spins.
        wanted = set(peers)
        seen_uuids = set()
        for _ in range(6):
            payload = await _recv_json(ws)
            _assert_graph_frame(payload)
            uuid_nodes = payload.get('graph', {}).get('uuid_nodes', {})
            seen_uuids |= set(uuid_nodes)
            if wanted <= seen_uuids:
                break
        assert wanted <= seen_uuids, \
            f'fed peers never reached the client; saw {sorted(seen_uuids)}'


@pytest.mark.asyncio
async def test_live_interface_stops_on_sentinel():
    """A `(None, None)` on the queue is the disconnect sentinel: the graph sets
    `stop` and the handler leaves its loop. Pinned because the sentinel is the
    only way the server closes a live socket on purpose -- without it the loop
    is unbounded, and a leaked handler per client is invisible until the process
    is out of tasks."""
    data_q = Queue()
    data_q.put((None, None))
    app = server.VizServer(_sim_dir(), 8998, False, data_q=data_q).app

    with pytest.raises(Exception):
        # The handler breaks and the socket closes; a receive on a closed
        # socket raises rather than returning a frame.
        async with app.test_client().websocket('/ws') as ws:
            for _ in range(4):
                await _recv_json(ws)


def test_default_implementation_is_reachable_by_name():
    """`register_implementation(..., is_default=True)` keyed the default by the
    enum MEMBER while `get_graph` is always called with a string (server.py
    passes `impl.value`), so selecting the default '' matched the enum and then
    raised KeyError. Unit-level rather than over the socket: the defect is in the
    registry, and the socket would only report it as a 500."""
    assert '' in ng.Graphs._MAP, sorted(map(str, ng.Graphs._MAP))
    graph = ng.Graphs.get_graph(ng.Graphs.Implementation.DEFAULT.value, 4)
    assert graph is not None


def test_live_implementation_is_registered_by_importing_the_server():
    """server.py asks the registry for 'live' by name on the data_q path. It
    used to rely on some other module having imported `live_graph` first --
    `inspector.py` does, so the app worked while every other consumer got
    `KeyError: 'live'` and a 500 on connect. Importing the server alone must be
    enough.

    Run in a FRESH interpreter on purpose: this module imports `live_graph`
    itself (for the LiveData labels), which registers 'live' and would make an
    in-process assertion pass no matter what the server imports. A control that
    cannot fail is not a control.

    The child inherits our `sys.path` via PYTHONPATH: `tests/conftest.py` adds
    the sibling monorepo trees in-process, and without handing them down the
    child fails on `autonomous_trust.core` -- an import-path error that looks
    nothing like the registration miss this test exists to catch. The only
    thing that may differ in the child is which modules got *imported*, never
    which are *importable*.
    """
    env = dict(os.environ)
    inherited = [p for p in sys.path if p]
    if env.get('PYTHONPATH'):
        inherited.append(env['PYTHONPATH'])
    env['PYTHONPATH'] = os.pathsep.join(inherited)
    proc = subprocess.run(
        [sys.executable, '-c',
         'from autonomous_trust.inspector.viz import server;'
         'from autonomous_trust.inspector.viz import network_graph as ng;'
         'raise SystemExit(0 if "live" in ng.Graphs._MAP else 1)'],
        capture_output=True, text=True, env=env)
    assert proc.returncode == 0, \
        f"importing viz.server alone did not register 'live': {proc.stderr[-2000:]}"
