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

import logging
import os
import asyncio
import quart

_logger = logging.getLogger(__name__)

from . import network_graph as ng
from . import social_graphs  # noqa  required import
# Registers the 'live' implementation that the data_q branch below asks for by
# name. Importing it HERE rather than relying on a caller to have imported it
# first: `inspector.py` happens to (`from .viz.live_graph import LiveData`), so
# the live path works in the app, but any other consumer constructing a
# VizServer with a data_q got `KeyError: 'live'` and a 500 on connect -- a
# module depending on a registration performed by a module it does not import.
from . import live_graph  # noqa  required import
from .middleware import SassASGIMiddleware, _sass_available
from ..security import (InspectorTLS, Authenticator, AuthLogLimiter,
                        authenticator_from_env, SecurityConfigError,
                        WS_CLOSE_UNAUTHORIZED)

default_port = 8000
initial_size = 12


class VizServer(object):
    def __init__(self, directory, port, debug=False, size=12, data_q=None, finished=None,
                 tls: InspectorTLS = None, authenticator: Authenticator = None):
        if finished is None:
            finished = lambda: None  # noqa
        self.finished = finished
        self.port = port
        # Same posture as the Dash control surface: off unless configured, and
        # refusing to start rather than quietly serving plaintext when a
        # half-configuration says otherwise.
        self.tls = InspectorTLS.from_env() if tls is None else tls
        self.authenticator = (authenticator_from_env() if authenticator is None
                              else authenticator)
        self._auth_log = AuthLogLimiter()
        _logger.debug('Directory on host: %s', directory)
        appname = __name__
        # Create app without static files first to avoid Flask >=3.0 KeyError
        # on PROVIDE_AUTOMATIC_OPTIONS during add_url_rule in __init__.
        self.app = quart.Quart(appname, static_url_path='', static_folder=None, template_folder=directory)
        self.app.config.setdefault('PROVIDE_AUTOMATIC_OPTIONS', True)
        # Now register the static folder after the config key exists.
        self.app.static_folder = directory
        self.app.add_url_rule(
            f"{self.app.static_url_path}/<path:filename>",
            view_func=self.app.send_static_file,
            endpoint='static',
        )
        self.app.debug = debug

        @self.app.after_request
        async def add_cors_headers(response):
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
            return response

        # PATH_INFO is required by SassASGIMiddleware for initial SCSS compilation at startup.
        # Only set if not already present, to avoid overwriting a real request's PATH_INFO.
        if 'PATH_INFO' not in os.environ:
            os.environ['PATH_INFO'] = '/scss/tekfive.scss'
        if _sass_available:
            self.app.asgi_app = SassASGIMiddleware(self.app, {appname: (os.path.join(directory, 'scss'),
                                                                        os.path.join(directory, 'css'), '/css', True)})

        @self.app.route("/")
        async def page():
            # The socket parameters are rendered INTO the page rather than
            # hardcoded in force.js, which assumed ws://127.0.0.1:8000. The
            # token travels here, in a response to an already-authorized page
            # request over the same TLS posture as the socket itself; putting it
            # in the socket URL instead would leak it into proxy logs and
            # browser history.
            return await quart.render_template(  # noqa
                "index.html",
                ws_scheme=self.tls.ws_scheme(),
                ws_port=self.port,
                ws_token=self._page_token())

        @self.app.websocket('/ws')
        async def ws():
            if not await self._authenticate_ws():
                return
            graph = None
            if data_q is not None:
                graph = ng.Graphs.get_graph('live', size, debug, data_q=data_q)
                _logger.debug('Visualizing live network graph')
            else:
                msg = await quart.websocket.receive()
                for impl in ng.Graphs.Implementation:  # noqa
                    if msg == impl.value:
                        graph = ng.Graphs.get_graph(impl.value, size, debug)
                        _logger.debug('Simulating %s network graph', msg)
                if graph is None:
                    raise RuntimeError('ERROR: no graph for unknown type')
            while True:
                seconds, data, stop = graph.get_update()
                if stop:
                    break
                if data is not None:
                    await quart.websocket.send(data)
                await asyncio.sleep(seconds)

    def _page_token(self) -> str:
        """The credential to embed in the page, or '' when auth is off.

        Only the token authenticator has something a page can carry. A future
        session- or certificate-based authenticator returns nothing here and
        authorizes the socket by its own means, which is why this asks the
        authenticator rather than reading the environment a second time.
        """
        return self.authenticator.page_credential()

    async def _authenticate_ws(self) -> bool:
        """Check the credential frame on an inbound /ws connection.

        Reads nothing when authentication is off — the first frame is the
        graph selector on the simulation path (`viz/js/force.js` sends it in
        `onopen`), and the live path never reads a frame at all, so consuming
        one unconditionally would break both.
        """
        if not self.authenticator.required:
            return True
        peer = 'unknown'
        try:
            peer = quart.websocket.remote_addr or 'unknown'
        except Exception:  # noqa - no request context in some test harnesses
            pass
        origin = None
        try:
            origin = quart.websocket.headers.get('Origin')
        except Exception:  # noqa
            pass
        try:
            credential = await quart.websocket.receive()
        except Exception as err:  # noqa - client vanished before authenticating
            self._log_refusal(peer, origin, 'no credential frame: %s' % err)
            return False
        result = self.authenticator.verify(credential, origin=origin, peer=peer)
        if not result:
            self._log_refusal(peer, origin, result.reason)
            await quart.websocket.close(WS_CLOSE_UNAUTHORIZED)
            return False
        self._auth_log.clear(peer)
        return True

    def _log_refusal(self, peer: str, origin, reason: str) -> None:
        should, count = self._auth_log.should_log(peer)
        if should:
            _logger.warning('viz /ws: refused %s (origin %r): %s '
                            '[%d attempt(s) from this peer]',
                            peer, origin, reason, count)

    def _bind_host(self) -> str:
        """The address `app.run` will actually bind.

        Resolved the way Quart resolves it — the host half of SERVER_NAME if
        configured, loopback otherwise — so the startup log can state the real
        bind instead of a plausible-looking 0.0.0.0, and so passing it back
        explicitly changes nothing about where the server listens.
        """
        server_name = self.app.config.get('SERVER_NAME')
        if server_name:
            return server_name.partition(':')[0] or '127.0.0.1'
        return '127.0.0.1'

    def run(self):
        kwargs = {}
        if self.tls.enabled:
            unsupported = self.tls.unsupported_by_paths_only()
            if unsupported:
                # Refused rather than dropped: this listener runs on Quart's
                # own server, which takes only cert/key paths. Accepting
                # AT_INSPECTOR_TLS_CLIENT_CA here would tell an operator that
                # client certificates are verified while nothing checked them.
                raise SecurityConfigError(
                    'the visualization server cannot honor %s: it serves via '
                    "Quart's built-in server, which accepts only a certificate "
                    'and an unencrypted key path. Use a decrypted key, and put '
                    'mutual TLS in a reverse proxy (or run this app under '
                    'hypercorn directly, where both are configurable).'
                    % ', '.join(unsupported))
            # Quart takes the paths rather than a context, and builds its own
            # hypercorn config from them.
            kwargs['certfile'] = self.tls.certfile
            kwargs['keyfile'] = self.tls.keyfile
        host = self._bind_host()
        _logger.info('Visualization server on %s://%s:%d — %s; %s',
                     self.tls.http_scheme(), host, self.port,
                     self.tls.describe(), self.authenticator.describe())
        self.app.run(host=host, port=self.port, **kwargs)

    def stop(self):
        self.finished()
        self.app.shutdown()
