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
import base64
import concurrent.futures
import json
import logging
import os.path
import socket
import threading
import time
from collections import defaultdict
from enum import Enum, auto
from queue import Queue, Empty
from typing import Callable, Union, Optional

import flask
import dash
from dash.development.base_component import Component
from dash_extensions.enrich import DashProxy, html
from dash_iconify import DashIconify
from plotly.basedatatypes import BaseFigure, BasePlotlyType
try:
    from websockets.asyncio.server import serve as websocket_serve, ServerConnection as WebSocketConnection
except ImportError:
    from websockets.legacy.server import serve as websocket_serve  # noqa
    from websockets.legacy.server import WebSocketConnection as WebSocketConnection  # noqa

from .async_update import bin_data_pb2 as BinaryData
from ..security import (InspectorTLS, Authenticator, AuthLogLimiter, SocketExposure,
                        authenticator_from_env, ws_exposure_from_env,
                        WS_CLOSE_UNAUTHORIZED, WS_CLOSE_BAD_ORIGIN)

# for imports:
from dash import Patch  # noqa
from dash_extensions.enrich import Output, Input, State, ALL, MATCH  # noqa
from dash_extensions.enrich import dcc  # noqa
from dash import callback_context as ctx  # noqa
from dash_extensions import WebSocket  # noqa


class IconSize(Enum):
    SMALL = auto()
    MEDIUM = auto()
    LARGE = auto()


def make_icon(icon_name: str, text: str = None, color: str = None, size: IconSize = IconSize.MEDIUM):
    # font_size_elt = 'font-size'
    font_size_elt = 'fontSize'
    if size == IconSize.SMALL:
        height = 30
        font_size = 8
    elif size == IconSize.MEDIUM:
        height = 40
        font_size = 10
    else:
        height = 50
        font_size = 12
    width = height
    if text is not None:
        width += font_size + 2
    if text is None:
        return [DashIconify(icon=icon_name, color=color, height=height, width=width)]
    return [DashIconify(icon=icon_name, color=color, height=height, width=width),
            html.Br(), html.Div(text, style={font_size_elt: font_size})]


class DashComponent(object):
    uses_react = True

    def __init__(self, app: dash.Dash):
        self.app = app  # for callbacks
        self.server = self.app.server  # for URL registration

    def div(self, *args, **kwargs) -> html.Div:
        raise NotImplementedError


def get_ip_addr():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return '127.0.0.1'


def websocket_origin(websocket) -> Optional[str]:
    """The `Origin` header of an inbound connection, across both APIs.

    `websockets` exposes this differently either side of its asyncio rewrite:
    the legacy server hung an `origin` attribute on the connection, while the
    asyncio `ServerConnection` carries the handshake in `request.headers` and has
    no `origin` at all. Reading `websocket.origin` unconditionally therefore
    raised `AttributeError` on every connection under the modern API, killing the
    handler before the allowlist could refuse anything or the client could
    register — a protection that reported nothing because it never ran. Both
    forms are accepted here rather than pinning one, since `pyproject.toml`
    admits the whole `>=10,<15` range.

    Returns None when the client sent no `Origin`, which is normal for a
    non-browser client and is not a refusal.
    """
    if hasattr(websocket, 'origin'):  # legacy server
        return websocket.origin
    request = getattr(websocket, 'request', None)  # asyncio server
    if request is not None:
        return request.headers.get('Origin')
    return None


class WSClient(object):
    # Minimal client record: the socket, the peer IP, and how the client
    # authenticated. `auth_method` is the authenticator's name ('none' when
    # authentication is off), which is what makes an unauthenticated fan-out
    # visible rather than merely undocumented. Session id / capability hints
    # are still held back until a concrete use case asks (see
    # DashControl.serve_websockets below for the "differentiate" companion
    # deferral).
    def __init__(self, sock, auth_method: str = 'none'):
        self.socket: WebSocketConnection = sock
        self.address = sock.remote_address[0]
        self.auth_method = auth_method


class DashControl(object):
    ws_port = 5005
    legacy = True

    def __init__(self, name: str, title: str, host: str = '0.0.0.0', port: int = 8050,
                 stylesheets: list[str] = None, pages_dir: str = None, logger: logging.Logger = None,
                 verbose: bool = False, proxied: bool = False,
                 tls: InspectorTLS = None, authenticator: Authenticator = None,
                 exposure: SocketExposure = None):
        # TLS, client authentication and listener exposure all default to
        # whatever the environment configures, which is "off"/"loopback" unless
        # an operator says otherwise. Passing them explicitly is for tests and
        # for an embedder that carries its own configuration.
        self.tls = InspectorTLS.from_env() if tls is None else tls
        self.authenticator = (authenticator_from_env() if authenticator is None
                              else authenticator)
        self.exposure = ws_exposure_from_env() if exposure is None else exposure
        self._auth_log = AuthLogLimiter()
        if stylesheets is None:
            stylesheets = []
        pages = False
        if pages_dir is not None:
            pages = True
        if host == '0.0.0.0':
            host = get_ip_addr()
        self.server_address = host, port
        # The websocket's bind address and the address `ws_url` advertises come
        # from the same object, so the listener can no longer hand out an
        # address it does not accept on. `server_address` is the DASHBOARD's
        # address and is deliberately not reused here: the two listeners are
        # separate sockets, and conflating them is what produced a loopback
        # listener advertising a routable host.
        self.ws_bind_host = self.exposure.bind_host
        self.ws_advertise_host = self.exposure.advertise_host(routable=host)
        self.exposure.validate(self.authenticator, self.tls, log=logger)

        if not verbose:
            logging.getLogger('werkzeug').setLevel(logging.WARNING)  # reduce useless callback noise from Flask
            logging.getLogger('websockets').setLevel(logging.WARNING)
        self.verbose = verbose
        self.inherited_logger = logger

        # Dash 4 bundles its own Plotly.js; the external "plotly-latest"
        # CDN URL is frozen at v1.58.5 (July 2021) and only produces a
        # console warning. jQuery is still needed by viz/js/force.js.
        external_scripts = [
            "https://code.jquery.com/jquery-3.6.0.min.js",
        ]

        self.ws_loop = asyncio.new_event_loop()
        self.ws_stop: Optional[asyncio.Future] = None
        # Set by serve_websockets(); halt() needs all three to shut the
        # service down in order rather than pulling the loop out from under it.
        self._ws_thread: Optional[threading.Thread] = None
        self._ws_service: Optional[concurrent.futures.Future] = None
        self._ws_sender: Optional[concurrent.futures.Future] = None
        self.ws_send_queue = Queue()
        self.websocket_handlers: dict[str, list[Callable]] = {}
        self.clients: list[WSClient] = []
        self._client_dir: dict[WebSocketConnection, WSClient] = {}
        self.allowed_origins: set[str] = {
            "http://localhost", "http://127.0.0.1",
            "http://localhost:5005", "http://127.0.0.1:5005",
            "http://localhost:8050", "http://127.0.0.1:8050",
        }
        if self.exposure.exposed:
            # An exposed listener is reached by pages served from the exposed
            # host, so the allowlist has to name it or the Origin check refuses
            # every real client — an exposure knob whose only effect is a 4003
            # would be worse than no knob at all. Both schemes and both ports
            # are listed because the page may be served with or without TLS and
            # from either listener.
            for scheme in ('http', 'https'):
                for a_port in (port, self.ws_port):
                    self.allowed_origins.add('%s://%s:%d'
                                             % (scheme, self.ws_advertise_host, a_port))

        self.server = flask.Flask(name)
        dash_class = dash.Dash
        if proxied:
            dash_class = DashProxy
        kwargs = {}
        if pages:
            kwargs['suppress_callback_exceptions'] = True
        self.app = dash_class(name, server=self.server, title=title, update_title=None,
                              assets_folder=os.path.join(os.path.dirname(__file__), 'assets'),
                              external_stylesheets=stylesheets, external_scripts=external_scripts,
                              use_pages=pages, pages_folder=pages_dir, **kwargs
                              )

        self.server.logger.log_level = logging.INFO
        self.app.logger.log_level = logging.INFO
        if verbose:
            self.server.logger.log_level = logging.DEBUG
            self.app.logger.log_level = logging.DEBUG
        if self.inherited_logger is not None:
            for handler in self.inherited_logger.handlers:
                self.app.logger.addHandler(handler)
                self.server.logger.addHandler(handler)
        self.app.use_reloader = False
        self.active_page = None

    def ws_url(self, component_name: str, params: list = None):
        param_str = ''
        if params is not None and len(params) > 0:
            param_str = '/' + '/'.join(map(str, params))
        # Scheme follows the listener: advertising ws:// for a wss:// server
        # produces a browser error with no server-side trace of the attempt.
        # Host likewise follows the listener, not the dashboard.
        return (f'{self.tls.ws_scheme()}://{self.ws_advertise_host}:{self.ws_port}'
                f'/{component_name}{param_str}')

    def _websocket_event_loop(self):
        loop = self.ws_loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_forever()
        finally:
            # Closing the loop belongs to the thread that ran it, and halt()
            # joins here before anything else touches it. Left open, the loop
            # is closed instead by its own __del__ during interpreter GC --
            # which is where a still-suspended _websocket_service was being
            # finalized and calling Server.close() -> loop.create_task() on an
            # already-closed loop ("Event loop is closed", raised out of a
            # GeneratorExit and reported as PytestUnraisableExceptionWarning).
            try:
                loop.close()
            except Exception:  # pragma: no cover - shutdown best-effort
                pass

    async def _websocket_service(self):
        if self.ws_stop is None:  # pragma: no cover - serve_websockets sets it
            self.ws_stop = asyncio.Future()
        if self.ws_stop.cancelled():
            # halt() landed between serve_websockets() scheduling this and the
            # loop getting to it. Never open the listener at all rather than
            # opening one nothing will close.
            return
        logger = logging.Logger(__name__ + '_websockets')
        logger.log_level = logging.INFO
        if self.verbose:
            logger.log_level = logging.DEBUG
        #if self.inherited_logger is not None:
        #    for handler in self.inherited_logger.handlers:
        #      logger.addHandler(handler)
        async with websocket_serve(self._websocket_handler, self.ws_bind_host, self.ws_port,
                                   logger=logger, compression=None,
                                   ssl=self.tls.context()):
            logger.info('Serving websockets at %s://%s:%d (%s)', self.tls.ws_scheme(),
                        self.ws_advertise_host, self.ws_port,
                        self.exposure.describe())
            # Both postures are logged at startup, on purpose: "no TLS" and "no
            # authentication" are states an operator should be able to see
            # without reading the configuration back.
            logger.info('Inspector websocket: %s; %s',
                        self.tls.describe(), self.authenticator.describe())
            try:
                await self.ws_stop
            except asyncio.CancelledError:
                # halt() cancels ws_stop to end the service. Caught rather than
                # propagated so that leaving this `async with` -- which is what
                # closes the listening socket and drains open connections -- is
                # an ordinary unwind on a still-running loop.
                logger.info('Inspector websocket: shutting down')

    async def _websocket_handler(self, websocket: WebSocketConnection):
        origin = websocket_origin(websocket)
        if self.allowed_origins and origin and origin not in self.allowed_origins:
            await websocket.close(WS_CLOSE_BAD_ORIGIN, "Origin not allowed")
            return
        if not await self._authenticate(websocket, origin):
            return
        async for message in websocket:
            if message == 'connect':
                client = WSClient(websocket, self.authenticator.name)
                self.clients.append(client)
                self._client_dir[websocket] = client
            elif message == 'disconnect':
                client = self._client_dir[websocket]
                self.clients.remove(client)
                del self._client_dir[websocket]
            event = message
            data = None
            try:
                json_obj = json.loads(message)
                event = json_obj['message']
                data = json_obj['data']
            except json.decoder.JSONDecodeError:
                pass
            if event in self.websocket_handlers:
                for func in self.websocket_handlers[event]:
                    func(data)

    async def _authenticate(self, websocket: WebSocketConnection, origin) -> bool:
        """Consume and check the credential frame. True = carry on.

        When authentication is off this reads NOTHING and returns True: the
        first frame belongs to the application protocol, and stealing it would
        break every existing client for a check that is not being made.

        When it is on, the first frame must be the credential. That costs one
        round trip and keeps the credential out of the URL, where it would be
        logged by every proxy in the path and land in browser history.
        """
        if not self.authenticator.required:
            return True
        peer = 'unknown'
        try:
            peer = websocket.remote_address[0]
        except (AttributeError, TypeError, IndexError):
            pass
        try:
            credential = await websocket.recv()
        except Exception as err:  # noqa - connection died before authenticating
            self._log_auth_refusal(peer, origin, 'no credential frame: %s' % err)
            return False
        result = self.authenticator.verify(credential, origin=origin, peer=peer)
        if not result:
            self._log_auth_refusal(peer, origin, result.reason)
            # The close reason names the mechanism but never why the credential
            # failed in detail -- "token mismatch" vs "no credential" is a
            # distinction the server logs and the client does not need.
            await websocket.close(WS_CLOSE_UNAUTHORIZED,
                                  'Unauthorized: %s credential required'
                                  % self.authenticator.name)
            return False
        self._auth_log.clear(peer)
        return True

    def _log_auth_refusal(self, peer: str, origin, reason: str) -> None:
        should, count = self._auth_log.should_log(peer)
        if not should:
            return
        self.app.logger.warning(
            'inspector websocket: refused %s (origin %r): %s [%d attempt(s) '
            'from this peer]', peer, origin, reason, count)

    async def _websocket_sender(self):
        while not self.ws_stop.cancelled():
            try:
                while True:
                    message = self.ws_send_queue.get_nowait()
                    for client in self.clients:
                        await client.socket.send(message)
            except Empty:
                pass
            await asyncio.sleep(0.1)

    # DEFERRED FEATURE: per-client message routing. `_websocket_sender`
    # broadcasts each enqueued message to every connected client
    # (lines 226-228). Differentiated routing — sending tailored updates
    # per client based on auth/session/subscription — needs (a) richer
    # WSClient state (see above) and (b) a routing predicate plumbed
    # through ws_send_queue. Not blocking current dashboard use cases.
    def serve_websockets(self):
        if self.ws_loop is None or self.ws_loop.is_closed():
            # halt() closes the loop, so a restart gets a fresh one rather
            # than "Event loop is closed" from run_coroutine_threadsafe.
            self.ws_loop = asyncio.new_event_loop()
        # Created here, not in the coroutine: halt() has to have something to
        # cancel even if it is called before the service has been scheduled.
        self.ws_stop = asyncio.Future(loop=self.ws_loop)
        self._ws_thread = threading.Thread(target=self._websocket_event_loop,
                                           daemon=True)
        self._ws_thread.start()
        self._ws_service = asyncio.run_coroutine_threadsafe(
            self._websocket_service(), self.ws_loop)
        self._ws_sender = asyncio.run_coroutine_threadsafe(
            self._websocket_sender(), self.ws_loop)

    def halt(self, timeout: float = 2.0):
        """Stop the websocket service from inside its own event loop.

        Cancelling ``ws_stop`` from this thread while stopping the loop in the
        same breath -- what this used to do -- leaves ``_websocket_service``
        suspended at ``await self.ws_stop`` forever: the loop stops before the
        cancellation is ever delivered, so the ``async with
        websocket_serve(...)`` block never exits and nothing closes the
        listener. The coroutine is finalized later during GC, by which time the
        loop has been closed by its own ``__del__``, and the ``Server.close()``
        in ``__aexit__`` raises "Event loop is closed" out of a ``GeneratorExit``
        -- an unraisable exception, which pytest reports and an operator sees as
        noise at shutdown.

        So the order matters: deliver the cancellation ON the loop thread, wait
        for both service coroutines to unwind (that is what runs ``__aexit__``
        and actually closes the socket), and only then stop the loop and join.
        Bounded by *timeout* because this also runs from the SIGINT handler in
        :meth:`run`, where a wedged shutdown must not cost the user the second
        ^C that hard-quits.
        """
        loop = self.ws_loop
        if loop is None or loop.is_closed():
            return

        def _cancel_stop():
            # cancel() on a future that is already done is a no-op that
            # returns False, so this needs no state check of its own.
            if self.ws_stop is not None:
                self.ws_stop.cancel()

        if loop.is_running():
            try:
                loop.call_soon_threadsafe(_cancel_stop)
            except RuntimeError:  # pragma: no cover - closed under us
                pass
            deadline = time.monotonic() + timeout
            for fut in (self._ws_service, self._ws_sender):
                if fut is None:
                    continue
                try:
                    fut.result(max(0.0, deadline - time.monotonic()))
                except (concurrent.futures.CancelledError,
                        asyncio.CancelledError, TimeoutError):
                    pass  # bounded on purpose; the loop stop below is the backstop
                except Exception as err:
                    self.app.logger.warning(
                        'inspector websocket: shutdown raised %s: %s',
                        err.__class__.__name__, err)
        else:
            # No loop thread to deliver it -- either the service was never
            # started, or its thread has not reached run_forever yet. Cancel
            # here; a service that starts afterwards sees a cancelled ws_stop
            # and declines to open the listener.
            _cancel_stop()
        try:
            # Also arms a loop that has not started running yet: the stop is
            # the first thing it will do.
            loop.call_soon_threadsafe(loop.stop)
        except RuntimeError:  # pragma: no cover - already stopped
            pass
        if self._ws_thread is not None:
            # The loop is closed by the thread on its way out, so joining is
            # also what makes it safe to reuse this DashControl.
            self._ws_thread.join(timeout)
            self._ws_thread = None
        elif not loop.is_running():
            # Nobody else will: halt() without a serve_websockets().
            loop.close()
        # `_ws_service` / `_ws_sender` are deliberately left in place: they are
        # done by now, and holding the finished futures is what lets a caller
        # (or a test) see HOW the service ended. serve_websockets() replaces
        # them on a restart.

    def callback(self, *args, **kwargs) -> Callable:
        """Pass-through decorator for callback handler definitions - pull from server"""
        return self.app.callback(*args, **kwargs)

    def callback_shared(self, *args) -> Callable:
        """Decorator for shared callback handler - pull from server, push out to all browsers"""
        def decorator(funct):
            def add_mod(output, ret_val, mods):
                mod_dict = defaultdict()
                mod_dict[output.component_id][output.component_property] = ret_val
                mods.append(mod_dict)

            def reg_input(inpt, fun):
                msg = inpt.component_id + '_' + inpt.component_property
                if msg not in self.websocket_handlers:
                    self.websocket_handlers[msg] = []
                self.websocket_handlers[msg].append(fun)

            def wrapper():
                ret_val = funct()
                mods = []
                if isinstance(args[0], Output):
                    add_mod(args[0], ret_val, mods)
                elif isinstance(args[0], (list, tuple)):
                    if not isinstance(ret_val, (list, tuple)) or len(ret_val) != len(args[0]):
                        raise RuntimeError(
                            f'Non-matching callback output: expected {len(args[0])} outputs but got {ret_val!r}')
                    for idx, output in enumerate(args[0]):
                        if isinstance(output, Output):
                            add_mod(output, ret_val[idx], mods)
                        else:
                            raise RuntimeError(
                                f'Invalid output element at index {idx}: expected Output, got {type(output).__name__}')
                else:
                    raise RuntimeError(
                        f'Invalid first callback argument: expected Output or list of Outputs, got {type(args[0]).__name__}')
                for mod in mods:
                    self.push_mods(mod)
                return ret_val

            if isinstance(args[1], Input):
                reg_input(args[1], wrapper)
            elif isinstance(args[1], (list, tuple)):
                for inpt in args[1]:
                    reg_input(inpt, wrapper)
        return decorator

    def callback_connect(self) -> Callable:
        """Decorator for connection callback handler - push from browser"""
        def decorator(funct):
            if 'connect' not in self.websocket_handlers:
                self.websocket_handlers['connect'] = []
            self.websocket_handlers['connect'].append(lambda x: funct('connect', x))
            if 'disconnect' not in self.websocket_handlers:
                self.websocket_handlers['disconnect'] = []
            self.websocket_handlers['disconnect'].append(lambda x: funct('disconnect', x))
        return decorator

    def clientside_callback(self, clientside_function, *args, **kwargs):
        return self.app.clientside_callback(clientside_function, *args, **kwargs)

    ComponentLike = Union[Component, str, int, float]

    PlotlyTypes = (Component, BaseFigure, BasePlotlyType)

    def _convert_sub_comp(self, value: ComponentLike) -> Optional[Union[dict, list, str, int, float]]:
        if isinstance(value, list):
            sub_list = []
            for sub in value:
                sub_list.append(self._convert_sub_comp(sub))
            return sub_list
        elif isinstance(value, self.PlotlyTypes):
            obj = value.to_plotly_json()
            if 'props' in obj:
                if 'children' in obj['props']:
                    obj['props']['children'] = self._convert_sub_comp(obj['props']['children'])
                elif 'figure' in obj['props']:
                    obj['props']['figure'] = self._convert_sub_comp(obj['props']['figure'])
            return obj
        else:
            return value

    def push_mods(self, mods: dict[str, dict[str, Union[ComponentLike, list[ComponentLike]]]]):
        """Asynchronous component updating; requires AsyncUpdate in the layout"""
        props = list()
        for ident in mods.keys():
            for prop_id in mods[ident].keys():
                prop = defaultdict()
                prop['id'] = ident
                prop['property'] = prop_id
                prop['value'] = self._convert_sub_comp(mods[ident][prop_id])
                props.append(prop)
        self.emit('modify', props)

    def emit(self, event: str, data: Union[str, bytes, list, dict] = None, binary: bool = False):
        """Websocket comm to server"""
        if binary:
            bdmsg = BinaryData.BinaryDataMsg()  # noqa
            bdmsg.event = event
            bdmsg.elt_id = data['id']
            bdmsg.size = len(data['data'])
            bdmsg.data = data['data']
            message: bytes = bdmsg.SerializeToString()
        else:
            message: str = json.dumps(dict(event=event, data=data))
        self.ws_send_queue.put(message)

    def run(self, host: str, port: int, **kwargs):
        kwargs['use_reloader'] = False  # *never* allow reloader (causes subtle bugs)
        import signal
        import threading
        # signal.signal() only works on the main thread of the main
        # interpreter. When the server is hosted in a background thread (e.g.
        # the multi-agency coordinator runs the dashboard in a daemon thread
        # while AT owns the main loop), installing a SIGINT handler raises
        # ValueError — and the owning main thread should handle signals
        # anyway. Only grab SIGINT when we ARE the main thread.
        if threading.current_thread() is threading.main_thread():
            def _on_sigint(_sig, _frame):
                # halt() only stops the websocket loop. Installing it as the
                # SIGINT handler REPLACED Python's default KeyboardInterrupt,
                # so ^C tore down the sockets and left the HTTP server in
                # serve_forever -- the app kept answering requests and had to
                # be killed. Re-raise so werkzeug unwinds normally, and drop
                # back to SIG_DFL first so a second ^C always hard-quits even
                # if shutdown wedges.
                self.halt()
                signal.signal(signal.SIGINT, signal.SIG_DFL)
                raise KeyboardInterrupt

            signal.signal(signal.SIGINT, _on_sigint)
        self.serve_websockets()
        # Serve the PAGE over the same posture as the socket. A token typed
        # into a page delivered over plaintext http is a token on the wire, so
        # the two listeners are configured together or not at all.
        ssl_context = self.tls.context()
        if ssl_context is not None and 'ssl_context' not in kwargs:
            kwargs['ssl_context'] = ssl_context
        self.app.logger.info('Inspector dashboard on %s://%s:%s — %s; %s',
                             self.tls.http_scheme(), host, port,
                             self.tls.describe(), self.authenticator.describe())
        self.app.run(host, port, **kwargs)
