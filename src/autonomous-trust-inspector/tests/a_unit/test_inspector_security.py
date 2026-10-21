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
"""Inspector transport security and client authentication.

Two properties matter more than the individual assertions here:

1. **Unconfigured is unchanged.** The default posture must be byte-identical to
   the behavior that existed before this module, because the demos, the
   dashboards and `test_dash_core.py` all rely on it. A security feature that
   changes the default breaks the thing it protects.
2. **Half-configured refuses to start.** Every asymmetric configuration is a
   listener an operator believes is protected and is not, so each one is
   asserted to raise rather than to warn.

The auth gate is exercised against fake sockets rather than a live server: what
is under test is *the order of operations* — that no frame is consumed when
authentication is off, and that exactly one is when it is on — which a real
server would hide behind timing.
"""
import asyncio
import ssl
from unittest.mock import MagicMock

import pytest

from autonomous_trust.inspector.security import (
    InspectorTLS, SecurityConfigError, TokenAuthenticator, NullAuthenticator,
    authenticator_from_env, AuthLogLimiter, AuthResult,
    ENV_TLS_CERT, ENV_TLS_KEY, ENV_TLS_CLIENT_CA, ENV_TLS_KEY_PASSWORD,
    ENV_WS_TOKEN, ENV_WS_BIND, WS_CLOSE_UNAUTHORIZED, WS_CLOSE_BAD_ORIGIN,
    MIN_TOKEN_LEN, SocketExposure, ws_exposure_from_env,
)

GOOD_TOKEN = 'a' * MIN_TOKEN_LEN


def _self_signed(tmp_path):
    """A throwaway cert/key pair, or a skip if we cannot make one."""
    crypto = pytest.importorskip('cryptography', reason='cryptography needed to mint a test cert')
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    cert_path = tmp_path / 'cert.pem'
    key_path = tmp_path / 'key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()))
    assert crypto is not None
    return str(cert_path), str(key_path)


class TestTLSDefaultIsOff:
    """The unconfigured posture, which every existing caller depends on."""

    def test_no_env_means_disabled(self):
        tls = InspectorTLS.from_env(env={})
        assert tls.enabled is False
        assert tls.context() is None

    def test_schemes_are_plaintext_when_off(self):
        tls = InspectorTLS.from_env(env={})
        assert tls.ws_scheme() == 'ws'
        assert tls.http_scheme() == 'http'

    def test_empty_strings_count_as_unset(self):
        # A compose file that defines the variable without a value must not be
        # read as "TLS requested"; it is the most likely way to trip the
        # half-configured guard by accident.
        tls = InspectorTLS.from_env(env={ENV_TLS_CERT: '', ENV_TLS_KEY: ''})
        assert tls.enabled is False

    def test_describe_names_the_knobs(self):
        # Operator-facing: the log line must say how to turn it on.
        text = InspectorTLS.from_env(env={}).describe()
        assert ENV_TLS_CERT in text and ENV_TLS_KEY in text


class TestTLSHalfConfiguredRefuses:
    def test_cert_without_key(self, tmp_path):
        cert, _ = _self_signed(tmp_path)
        with pytest.raises(SecurityConfigError) as exc:
            InspectorTLS(certfile=cert)
        assert ENV_TLS_KEY in str(exc.value)

    def test_key_without_cert(self, tmp_path):
        _, key = _self_signed(tmp_path)
        with pytest.raises(SecurityConfigError) as exc:
            InspectorTLS(keyfile=key)
        assert ENV_TLS_CERT in str(exc.value)

    def test_missing_cert_file_names_the_path(self):
        with pytest.raises(SecurityConfigError) as exc:
            InspectorTLS(certfile='/nonexistent/cert.pem', keyfile='/nonexistent/key.pem')
        assert '/nonexistent/cert.pem' in str(exc.value)

    def test_client_ca_without_cert(self, tmp_path):
        ca = tmp_path / 'ca.pem'
        ca.write_text('')
        with pytest.raises(SecurityConfigError) as exc:
            InspectorTLS(client_ca=str(ca))
        assert ENV_TLS_CLIENT_CA in str(exc.value)


class TestTLSEnabled:
    def test_context_is_a_server_context(self, tmp_path):
        cert, key = _self_signed(tmp_path)
        tls = InspectorTLS(certfile=cert, keyfile=key)
        assert tls.enabled is True
        ctx = tls.context()
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2

    def test_schemes_follow_tls(self, tmp_path):
        cert, key = _self_signed(tmp_path)
        tls = InspectorTLS(certfile=cert, keyfile=key)
        assert tls.ws_scheme() == 'wss'
        assert tls.http_scheme() == 'https'

    def test_mismatched_pair_is_diagnosed(self, tmp_path):
        cert, _ = _self_signed(tmp_path)
        _, other_key = _self_signed(tmp_path / 'second' if (tmp_path / 'second').mkdir() is None else tmp_path)
        tls = InspectorTLS(certfile=cert, keyfile=other_key)
        with pytest.raises(SecurityConfigError) as exc:
            tls.context()
        # The message must name both paths; "SSL error" alone is unactionable.
        assert cert in str(exc.value)

    def test_fresh_context_per_call(self, tmp_path):
        cert, key = _self_signed(tmp_path)
        tls = InspectorTLS(certfile=cert, keyfile=key)
        assert tls.context() is not tls.context()


class TestTokenAuthenticator:
    def test_correct_token_accepted(self):
        auth = TokenAuthenticator(GOOD_TOKEN)
        assert auth.verify(GOOD_TOKEN)

    def test_bytes_credential_accepted(self):
        auth = TokenAuthenticator(GOOD_TOKEN)
        assert auth.verify(GOOD_TOKEN.encode('utf-8'))

    def test_wrong_token_refused_with_reason(self):
        auth = TokenAuthenticator(GOOD_TOKEN)
        result = auth.verify('b' * MIN_TOKEN_LEN)
        assert not result
        assert 'mismatch' in result.reason

    def test_absent_credential_refused(self):
        result = TokenAuthenticator(GOOD_TOKEN).verify(None)
        assert not result
        assert 'no credential' in result.reason

    def test_unusable_type_refused_not_crashed(self):
        # A client can send anything; a TypeError here would be a denial of
        # service against the server rather than the client.
        result = TokenAuthenticator(GOOD_TOKEN).verify({'not': 'a token'})
        assert not result
        assert 'unusable type' in result.reason

    def test_empty_token_configuration_refused(self):
        with pytest.raises(SecurityConfigError):
            TokenAuthenticator('')

    def test_short_token_refused_as_placeholder(self):
        with pytest.raises(SecurityConfigError) as exc:
            TokenAuthenticator('changeme')
        assert str(MIN_TOKEN_LEN) in str(exc.value)

    def test_required_flag_drives_the_handler(self):
        assert TokenAuthenticator(GOOD_TOKEN).required is True
        assert NullAuthenticator().required is False

    def test_page_credential_is_the_token(self):
        assert TokenAuthenticator(GOOD_TOKEN).page_credential() == GOOD_TOKEN

    def test_null_offers_no_page_credential(self):
        # A page must not carry a credential that does not exist, or the client
        # will send a spurious first frame and desynchronize the protocol.
        assert NullAuthenticator().page_credential() == ''


class TestAuthenticatorFromEnv:
    def test_absent_token_gives_null(self):
        assert isinstance(authenticator_from_env(env={}), NullAuthenticator)

    def test_present_token_gives_token_auth(self):
        auth = authenticator_from_env(env={ENV_WS_TOKEN: GOOD_TOKEN})
        assert isinstance(auth, TokenAuthenticator)

    def test_empty_token_env_is_off_not_broken(self):
        # Distinguishes "unset" from "set to nothing": the latter must not
        # raise here, because a compose file with a blank default would then
        # take the whole dashboard down.
        assert isinstance(authenticator_from_env(env={ENV_WS_TOKEN: ''}), NullAuthenticator)

    def test_null_describe_names_the_knob(self):
        assert ENV_WS_TOKEN in NullAuthenticator().describe()


class TestAuthLogLimiter:
    def test_first_attempt_always_logs(self):
        lim = AuthLogLimiter(every=10)
        should, count = lim.should_log('1.2.3.4')
        assert should and count == 1

    def test_subsequent_attempts_suppressed_then_sampled(self):
        lim = AuthLogLimiter(every=5)
        lim.should_log('p')
        results = [lim.should_log('p')[0] for _ in range(9)]
        # attempts 2-4 quiet, 5 logs, 6-9 quiet, 10 logs
        assert results.count(True) == 2

    def test_count_is_carried_so_volume_stays_visible(self):
        lim = AuthLogLimiter(every=3)
        for _ in range(2):
            lim.should_log('p')
        _, count = lim.should_log('p')
        assert count == 3

    def test_peers_counted_independently(self):
        lim = AuthLogLimiter(every=100)
        assert lim.should_log('a')[0] is True
        assert lim.should_log('b')[0] is True

    def test_success_clears_so_diagnostics_return(self):
        lim = AuthLogLimiter(every=1000)
        lim.should_log('p')
        lim.clear('p')
        should, count = lim.should_log('p')
        assert should and count == 1


class _FakeSocket:
    """Minimal stand-in for a websockets ServerConnection."""

    def __init__(self, frames=(), origin=None, peer='10.0.0.9'):
        self._frames = list(frames)
        self.origin = origin
        self.remote_address = (peer, 40000)
        self.closed_with = None
        self.sent = []

    async def recv(self):
        if not self._frames:
            raise ConnectionError('closed before sending a frame')
        return self._frames.pop(0)

    async def close(self, code=1000, reason=''):
        self.closed_with = (code, reason)

    async def send(self, message):
        self.sent.append(message)

    def __aiter__(self):
        async def gen():
            while self._frames:
                yield self._frames.pop(0)
        return gen()


try:
    from autonomous_trust.inspector.dash_components.core import DashControl
    has_dash = True
except (ImportError, ModuleNotFoundError):
    has_dash = False


@pytest.mark.skipif(not has_dash, reason='dash_components dependencies not available')
class TestDashControlAuthGate:
    """The order-of-operations property: who consumes the first frame."""

    @staticmethod
    def _ctl(authenticator):
        ctl = DashControl('test', 'Test', host='127.0.0.1', port=8050,
                          authenticator=authenticator, tls=InspectorTLS())
        # Every refusal below is deliberate, and `_log_auth_refusal` writes it
        # through `app.logger` (core.py). Mock that logger so the tests ASSERT
        # the refusal was logged instead of printing it into the suite output,
        # where a deliberate refusal reads as a failure.
        ctl.app.logger = MagicMock()
        return ctl

    def test_no_frame_consumed_when_auth_is_off(self):
        # THE regression guard for every existing client: the application's
        # first frame must still be the application's.
        ctl = self._ctl(NullAuthenticator())
        sock = _FakeSocket(frames=['live'])
        assert asyncio.run(ctl._authenticate(sock, None)) is True
        assert sock._frames == ['live'], 'auth-off path consumed an application frame'

    def test_valid_token_consumes_exactly_one_frame(self):
        ctl = self._ctl(TokenAuthenticator(GOOD_TOKEN))
        sock = _FakeSocket(frames=[GOOD_TOKEN, 'live'])
        assert asyncio.run(ctl._authenticate(sock, None)) is True
        assert sock._frames == ['live']
        assert sock.closed_with is None

    def test_bad_token_closes_4401(self):
        ctl = self._ctl(TokenAuthenticator(GOOD_TOKEN))
        sock = _FakeSocket(frames=['wrong-token-value-here'])
        assert asyncio.run(ctl._authenticate(sock, None)) is False
        assert sock.closed_with[0] == WS_CLOSE_UNAUTHORIZED
        # The server's side of the refusal: silent rejections are unoperable.
        assert ctl.app.logger.warning.called

    def test_close_reason_does_not_leak_which_check_failed(self):
        ctl = self._ctl(TokenAuthenticator(GOOD_TOKEN))
        sock = _FakeSocket(frames=['wrong-token-value-here'])
        asyncio.run(ctl._authenticate(sock, None))
        assert 'mismatch' not in sock.closed_with[1]

    def test_client_vanishing_before_auth_is_refused_not_raised(self):
        ctl = self._ctl(TokenAuthenticator(GOOD_TOKEN))
        sock = _FakeSocket(frames=[])
        assert asyncio.run(ctl._authenticate(sock, None)) is False
        assert ctl.app.logger.warning.called

    def test_ws_url_scheme_follows_tls(self, tmp_path):
        cert, key = _self_signed(tmp_path)
        ctl = DashControl('test', 'Test', host='127.0.0.1', port=8050,
                          authenticator=NullAuthenticator(),
                          tls=InspectorTLS(certfile=cert, keyfile=key))
        assert ctl.ws_url('graph').startswith('wss://')

    def test_ws_url_plaintext_by_default(self):
        ctl = self._ctl(NullAuthenticator())
        assert ctl.ws_url('graph') == 'ws://127.0.0.1:5005/graph'

    def test_client_record_carries_auth_method(self):
        ctl = self._ctl(TokenAuthenticator(GOOD_TOKEN))
        assert ctl.authenticator.name == 'token'


class TestAuthResult:
    def test_truthiness(self):
        assert AuthResult(True)
        assert not AuthResult(False, 'nope')

    def test_repr_carries_reason(self):
        assert 'nope' in repr(AuthResult(False, 'nope'))


class TestPathsOnlyListenerLimits:
    """What a cert/key-paths-only listener silently drops, and does not.

    Quart's built-in server takes a certificate and a key path — there is no
    argument for a key passphrase, and its `ca_certs` does not make client
    certificates *required*. So `VizServer` must refuse those two rather than
    start a listener whose posture is weaker than the configuration reads.
    """

    def test_plain_cert_and_key_are_fully_supported(self, tmp_path):
        cert, key = _self_signed(tmp_path)
        tls = InspectorTLS(certfile=cert, keyfile=key)
        assert tls.unsupported_by_paths_only() == []

    def test_key_password_is_reported_unsupported(self, tmp_path):
        cert, key = _self_signed(tmp_path)
        tls = InspectorTLS(certfile=cert, keyfile=key, password='secret')
        assert tls.unsupported_by_paths_only() == [ENV_TLS_KEY_PASSWORD]

    def test_client_ca_is_reported_unsupported(self, tmp_path):
        cert, key = _self_signed(tmp_path)
        tls = InspectorTLS(certfile=cert, keyfile=key, client_ca=cert)
        assert tls.unsupported_by_paths_only() == [ENV_TLS_CLIENT_CA]

    def test_both_reported_together(self, tmp_path):
        cert, key = _self_signed(tmp_path)
        tls = InspectorTLS(certfile=cert, keyfile=key, password='secret',
                           client_ca=cert)
        assert tls.unsupported_by_paths_only() == [ENV_TLS_KEY_PASSWORD,
                                                  ENV_TLS_CLIENT_CA]

    def test_tls_off_reports_nothing(self):
        # Not "everything is unsupported": with no certificate there is no
        # posture to misrepresent, and the caller must still start.
        assert InspectorTLS().unsupported_by_paths_only() == []


class TestVizServerRun:
    """VizServer's startup posture. `run()` is inspected without being awaited
    — the refusal has to happen *before* the listener opens, so the assertion
    is that the call raises instead of serving."""

    @staticmethod
    def _server(tmp_path, **kw):
        server = pytest.importorskip(
            'autonomous_trust.inspector.viz.server',
            reason='quart needed for the visualization server')
        directory = tmp_path / 'pages'
        directory.mkdir(exist_ok=True)
        return server.VizServer(str(directory), 8999, False, 12, **kw)

    def test_mtls_configuration_refused_not_dropped(self, tmp_path):
        cert, key = _self_signed(tmp_path)
        viz = self._server(tmp_path,
                           tls=InspectorTLS(certfile=cert, keyfile=key,
                                            client_ca=cert),
                           authenticator=NullAuthenticator())
        with pytest.raises(SecurityConfigError) as err:
            viz.run()
        assert ENV_TLS_CLIENT_CA in str(err.value)

    def test_encrypted_key_refused_not_dropped(self, tmp_path):
        cert, key = _self_signed(tmp_path)
        viz = self._server(tmp_path,
                           tls=InspectorTLS(certfile=cert, keyfile=key,
                                            password='secret'),
                           authenticator=NullAuthenticator())
        with pytest.raises(SecurityConfigError) as err:
            viz.run()
        assert ENV_TLS_KEY_PASSWORD in str(err.value)

    def test_bind_host_is_loopback_by_default(self, tmp_path):
        viz = self._server(tmp_path, tls=InspectorTLS(),
                           authenticator=NullAuthenticator())
        assert viz._bind_host() == '127.0.0.1'

    def test_bind_host_follows_server_name(self, tmp_path):
        # The log line must name the bind Quart will actually use, which
        # SERVER_NAME can move off loopback.
        viz = self._server(tmp_path, tls=InspectorTLS(),
                           authenticator=NullAuthenticator())
        viz.app.config['SERVER_NAME'] = '0.0.0.0:8999'
        assert viz._bind_host() == '0.0.0.0'

    def test_page_token_empty_when_auth_off(self, tmp_path):
        viz = self._server(tmp_path, tls=InspectorTLS(),
                           authenticator=NullAuthenticator())
        assert viz._page_token() == ''

    def test_page_token_present_when_token_auth(self, tmp_path):
        viz = self._server(tmp_path, tls=InspectorTLS(),
                           authenticator=TokenAuthenticator(GOOD_TOKEN))
        assert viz._page_token() == GOOD_TOKEN


# --- The live path: viz /ws end to end -------------------------------------
# `VizServer`'s socket is the one the dashboard actually uses (force.js connects
# to /ws), so the gate is exercised through Quart's test client rather than a
# fake. What these pin down is the FRAME ORDER contract force.js depends on: the
# credential precedes the graph selector when auth is on, and no credential is
# expected at all when it is off.

VIZ_RECV_TIMEOUT = 10.0


def _viz(tmp_path=None, **kw):
    server = pytest.importorskip('autonomous_trust.inspector.viz.server',
                                 reason='quart needed for the visualization server')
    import os
    sim_dir = os.path.abspath(os.path.dirname(server.__file__))
    return server.VizServer(sim_dir, 8997, False, 12, **kw)


def _selector():
    from autonomous_trust.inspector.viz import network_graph as ng
    return ng.Graphs.Implementation.RANDOM.value


@pytest.mark.asyncio
async def test_viz_ws_accepts_token_then_selector():
    """Token first, selector second, graph flows. The positive control: it
    proves the credential frame is consumed as the credential and the selector
    still reaches the application."""
    viz = _viz(tls=InspectorTLS(), authenticator=TokenAuthenticator(GOOD_TOKEN))
    async with viz.app.test_client().websocket('/ws') as ws:
        await ws.send(GOOD_TOKEN)
        await ws.send(_selector())
        import json
        raw = await asyncio.wait_for(ws.receive(), timeout=VIZ_RECV_TIMEOUT)
        payload = json.loads(raw)
    assert payload['type'] == 'new'
    assert len(payload['nodes']) == 12


async def _expect_refusal(viz, frames):
    """Send `frames` and assert the server closed with WS_CLOSE_UNAUTHORIZED.

    The close CODE is asserted, not merely that something raised: a handler that
    crashed for an unrelated reason would also raise, and would pass a test that
    only demanded an exception.
    """
    from quart.testing.connections import WebsocketDisconnectError
    with pytest.raises(WebsocketDisconnectError) as err:
        async with viz.app.test_client().websocket('/ws') as ws:
            for frame in frames:
                await ws.send(frame)
            await asyncio.wait_for(ws.receive(), timeout=VIZ_RECV_TIMEOUT)
    assert err.value.args[0] == WS_CLOSE_UNAUTHORIZED, err.value.args


@pytest.mark.asyncio
async def test_viz_ws_refuses_wrong_token_before_any_frame():
    viz = _viz(tls=InspectorTLS(), authenticator=TokenAuthenticator(GOOD_TOKEN))
    await _expect_refusal(viz, ['b' * MIN_TOKEN_LEN, _selector()])


@pytest.mark.asyncio
async def test_viz_ws_refuses_selector_sent_as_credential():
    """A client that skips the token — an old force.js against a new server —
    is refused rather than served, and its selector is not mistaken for one."""
    viz = _viz(tls=InspectorTLS(), authenticator=TokenAuthenticator(GOOD_TOKEN))
    await _expect_refusal(viz, [_selector()])


@pytest.mark.asyncio
async def test_viz_ws_unchanged_when_auth_off():
    """The default posture: the selector is the FIRST frame, exactly as before
    this module existed. Regressing this breaks every existing client."""
    viz = _viz(tls=InspectorTLS(), authenticator=NullAuthenticator())
    async with viz.app.test_client().websocket('/ws') as ws:
        await ws.send(_selector())
        import json
        payload = json.loads(await asyncio.wait_for(ws.receive(),
                                                    timeout=VIZ_RECV_TIMEOUT))
    assert payload['type'] == 'new'


@pytest.mark.asyncio
async def test_page_carries_socket_scheme_and_no_token_by_default():
    viz = _viz(tls=InspectorTLS(), authenticator=NullAuthenticator())
    body = (await (await viz.app.test_client().get('/')).get_data()).decode()
    assert 'scheme: "ws"' in body
    # An empty token is what tells force.js to send NO credential frame.
    assert 'token: ""' in body


@pytest.mark.asyncio
async def test_page_carries_token_and_wss_when_configured(tmp_path):
    cert, key = _self_signed(tmp_path)
    viz = _viz(tls=InspectorTLS(certfile=cert, keyfile=key),
               authenticator=TokenAuthenticator(GOOD_TOKEN))
    body = (await (await viz.app.test_client().get('/')).get_data()).decode()
    assert 'scheme: "wss"' in body
    assert 'token: "%s"' % GOOD_TOKEN in body


class TestSocketExposure:
    """Bind address and advertised address, which used to be independent.

    The defect: the listener bound `127.0.0.1` while `ws_url()` advertised the
    host's routable address, so every off-host client was handed an address
    nothing accepted. These tests pin the invariant that replaced it — the
    advertised host is always one the listener accepts on — rather than pinning
    the particular strings.
    """

    def test_default_is_loopback(self):
        exp = SocketExposure()
        assert exp.bind_host == '127.0.0.1'
        assert exp.is_loopback and not exp.exposed

    def test_advertised_equals_bound(self):
        exp = SocketExposure('10.27.4.19')
        assert exp.advertise_host(routable='192.168.1.5') == '10.27.4.19', \
            'advertised host must be the bound host, not the routable one'

    def test_loopback_advertises_loopback_even_with_a_routable_address(self):
        # THE regression guard for the original defect: a routable address being
        # available is not a reason to advertise it.
        exp = SocketExposure()
        assert exp.advertise_host(routable='10.27.4.19') == '127.0.0.1'

    def test_wildcard_advertises_the_routable_address(self):
        # The one case where advertised != bound, and still truthful: a wildcard
        # listener does accept on the routable address, and `0.0.0.0` is not
        # somewhere a client can connect.
        exp = SocketExposure('0.0.0.0')
        assert exp.is_wildcard and exp.exposed
        assert exp.advertise_host(routable='10.27.4.19') == '10.27.4.19'

    def test_wildcard_without_a_routable_address_falls_back_to_loopback(self):
        assert SocketExposure('0.0.0.0').advertise_host() == '127.0.0.1'

    def test_empty_bind_is_loopback_not_wildcard(self):
        # `websockets` treats '' as loopback, so the advertised value follows.
        exp = SocketExposure('')
        assert exp.is_loopback and not exp.exposed
        assert exp.advertise_host(routable='10.27.4.19') == '127.0.0.1'

    def test_whitespace_is_stripped(self):
        assert SocketExposure(' 127.0.0.1 ').is_loopback

    def test_from_env_absent_is_loopback(self):
        assert ws_exposure_from_env({}).bind_host == '127.0.0.1'

    def test_from_env_reads_the_bind(self):
        assert ws_exposure_from_env({ENV_WS_BIND: '0.0.0.0'}).bind_host == '0.0.0.0'

    def test_empty_env_value_is_loopback(self):
        assert ws_exposure_from_env({ENV_WS_BIND: ''}).is_loopback

    def test_describe_names_the_knob_when_closed(self):
        assert ENV_WS_BIND in SocketExposure().describe()

    def test_describe_is_loud_when_open(self):
        assert 'OFF-HOST' in SocketExposure('0.0.0.0').describe()


class TestExposureValidation:
    """Exposing the listener requires a credential; missing TLS only warns."""

    def test_loopback_needs_nothing(self):
        SocketExposure().validate(NullAuthenticator(), InspectorTLS())

    def test_exposed_without_auth_is_refused(self):
        with pytest.raises(SecurityConfigError) as err:
            SocketExposure('0.0.0.0').validate(NullAuthenticator(), InspectorTLS())
        # The message has to name both ways out, not just the failure.
        assert ENV_WS_TOKEN in str(err.value)
        assert ENV_WS_BIND in str(err.value)

    def test_exposed_with_token_is_allowed(self):
        SocketExposure('0.0.0.0').validate(TokenAuthenticator(GOOD_TOKEN),
                                           InspectorTLS())

    def test_exposed_without_tls_warns(self, caplog):
        import logging as _logging
        with caplog.at_level(_logging.WARNING):
            SocketExposure('10.27.4.19').validate(TokenAuthenticator(GOOD_TOKEN),
                                                  InspectorTLS())
        # getMessage() applies the lazy %-args, which is where the bind address
        # and the two env var names actually live.
        messages = [r.getMessage() for r in caplog.records]
        assert any('without TLS' in m for m in messages), caplog.text
        assert any('10.27.4.19' in m and ENV_TLS_CERT in m for m in messages), messages

    def test_exposed_with_tls_does_not_warn(self, tmp_path, caplog):
        import logging as _logging
        cert, key = _self_signed(tmp_path)
        with caplog.at_level(_logging.WARNING):
            SocketExposure('10.27.4.19').validate(
                TokenAuthenticator(GOOD_TOKEN),
                InspectorTLS(certfile=cert, keyfile=key))
        assert not caplog.records, caplog.text


class TestDashControlExposure:
    """The wiring: one value feeds the bind and the advertisement."""

    def test_url_follows_the_listener_not_the_dashboard(self):
        # The dashboard is on a routable address; the socket is not. Before this
        # change `ws_url` reported the dashboard's host for the socket's port.
        ctl = DashControl('test', 'Test', host='10.27.4.19', port=8050,
                          authenticator=NullAuthenticator(), tls=InspectorTLS())
        assert ctl.server_address[0] == '10.27.4.19'
        assert ctl.ws_bind_host == '127.0.0.1'
        assert ctl.ws_url('graph') == 'ws://127.0.0.1:5005/graph'

    def test_exposed_bind_is_advertised_and_bound_alike(self):
        ctl = DashControl('test', 'Test', host='10.27.4.19', port=8050,
                          authenticator=TokenAuthenticator(GOOD_TOKEN),
                          tls=InspectorTLS(),
                          exposure=SocketExposure('10.27.4.19'))
        assert ctl.ws_bind_host == ctl.ws_advertise_host == '10.27.4.19'
        assert ctl.ws_url('graph') == 'ws://10.27.4.19:5005/graph'

    def test_wildcard_bind_advertises_the_dashboard_host(self):
        # `host` is what the dashboard resolved, and a wildcard listener does
        # accept there — so it is the honest thing to advertise.
        ctl = DashControl('test', 'Test', host='10.27.4.19', port=8050,
                          authenticator=TokenAuthenticator(GOOD_TOKEN),
                          tls=InspectorTLS(),
                          exposure=SocketExposure('0.0.0.0'))
        assert ctl.ws_bind_host == '0.0.0.0'
        assert ctl.ws_advertise_host == '10.27.4.19'

    def test_exposed_bind_without_auth_refuses_construction(self):
        # Before the listener exists, not at first connection.
        with pytest.raises(SecurityConfigError):
            DashControl('test', 'Test', host='10.27.4.19', port=8050,
                        authenticator=NullAuthenticator(), tls=InspectorTLS(),
                        exposure=SocketExposure('0.0.0.0'))

    def test_exposed_bind_extends_the_origin_allowlist(self):
        """An exposure knob that left the Origin check on loopback would refuse
        every client it just made reachable."""
        ctl = DashControl('test', 'Test', host='10.27.4.19', port=8050,
                          authenticator=TokenAuthenticator(GOOD_TOKEN),
                          tls=InspectorTLS(),
                          exposure=SocketExposure('10.27.4.19'))
        assert 'http://10.27.4.19:8050' in ctl.allowed_origins
        assert 'https://10.27.4.19:8050' in ctl.allowed_origins
        assert 'http://10.27.4.19:5005' in ctl.allowed_origins

    def test_loopback_leaves_the_allowlist_alone(self):
        ctl = DashControl('test', 'Test', host='10.27.4.19', port=8050,
                          authenticator=NullAuthenticator(), tls=InspectorTLS())
        assert not any('10.27.4.19' in o for o in ctl.allowed_origins)


# --- The DashControl listener, for real ------------------------------------
# These start an actual `websockets` server. The fake-socket tests above cover
# the ORDER of operations; only a real handshake covers the parts the library
# supplies — which is why `websocket.origin` could raise `AttributeError` on
# every connection under the asyncio API while every fake-socket test passed.

WS_PROBE_TIMEOUT = 5.0


def _free_port():
    import socket as _socket
    with _socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class _Listener:
    """A DashControl serving its websocket on a free loopback port."""

    def __init__(self, **kw):
        self.ctl = DashControl('live', 'Live', host='127.0.0.1', port=8050,
                               tls=InspectorTLS(), **kw)
        self.ctl.ws_port = _free_port()
        # The refusal tests below expect refusals, and each one logs from the
        # listener thread. Mock the logger so the expected warnings stay out of
        # the suite output; the verdict is read from the close code, which is
        # the client-observable truth these tests are about.
        self.ctl.app.logger = MagicMock()

    def __enter__(self):
        import time
        self.ctl.serve_websockets()
        time.sleep(0.8)  # let the loop thread bind before the first probe
        return self.ctl

    def __exit__(self, *exc):
        import time
        self.ctl.halt()
        time.sleep(0.3)
        return False


async def _probe(url, token=None, origin=None):
    """Connect, optionally authenticate, and report the server's verdict.

    The verdict is read by awaiting the close rather than by the absence of an
    error: a client that sends and exits never observes the refusal, which makes
    a rejected connection look accepted.
    """
    from websockets.asyncio.client import connect as ws_connect
    kwargs = {'open_timeout': WS_PROBE_TIMEOUT}
    if origin is not None:
        kwargs['origin'] = origin
    try:
        async with ws_connect(url, **kwargs) as ws:
            if token is not None:
                await ws.send(token)
            await ws.send('connect')
            try:
                await asyncio.wait_for(ws.wait_closed(), timeout=2.0)
            except asyncio.TimeoutError:
                return None  # still open == accepted
            return ws.close_code
    except Exception as err:  # refused during or right after the handshake
        rcvd = getattr(err, 'rcvd', None)  # ConnectionClosed.code is deprecated
        return getattr(rcvd, 'code', None) or getattr(err, 'code', None)


@pytest.mark.asyncio
async def test_live_listener_accepts_a_valid_token_and_registers_the_client():
    with _Listener(authenticator=TokenAuthenticator(GOOD_TOKEN)) as ctl:
        assert await _probe(ctl.ws_url('graph'), token=GOOD_TOKEN) is None
        # Server-side truth: the 'connect' frame reached the application. The
        # origin defect showed up exactly here, as a connection that looked
        # accepted from outside while the handler had already died.
        assert len(ctl.clients) == 1
        assert ctl.clients[0].auth_method == 'token'


@pytest.mark.asyncio
async def test_live_listener_refuses_a_bad_token():
    with _Listener(authenticator=TokenAuthenticator(GOOD_TOKEN)) as ctl:
        assert await _probe(ctl.ws_url('graph'),
                            token='y' * MIN_TOKEN_LEN) == WS_CLOSE_UNAUTHORIZED
        assert ctl.clients == []


@pytest.mark.asyncio
async def test_live_listener_refuses_a_missing_token():
    with _Listener(authenticator=TokenAuthenticator(GOOD_TOKEN)) as ctl:
        # The application frame is taken as the credential and fails as one, so
        # a client that skips authentication cannot slip a command through.
        assert await _probe(ctl.ws_url('graph')) == WS_CLOSE_UNAUTHORIZED
        assert ctl.clients == []


@pytest.mark.asyncio
async def test_live_listener_refuses_a_disallowed_origin():
    """The Origin allowlist, which was unreachable code under the asyncio API."""
    with _Listener(authenticator=TokenAuthenticator(GOOD_TOKEN)) as ctl:
        assert await _probe(ctl.ws_url('graph'), token=GOOD_TOKEN,
                            origin='http://evil.example') == WS_CLOSE_BAD_ORIGIN
        assert ctl.clients == []


@pytest.mark.asyncio
async def test_live_listener_accepts_an_allowed_origin():
    with _Listener(authenticator=TokenAuthenticator(GOOD_TOKEN)) as ctl:
        assert await _probe(ctl.ws_url('graph'), token=GOOD_TOKEN,
                            origin='http://127.0.0.1:8050') is None
        assert len(ctl.clients) == 1


@pytest.mark.asyncio
async def test_halt_closes_the_listener_and_unwinds_the_service():
    """Shutdown has to happen INSIDE the websocket loop while it still runs.

    `halt()` used to stop the loop and cancel `ws_stop` in the same breath, so
    the cancellation was never delivered: `_websocket_service` stayed suspended
    at `await self.ws_stop`, the `async with websocket_serve(...)` block never
    exited, and the listening socket was closed by nothing. Python finalized
    the coroutine during GC instead -- after the loop had been closed by its
    own `__del__` -- and `Server.close()` raised "Event loop is closed" out of a
    `GeneratorExit`, which surfaces as an unraisable exception (pytest reports
    it; an operator sees it as noise at ^C).

    Binding the port is the assertion that matters: it can only succeed if the
    listener was really closed, which only happens if `__aexit__` ran.
    """
    import socket as _socket
    listener = _Listener(authenticator=NullAuthenticator())
    with listener as ctl:
        port = ctl.ws_port
        assert await _probe(ctl.ws_url('graph')) is None

    assert ctl._ws_service.done(), 'the service coroutine was abandoned, not unwound'
    assert ctl._ws_sender.done(), 'the sender coroutine was abandoned, not unwound'
    assert ctl.ws_loop.is_closed(), 'the loop thread must close the loop it ran'
    with _socket.socket() as sock:
        # SO_REUSEADDR only forgives the TIME_WAIT left by the probe's own
        # connection; binding over a socket that is still LISTENing is still
        # EADDRINUSE, which is the leak this is looking for.
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        sock.bind(('127.0.0.1', port))


@pytest.mark.asyncio
async def test_live_listener_unauthenticated_default_still_accepts():
    """The default posture, end to end: no credential expected, and the first
    frame is the application's."""
    with _Listener(authenticator=NullAuthenticator()) as ctl:
        assert await _probe(ctl.ws_url('graph')) is None
        assert len(ctl.clients) == 1
        assert ctl.clients[0].auth_method == 'none'


class TestWebSocketOrigin:
    """`Origin` is read differently either side of the websockets asyncio
    rewrite, and `pyproject.toml` admits both."""

    def test_legacy_attribute_is_used(self):
        from autonomous_trust.inspector.dash_components.core import websocket_origin

        class Legacy:
            origin = 'http://legacy.example'

        assert websocket_origin(Legacy()) == 'http://legacy.example'

    def test_legacy_none_is_preserved_not_confused_with_absence(self):
        from autonomous_trust.inspector.dash_components.core import websocket_origin

        class Legacy:
            origin = None

        assert websocket_origin(Legacy()) is None

    def test_asyncio_request_headers_are_used(self):
        from autonomous_trust.inspector.dash_components.core import websocket_origin

        class Request:
            headers = {'Origin': 'http://modern.example'}

        class Modern:
            request = Request()

        assert websocket_origin(Modern()) == 'http://modern.example'

    def test_no_origin_header_is_none(self):
        from autonomous_trust.inspector.dash_components.core import websocket_origin

        class Request:
            headers = {}

        class Modern:
            request = Request()

        assert websocket_origin(Modern()) is None

    def test_neither_shape_is_none_not_an_error(self):
        from autonomous_trust.inspector.dash_components.core import websocket_origin
        assert websocket_origin(object()) is None
