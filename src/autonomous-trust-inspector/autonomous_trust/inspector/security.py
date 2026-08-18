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
"""Transport security and client authentication for the inspector's servers.

The inspector serves a dashboard and streams live mesh state over WebSockets.
Until now that traffic was plaintext with no client authentication: the only
protections were an `Origin` allowlist and a loopback bind, neither of which
survives a deployment that publishes the port -- which
`deploy/multi_agency/docker-compose.yaml` and the Kubernetes Service both do.

Two mechanisms live here, and they are deliberately independent:

* **TLS** (:class:`InspectorTLS`) -- wraps every listener when a certificate is
  configured. Off by default, because the default deployment is a loopback bind
  where a certificate would only be ceremony.
* **Client authentication** (:class:`Authenticator`) -- a shared bearer token
  checked at connect time. Also off by default.
* **Exposure** (:class:`SocketExposure`) -- which address the WebSocket listener
  binds, and therefore which address it may advertise. Loopback by default, and
  the two values are derived from one so they cannot disagree.

Both are **opt-in but fail-closed**: unconfigured means today's behavior exactly,
while *half*-configured (a certificate without its key, say) refuses to start.
Silently serving plaintext to an operator who asked for TLS is the one outcome
worth crashing to avoid.

The token check sits behind :class:`Authenticator` so that the stronger schemes
already present elsewhere in this tree -- an `OperatorSession` issued by the
PIV+MFA flow (`doc/architecture/operator-access.md`), or an mTLS client
certificate chaining to the configured ZTA anchors
(`doc/architecture/zta-integration.md`) -- can replace it without touching a
single connection handler. A shared token is the weakest of the three; it is
here because it needs no provisioning, and the seam is here so it need not be
the last word.
"""
import hmac
import logging
import os
import ssl
from typing import Optional

logger = logging.getLogger(__name__)

#: Filesystem paths to the server certificate and its private key. Both or
#: neither: see :meth:`InspectorTLS.from_env`.
ENV_TLS_CERT = 'AT_INSPECTOR_TLS_CERT'
ENV_TLS_KEY = 'AT_INSPECTOR_TLS_KEY'
#: Optional passphrase for an encrypted key. Absent means the key is unencrypted.
ENV_TLS_KEY_PASSWORD = 'AT_INSPECTOR_TLS_KEY_PASSWORD'
#: Optional CA bundle. Present ONLY to make the mTLS upgrade a configuration
#: change rather than a code change; nothing requires client certificates today.
ENV_TLS_CLIENT_CA = 'AT_INSPECTOR_TLS_CLIENT_CA'
#: Shared bearer token a WebSocket client must present. Absent = no auth.
ENV_WS_TOKEN = 'AT_INSPECTOR_WS_TOKEN'
#: Address the `DashControl` WebSocket listener binds. Absent = loopback, which
#: is where it has always bound. See :class:`SocketExposure`.
ENV_WS_BIND = 'AT_INSPECTOR_WS_BIND'

#: Addresses that reach a listener only from the machine it runs on. `''` is
#: included because an empty bind means loopback to `websockets`, not a wildcard.
LOOPBACK_HOSTS = frozenset({'127.0.0.1', 'localhost', '::1', ''})
#: Wildcard binds accept on every interface and are therefore not addresses a
#: client can be handed -- see :meth:`SocketExposure.advertise_host`.
WILDCARD_HOSTS = frozenset({'0.0.0.0', '::', '*'})

#: WebSocket close code for a client that did not authenticate. 4401 rather than
#: 1008 (policy violation) so an operator reading a browser console can tell
#: "you are not authenticated" from any other policy refusal; the 44xx range is
#: application-private, and 4401 echoes HTTP 401 on purpose.
WS_CLOSE_UNAUTHORIZED = 4401
#: WebSocket close code for a disallowed `Origin`. Pre-existing value, kept.
WS_CLOSE_BAD_ORIGIN = 4003

#: A token shorter than this is refused at construction. Not a strength
#: estimate -- it catches the placeholder ("changeme", "token", an empty
#: string left by a template) that would otherwise look like security.
MIN_TOKEN_LEN = 16


class SecurityConfigError(RuntimeError):
    """Configuration that cannot be honored as written.

    Raised rather than warned-and-ignored: every instance means an operator
    asked for a protection that would not actually be applied.
    """


class InspectorTLS(object):
    """Server-side TLS for the inspector's listeners, or nothing at all.

    ``enabled`` is False in the default configuration, and every accessor is
    safe to call in that state -- callers ask for a context and get ``None``,
    which is what both `websockets` and Quart want when TLS is off.
    """

    def __init__(self, certfile: str = None, keyfile: str = None,
                 password: str = None, client_ca: str = None):
        self.certfile = certfile
        self.keyfile = keyfile
        self._password = password
        self.client_ca = client_ca
        if bool(certfile) != bool(keyfile):
            # The dangerous asymmetry: cert-without-key would fall through to a
            # plaintext listener on a port the operator believes is encrypted.
            have, missing = ((ENV_TLS_CERT, ENV_TLS_KEY) if certfile
                             else (ENV_TLS_KEY, ENV_TLS_CERT))
            raise SecurityConfigError(
                'inspector TLS is half-configured: %s is set but %s is not. '
                'Set both to serve TLS, or neither to serve plaintext on the '
                'loopback bind; refusing to start a listener that is neither.'
                % (have, missing))
        for label, path in (('certificate', certfile), ('private key', keyfile),
                            ('client CA bundle', client_ca)):
            if path and not os.path.isfile(path):
                raise SecurityConfigError(
                    'inspector TLS %s not found at %r (cwd %r). The path is '
                    'read verbatim from the environment; a container needs it '
                    'mounted, not merely present on the host.'
                    % (label, path, os.getcwd()))
        if client_ca and not certfile:
            raise SecurityConfigError(
                '%s is set without %s: client certificates cannot be verified '
                'on a plaintext listener.' % (ENV_TLS_CLIENT_CA, ENV_TLS_CERT))

    @classmethod
    def from_env(cls, env: dict = None) -> 'InspectorTLS':
        """Read the TLS configuration from the process environment."""
        env = os.environ if env is None else env
        return cls(certfile=env.get(ENV_TLS_CERT) or None,
                   keyfile=env.get(ENV_TLS_KEY) or None,
                   password=env.get(ENV_TLS_KEY_PASSWORD) or None,
                   client_ca=env.get(ENV_TLS_CLIENT_CA) or None)

    @property
    def enabled(self) -> bool:
        return bool(self.certfile and self.keyfile)

    @property
    def requires_client_cert(self) -> bool:
        return bool(self.client_ca)

    def ws_scheme(self) -> str:
        return 'wss' if self.enabled else 'ws'

    def http_scheme(self) -> str:
        return 'https' if self.enabled else 'http'

    def context(self) -> Optional[ssl.SSLContext]:
        """A server :class:`ssl.SSLContext`, or ``None`` when TLS is off.

        A fresh context per call: `websockets` and Quart each own the one they
        are given, and sharing one across listeners couples their lifetimes for
        no benefit.
        """
        if not self.enabled:
            return None
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        # TLS 1.2 is the floor. Python's default already refuses SSLv3/TLS1.0,
        # but saying so here means a future interpreter default cannot quietly
        # lower it.
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.load_cert_chain(self.certfile, self.keyfile, password=self._password)
        except (ssl.SSLError, OSError) as err:
            raise SecurityConfigError(
                'inspector TLS certificate/key at %r/%r could not be loaded: '
                '%s. A mismatched pair and an encrypted key with no %s both '
                'land here.' % (self.certfile, self.keyfile, err,
                                ENV_TLS_KEY_PASSWORD))
        if self.client_ca:
            ctx.load_verify_locations(cafile=self.client_ca)
            ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def unsupported_by_paths_only(self) -> list[str]:
        """Configured options a listener that takes only cert/key paths drops.

        Quart's `app.run` (and the hypercorn config it builds) accepts a
        certificate and a key *path* and nothing else: there is no argument for
        a key passphrase and none that turns `ca_certs` into an actual
        requirement. Both settings would therefore be accepted and then not
        applied -- the client-CA case being a genuine downgrade, since the
        operator believes client certificates are being verified. A caller in
        that position asks this and refuses to start.
        """
        if not self.enabled:
            return []
        unsupported = []
        if self._password:
            unsupported.append(ENV_TLS_KEY_PASSWORD)
        if self.client_ca:
            unsupported.append(ENV_TLS_CLIENT_CA)
        return unsupported

    def describe(self) -> str:
        """One line an operator can act on, for the startup log."""
        if not self.enabled:
            return ('TLS off (set %s and %s to enable); traffic is plaintext, '
                    'so bind loopback or terminate TLS in front'
                    % (ENV_TLS_CERT, ENV_TLS_KEY))
        detail = 'TLS on, cert %s' % self.certfile
        if self.client_ca:
            detail += ', client certificates REQUIRED against %s' % self.client_ca
        return detail


class SocketExposure(object):
    """Where the WebSocket listener binds, and therefore what it advertises.

    These were two independent values, and they disagreed: the listener bound
    `127.0.0.1` while `DashControl.ws_url()` handed out the host's routable
    address, so every client that was not on the server's own machine received
    an address nothing was listening on. Nobody noticed because the live
    dashboard's socket is `viz`'s `/ws` on the page's own origin, leaving the
    system tests as the only clients of this listener.

    The fix is structural rather than a corrected string: bind address and
    advertised address are derived from **one** value here, so they cannot drift
    apart again. The invariant is that the advertised host is always one the
    listener actually accepts on.

    The default is loopback, exactly as before. Moving the bind is a deliberate
    act with a deliberate consequence, which is why :meth:`validate` refuses an
    exposed listener that no credential guards.
    """

    default_bind = '127.0.0.1'

    def __init__(self, bind_host: str = None):
        self.bind_host = self.default_bind if bind_host is None else bind_host.strip()

    @classmethod
    def from_env(cls, env: dict = None) -> 'SocketExposure':
        env = os.environ if env is None else env
        return cls(env.get(ENV_WS_BIND) or None)

    @property
    def is_loopback(self) -> bool:
        return self.bind_host in LOOPBACK_HOSTS

    @property
    def is_wildcard(self) -> bool:
        return self.bind_host in WILDCARD_HOSTS

    @property
    def exposed(self) -> bool:
        """True when something other than this machine can reach the listener."""
        return not self.is_loopback

    def advertise_host(self, routable: str = None) -> str:
        """The host to hand a client, which the listener is guaranteed to accept.

        A wildcard bind is the one case where the advertised address cannot
        simply *be* the bind address -- `0.0.0.0` is not somewhere a client can
        connect. The routable address is used instead, and that remains truthful
        precisely because a wildcard listener does accept there. Everything else
        advertises what it binds, verbatim.
        """
        if self.is_wildcard:
            return routable or self.default_bind
        if self.bind_host == '':
            return self.default_bind
        return self.bind_host

    def validate(self, authenticator: 'Authenticator', tls: InspectorTLS,
                 log: logging.Logger = None) -> None:
        """Refuse an exposed listener with no client authentication.

        A loopback listener is already reachable only by processes on the host,
        so the previous default needs nothing new to stay as safe as it was.
        Moving the bind off loopback puts a socket that streams live mesh state
        -- and accepts inbound frames the dashboard acts on -- in front of
        whoever can route to it. Requiring a credential there is strict from the
        outset because this setting is new: no existing deployment can be broken
        by the requirement, and the alternative is a knob whose only effect is to
        publish an unauthenticated feed.

        Missing TLS on an exposed bind warns rather than refuses: terminating
        TLS in a proxy ahead of a private-network bind is a legitimate
        deployment, and one this code cannot distinguish from a careless one.
        """
        if not self.exposed:
            return
        if not authenticator.required:
            raise SecurityConfigError(
                '%s is set to %r, which accepts connections from beyond this '
                'machine, but no client authentication is configured. Set %s to '
                'require a credential, or leave %s unset to keep the listener on '
                'loopback; refusing to publish an unauthenticated live feed.'
                % (ENV_WS_BIND, self.bind_host, ENV_WS_TOKEN, ENV_WS_BIND))
        if not tls.enabled:
            # Falls back to this module's logger rather than dropping the
            # warning: the caller's logger is optional, and "exposed without
            # TLS" is the last thing that should go unsaid because of that.
            (log or logger).warning(
                'inspector websocket is bound to %s (reachable off-host) '
                'without TLS: the bearer token and every frame cross the '
                'network in cleartext. Set %s and %s, or terminate TLS in front '
                'of this listener.', self.bind_host, ENV_TLS_CERT, ENV_TLS_KEY)

    def describe(self) -> str:
        """One line an operator can act on, for the startup log."""
        if self.is_loopback:
            return ('bound to %s (this machine only; set %s to expose it)'
                    % (self.bind_host or self.default_bind, ENV_WS_BIND))
        return 'bound to %s — REACHABLE OFF-HOST' % self.bind_host


def ws_exposure_from_env(env: dict = None) -> SocketExposure:
    """The listener exposure this process is configured for."""
    return SocketExposure.from_env(env)


class AuthResult(object):
    """Outcome of one authentication attempt.

    Carries the reason as well as the verdict: a refusal an operator cannot
    diagnose from the log is a support ticket.
    """

    __slots__ = ('ok', 'reason')

    def __init__(self, ok: bool, reason: str = ''):
        self.ok = ok
        self.reason = reason

    def __bool__(self) -> bool:
        return self.ok

    def __repr__(self) -> str:
        return 'AuthResult(ok=%r, reason=%r)' % (self.ok, self.reason)


OK = AuthResult(True)


class Authenticator(object):
    """The seam a connection handler talks to.

    Subclasses decide what a credential is. ``required`` tells a handler
    whether to expect a credential frame at all -- the handler must not read
    one when authentication is off, because that frame position belongs to the
    application protocol (`viz/js/force.js` sends its graph selector first).
    """

    required = False
    name = 'none'

    def verify(self, credential, origin: str = None, peer: str = None) -> AuthResult:
        raise NotImplementedError

    def describe(self) -> str:
        raise NotImplementedError

    def page_credential(self) -> str:
        """What the server may embed in a page it serves, or ''.

        A shared token can travel this way; a session token or a client
        certificate cannot and must not, so the default is nothing. Asking the
        authenticator keeps that judgement with the mechanism instead of in
        every template that renders a socket URL.
        """
        return ''


class NullAuthenticator(Authenticator):
    """No client authentication: every connection is accepted.

    The default, and correct for a loopback-bound dashboard on a developer
    machine. It is a *named* class rather than a ``None`` check so that
    "unauthenticated" is a visible state in logs and tests.
    """

    required = False
    name = 'none'

    def verify(self, credential, origin: str = None, peer: str = None) -> AuthResult:
        return OK

    def describe(self) -> str:
        return ('client authentication off (set %s to require a bearer token); '
                'any client that passes the Origin check may connect'
                % ENV_WS_TOKEN)


class TokenAuthenticator(Authenticator):
    """A single shared bearer token, compared in constant time.

    The weakest of the three schemes sketched in this module's docstring, and
    the only one needing no provisioning. Its honest limits: one secret for
    every viewer, no revocation short of restarting with a new value, and no
    notion of *which* human is connected. When any of those matters, replace
    this object -- not the handlers.
    """

    required = True
    name = 'token'

    def __init__(self, token: str):
        if not token:
            raise SecurityConfigError(
                '%s is empty; unset it to disable authentication rather than '
                'setting it to nothing, which would accept the empty string as '
                'a credential.' % ENV_WS_TOKEN)
        if len(token) < MIN_TOKEN_LEN:
            raise SecurityConfigError(
                '%s is %d characters; at least %d are required. A short value '
                'is usually a placeholder left in a template, which reads as '
                'protection while providing none.'
                % (ENV_WS_TOKEN, len(token), MIN_TOKEN_LEN))
        self._token = token.encode('utf-8')

    def verify(self, credential, origin: str = None, peer: str = None) -> AuthResult:
        if credential is None:
            return AuthResult(False, 'no credential offered')
        if isinstance(credential, (bytes, bytearray)):
            offered = bytes(credential)
        elif isinstance(credential, str):
            offered = credential.encode('utf-8')
        else:
            return AuthResult(False, 'credential of unusable type %s'
                                     % type(credential).__name__)
        # compare_digest over the raw bytes: it is the length-independent
        # comparison, and it must see the ENCODED forms so a unicode
        # normalization difference cannot become a timing signal.
        if hmac.compare_digest(offered, self._token):
            return OK
        return AuthResult(False, 'token mismatch')

    def describe(self) -> str:
        return 'client authentication ON (shared bearer token from %s)' % ENV_WS_TOKEN

    def page_credential(self) -> str:
        return self._token.decode('utf-8')


def authenticator_from_env(env: dict = None) -> Authenticator:
    """The authenticator this process is configured for.

    Absent token -> :class:`NullAuthenticator`, which is today's behavior.
    """
    env = os.environ if env is None else env
    token = env.get(ENV_WS_TOKEN)
    if not token:
        return NullAuthenticator()
    return TokenAuthenticator(token)


class AuthLogLimiter(object):
    """Rate-limits per-peer refusal logging.

    A rejected client typically retries in a loop, and one line per attempt
    turns a misconfiguration into a log outage that hides the very message
    explaining it. First refusal per peer is logged in full; after that, one
    line per ``every`` attempts, carrying the running count so the volume is
    still visible. Mirrors the 1-in-100 discipline the video receivers use for
    their own flood-prone drop path.
    """

    def __init__(self, every: int = 50):
        self.every = max(1, every)
        self.counts: dict = {}

    def should_log(self, peer: str) -> tuple[bool, int]:
        n = self.counts.get(peer, 0) + 1
        self.counts[peer] = n
        return (n == 1 or n % self.every == 0), n

    def clear(self, peer: str) -> None:
        """Forget a peer's refusals, called on a successful connect so a
        transient misconfiguration does not permanently suppress its own
        diagnostics."""
        self.counts.pop(peer, None)
