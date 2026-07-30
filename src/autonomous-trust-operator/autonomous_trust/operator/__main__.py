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
"""Launch the AutonomousTrust Operator console.

    python -m autonomous_trust.operator              # real node bridge
    python -m autonomous_trust.operator --demo       # mock node + software PIV

``--demo`` runs a ``DemoNode`` (seeded directory; answers submitted tasks with
synthetic results) and a self-minted software-token activator (plan §7.1), so the
whole flow -- activate, browse, submit, see a verified result -- works with no
card, cohort, or network. ``--software-cert/-key/--ca-bundle`` wire the same
software-token activator against on-disk PKI for dev/CI against a real directory.

With no token flags the console reports **live card presence** via a PIN-less
PKCS#11 probe against an autodetected ``opensc-pkcs11.so`` (plan §7.1 stage 3);
override the module with ``$AUTONOMOUS_TRUST_PKCS11_MODULE`` when the middleware
lives elsewhere (vendor module / CACKey).

``--ca-bundle`` **alone** (no software cert/key) activates against that live card:
the PIN opens a PKCS#11 session, the card signs the challenge, and its cert chain
is verified against the bundle -- which may be PEM, DER, or a PKCS#7 ``.p7b``.
"""
from __future__ import annotations

import argparse
import tempfile
from typing import Any, Callable

from .app import OperatorApp
from .bridge import OperatorNodeBridge
from . import demo as _demo


def live_token_provider() -> Callable[[], Any]:
    """A ``callable() -> TokenProbe`` reporting live card presence with no PIN.

    Imported lazily and degraded to a "no token" answer if the ZTA/PIV module is
    unavailable, so the console still starts on a box without PKCS#11 support.
    """
    def probe():
        from autonomous_trust.core.identity.zta.piv.pkcs11 import probe_token
        return probe_token()
    return probe


def software_token_provider(token: Any) -> Callable[[], Any]:
    """Presence for the dev/demo software token -- labeled as such so the status
    line never implies a real card is in a reader."""
    from autonomous_trust.core.identity.zta.piv.pkcs11 import TokenProbe

    def probe():
        return TokenProbe(bool(token.is_present()), None, 'software token (dev)')
    return probe


class _TokenError:
    """Activation outcome when the card could not be opened at all -- shaped like
    an ``ActivationResult`` (``.status``/``.reason``) for the Activate view."""

    def __init__(self, status: str, reason: str) -> None:
        self.status = status
        self.reason = reason


def live_card_activator(ca_bundle_path: str,
                        module_path: str = '',
                        slot: Any = None,
                        crl_path: str = '',
                        totp_secret: str = '',
                        token_factory: Any = None) -> Callable[[str, str], Any]:
    """An ``activator(pin, mfa)`` that runs activation against the **live PIV
    card**: the PIN opens a PKCS#11 session (`PyKcs11Token`), the card signs the
    server-issued challenge, and the cert chain is verified against
    ``ca_bundle_path`` (plan §7.1 stage 3).

    The token is opened per activation and **closed immediately afterwards**: the
    PIN is held only for the login, and no PKCS#11 session outlives the call --
    which also keeps the status line's `probe_token` safe to run, since its
    process-global C_Finalize would otherwise tear down a live session.

    :param token_factory: ``callable(module_path, pin, slot) -> PivToken`` seam
        for tests; defaults to `PyKcs11Token`.
    """
    def activate(pin: str, mfa: str):
        from autonomous_trust.core.identity.zta.piv.pkcs11 import (
            PivTokenError, PyKcs11Token)
        factory = token_factory or PyKcs11Token
        try:
            token = factory(module_path or None, pin, slot)
        except PivTokenError as err:
            text = str(err)
            # A refused PIN is an authentication failure; anything else (no
            # module, no card, no binding) is the verifier being unable to run.
            status = 'REJECTED' if 'PIN' in text else 'UNAVAILABLE'
            return _TokenError(status, text)
        except Exception as err:  # defensive: a middleware crash must not kill the UI
            return _TokenError('UNAVAILABLE', 'could not open PIV token: %s' % err)
        try:
            from autonomous_trust.core.operator.activate import activate as core
            return core(token, ca_bundle_path, crl_path=crl_path,
                        totp_secret=totp_secret, totp_code=mfa or '')
        finally:
            try:
                token.close()  # logout + drop the session; never persist the PIN
            except Exception:
                pass
    return activate


def parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog='autonomous_trust.operator')
    ap.add_argument('--demo', action='store_true',
                    help='run a mock node (seeded directory + synthetic results) '
                         'with a self-minted software-token activator')
    ap.add_argument('--software-cert', help='dev activator: leaf cert (PEM/DER)')
    ap.add_argument('--software-key', help='dev activator: leaf private key')
    ap.add_argument('--ca-bundle', help='ZTA CA bundle for the dev activator')
    ap.add_argument('--totp-secret', default='',
                    help='base32 TOTP secret (enforces 2FA)')
    ap.add_argument('--pkcs11-module', default='',
                    help='live card: PKCS#11 module path (default: autodetected '
                         'opensc-pkcs11.so, or $AUTONOMOUS_TRUST_PKCS11_MODULE)')
    ap.add_argument('--slot', type=int, default=None,
                    help='live card: PKCS#11 slot index (default: first with a token)')
    ap.add_argument('--crl-path', default='',
                    help='CRL for revocation checks (PEM or DER)')
    return ap.parse_args(argv)


def build_app(args: argparse.Namespace) -> OperatorApp:
    """Construct the console from parsed args without running it, so the
    entry-point wiring (``--demo``, dev activator) is testable headless."""
    activator = None
    if args.software_cert and args.software_key and args.ca_bundle:
        activator = _demo.software_activator_from_files(
            args.software_cert, args.software_key, args.ca_bundle,
            totp_secret=args.totp_secret)
    elif args.ca_bundle and not args.demo:
        # A CA bundle with no software cert+key means the token is the card in the
        # reader: everything activation needs is then present (chain to verify
        # against + a PIN-unlockable key on the card), so wire the live activator.
        activator = live_card_activator(
            args.ca_bundle, module_path=args.pkcs11_module, slot=args.slot,
            crl_path=args.crl_path, totp_secret=args.totp_secret)

    if args.demo:
        directory = _demo.demo_directory()
        # A self-minted software-token activator so demo activation really
        # VERIFIES (best-effort: falls back to the app's stub if PKI minting
        # is unavailable, e.g. cryptography missing).
        if activator is None:
            try:
                token, ca_bundle = _demo.mint_demo_pki(tempfile.mkdtemp())
                activator = _demo.software_activator(token, ca_bundle)
            except Exception:
                activator = None
        bridge = OperatorNodeBridge(node_factory=lambda: _demo.DemoNode(directory))
        return OperatorApp(bridge=bridge, activator=activator, auto_start=True,
                           token_provider=_token_provider_for(activator))
    return OperatorApp(activator=activator,
                       token_provider=_token_provider_for(activator))


def _token_provider_for(activator: Any) -> Callable[[], Any]:
    """Presence follows the token actually in use: the software token when one is
    wired (``--demo`` / ``--software-cert``), otherwise the live card probe."""
    token = getattr(activator, 'token', None)
    if token is not None and callable(getattr(token, 'is_present', None)):
        return software_token_provider(token)
    return live_token_provider()


def main(argv=None) -> int:
    build_app(parse_args(argv)).run()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
