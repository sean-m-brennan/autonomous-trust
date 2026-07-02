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
"""
from __future__ import annotations

import argparse
import tempfile

from .app import OperatorApp
from .bridge import OperatorNodeBridge
from . import demo as _demo


def parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog='autonomous_trust.operator')
    ap.add_argument('--demo', action='store_true',
                    help='run a mock node (seeded directory + synthetic results) '
                         'with a self-minted software-token activator')
    ap.add_argument('--software-cert', help='dev activator: leaf cert (PEM/DER)')
    ap.add_argument('--software-key', help='dev activator: leaf private key')
    ap.add_argument('--ca-bundle', help='ZTA CA bundle for the dev activator')
    ap.add_argument('--totp-secret', default='',
                    help='dev activator: base32 TOTP secret (enforces 2FA)')
    return ap.parse_args(argv)


def build_app(args: argparse.Namespace) -> OperatorApp:
    """Construct the console from parsed args without running it, so the
    entry-point wiring (``--demo``, dev activator) is testable headless."""
    activator = None
    if args.software_cert and args.software_key and args.ca_bundle:
        activator = _demo.software_activator_from_files(
            args.software_cert, args.software_key, args.ca_bundle,
            totp_secret=args.totp_secret)

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
        return OperatorApp(bridge=bridge, activator=activator, auto_start=True)
    return OperatorApp(activator=activator)


def main(argv=None) -> int:
    build_app(parse_args(argv)).run()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
