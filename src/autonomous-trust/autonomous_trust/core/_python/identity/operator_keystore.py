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
"""The operator's software keystore: where the one ed25519 key per human lives,
outside every node's config directory (FEATURE_SPLIT_PLAN Phase 6 kept it in
the core when operator activation moved to the operator distribution, because
first contact's device certs and backups use it with no PIV involved:
tools/device_cert.py, tools/backup.py).
"""
import os


def operator_key_path(keystore_dir: str = '') -> str:
    """Where the operator's ed25519 signing key lives.

    **Not in the node's config directory, deliberately.** One key per operator,
    stable across every node that human guards (ethne D24: per-node keys would let
    one person present as N guardians), which means a node that could read it could
    impersonate that human on all their other nodes. It belongs to the operator, so
    it lives with the operator: ``$AT_OPERATOR_KEYSTORE``, else
    ``$XDG_CONFIG_HOME/at-operator``, else ``~/.config/at-operator``.
    """
    base = (keystore_dir or os.environ.get('AT_OPERATOR_KEYSTORE', '')
            or os.path.join(os.environ.get(
                'XDG_CONFIG_HOME', os.path.expanduser('~/.config')),
                'at-operator'))
    return os.path.join(base, 'operator_ed25519.key')


def load_or_create_operator_key(keystore_dir: str = '') -> tuple:
    """Return ``(private_key_hex, public_key_bytes)`` for this operator, creating
    the key on first use.

    Stored 0600 in a 0700 directory, hex-encoded to match how every other key in
    this tree is persisted (`Signature.to_dict`). Created only when an operator
    asks to bind one — see `activate(bind_operator_key=True)`.
    """
    from nacl.encoding import HexEncoder
    from .sign import Signature  # local: heavy import
    path = operator_key_path(keystore_dir)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    if os.path.isfile(path):
        with open(path, 'rb') as fp:
            hex_seed = fp.read().strip()
        sig = Signature(hex_seed, public_only=False)
    else:
        sig = Signature.generate()
        hex_seed = sig.private.encode(encoder=HexEncoder)
        with open(path, 'wb') as fp:
            fp.write(hex_seed)
        os.chmod(path, 0o600)
    return hex_seed, bytes(sig.public)
