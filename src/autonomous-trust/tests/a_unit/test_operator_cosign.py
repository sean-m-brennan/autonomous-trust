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
"""Out-of-band co-signing with the operator key.

A governance tier above AT (ethne charters a node→guardian edge and requires the named
guardian to co-sign it) exports the bytes of a record and needs this operator's
signature over them. The key must not travel to do that — it lives in the operator's
own keystore precisely so a node that could read it could not impersonate that human on
their other nodes — so what travels is the payload one way and the signature back.

These also cover the keystore functions themselves, which the operator-key slice built
and left untested.
"""
import os
import stat
import subprocess
import sys

import pytest
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from autonomous_trust.core._python.operator.activate import (
    load_or_create_operator_key,
    operator_key_path,
    operator_public_key,
    sign_with_operator_key,
)

PAYLOAD = b'canonical bytes of some governance record'


@pytest.fixture
def keystore(tmp_path):
    """An operator keystore with a bound key, as `--bind-operator-key` leaves it."""
    d = str(tmp_path / 'at-operator')
    load_or_create_operator_key(d)
    return d


# --- the keystore the co-signature rests on -----------------------------------

def test_the_key_is_created_once_and_is_stable(tmp_path):
    d = str(tmp_path / 'ks')
    first_seed, first_pub = load_or_create_operator_key(d)
    second_seed, second_pub = load_or_create_operator_key(d)
    # One key per operator, stable across every node they guard: a second call must
    # not mint a second identity.
    assert first_seed == second_seed and first_pub == second_pub
    assert len(first_pub) == 32


def test_the_key_file_is_private_and_outside_any_node_config(tmp_path):
    d = str(tmp_path / 'ks')
    load_or_create_operator_key(d)
    path = operator_key_path(d)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, oct(mode)
    assert stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode) == 0o700


def test_the_default_path_is_the_operators_not_the_nodes(monkeypatch):
    monkeypatch.setenv('AT_OPERATOR_KEYSTORE', '/tmp/explicit-keystore')
    assert operator_key_path().startswith('/tmp/explicit-keystore')
    monkeypatch.delenv('AT_OPERATOR_KEYSTORE')
    monkeypatch.setenv('XDG_CONFIG_HOME', '/tmp/xdg')
    assert operator_key_path() == '/tmp/xdg/at-operator/operator_ed25519.key'


# --- co-signing ---------------------------------------------------------------

def test_a_signature_verifies_under_the_published_public_key(keystore):
    sig = sign_with_operator_key(PAYLOAD, keystore)
    assert len(sig) == 64
    VerifyKey(operator_public_key(keystore)).verify(PAYLOAD, sig)


def test_a_signature_over_other_bytes_does_not_verify(keystore):
    """The negative half: without it, the test above would pass against a verify that
    accepted anything."""
    sig = sign_with_operator_key(PAYLOAD, keystore)
    with pytest.raises(BadSignatureError):
        VerifyKey(operator_public_key(keystore)).verify(b'different bytes', sig)


def test_signing_is_deterministic_so_both_sides_agree_byte_for_byte(keystore):
    """ed25519 signatures are deterministic, which is what lets the governance tier
    pin a cross-library test vector rather than trusting a live round trip."""
    assert sign_with_operator_key(PAYLOAD, keystore) == sign_with_operator_key(PAYLOAD, keystore)


def test_signing_without_a_bound_key_refuses_rather_than_minting_one(tmp_path):
    """A fresh key would produce a signature no node's binding attests to — a
    signature that names a human nobody agreed was there."""
    empty = str(tmp_path / 'never-bound')
    with pytest.raises(FileNotFoundError, match='bind-operator-key'):
        sign_with_operator_key(PAYLOAD, empty)
    with pytest.raises(FileNotFoundError):
        operator_public_key(empty)
    # And it really did not create one.
    assert not os.path.exists(operator_key_path(empty))


def test_the_public_key_is_raw_bytes_not_an_identifier_format(keystore):
    """AT has no business knowing how the tier above names a key: it publishes the raw
    ed25519 public key, and ethne derives a did:key from exactly these bytes."""
    pub = operator_public_key(keystore)
    assert isinstance(pub, bytes) and len(pub) == 32
    _seed, from_keystore = load_or_create_operator_key(keystore)
    assert pub == from_keystore


# --- the CLI verbs ------------------------------------------------------------

def _cli(*args, stdin=None):
    return subprocess.run(
        [sys.executable, '-m', 'autonomous_trust.core._python.operator', *args],
        capture_output=True, input=stdin,
        env={**os.environ, 'PYTHONPATH': os.pathsep.join(sys.path)},
    )


def test_the_sign_verb_needs_no_card_and_no_ca_bundle(keystore, tmp_path):
    """The co-signing verbs touch only the keystore. Demanding a PIV token or a CA
    bundle for them would be a lie about what they need — and would make the seam
    unusable exactly where it matters, on a machine with no reader attached."""
    f = tmp_path / 'payload.bin'
    f.write_bytes(PAYLOAD)
    r = _cli('--operator-keystore', keystore, '--sign-file', str(f))
    assert r.returncode == 0, r.stderr.decode()
    sig = bytes.fromhex(r.stdout.decode().strip())
    VerifyKey(operator_public_key(keystore)).verify(PAYLOAD, sig)
    # It says what it signed, so the operator can compare against the description the
    # exporting tier showed them.
    assert b'sha256=' in r.stderr and b'%d bytes' % len(PAYLOAD) in r.stderr


def test_the_sign_verb_reads_stdin(keystore):
    r = _cli('--operator-keystore', keystore, '--sign-file', '-', stdin=PAYLOAD)
    assert r.returncode == 0, r.stderr.decode()
    VerifyKey(operator_public_key(keystore)).verify(
        PAYLOAD, bytes.fromhex(r.stdout.decode().strip()))


def test_the_print_key_verb_agrees_with_the_library(keystore):
    r = _cli('--operator-keystore', keystore, '--print-operator-key')
    assert r.returncode == 0, r.stderr.decode()
    assert bytes.fromhex(r.stdout.decode().strip()) == operator_public_key(keystore)


def test_activation_still_requires_its_ca_bundle(tmp_path):
    """NEGATIVE CONTROL for relaxing `--ca-bundle`: making it optional must not make
    it optional for the thing that actually needs it."""
    r = _cli('--module', '/nonexistent.so')
    assert r.returncode != 0
    assert b'--ca-bundle is required' in r.stderr


def test_a_missing_payload_file_is_named(keystore):
    r = _cli('--operator-keystore', keystore, '--sign-file', '/no/such/payload')
    assert r.returncode == 2
    assert b'/no/such/payload' in r.stderr
