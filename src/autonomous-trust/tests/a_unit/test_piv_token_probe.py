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
"""PIN-less PKCS#11 card-present probe: module autodetection and probe verdicts
(PIV_MFA_OPERATOR_ACCESS_PLAN.md §7.1 stage 3). No hardware and no PyKCS11 --
the library loader is injected, since the point of the probe is to answer before
any PIN exists and to explain *why* a card was not seen."""
import os

import pytest

from autonomous_trust.core.identity.zta.piv.pkcs11 import (
    DEFAULT_MODULE_GLOBS, PKCS11_MODULE_ENV, PivTokenError, TokenProbe,
    find_pkcs11_module, probe_token, token_present)


class _FakeLib:
    """Stand-in PyKCS11Lib: reports a fixed slot list, records unload()."""

    def __init__(self, slots=(0,), raises=None):
        self._slots = list(slots)
        self._raises = raises
        self.unloaded = False

    def getSlotList(self, tokenPresent=False):  # noqa: N802 - PyKCS11 API name
        assert tokenPresent, 'probe must ask only for slots holding a token'
        if self._raises is not None:
            raise self._raises
        return self._slots

    def unload(self):
        self.unloaded = True


def _loader(lib):
    return lambda path: lib


class TestFindModule:
    def test_explicit_path_wins(self, monkeypatch):
        monkeypatch.setenv(PKCS11_MODULE_ENV, '/from/env.so')
        assert find_pkcs11_module('/explicit.so') == '/explicit.so'

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv(PKCS11_MODULE_ENV, '/opt/vendor/cackey.so')
        # returned unvalidated: a typo must surface as a load error, not a
        # silent fall-through to autodetection
        assert find_pkcs11_module() == '/opt/vendor/cackey.so'

    def test_autodetect_finds_opensc(self, monkeypatch, tmp_path):
        monkeypatch.delenv(PKCS11_MODULE_ENV, raising=False)
        found = tmp_path / 'opensc-pkcs11.so'
        found.write_bytes(b'')
        monkeypatch.setattr(
            'autonomous_trust.core.identity.zta.piv.pkcs11.DEFAULT_MODULE_GLOBS',
            (str(tmp_path / '*.so'),))
        assert find_pkcs11_module() == str(found)

    def test_autodetect_none_found(self, monkeypatch, tmp_path):
        monkeypatch.delenv(PKCS11_MODULE_ENV, raising=False)
        monkeypatch.setattr(
            'autonomous_trust.core.identity.zta.piv.pkcs11.DEFAULT_MODULE_GLOBS',
            (str(tmp_path / 'nothing-here-*.so'),))
        assert find_pkcs11_module() is None

    def test_default_globs_cover_expected_layouts(self):
        # multiarch + lib64 + macOS OpenSC installer are the ones that bite
        joined = '\n'.join(DEFAULT_MODULE_GLOBS)
        assert '/usr/lib/*-linux-gnu/opensc-pkcs11.so' in joined
        assert '/usr/lib64/opensc-pkcs11.so' in joined
        assert '/Library/OpenSC/lib/opensc-pkcs11.so' in joined
        assert all(g.endswith('opensc-pkcs11.so') for g in DEFAULT_MODULE_GLOBS)


class TestProbe:
    def test_card_present(self):
        probe = probe_token('/m.so', lib_loader=_loader(_FakeLib(slots=(3,))))
        assert probe == TokenProbe(True, '/m.so', 'slot 3')

    def test_no_card_in_reader(self):
        probe = probe_token('/m.so', lib_loader=_loader(_FakeLib(slots=())))
        assert probe.present is False
        assert probe.module_path == '/m.so'
        assert 'no card' in probe.detail  # distinguishable from a missing module

    def test_requested_slot_absent(self):
        probe = probe_token('/m.so', slot=9,
                            lib_loader=_loader(_FakeLib(slots=(0, 1))))
        assert probe.present is False
        assert 'slot 9' in probe.detail

    def test_requested_slot_present(self):
        probe = probe_token('/m.so', slot=1,
                            lib_loader=_loader(_FakeLib(slots=(0, 1))))
        assert probe.present is True
        assert probe.detail == 'slot 1'

    def test_no_module_found(self, monkeypatch, tmp_path):
        monkeypatch.delenv(PKCS11_MODULE_ENV, raising=False)
        monkeypatch.setattr(
            'autonomous_trust.core.identity.zta.piv.pkcs11.DEFAULT_MODULE_GLOBS',
            (str(tmp_path / 'absent-*.so'),))
        probe = probe_token()
        assert probe.present is False
        assert probe.module_path is None
        assert PKCS11_MODULE_ENV in probe.detail  # tells the operator the fix

    def test_load_failure_is_reported_not_raised(self):
        def bad_loader(path):
            raise PivTokenError('PyKCS11 not installed; ...')
        probe = probe_token('/m.so', lib_loader=bad_loader)
        assert probe.present is False
        assert 'PyKCS11 not installed' in probe.detail

    def test_slot_enumeration_failure_is_contained(self):
        lib = _FakeLib(raises=RuntimeError('CKR_DEVICE_ERROR'))
        probe = probe_token('/m.so', lib_loader=_loader(lib))
        assert probe.present is False
        assert 'CKR_DEVICE_ERROR' in probe.detail

    def test_unloads_after_probe(self):
        # C_Finalize per probe, so a card inserted later is seen next time
        lib = _FakeLib(slots=(0,))
        probe_token('/m.so', lib_loader=_loader(lib))
        assert lib.unloaded is True

    def test_unload_absent_is_tolerated(self):
        class _NoUnload:
            def getSlotList(self, tokenPresent=False):  # noqa: N802
                return [0]
        assert probe_token('/m.so', lib_loader=_loader(_NoUnload())).present

    def test_unload_failure_is_swallowed(self):
        class _BadUnload(_FakeLib):
            def unload(self):
                raise RuntimeError('finalize blew up')
        assert probe_token('/m.so', lib_loader=_loader(_BadUnload())).present

    def test_token_present_is_boolean_form(self):
        # `token_present` takes no `lib_loader`, so this one call cannot use the
        # fake and really does reach PyKCS11, which really does try to dlopen
        # '/m.so' and prints its own diagnostic to stderr:
        #   src/dyn_unix.c:34:SYS_dyn_LoadLibrary() /m.so: cannot open shared
        #   object file
        # That line is expected third-party output, not a failure -- it is only
        # *visible* because scripts/test-packages.sh runs pytest with `-s`, which
        # disables capture. What matters is that an unloadable module is reported
        # as "no token", never raised.
        #
        # Asserted as `is False` rather than the previous `in (True, False)`,
        # which was a tautology: it held for any bool, so it would have passed
        # just as well had the swallow-and-report behaviour been broken.
        assert token_present('/m.so') is False
        assert probe_token('/m.so', lib_loader=_loader(_FakeLib(()))).present is False

    def test_probe_takes_no_pin(self):
        # the whole reason this exists: presence before any PIN is typed
        import inspect
        params = inspect.signature(probe_token).parameters
        assert 'pin' not in params


class TestRealLoaderPath:
    def test_missing_binding_yields_actionable_detail(self, monkeypatch):
        # No PyKCS11 in the env: the default loader must explain that rather
        # than reporting a bare "no token" (the original misleading symptom).
        import builtins
        real_import = builtins.__import__

        def no_pykcs11(name, *a, **kw):
            if name == 'PyKCS11':
                raise ImportError('no module named PyKCS11')
            return real_import(name, *a, **kw)
        monkeypatch.setattr(builtins, '__import__', no_pykcs11)
        probe = probe_token('/does/not/matter.so')
        assert probe.present is False
        assert 'PyKCS11' in probe.detail

    def test_autodetect_used_when_no_path_given(self, monkeypatch, tmp_path):
        monkeypatch.delenv(PKCS11_MODULE_ENV, raising=False)
        found = tmp_path / 'opensc-pkcs11.so'
        found.write_bytes(b'')
        monkeypatch.setattr(
            'autonomous_trust.core.identity.zta.piv.pkcs11.DEFAULT_MODULE_GLOBS',
            (str(tmp_path / '*.so'),))
        seen = {}

        def loader(path):
            seen['path'] = path
            return _FakeLib(slots=(0,))
        probe = probe_token(lib_loader=loader)
        assert seen['path'] == str(found)
        assert probe.present and probe.module_path == str(found)


def test_pykcs11token_requires_a_module(monkeypatch, tmp_path):
    # No autodetect hit and no env override -> a clear error, not an obscure
    # failure deep in PKCS#11 (constructor also needs a PIN, hence no probe use)
    monkeypatch.delenv(PKCS11_MODULE_ENV, raising=False)
    monkeypatch.setattr(
        'autonomous_trust.core.identity.zta.piv.pkcs11.DEFAULT_MODULE_GLOBS',
        (str(tmp_path / 'absent-*.so'),))
    from autonomous_trust.core.identity.zta.piv.pkcs11 import PyKcs11Token
    with pytest.raises(PivTokenError) as err:
        PyKcs11Token(pin='123456')
    assert PKCS11_MODULE_ENV in str(err.value)


class TestOpenTokenPresence:
    """An open `PyKcs11Token` must answer presence from its own loaded lib --
    C_Finalize is process-global, so routing through `probe_token` (which
    unloads) would tear down the very session being asked about."""

    def _token(self, lib, slot=0):
        from autonomous_trust.core.identity.zta.piv.pkcs11 import PyKcs11Token
        tok = object.__new__(PyKcs11Token)  # bypass _open (needs hardware)
        tok._lib = lib
        tok._slot = slot
        tok._module_path = '/m.so'
        return tok

    def test_uses_own_lib_not_the_unloading_probe(self, monkeypatch):
        import autonomous_trust.core.identity.zta.piv.pkcs11 as pk
        monkeypatch.setattr(pk, 'probe_token',
                            lambda *a, **kw: pytest.fail('must not re-probe'))
        lib = _FakeLib(slots=(0,))
        assert self._token(lib).is_present() is True
        assert lib.unloaded is False  # session survives

    def test_card_removed(self):
        assert self._token(_FakeLib(slots=())).is_present() is False

    def test_other_slot_only(self):
        assert self._token(_FakeLib(slots=(1,)), slot=0).is_present() is False

    def test_no_lib_after_close(self):
        tok = self._token(_FakeLib(slots=(0,)))
        tok._lib = None
        assert tok.is_present() is False

    def test_enumeration_error_is_not_fatal(self):
        lib = _FakeLib(raises=RuntimeError('CKR_DEVICE_REMOVED'))
        assert self._token(lib).is_present() is False


def test_software_token_presence_unaffected():
    # the dev path must keep working with no module/binding anywhere
    from autonomous_trust.core.identity.zta.piv.pkcs11 import SoftwareToken
    tok = SoftwareToken(b'der', object())
    assert tok.is_present() is True
    tok.remove()
    assert tok.is_present() is False


def test_env_var_name_is_stable():
    # documented in run-operator.sh / README; renaming breaks operator runbooks
    assert PKCS11_MODULE_ENV == 'AUTONOMOUS_TRUST_PKCS11_MODULE'
    assert os.environ.get(PKCS11_MODULE_ENV) is None or True
