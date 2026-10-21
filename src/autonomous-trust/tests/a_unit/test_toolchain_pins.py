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
"""The conda toolchain pin is stated in seven places; this fails when they drift.

A working docker build broke because every conda input floated --
an untagged `FROM condaforge/miniforge3`, an unbounded base-env install that
dragged conda forward with it, a `releases/latest/download` installer, and
`miniforge-version: latest` in CI. The fix records one pin in
`config/cfg/toolchain-pins.env`; the risk it introduces is that six consumers
now restate that value and can be edited apart, which would silently return one
build path to floating.

Docker cannot run in the sandbox, so these are the only checks of that fix that
execute anywhere cheap. They deliberately assert the *shape* of a pin (tag AND
digest, since Miniforge re-pushes tags) rather than one particular version, so
moving the pin needs one edit per file and no test edits.
"""
import os
import re

import pytest

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                     '..', '..', '..', '..'))
_PINS = os.path.join(_REPO, 'config', 'cfg', 'toolchain-pins.env')

if not os.path.exists(_PINS):        # installed package, not a source checkout
    pytest.skip('config/cfg/toolchain-pins.env not present',
                allow_module_level=True)

# Every Dockerfile that builds FROM the conda base image.
_DOCKERFILES = (
    os.path.join('src', 'autonomous-trust', 'Dockerfile-devel'),
    os.path.join('src', 'autonomous-trust', 'Dockerfile'),
    os.path.join('src', 'Dockerfile-build'),
)

_WORKFLOWS = (
    os.path.join('.github', 'workflows', 'tests.yml'),
    os.path.join('.github', 'workflows', 'conformance.yml'),
)


def _read(rel):
    with open(os.path.join(_REPO, rel)) as f:
        return f.read()


def _pins():
    """Parse the pins file the way `source` would, minus the comments."""
    values = {}
    for line in _read(os.path.join('config', 'cfg', 'toolchain-pins.env')).splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, _, val = line.partition('=')
        values[key.strip()] = val.strip()
    return values


class TestPinsFile:
    def test_the_three_values_are_present(self):
        pins = _pins()
        assert set(pins) >= {'MINIFORGE_VERSION', 'MINIFORGE_DIGEST',
                             'MINIFORGE_IMAGE'}, pins

    def test_the_image_is_pinned_by_tag_and_digest(self):
        # A tag alone is not a pin: Miniforge re-pushed 26.3.2-3's image months
        # after its release, which is how an unchanged tag delivered new conda
        # packages.
        image = _pins()['MINIFORGE_IMAGE']
        assert re.fullmatch(r'condaforge/miniforge3:[\w.+-]+@sha256:[0-9a-f]{64}',
                            image), image

    def test_the_image_is_composed_of_the_version_and_digest(self):
        pins = _pins()
        assert pins['MINIFORGE_IMAGE'] == (
            'condaforge/miniforge3:%s@%s' % (pins['MINIFORGE_VERSION'],
                                             pins['MINIFORGE_DIGEST']))

    def test_the_digest_names_its_algorithm(self):
        assert re.fullmatch(r'sha256:[0-9a-f]{64}', _pins()['MINIFORGE_DIGEST'])


class TestDockerfiles:
    @pytest.mark.parametrize('rel', _DOCKERFILES)
    def test_no_unpinned_conda_base_remains(self, rel):
        text = _read(rel)
        assert not re.search(r'^FROM\s+condaforge/miniforge3\s*$', text,
                             re.MULTILINE), \
            '%s builds FROM an untagged conda base (want config/cfg/toolchain-pins.env)' % rel

    @pytest.mark.parametrize('rel', _DOCKERFILES)
    def test_arg_default_matches_the_pins_file(self, rel):
        found = re.findall(r'^ARG\s+MINIFORGE_IMAGE=(\S+)\s*$', _read(rel),
                           re.MULTILINE)
        assert found, '%s declares no ARG MINIFORGE_IMAGE default' % rel
        for value in found:
            assert value == _pins()['MINIFORGE_IMAGE'], \
                '%s pins %s, toolchain-pins.env pins %s' % (
                    rel, value, _pins()['MINIFORGE_IMAGE'])

    @pytest.mark.parametrize('rel', _DOCKERFILES)
    def test_the_from_consumes_the_arg(self, rel):
        assert re.search(r'^FROM\s+\$\{MINIFORGE_IMAGE\}\s*$', _read(rel),
                         re.MULTILINE), \
            '%s declares the ARG but does not build FROM it' % rel

    def test_no_dockerfile_floats_base_conda_forward(self):
        # An unbounded base-env update undoes the digest pin from inside the
        # image; that is how conda reached the conda version in the traceback
        # quoted in config/cfg/toolchain-pins.env.
        for rel in _DOCKERFILES:
            for line in _read(rel).splitlines():
                stripped = line.strip()
                if stripped.startswith('#'):
                    continue
                assert not re.search(r'conda\s+update\b.*-n\s+base', stripped), \
                    '%s floats base conda: %s' % (rel, stripped)


class TestRattlerIsGone:
    """The plugin's only justification was the conda-pypi:: specs, now retired."""

    def test_devel_environ_has_no_active_conda_pypi_specs(self):
        for line in _read(os.path.join('config', 'cfg',
                                       'devel_environ.yml')).splitlines():
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            assert 'conda-pypi::' not in stripped, stripped

    def test_no_dockerfile_installs_or_selects_the_rattler_solver(self):
        for rel in _DOCKERFILES:
            for line in _read(rel).splitlines():
                stripped = line.strip()
                if stripped.startswith('#'):
                    continue
                assert 'rattler' not in stripped, '%s: %s' % (rel, stripped)

    def test_no_dockerfile_keeps_the_shard_workaround(self):
        # It gated a code path only the rattler plugin took, and costs full
        # repodata.json fetches; if this reappears, so should its reason. The
        # comments explaining its removal may name it, so only live lines count.
        for rel in _DOCKERFILES:
            for line in _read(rel).splitlines():
                stripped = line.strip()
                if stripped.startswith('#'):
                    continue
                assert 'repodata_use_shards' not in stripped, \
                    '%s: %s' % (rel, stripped)


class TestSetupDevScript:
    def test_the_installer_release_comes_from_the_pin(self):
        text = _read(os.path.join('scripts', 'setup-dev.sh'))
        assert 'releases/download/${MINIFORGE_VERSION}/' in text, \
            'setup-dev.sh does not fetch the pinned Miniforge release'

    def test_it_sources_the_pins_file(self):
        text = _read(os.path.join('scripts', 'setup-dev.sh'))
        assert 'toolchain-pins.env' in text

    def test_the_unbounded_base_conda_update_is_gone(self):
        for line in _read(os.path.join('scripts',
                                       'setup-dev.sh')).splitlines():
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            assert not re.search(r'conda\s+update\s+-n\s+base', stripped), \
                stripped


class TestBuildDockerScript:
    def test_it_passes_the_pin_as_a_build_arg(self):
        text = _read(os.path.join('scripts', 'build-docker.sh'))
        assert 'toolchain-pins.env' in text
        assert 'MINIFORGE_IMAGE=$MINIFORGE_IMAGE' in text


class TestCiLocalScript:
    def test_the_container_default_comes_from_the_pin(self):
        # A local `ci-local.sh --conformance` that solves against a different
        # Miniforge than CI and the images is a false mirror of the job.
        text = _read(os.path.join('scripts', 'ci-local.sh'))
        assert 'toolchain-pins.env' in text
        assert '${MINIFORGE_IMAGE:-' in text


class TestWorkflows:
    @pytest.mark.parametrize('rel', _WORKFLOWS)
    def test_miniforge_version_is_pinned_to_the_recorded_release(self, rel):
        found = re.findall(r'^\s*miniforge-version:\s*(\S+)\s*$', _read(rel),
                           re.MULTILINE)
        assert found, '%s provisions no miniforge-version' % rel
        for value in found:
            assert value != 'latest', '%s still provisions a floating Miniforge' % rel
            assert value == _pins()['MINIFORGE_VERSION'], \
                '%s provisions %s, toolchain-pins.env pins %s' % (
                    rel, value, _pins()['MINIFORGE_VERSION'])
