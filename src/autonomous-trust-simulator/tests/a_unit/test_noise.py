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

import numpy as np
import pytest

try:
    from autonomous_trust.simulator.video.noise import Noise, add_noise
    _has_noise = True
except ImportError:
    _has_noise = False

pytestmark = pytest.mark.skipif(not _has_noise, reason='simulator video deps missing')

# Evaluated at collection time, so must be safe even when the import failed.
_MODES = list(Noise) if _has_noise else []


def _color():
    return np.full((16, 16, 3), 128, dtype=np.uint8)


def _gray():
    return np.full((16, 16), 128, dtype=np.uint8)


class TestNoiseContract:
    """§6 noise.py:52 -- every mode must return a valid uint8 image of the
    same shape, so POISSON/SPECKLE are usable rather than silently broken."""

    @pytest.mark.parametrize('mode', _MODES)
    def test_color_output_is_valid_uint8(self, mode):
        img = _color()
        out = add_noise(mode, img)
        assert out.dtype == np.uint8
        assert out.shape == img.shape
        assert out.min() >= 0 and out.max() <= 255

    @pytest.mark.parametrize('mode', _MODES)
    def test_grayscale_output_is_valid_uint8(self, mode):
        # GAUSSIAN and SPECKLE both previously raised ValueError unpacking
        # a 2-tuple into row,col,ch on grayscale frames.
        img = _gray()
        out = add_noise(mode, img)
        assert out.dtype == np.uint8
        assert out.shape == img.shape
        assert out.min() >= 0 and out.max() <= 255

    def test_poisson_zero_image_returns_valid_frame(self):
        # only-noise path: must not raise (guarded log2(0)) and must yield a
        # valid uint8 frame. Shot noise on a zero signal is legitimately ~0.
        out = add_noise(Noise.POISSON, None, shape=(16, 16, 3))
        assert out.dtype == np.uint8
        assert out.shape == (16, 16, 3)

    def test_poisson_adds_variation_to_flat_signal(self):
        # On a non-trivial signal, Poisson must actually perturb pixels.
        img = _color()
        out = add_noise(Noise.POISSON, img)
        assert out.std() > 0
