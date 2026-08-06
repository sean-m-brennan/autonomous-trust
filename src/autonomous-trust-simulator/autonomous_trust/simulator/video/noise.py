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

from enum import Enum
import random

import cv2
import numpy as np


class Noise(str, Enum):
    GAUSSIAN = 'gauss'
    SALT_PEPPER = 's&p'
    POISSON = 'poisson'
    SPECKLE = 'speckle'


def add_noise(noise, image, shape=None):
    if image is None and shape is not None:  # only noise
        image = np.zeros(shape, np.uint8)

    if noise == Noise.GAUSSIAN:
        # image.shape[:2] tolerates both grayscale (H, W) and
        # multi-channel (H, W, C) frames; the same Gaussian field is
        # added to every channel.
        row, col = image.shape[:2]
        mean = random.randint(0, 200)
        var = random.randint(100, 400)
        sigma = var ** 0.5
        gauss = np.random.normal(mean, sigma, (row, col))
        noisy = image.astype(np.float32)

        if image.ndim == 2:
            noisy = noisy + gauss
        else:
            for c in range(image.shape[2]):
                noisy[:, :, c] = image[:, :, c] + gauss
        cv2.normalize(noisy, noisy, 0, 255, cv2.NORM_MINMAX, dtype=-1)
        noisy = noisy.astype(np.uint8)
        return noisy
    elif noise == Noise.SALT_PEPPER:
        s_vs_p = 0.5
        amount = 0.004
        out = np.copy(image)
        # Salt mode
        num_salt = np.ceil(amount * image.size * s_vs_p)
        coords = [np.random.randint(0, i - 1, int(num_salt))
                  for i in image.shape]
        out[coords] = 1

        # Pepper mode
        num_pepper = np.ceil(amount * image.size * (1. - s_vs_p))
        coords = [np.random.randint(0, i - 1, int(num_pepper))
                  for i in image.shape]
        out[coords] = 0
        return out
    elif noise == Noise.POISSON:
        # Shot noise: sample each pixel from a Poisson distribution with
        # lambda = pixel intensity. Guard against an all-zero image (the
        # only-noise path) where every sample would collapse to zero.
        lam = np.clip(image.astype(np.float32), 1e-6, None)
        noisy = np.random.poisson(lam).astype(np.float32)
        cv2.normalize(noisy, noisy, 0, 255, cv2.NORM_MINMAX, dtype=-1)
        return noisy.astype(np.uint8)
    elif noise == Noise.SPECKLE:
        # Multiplicative Gaussian noise; np.random.randn matches the
        # image shape (works for both grayscale and multi-channel).
        gauss = np.random.randn(*image.shape).astype(np.float32)
        noisy = image.astype(np.float32) * (1.0 + gauss)
        cv2.normalize(noisy, noisy, 0, 255, cv2.NORM_MINMAX, dtype=-1)
        return noisy.astype(np.uint8)
    else:
        return image
