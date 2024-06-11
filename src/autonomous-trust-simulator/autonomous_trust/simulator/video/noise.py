# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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
        row, col, ch = image.shape
        mean = random.randint(0, 200)
        var = random.randint(100, 400)
        sigma = var ** 0.5
        gauss = np.random.normal(mean, sigma, (row, col))
        noisy = np.zeros(image.shape, np.float32)

        if len(image.shape) == 2:
            noisy = image + gauss
        else:
            noisy[:, :, 0] = image[:, :, 0] + gauss
            noisy[:, :, 1] = image[:, :, 1] + gauss
            noisy[:, :, 2] = image[:, :, 2] + gauss
        cv2.normalize(noisy, noisy, 0, 255, cv2.NORM_MINMAX, dtype=-1)
        noisy = noisy.astype(np.uint8)
        return noisy
    elif noise == Noise.SALT_PEPPER:  # FIXME the rest of these do not work
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
        vals = len(np.unique(image))
        vals = 2 ** np.ceil(np.log2(vals))
        noisy = np.random.poisson(image * vals) / float(vals)
        return noisy
    elif noise == Noise.SPECKLE:
        row, col, ch = image.shape
        gauss = np.random.randn(row, col, ch)
        gauss = gauss.reshape((row, col, ch))
        noisy = image + image * gauss
        return noisy
    else:
        return image
