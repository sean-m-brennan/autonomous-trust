# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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
import msgpack
import msgpack_numpy as msg_np


def serialize(data: np.ndarray, fast=False) -> bytes:
    return msgpack.packb(data, default=msg_np.encode)


def deserialize(data: bytes, fast=False) -> np.ndarray:
    return msgpack.unpackb(data, object_hook=msg_np.decode)
