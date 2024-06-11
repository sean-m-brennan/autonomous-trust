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

import pickle

import numpy as np
import msgpack
import msgpack_numpy as msg_np


def serialize(data: np.ndarray, fast=False) -> bytes:
    if fast:
        return pickle.dumps(data)
    return msgpack.packb(data, default=msg_np.encode)


def deserialize(data: bytes, fast=False) -> np.ndarray:
    if fast:
        return pickle.loads(data)  # note: insecure, but fast, must trust sender
    return msgpack.unpackb(data, object_hook=msg_np.decode)
