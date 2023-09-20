import pickle

import numpy as np
import msgpack
import msgpack_numpy as msg_np


def serialize(frame: np.ndarray, fast=False) -> bytes:
    if fast:
        return pickle.dumps(frame)
    return msgpack.packb(frame, default=msg_np.encode)


def deserialize(data: bytes, fast=False) -> np.ndarray:
    if fast:
        return pickle.loads(data)  # note: insecure, but fast, must trust sender
    return msgpack.unpackb(data, object_hook=msg_np.decode)
