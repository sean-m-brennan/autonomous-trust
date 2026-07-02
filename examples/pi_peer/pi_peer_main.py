# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Launcher: stream a microdrone's ISR Readings to a C ``at_demo`` node.

Runs as a sidecar next to the C node (Stretch Goal 3, Path B). It builds a
``FlightStub`` for the peer, then on a fixed cadence ticks it and writes each
batch to the C node's ``--ingest-readings`` AF_UNIX ``SOCK_STREAM`` socket as a
length-prefixed JSON frame:  ``[uint32 big-endian length][JSON array bytes]``.

The C node is the socket *server*; this launcher is the *client* and retries the
connect until the node is up, reconnecting if the stream drops.

Usage:
    python pi_peer_main.py <peer-name> [--socket PATH] [--cadence SEC]

Env:
    AT_PEER_NAME      peer name (overrides argv[1])
    AT_INGEST_SOCKET  socket path (overrides --socket; default /ingest/<peer>.sock)
    AT_DEMO_T0_EPOCH  shared scenario clock origin (unix seconds)
    AT_SQUAD_SIZE / AT_SWARM_SIZE / ... — scenario roster knobs (see flight_stub)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import struct
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
from flight_stub import FlightStub  # noqa: E402

logger = logging.getLogger("pi_peer")

# Guard against the UDP transport's 65507-byte truncation on the C side: keep
# each emitted frame well under it. Detection batches with crops are a few KB,
# so this only ever trips on a pathological tick — then we log + drop the frame
# rather than let the C node truncate it silently.
MAX_FRAME_BYTES = 60 * 1024


def _connect(path: str, retry_sec: float = 1.0) -> socket.socket:
    """Block until the C node's ingest socket is connectable."""
    announced = False
    while True:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(path)
            logger.info("connected to ingest socket %s", path)
            return s
        except (FileNotFoundError, ConnectionRefusedError, OSError) as e:
            if not announced:
                logger.info("waiting for ingest socket %s (%s)", path, e)
                announced = True
            time.sleep(retry_sec)


def run(peer_name: str, sock_path: str, cadence: float) -> int:
    stub = FlightStub(peer_name)
    logger.info("flight stub up for %s (t0=%.0f, cadence=%.2fs) -> %s",
                peer_name, stub.t0_epoch, cadence, sock_path)

    conn = _connect(sock_path)
    while True:
        loop_start = time.time()
        try:
            batch = stub.tick()
        except Exception:
            logger.exception("tick failed; skipping")
            batch = []

        if batch:
            payload = json.dumps(batch, separators=(",", ":")).encode("utf-8")
            if len(payload) > MAX_FRAME_BYTES:
                logger.warning("batch %d bytes exceeds %d cap; dropping (%d readings)",
                               len(payload), MAX_FRAME_BYTES, len(batch))
            else:
                frame = struct.pack("!I", len(payload)) + payload
                try:
                    conn.sendall(frame)
                except (BrokenPipeError, ConnectionResetError, OSError) as e:
                    logger.warning("ingest stream dropped (%s); reconnecting", e)
                    try:
                        conn.close()
                    except OSError:
                        pass
                    conn = _connect(sock_path)

        # Fixed cadence, minus the work already spent this loop.
        time.sleep(max(0.0, cadence - (time.time() - loop_start)))


def main(argv=None) -> int:
    logging.basicConfig(
        level=logging.INFO, stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("peer_name", nargs="?", help="microdrone peer name")
    p.add_argument("--socket", help="ingest socket path "
                   "(default: $AT_INGEST_SOCKET or /ingest/<peer>.sock)")
    p.add_argument("--cadence", type=float, default=0.5,
                   help="seconds between reading batches (default 0.5)")
    args = p.parse_args(argv)

    peer_name = os.environ.get("AT_PEER_NAME") or args.peer_name
    if not peer_name:
        p.error("peer name required (argv or AT_PEER_NAME)")

    sock_path = (os.environ.get("AT_INGEST_SOCKET") or args.socket
                 or f"/ingest/{peer_name}.sock")

    try:
        return run(peer_name, sock_path, args.cadence)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
