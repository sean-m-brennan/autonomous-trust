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
"""The MITM sidecar: a capture and replay process in one node's network
namespace.

It runs as root with ``NET_RAW`` beside the target node (compose
``network_mode: service:<target>``), so it sees exactly what the target sends
and receives and can send from the target's own address. Nothing but the
standard library is needed:

1. For ``MITM_CAPTURE_S`` seconds it reads every frame on an ``AF_PACKET``
   socket and keeps the UDP ones to or from AT's ports (point-to-point
   ``MITM_PORT``, group traffic one above), writing each payload with its
   direction, addresses and ports as one JSON line to
   ``/capture/frames.jsonl``.
2. At ``MITM_REPLAY_AT_S`` seconds from start it resends every captured
   target-to-victim point-to-point payload to the victim's port, from a UDP
   socket bound to the target's address, as the node itself sends, and logs
   ``MITM_REPLAYED <n> at <epoch>``.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
UDP = 17
DEFAULT_PORT = 27787


def parse_frame(frame: bytes, ports=(DEFAULT_PORT, DEFAULT_PORT + 1)):
    """(src, dst, sport, dport, payload) of an Ethernet/IPv4/UDP frame to or
    from one of ``ports``; None for anything else."""
    if len(frame) < 14 + 20 + 8:
        return None
    if struct.unpack('!H', frame[12:14])[0] != ETH_P_IP:
        return None
    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    if ip[0] >> 4 != 4 or ip[9] != UDP or len(ip) < ihl + 8:
        return None
    total = struct.unpack('!H', ip[2:4])[0]
    src = socket.inet_ntoa(ip[12:16])
    dst = socket.inet_ntoa(ip[16:20])
    sport, dport, length = struct.unpack('!HHH', ip[ihl:ihl + 6])
    if sport not in ports and dport not in ports:
        return None
    end = min(len(ip), total, ihl + length)
    return src, dst, sport, dport, bytes(ip[ihl + 8:end])


def replayable(rows, target: str, victim: str, port: int = DEFAULT_PORT):
    """The payloads to replay: what the target sent the victim
    point-to-point, in the order it sent them."""
    return [bytes.fromhex(r['hex']) for r in rows
            if r['src'] == target and r['dst'] == victim
            and int(r['dport']) == port]


def capture(seconds: float, target: str, out_path: str,
            port: int = DEFAULT_PORT) -> list:
    """Capture for ``seconds``; write and return the rows."""
    rows = []
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(ETH_P_ALL))
    sock.settimeout(1.0)
    end = time.time() + seconds
    with open(out_path, 'w') as out:
        while time.time() < end:
            try:
                frame, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            # The loopback copy of a frame would be counted twice.
            if addr[0] == 'lo':
                continue
            parsed = parse_frame(frame, (port, port + 1))
            if parsed is None:
                continue
            src, dst, sport, dport, payload = parsed
            row = {'t': round(time.time(), 3),
                   'dir': 'out' if src == target else 'in',
                   'src': src, 'dst': dst, 'sport': sport, 'dport': dport,
                   'hex': payload.hex()}
            rows.append(row)
            out.write(json.dumps(row) + '\n')
            out.flush()
    sock.close()
    return rows


def replay(payloads, target: str, victim: str, port: int = DEFAULT_PORT) -> int:
    """Send each payload to the victim from the target's address."""
    sent = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((target, 0))
        for payload in payloads:
            sock.sendto(payload, (victim, port))
            sent += 1
            time.sleep(0.005)
    return sent


def main():
    start = time.time()
    target = os.environ['MITM_TARGET']
    victim = os.environ['MITM_VICTIM']
    port = int(os.environ.get('MITM_PORT', DEFAULT_PORT))
    out_dir = os.environ.get('MITM_OUT', '/capture')
    os.makedirs(out_dir, exist_ok=True)
    rows = capture(float(os.environ.get('MITM_CAPTURE_S', '600')), target,
                   os.path.join(out_dir, 'frames.jsonl'), port)
    print('MITM_CAPTURED %d' % len(rows), flush=True)
    wait = start + float(os.environ.get('MITM_REPLAY_AT_S', '660')) - time.time()
    if wait > 0:
        time.sleep(wait)
    at = time.time()
    n = replay(replayable(rows, target, victim, port), target, victim, port)
    print('MITM_REPLAYED %d at %.3f' % (n, at), flush=True)
    # Stay up, so the harness reads this log before it brings the run down.
    while True:
        time.sleep(3600)


if __name__ == '__main__':
    sys.exit(main())
