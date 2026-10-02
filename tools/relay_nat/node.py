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
"""One node of the relay NAT check (tools/relay_nat/run.sh).

Roles:
  relay   serve as a rendezvous relay (AT_RELAY=1) until --share/done appears
  alice   register with --relay, mint a link, write it to --share/link, wait
          for the handshake, write --share/alice.result
  bob     wait for --share/link, add Alice from it, wait for the handshake,
          write --share/bob.result

The two sides talk only through files in --share, which network namespaces do
not isolate, and through AT. A result file holds "ok <detail>" or
"fail <detail>"; run.sh reads them.

--loopback runs a node on a loopback address without real interfaces -- how
this driver itself is checked where namespaces are unavailable.
"""
import argparse
import json
import logging
import os
import queue
import sys
import threading
import time
from unittest.mock import patch


def _write(path, text):
    tmp = path + '.tmp'
    with open(tmp, 'w') as fh:
        fh.write(text + '\n')
    os.replace(tmp, path)


def _wait_file(path, deadline):
    while time.monotonic() < deadline:
        if os.path.exists(path):
            with open(path) as fh:
                return fh.read().strip()
        time.sleep(0.2)
    return None


def _await(q_out, want, deadline):
    from autonomous_trust.first_contact.first_contact import FirstContactEvent
    while time.monotonic() < deadline:
        try:
            ev = q_out.get(timeout=1)
        except queue.Empty:
            continue
        if isinstance(ev, FirstContactEvent) and (ev.kind == want
                                                  or ev.kind == 'refused'):
            return ev
    return None


def _drive(args, q_in, q_out):
    from autonomous_trust.core import Process
    from autonomous_trust.core.app_verbs import AppRequest
    from autonomous_trust.first_contact import first_contact as fc
    deadline = time.monotonic() + args.timeout
    result = os.path.join(args.share, '%s.result' % args.role)
    time.sleep(args.startup)
    try:
        if args.role == 'relay':
            _wait_file(os.path.join(args.share, 'done'), deadline)
            return
        if args.role == 'alice':
            q_in.put(AppRequest(fc.APP_INVITE, json.dumps({'ref': 'nat'})))
            ev = _await(q_out, fc.EVENT_INVITATION, deadline)
            if ev is None or ev.kind != fc.EVENT_INVITATION:
                _write(result, 'fail no invitation: %r' % ev)
                return
            _write(os.path.join(args.share, 'link'), ev.blob)
        else:
            link = _wait_file(os.path.join(args.share, 'link'), deadline)
            if link is None:
                _write(result, 'fail no link from alice')
                return
            q_in.put(AppRequest(fc.APP_INITIATE, json.dumps(
                {'ref': 'nat', 'invitation': link})))
        ev = _await(q_out, fc.EVENT_ESTABLISHED, deadline)
        if ev is None or ev.kind != fc.EVENT_ESTABLISHED:
            _write(result, 'fail not established: %r' % ev)
        else:
            _write(result, 'ok established with %s (%s)' % (ev.nickname, ev.role))
    finally:
        if args.role != 'relay':
            _wait_file(os.path.join(args.share, 'done'), deadline)
        q_in.put(Process.sig_quit)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('role', choices=('relay', 'alice', 'bob'))
    ap.add_argument('--root', required=True, help='AUTONOMOUS_TRUST_ROOT')
    ap.add_argument('--share', required=True, help='directory both sides can read')
    ap.add_argument('--relay', default='', help='host:port of the relay (alice)')
    ap.add_argument('--relay-port', type=int, default=27790)
    ap.add_argument('--port', type=int, default=0, help='AT_COMM_PORT')
    ap.add_argument('--timeout', type=float, default=120.0)
    ap.add_argument('--startup', type=float, default=10.0)
    ap.add_argument('--loopback', default='', help='run on this loopback address')
    args = ap.parse_args(argv)

    os.environ['AUTONOMOUS_TRUST_ROOT'] = args.root
    os.environ['AT_FIRST_CONTACT'] = '1'
    if args.port:
        os.environ['AT_COMM_PORT'] = str(args.port)
    if args.role == 'relay':
        os.environ['AT_RELAY'] = '1'
        os.environ['AT_RELAY_PORT'] = str(args.relay_port)
    if args.relay:
        os.environ['AT_USE_RELAY'] = args.relay

    from autonomous_trust.core import AutonomousTrust
    from autonomous_trust.core.config import Configuration
    from autonomous_trust.core.config.generate import generate_identity

    patches = []
    if args.loopback:
        addrs = {'ip4': args.loopback, 'ip6': None, 'mac': '00:11:22:33:44:55',
                 'ip4_subnet': '255.0.0.0', 'ip6_subnet': None,
                 'mac_bcast': 'ff:ff:ff:ff:ff:ff'}
        patches.append(patch('autonomous_trust.core.network.network.Network.get_addresses',
                             return_value=addrs))
    for p in patches:
        p.start()
    cfg_dir = os.path.join(args.root, 'etc', 'at')
    if not os.path.exists(os.path.join(cfg_dir, 'identity.cfg.json')):
        os.makedirs(cfg_dir, exist_ok=True)
        generate_identity(cfg_dir, randomize=True)
    # First contact's plaintext verbs: granted, as a deployment must
    # (unencrypted_verbs.cfg.json, FEATURE_SPLIT_PLAN D8).
    from autonomous_trust.core import plaintext_verbs
    from autonomous_trust.first_contact import first_contact
    plaintext_verbs.write(cfg_dir, first_contact.EXTENSION.plaintext_verbs)

    q_in, q_out = queue.Queue(), queue.Queue()
    threading.Thread(target=_drive, args=(args, q_in, q_out), daemon=True).start()
    log = os.path.join(args.share, '%s.log' % args.role)
    AutonomousTrust(multiproc=False, log_level=logging.INFO, logfile=log,
                    testing=True, silent=True).run_forever(q_in=q_in, q_out=q_out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
