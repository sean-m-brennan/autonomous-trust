#!/usr/bin/env python3
# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Apache-2.0 — see source headers in autonomous_trust/.../core/_python/_probes/
# ******************
"""
Aggregate probe JSONL files across an AT run.

The probes package writes one JSONL file per process to the shared
$AT_PROBES_DIR (default /var/at-probes). In docker-compose every
container mounts the same named volume at that path; in the
in-process harness every fork writes to the same /tmp directory.
This script reads them all and prints a sorted counter table.

Usage:
    probe-tail.py                      # aggregate counters
    probe-tail.py --by host            # break down per peer
    probe-tail.py --by all             # peer x layer x event x reason
    probe-tail.py --raw                # dump non-counter events
    probe-tail.py --dir /path          # override AT_PROBES_DIR
"""
import argparse
import collections
import json
import os
import sys
from pathlib import Path


def _peer_from_filename(p: Path) -> str:
    # probes_<host>_pid<n>_<stamp>.jsonl  →  <host>
    parts = p.name.split('_')
    return parts[1] if len(parts) >= 2 else '?'


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--dir', default=os.environ.get('AT_PROBES_DIR', '/var/at-probes'))
    ap.add_argument('--by', choices=['layer', 'host', 'all'], default='layer',
                    help='aggregation key (default: layer)')
    ap.add_argument('--raw', action='store_true', help='print non-counter events')
    args = ap.parse_args()

    base = Path(args.dir)
    if not base.is_dir():
        print('no probe dir at %s' % base, file=sys.stderr)
        return 1

    files = sorted(base.glob('probes_*.jsonl'))
    if not files:
        print('no probes_*.jsonl files in %s' % base, file=sys.stderr)
        return 1

    totals = collections.Counter()
    for path in files:
        host = _peer_from_filename(path)
        with path.open() as f:
            for line in f:
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if ev.get('layer') == 'counters' and ev.get('event') == 'snapshot':
                    for item in ev.get('items', []):
                        layer = item['layer']
                        event = item['event']
                        reason = item.get('reason') or ''
                        count = item['count']
                        if args.by == 'host':
                            key = (host, layer, event, reason)
                        elif args.by == 'all':
                            key = (host, layer, event, reason)
                        else:
                            key = (layer, event, reason)
                        totals[key] += count
                elif args.raw:
                    print(json.dumps(ev))

    if args.raw:
        return 0

    if not totals:
        print('no counter snapshots found', file=sys.stderr)
        return 1

    widths = [max(len(str(k[i])) for k in totals) for i in range(len(next(iter(totals))))]
    for key in sorted(totals):
        cells = '  '.join(str(c).ljust(w) for c, w in zip(key, widths))
        print('%s  %d' % (cells, totals[key]))
    return 0


if __name__ == '__main__':
    sys.exit(main())
