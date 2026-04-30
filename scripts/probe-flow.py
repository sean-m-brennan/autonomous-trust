#!/usr/bin/env python3
# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#  Apache-2.0 — see source headers in autonomous_trust/.../core/_python/_probes/
# ******************
"""
Read the AT debug-probe JSONL stream and answer common questions.

The probes package emits two event families:

* **msg** layer — every Message lifecycle hook keyed by trace_id
  (new, parse, dispatched, queue_full, unknown_target, unhandled,
  outbound_routed, ...). Lets us reconstruct cross-process timelines.
* **counters** layer — periodic (layer, event, reason, count) deltas
  flushed every AT_PROBES_COUNTER_SEC. Deltas sum to totals.

Other layers (peer.set, net.mystery, bridge.task, ...) emit ad-hoc
events through the same writer.

Subcommands:
    probe-flow.py <trace_id_prefix>               reconstruct one timeline
    probe-flow.py --all                           list distinct trace_ids
    probe-flow.py --orphans [--by-function FN]    new/parse w/o terminal
    probe-flow.py --has-from-audit [FN]           has_from distribution
    probe-flow.py --peer-set-audit                peer-set propagation
    probe-flow.py --counts EVENT                  per (host, function) count
                                                  for one msg-layer event;
                                                  e.g. outbound_routed, parse,
                                                  new, dispatched, unhandled
    probe-flow.py --counters                      aggregate counter deltas
                                                  (sum every snapshot in the
                                                  run); --layer-prefix to
                                                  scope, --host to filter
    probe-flow.py --sample-trace --event E        list first N trace_ids
                                                  matching --event/--host/
                                                  --function (default N=10)

Most subcommands accept --host SUB and --function-substr SUB to narrow
to a host (matches probes_<host>_*.jsonl) or a Message.function
substring.

Examples:
    # Where is rep traffic going on the wire? (replaces the ad-hoc python
    # one-liner that sliced outbound_routed by host x function.)
    probe-flow.py --counts outbound_routed --function-substr reputation \\
                  --dir deploy/civilian/at-probes

    # Did the bridge's tasking_tick(3) fire and how many messages did it
    # actually queue? Counter aggregates from the inspector probe file.
    probe-flow.py --counters --layer-prefix bridge.task \\
                  --host inspector --dir deploy/civilian/at-probes

    # Pick five inspector-origin rep_req trace_ids to reconstruct.
    probe-flow.py --sample-trace --event new --host inspector \\
                  --function 'request reputation' -n 5 \\
                  --dir deploy/civilian/at-probes
"""
import argparse
import collections
import json
import os
import sys
from pathlib import Path


def _iter_events(base: Path, layer_filter=None, host_substr: str | None = None):
    for path in sorted(base.glob('probes_*.jsonl')):
        host = path.name.split('_')[1] if '_' in path.name else '?'
        if host_substr and host_substr not in host:
            continue
        with path.open() as f:
            for line in f:
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if layer_filter is not None and ev.get('layer') not in layer_filter:
                    continue
                ev['_host'] = host
                yield ev


def _iter_msg_events(base: Path, host_substr: str | None = None):
    yield from _iter_events(base, {'msg'}, host_substr=host_substr)


def cmd_one(events, prefix: str) -> int:
    matches = [e for e in events if e.get('trace_id', '').startswith(prefix)]
    if not matches:
        print(f'no events matching trace_id prefix {prefix!r}', file=sys.stderr)
        return 1
    matches.sort(key=lambda e: e['t'])
    # If prefix matches multiple distinct trace_ids, group by trace_id.
    by_id = collections.defaultdict(list)
    for e in matches:
        by_id[e['trace_id']].append(e)
    for tid, evs in by_id.items():
        print(f'=== trace_id {tid} ({len(evs)} events) ===')
        t0 = evs[0]['t']
        for e in evs:
            dt = (e['t'] - t0) * 1000  # ms
            ctx = ' '.join('%s=%s' % (k, v) for k, v in e.items()
                           if k not in ('t', 'pid', 'host', 'layer', 'event',
                                        'trace_id', '_host', 'process', 'function'))
            print('  +%7.1fms  %-13s  %-22s  %s%s' % (
                dt, e['_host'], '%s.%s' % (e.get('process', '?'), e.get('function', '?')),
                e['event'], (' | ' + ctx) if ctx else ''))
    return 0


def cmd_all(events) -> int:
    by_id = collections.Counter()
    for e in events:
        by_id[e.get('trace_id', '?')] += 1
    for tid, n in by_id.most_common():
        print('%s  %d' % (tid, n))
    return 0


def cmd_peer_set_audit(base: Path) -> int:
    # Read peer.set + net.mystery events. Show, per host:
    #   - peers added (by source: peer_accepted / handle_acceptance / handle_confirm_peer)
    #   - peer.set silent_drops by reason
    #   - mystery resolutions / age-outs grouped by from_addr (top 10)
    by_host = collections.defaultdict(lambda: {
        'added_by_source': collections.Counter(),
        'silent_drop_by_reason': collections.Counter(),
        'no_prior_potential': 0,
        'mystery_resolved_by_addr': collections.Counter(),
        'mystery_aged_by_addr': collections.Counter(),
        'add_requests_by_source': collections.Counter(),
    })
    for ev in _iter_events(base, {'peer.set', 'net.mystery'}):
        host = ev['_host']
        layer = ev['layer']
        event = ev.get('event')
        if layer == 'peer.set':
            if event == 'added':
                by_host[host]['added_by_source']['(via peers.add)'] += 1
            elif event == 'add_request':
                by_host[host]['add_requests_by_source'][ev.get('source', '?')] += 1
            elif event == 'silent_drop':
                by_host[host]['silent_drop_by_reason'][ev.get('reason', '?')] += 1
            elif event == 'no_prior_potential':
                by_host[host]['no_prior_potential'] += 1
        elif layer == 'net.mystery':
            if event == 'resolved':
                by_host[host]['mystery_resolved_by_addr'][ev.get('from_addr', '?')] += 1
            elif event == 'aged_out':
                by_host[host]['mystery_aged_by_addr'][ev.get('from_addr', '?')] += 1

    if not by_host:
        print('no peer.set / net.mystery events found', file=sys.stderr)
        return 1

    for host in sorted(by_host):
        d = by_host[host]
        print('=== %s ===' % host)
        if d['add_requests_by_source']:
            print('  _add_peer call sources (which idprocess path triggered admission):')
            for src, n in d['add_requests_by_source'].most_common():
                print('    %-22s %d' % (src, n))
        if d['added_by_source']:
            print('  peers.listing inserts:')
            for src, n in d['added_by_source'].most_common():
                print('    %-22s %d' % (src, n))
        if d['silent_drop_by_reason']:
            print('  handle_confirm_peer silent drops:')
            for reason, n in d['silent_drop_by_reason'].most_common():
                print('    %-22s %d' % (reason, n))
        if d['no_prior_potential']:
            print('  handle_confirm_peer added without prior announcement:')
            print('    %-22s %d  (proxy for UDP-multicast loss)' %
                  ('no_prior_potential', d['no_prior_potential']))
        if d['mystery_resolved_by_addr']:
            print('  mystery resolved (top 10 source addrs):')
            for addr, n in d['mystery_resolved_by_addr'].most_common(10):
                print('    %-22s %d' % (addr, n))
        if d['mystery_aged_by_addr']:
            print('  mystery aged-out (top 10 source addrs — these are losses):')
            for addr, n in d['mystery_aged_by_addr'].most_common(10):
                print('    %-22s %d' % (addr, n))
        print()
    return 0


def cmd_has_from_audit(events, fn_filter: str | None) -> int:
    # Tally has_from distribution at 'new' (origin) and 'parse' (wire
    # arrival) per host × function. Answers the from_whom question:
    # if 'new' is mostly has_from=False, the producer constructs the
    # Message without a from_whom (construction-side bug). If 'new'
    # has_from=True dominates but 'parse' has_from=False shows up,
    # the wire roundtrip is dropping it.
    by_key = collections.Counter()
    for e in events:
        if e.get('event') not in ('new', 'parse'):
            continue
        fn = e.get('function')
        if fn_filter and fn != fn_filter:
            continue
        host = e.get('_host', '?')
        ev = e.get('event')
        has_from = bool(e.get('has_from', False))
        by_key[(host, fn, ev, has_from)] += 1
    if not by_key:
        print('no new/parse events match', file=sys.stderr)
        return 1
    print('host                              function          event   has_from  count')
    for (host, fn, ev, hf), n in sorted(by_key.items()):
        print('%-32s  %-16s  %-6s  %-8s  %d' % (host, fn, ev, hf, n))
    return 0


def cmd_breakdown(base: Path, layer: str, event_filter: str | None,
                  group_by: list[str], host_substr: str | None) -> int:
    # Sum emit events of (layer[, event]), grouped by the requested
    # context fields. Replaces ad-hoc python loops that filter the
    # JSONL stream by some `from_addr`/`peer_uuid`/`reason` and bin
    # the result. Counter-snapshot rows are skipped (use --counters
    # for those) since their semantics differ — these are per-event,
    # those are aggregated deltas.
    if not group_by:
        group_by = ['host']
    counter: collections.Counter = collections.Counter()
    for ev in _iter_events(base, {layer}, host_substr=host_substr):
        # Skip the periodic counter snapshot — it's a different layer
        # already (and skipped here defensively if a caller passed
        # --breakdown counters:snapshot).
        if ev.get('event') == 'snapshot' and ev.get('layer') == 'counters':
            continue
        if event_filter and ev.get('event') != event_filter:
            continue
        key_parts = []
        for f in group_by:
            if f == 'host':
                key_parts.append(ev.get('_host', '?'))
            else:
                v = ev.get(f)
                key_parts.append('-' if v is None else str(v))
        counter[tuple(key_parts)] += 1
    if not counter:
        print('no %s%s events match%s' % (
            layer,
            (':%s' % event_filter) if event_filter else '',
            (' host~=%r' % host_substr) if host_substr else ''),
            file=sys.stderr)
        return 1
    header_widths = [max(20, len(g) + 2) for g in group_by]
    header = '  '.join(g.ljust(w) for g, w in zip(group_by, header_widths))
    print(header + '  count')
    for key, n in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])):
        line = '  '.join(p.ljust(w) for p, w in zip(key, header_widths))
        print('%s  %d' % (line, n))
    return 0


def cmd_counts(events, target_event: str, fn_substr: str | None) -> int:
    # Per (host, function) count of one msg-layer event (e.g. outbound_routed,
    # parse, new). Replaces the recurring ad-hoc python snippets that did the
    # same slice-and-bin operation on the JSONL output.
    c = collections.Counter()
    for e in events:
        if e.get('event') != target_event:
            continue
        fn = e.get('function') or '?'
        if fn_substr and fn_substr not in fn:
            continue
        c[(e['_host'], fn)] += 1
    if not c:
        print('no msg-layer %s events%s' % (
            target_event,
            (' with function~=%r' % fn_substr) if fn_substr else ''),
            file=sys.stderr)
        return 1
    print('# %s%s' % (
        target_event,
        (' (function~=%r)' % fn_substr) if fn_substr else ''))
    print('%-18s  %-35s  %s' % ('host', 'function', 'count'))
    for (h, f), n in sorted(c.items()):
        print('%-18s  %-35s  %d' % (h, f, n))
    return 0


def cmd_counters(base: Path, layer_prefix: str | None, host_substr: str | None) -> int:
    # Sum the periodic (layer, event, reason, count) deltas the counters
    # package writes as 'counters'/'snapshot' rows. AT_PROBES_COUNTER_SEC
    # controls flush cadence, so a counter total = sum of all its deltas
    # in the run.
    totals: dict[tuple[str, str, str, str], int] = collections.Counter()
    for ev in _iter_events(base, {'counters'}, host_substr=host_substr):
        if ev.get('event') != 'snapshot':
            continue
        host = ev['_host']
        for item in ev.get('items') or ():
            layer = item.get('layer', '?')
            if layer_prefix and not layer.startswith(layer_prefix):
                continue
            event = item.get('event', '?')
            reason = item.get('reason') or ''
            n = int(item.get('count') or 0)
            totals[(host, layer, event, reason)] += n
    if not totals:
        print('no counter snapshots match%s%s' % (
            (' layer_prefix=%r' % layer_prefix) if layer_prefix else '',
            (' host~=%r' % host_substr) if host_substr else ''),
            file=sys.stderr)
        return 1
    print('%-18s  %-22s  %-22s  %-18s  %s' %
          ('host', 'layer', 'event', 'reason', 'total'))
    for (host, layer, event, reason), n in sorted(totals.items()):
        print('%-18s  %-22s  %-22s  %-18s  %d' %
              (host, layer, event, reason or '-', n))
    return 0


def cmd_sample_trace(events, target_event: str, fn_substr: str | None,
                     host_substr: str | None, limit: int) -> int:
    # First N trace_ids matching the criteria — handy for piping into a
    # follow-up `probe-flow.py <trace_id>` reconstruction. Replaces the
    # python one-liner that scanned a host's probe file for matching new
    # events.
    seen: list[str] = []
    seen_set: set[str] = set()
    for e in events:
        if e.get('event') != target_event:
            continue
        fn = e.get('function') or ''
        if fn_substr and fn_substr not in fn:
            continue
        if host_substr and host_substr not in e.get('_host', ''):
            continue
        tid = e.get('trace_id')
        if not tid or tid in seen_set:
            continue
        seen_set.add(tid)
        seen.append(tid)
        if len(seen) >= limit:
            break
    if not seen:
        print('no trace_ids match', file=sys.stderr)
        return 1
    for tid in seen:
        print(tid)
    return 0


def cmd_orphans(events, fn_filter: str | None) -> int:
    # An orphan is a trace_id that has 'new' or 'parse' but never reaches
    # 'dispatched' or 'unhandled'. These are messages lost between
    # construction and final disposition.
    seen_birth = set()
    seen_terminal = set()
    fn_by_id = {}
    host_by_id = {}
    for e in events:
        tid = e.get('trace_id')
        if not tid:
            continue
        ev = e.get('event')
        fn_by_id.setdefault(tid, e.get('function', '?'))
        host_by_id.setdefault(tid, e.get('_host', '?'))
        if ev in ('new', 'parse'):
            seen_birth.add(tid)
        if ev in ('dispatched', 'unhandled', 'queue_full', 'unknown_target'):
            seen_terminal.add(tid)
    orphans = sorted(seen_birth - seen_terminal)
    if fn_filter:
        orphans = [t for t in orphans if fn_by_id.get(t) == fn_filter]
    print('# %d orphan trace_ids%s' % (
        len(orphans),
        ('  (function=%s)' % fn_filter) if fn_filter else ''))
    for tid in orphans:
        print('%s  %s  %s' % (tid, host_by_id[tid], fn_by_id[tid]))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('trace_id_prefix', nargs='?', default=None,
                    help='trace_id (full or prefix) to reconstruct')
    ap.add_argument('--dir', default=os.environ.get('AT_PROBES_DIR', '/var/at-probes'))
    ap.add_argument('--all', action='store_true', help='list distinct trace_ids by event count')
    ap.add_argument('--orphans', action='store_true',
                    help='trace_ids that started but never reached a terminal event')
    ap.add_argument('--by-function', default=None,
                    help='restrict --orphans to a Message.function name')
    ap.add_argument('--has-from-audit', metavar='FN', default=None, nargs='?', const='',
                    help='has_from distribution at new/parse events; '
                         'optional Message.function filter')
    ap.add_argument('--peer-set-audit', action='store_true',
                    help='peer-set propagation diagnostic per host')
    ap.add_argument('--counts', metavar='EVENT', default=None,
                    help='per-(host, function) count of one msg-layer event '
                         '(outbound_routed, parse, new, dispatched, ...)')
    ap.add_argument('--counters', action='store_true',
                    help='sum periodic counter deltas (counters/snapshot rows)')
    ap.add_argument('--layer-prefix', default=None,
                    help='restrict --counters to layers starting with this prefix')
    ap.add_argument('--breakdown', metavar='LAYER[:EVENT]', default=None,
                    help='count events of LAYER (optionally filtered to '
                         'EVENT), grouped by --by fields. Replaces ad-hoc '
                         'python loops that bin emit events by from_addr / '
                         'peer_uuid / reason / etc.')
    ap.add_argument('--by', default=None,
                    help='comma-separated field names for --breakdown '
                         '(e.g. host,from_addr). Default: host')
    ap.add_argument('--sample-trace', action='store_true',
                    help='print first N trace_ids matching --event/--host/--function')
    ap.add_argument('--event', default=None,
                    help='msg-layer event name (used by --sample-trace; '
                         'default: new)')
    ap.add_argument('--host', default=None,
                    help='restrict to hosts whose probe file matches this substring')
    ap.add_argument('--function', dest='function_substr', default=None,
                    help='restrict to messages whose Message.function contains '
                         'this substring (used by --counts and --sample-trace)')
    ap.add_argument('-n', '--limit', type=int, default=10,
                    help='--sample-trace limit (default 10)')
    args = ap.parse_args()

    base = Path(args.dir)
    if not base.is_dir():
        print('no probe dir at %s' % base, file=sys.stderr)
        return 1

    if args.peer_set_audit:
        return cmd_peer_set_audit(base)
    if args.counters:
        return cmd_counters(base, args.layer_prefix, args.host)
    if args.breakdown:
        if ':' in args.breakdown:
            layer, _, evt = args.breakdown.partition(':')
            evt_filter = evt or None
        else:
            layer, evt_filter = args.breakdown, None
        group_by = [s.strip() for s in (args.by or 'host').split(',') if s.strip()]
        return cmd_breakdown(base, layer, evt_filter, group_by, args.host)

    events = list(_iter_msg_events(base, host_substr=args.host))
    if not events:
        print('no msg-layer events found in %s' % base, file=sys.stderr)
        return 1

    if args.all:
        return cmd_all(events)
    if args.orphans:
        return cmd_orphans(events, args.by_function)
    if args.has_from_audit is not None:
        return cmd_has_from_audit(events, args.has_from_audit or None)
    if args.counts:
        return cmd_counts(events, args.counts, args.function_substr)
    if args.sample_trace:
        return cmd_sample_trace(events, args.event or 'new',
                                args.function_substr, args.host, args.limit)
    if not args.trace_id_prefix:
        ap.error('provide a trace_id prefix or one of: --all, --orphans, '
                 '--has-from-audit, --peer-set-audit, --counts, --counters, '
                 '--breakdown, --sample-trace')
    return cmd_one(events, args.trace_id_prefix)


if __name__ == '__main__':
    sys.exit(main())
