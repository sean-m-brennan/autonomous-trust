<!--
 Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
 Licensed under the Apache License, Version 2.0.
-->
[< Networking](networking.md)

# TCP Connection Pooling

The TCP transport reuses one connection per peer for many messages instead
of opening a fresh connection for each one. Pooling is **on by default** since
2026-08-10; with `AT_NET_POOL=0` the transport behaves exactly as it always
has, one `connect`/`send`/`close` per message.

> Sending is pooled in the Python `TCPNetworkProcess` (`network/tcp.py`); C
> senders (`src/c/autonomous_trust/network/net_transport_tcp.c`) still connect
> per message. **Receiving** reuses in both runtimes. Pooling changes only the
> connection *lifecycle*, not the wire *format*, so a pooling node and a
> per-message node interoperate — with one historical exception that cost
> silent message loss, described under [Interoperability](#interoperability).

## Why pooling exists

Without pooling, `TCPNetworkProcess` opens a TCP connection for every
application message: `socket()`, `connect()`, send one length-prefixed frame,
`close()`. The receiver mirrors it, accepting a client socket, reading exactly
one frame, then dropping the socket. Every message therefore costs a full
handshake and teardown on both ends.

In a co-located cohort this is expensive. With dozens of processes on one host,
the handshake and per-connection setup rate tracks the message rate and burns a
continuous slice of CPU, independent of the poll cadence. Pooling reuses a
connection across many messages, so in steady state the handshake rate drops
from roughly one per message to roughly one per peer per idle period.

## Framing is unchanged

Each message is a 4-byte big-endian length prefix followed by that many bytes
of payload (`struct.pack('!I', len)` + body). A pooled connection simply
carries many of these frames back to back. `_recv` already reads exactly one
frame at a time, so a persistent reader is the same read logic called in a
loop. Because the bytes on the wire are identical either way, the conformance
corpus (which pins message bytes, not connection lifecycle) is unaffected.

## Send side: the connection pool

`TCPNetworkProcess` keeps a pool keyed by destination:

- `self._conn_pool`: a `dict` mapping `(host, port)` to a `_PooledConn`
  (the live socket plus the wall-clock time it was last used).
- `self._pool_lock`: a `threading.Lock` guarding the pool. Sends run on the
  network main loop, so the lock mainly guards the loop against the group and
  ping paths rather than heavy contention.

`_send_tcp` picks the path based on the feature flag. With pooling off it runs
the historical inline `connect`/`send`/`close`. With pooling on it calls
`_send_tcp_pooled`:

```mermaid
flowchart TD
    Start["_send_tcp_pooled(msg, host, port)"] --> Get{"pooled socket<br/>for (host, port)?"}
    Get -- "hit" --> Reuse["reuse socket<br/>(reuse counter)"]
    Get -- "miss" --> Cap{"pool at<br/>max size?"}
    Cap -- "yes" --> EvictOld["evict oldest idle<br/>(evict_cap)"]
    Cap -- "no" --> Connect
    EvictOld --> Connect["connect + set keepalive<br/>(connect counter)"]
    Reuse --> Write["write framed message"]
    Connect --> Write
    Write --> Ok{"send ok?"}
    Ok -- "yes" --> Touch["update last_used, keep open"]
    Ok -- "no (reset / broken pipe)" --> Evict["close + evict socket"]
    Evict --> Retry{"first attempt?"}
    Retry -- "yes" --> Reconnect["reconnect once<br/>(reconnect counter)"]
    Reconnect --> Get
    Retry -- "no" --> Raise["raise TransmissionError"]
```

Three behaviors are worth calling out:

**Reconnect once.** A pooled socket can be half-open: the peer recycled or reset
it, but this side has not noticed yet. The first write on such a socket fails
with a socket error. The pool closes and evicts it, then reconnects and retries
exactly once. A second failure raises `TransmissionError`, which is what the
caller already handles for the per-message path.

**Keepalive.** New pooled sockets get `SO_KEEPALIVE`, plus idle, interval, and
count tuning where the platform exposes them (Linux `TCP_KEEPIDLE`,
`TCP_KEEPINTVL`, `TCP_KEEPCNT`). This lets the OS notice a dead peer on an
otherwise idle connection.

**Idle reaping.** `reap_idle_conns` runs once per main-loop iteration and
rate-limits itself. On each sweep it closes and evicts any connection idle
longer than the TTL, so the pool does not hold file descriptors open for peers
that have gone quiet. A live-connection cap bounds the pool size directly; when
a new destination would exceed it, the oldest idle connection is evicted first.

## Receive side: persistent readers

When a sender keeps its connection open and streams frames, the receiver cannot
go back to `accept` after a single read. With pooling on, `start_receivers`
launches an acceptor thread per channel instead of the accept-read-one receiver:

- The acceptor loops on `accept`. It applies the same gates as the per-message
  path, dropping its own address and blacklisted senders, and enforces the
  live-connection cap. For each surviving connection it hands the client socket
  to a reader thread.
- Each reader loops `_recv` on its socket, appending `(raw, from_addr)` to the
  same `peer_messages` (or `group_messages`) deque the main loop already
  drains. Downstream attribution and rate tracking are therefore unchanged. The
  reader exits when the peer disconnects, on a transmission error, or after the
  socket has been idle past the TTL, then closes the socket and removes itself
  from the live set.

This is the thread-per-connection model, which suits the cohort sizes seen here
(roughly ten to twenty connections per node). Its cost is one thread and one
file descriptor per live peer connection, bounded by the cap. A selector-based
single reader would scale to far more connections with O(1) threads, at the
price of per-connection read buffers to reassemble frames across partial
wakeups. That is the escape hatch if a much larger cohort ever needs it; it is
not implemented today.

## Concurrency

The send pool is guarded by one lock. Sends originate on the network main loop,
so the lock's job is to keep the group and ping paths from racing the loop, not
to arbitrate many concurrent senders. Receive readers are independent, one per
connection, each feeding a thread-safe deque, which was already the case for the
per-message receivers.

The pool lock and the reader-set lock are `threading.Lock` objects, which cannot
be pickled across the multiprocessing spawn handoff. They are therefore created
in `_init_transport`, which runs once in the worker subprocess before any
receiver thread starts, mirroring how the ping thread pool is created lazily for
the same reason. At shutdown, `close_connections` drains the send pool; reader
threads notice the stop flag and close their own sockets.

## Interoperability

Pooling changes lifecycle, not wire bytes, so a pooling node interoperates with
a per-message node in either direction:

- A pooling sender talking to a receiver that takes **one frame per connection**
  is NOT safe, and no sender-side check can make it safe. Measured against a
  one-frame receiver that waits 0.5 s before reading: of four frames sent 50 ms
  apart, **one arrived and three were lost, with no error raised on either
  side.** The reason there is nothing to detect is that the socket is genuinely
  healthy at write time — the peer has not closed it, it simply is never going
  to read a second frame from it, and the frames already in its buffer are
  discarded when it closes.

  (The narrower case, where the peer has *already* closed, is self-correcting
  and always was: the frame's length prefix and body go out as two `send`s, the
  RST from the first is seen by the second, and `_send_tcp_pooled`'s
  reconnect-once retry re-sends the whole frame. Measured 20/20 delivered. The
  `_peer_gone` probe added in 2026-08-10 turns that failed-write-and-retry into
  a clean reconnect — worth having, but it is not what makes pooling safe.)

  What makes it safe is the **receiver** reading many frames per connection,
  which both runtimes now do. Same four-frame scenario against the fixed C
  receiver: 4/4 delivered over one connection.
- A per-message sender talking to a pooling receiver succeeds. The persistent
  reader accepts the connection, reads the single frame, and then sees a clean
  close on the next read and exits. Each message costs one short-lived reader
  thread, which is fine at these cohort sizes.

Both runtimes now reuse on the receive side. C's transport
(`net_transport_tcp.c`) holds accepted connections open between frames, serving
the ones it already holds before accepting a new one, bounded by the same
`AT_NET_CONN_IDLE_TTL` / `AT_NET_MAX_CONNS` knobs with the same defaults. C
senders still connect per message; that is a missed optimization, not a
correctness gap, since a per-message sender is exactly the case a pooling
receiver already handles.

Because the two sides negotiate nothing about connection reuse, a cohort can mix
pooling and non-pooling nodes — with one caveat that is a genuine flag day, and
the reason `AT_NET_POOL` defaulting to on is a fleet-wide decision rather than a
per-node one:

> **A C node built before 2026-08-10 takes one frame per connection.** A pooling
> Python sender talking to one loses frames silently, as measured above. Any
> fleet still running such nodes must set `AT_NET_POOL=0` until they are
> rebuilt. Nothing detects this at runtime — the sender sees successful writes
> and the receiver sees well-formed frames; the messages simply are not there.

## Configuration

Pooling is controlled from `system.py`, which reads the following environment
variables at import time. C reads the same names, with the same defaults
(`net_conn_idle_ttl_resolve` / `net_max_live_conns_resolve` in `net_proc.c`),
so one deployment setting tunes both runtimes.

| Setting | Env var | Default | Meaning |
|---------|---------|---------|---------|
| `net_persistent_conn` | `AT_NET_POOL` | **on** (since 2026-08-10) | Connection pooling and persistent readers. Set `0` for the per-message path. |
| `net_conn_idle_ttl` | `AT_NET_CONN_IDLE_TTL` | 30 s | Close a pooled or accepted connection after this long idle. |
| `net_max_live_conns` | `AT_NET_MAX_CONNS` | 64 | Cap on simultaneous live connections per direction. |

The per-message path stays in place as the fallback `AT_NET_POOL=0` selects; it
is the right setting for a fleet with pre-2026-08-10 C nodes still in it, and
the one to try first if a network problem appears after this change.

Still unmeasured under load: the CPU and churn numbers that motivated pooling
were taken against the per-message baseline, and the pooled path has unit-level
coverage on both runtimes but has not been run against the multi-agency cohort.
`net.tcp.send/reuse` dominating `net.tcp.send/connect` is the signal to look for.

## Metrics

When probes are enabled (`AT_PROBES`), the transport emits counters that show
whether pooling is doing its job. Reuse should dominate connects, and the accept
rate should fall well below the message rate.

| Counter | Meaning |
|---------|---------|
| `net.tcp.send/reuse` | Message sent on an existing pooled socket. |
| `net.tcp.send/connect` | New connection opened (also emitted by the per-message path). |
| `net.tcp.send/reconnect` | Pooled socket was dead; reconnected once. |
| `net.tcp.send/connect_failed` | `connect` itself failed. |
| `net.tcp.pool/evict_idle` | Connections closed by the idle reaper. |
| `net.tcp.pool/evict_cap` | Oldest connection evicted to respect the cap. |
| `net.tcp.{peer,group}/accepted` | Inbound connection accepted. |
| `net.tcp.{peer,group}/drop` | Inbound connection refused (own address, blacklist, or cap). |
| `net.tcp.reader/open`, `net.tcp.reader/close` | Persistent reader started or exited (close carries a reason). |

## Failure handling

- **Half-open or reset sockets** on the send side are caught by the
  reconnect-once retry, backed by keepalive for connections that sit idle.
- **Resource exhaustion.** Long-lived sockets widen the surface for a peer that
  tries to hold many connections open. The live-connection cap and idle TTL
  bound both directions, and the accept-time blacklist and own-address gates
  still apply before a reader thread is ever created.
- **Ordering** is preserved, since frames are sequential within a connection.

[< Networking](networking.md)
