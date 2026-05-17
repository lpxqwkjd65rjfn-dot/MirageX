# Mobile-network optimisation

> Goal: make the *50th percentile* of pages still load when the link is
> losing 5–10% of packets, jittering by ≥100ms, and roaming between
> Wi-Fi and LTE.

This document explains, knob by knob, what the `[mobile]` block does
and why it matters. The TL;DR: every default is already tuned for a
typical 4G/5G handset. Deviate from defaults only if you have a
specific environment in mind.

## 1. Congestion control

```toml
[mobile]
congestion = "bbr"   # default
```

* **`cubic`** is the kernel default on most systems. It treats every
  packet loss as congestion, which is exactly wrong on cellular
  links where loss is more often a *radio* event.
* **`bbr` / `bbr2`** measure the bottleneck bandwidth + RTT and pace
  to that target. Result: 2–3× higher throughput on lossy LTE
  links in published measurements (Google, Verizon).
* **`prague` (L4S)** uses ECN to decouple the loss signal from the
  congestion signal. Experimental — useful only with cooperative
  carriers.

The engine sets `TCP_CONGESTION` via `setsockopt` where the OS
exposes it (Linux). On macOS/iOS/Windows the knob is silently
ignored.

## 2. Pacing

```toml
[mobile.pacing]
enabled = true
min_inter_packet_us = 0
burst_bytes = 65536   # ~1 BDP at 50ms × 10 Mb/s
```

Carriers shape per-flow on a millisecond timer. A 64 KiB write that
hits the radio interface in <100 µs typically triggers an immediate
drop; the same 64 KiB paced over the RTT typically does not.

The pacer is bypassed for kernel-paced sockets (Linux with
`SO_PACING`/`SO_MAX_PACING_RATE` set; the kernel's TCP BBR already
paces internally). For QUIC, the pacer is the only line of defence.

## 3. Multipath

```toml
[mobile]
multipath = "auto"   # off / auto / force
```

Where the OS exposes more than one default-route interface (Wi-Fi
+ cellular), the engine opens parallel sub-streams over each. The
implementation today is connection-level (open two TCP
connections, balance writes across them) and migrates upward to
real MP-QUIC once the QUIC stack lands.

Effect on packet loss bursts: an outage on one path becomes a *delay*,
not a *drop*. End-to-end progress continues uninterrupted as long as
at least one path is still alive.

## 4. 0-RTT TLS

```toml
[mobile]
zero_rtt = true
```

Eliminates one full RTT on every reconnect — meaningful on cellular
networks where the average RTT is ≥80 ms. The Reality connector
preserves the resumption ticket on disk (`$XDG_DATA_HOME/miragex`)
across runs.

## 5. Pre-warm pool

```toml
[mobile]
prewarm = 2
```

Keeps `N` pre-established outbound connections hot at any time. The
first user request consumes one immediately, eliminating the TCP +
TLS handshake cost from the critical path. The pool replenishes
asynchronously so the *next* request starts from the warm cache
too.

## 6. Forward error correction

```toml
[mobile]
fec_group      = 8
fec_redundancy = 2
```

For datagram transports (QUIC, MASQUE) the engine emits 2 FEC packets
per 8 data packets, so a 25% loss burst is fully recoverable without
retransmissions. Disabled by default (`fec_group = 0`) — only useful
when the headline RTT is ≥150 ms, because at lower RTTs the cost of
retransmission is already negligible.

## 7. Parallel streams

```toml
[mobile]
parallel_streams = 2
```

Cellular schedulers allocate bandwidth per-flow. 2–4 parallel
streams measurably out-throughput a single one on links with
≥50 ms RTT — at the cost of slightly worse fairness with co-tenants.
MirageX defaults to 2.

## 8. Smooth roaming

```toml
[mobile]
smooth_roaming = true
```

Detects interface flaps (`SCNetworkReachability` on macOS/iOS,
`NetworkChangeNotifier` on Android, `RTM_NEWLINK` on Linux) and
migrates live flows without dropping the application TCP socket.

For QUIC/MASQUE this is a true connection migration. For TCP it's
implemented as a graceful re-dial that preserves the application
view; the engine buffers up to 64 KiB of payload across the
re-dial.

## Putting it all together: cellular tuning checklist

1. `congestion = "bbr"` — default; do not change.
2. `[mobile.pacing].enabled = true`, `burst_bytes` ≈ BDP.
3. `zero_rtt = true`.
4. `prewarm = 2` (raise to 4 on links with RTT ≥ 150 ms).
5. `parallel_streams = 2`.
6. `smooth_roaming = true`.
7. FEC stays off unless you measure it helps.
