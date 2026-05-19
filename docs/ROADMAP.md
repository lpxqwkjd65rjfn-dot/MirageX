# Roadmap

This is the public TODO list. Items are grouped by priority bucket.

See [`BETA-RUNBOOK.md`](BETA-RUNBOOK.md) for the current beta release
status (what works today, what doesn't, smoke-test recipe).

## P0 — finish the reference stack

* [x] Forged-ClientHello wire-format primitives inside
      `mirage-tls-reality` (wire / keys / aead / fingerprint / hello).
      Foundation merged; connector swap still pending.
* [ ] Wire the forged-ClientHello + Reality auth signature into
      `RealityConnector::connect` so the live handshake replaces the
      current plain-rustls path.
* [ ] HTTP/2 stream plumbing inside `mirage-transport-xhttp` (single-stream
      mode, then packet-split mode).
* [ ] Vision splice fast-path inside `mirage-vision` + engine integration
      (the flow marker on the VLESS addons is already emitted).
* [ ] UDP CONNECT path for VLESS (UoT-style + native UDP-ASSOCIATE).
* [ ] `mirage-cli`: `subscribe` subcommand that consumes a subscription URL.

## P1 — the rest of the Xray protocol family

* [ ] VMess outbound (AES-128-GCM, chacha20-poly1305, aead-zero).
* [ ] Trojan outbound (+Vision/Reality).
* [ ] Shadowsocks outbound (AEAD, AEAD-2022).
* [ ] SOCKS5 + HTTP CONNECT chained outbounds.
* [ ] WebSocket, HTTPUpgrade, gRPC transports.

## P1 — inbound side

* [ ] SOCKS5 user/pass + UDP ASSOCIATE.
* [ ] HTTP CONNECT inbound.
* [ ] Mixed inbound (auto-detect SOCKS5 vs HTTP on the same port).
* [ ] TUN inbound (`mirage-tun`) on Linux, macOS, Windows, Android, iOS.
* [ ] Transparent inbound (Linux TPROXY + iptables/nftables setup).

## P1 — routing

* [ ] CIDR matcher backed by a radix tree.
* [ ] geosite/.dat loader (v2fly format).
* [ ] geoip/.dat loader.
* [ ] Process matcher (Windows IP-Helper, macOS `proc_pidfdinfo`,
      Linux `/proc/net/...`).
* [ ] Sniffed-protocol matcher (TLS SNI, HTTP Host, QUIC ALPN).

## P2 — mobile

* [ ] BBRv2/BBRv3 advisor (per-flow target rate).
* [ ] FEC layer for QUIC (Raptor-style block code).
* [ ] Multipath QUIC scheduler with explicit path probing.
* [ ] Battery-aware mode: shorter keep-alives, pause pre-warm when on
      battery + locked screen.

## P2 — GUIs

* [ ] Tauri-based desktop GUI for Linux/macOS/Windows.
* [ ] Jetpack Compose GUI for Android (links `mirage-engine` via JNI).
* [ ] SwiftUI GUI for iOS (links `mirage-engine` via `cargo lipo`).

## P3 — research

* [ ] MASQUE / CONNECT-UDP transport.
* [ ] Post-quantum hybrid key exchange (X25519-Kyber768).
* [ ] WebTransport transport (HTTP/3 datagrams).
