# Protocol matrix

The table below tracks the on-the-wire feature coverage of the current
release. ✅ = implemented in this revision, 🚧 = scaffolded
(crate exists, public API stable, internals being filled in), ⏳ =
planned, ❌ = explicit non-goal.

## Inner protocols

| Protocol | TCP | UDP | Mux | Flow tags |
| --- | --- | --- | --- | --- |
| VLESS | ✅ | 🚧 | 🚧 | `none`, `xtls-rprx-vision` |
| VMess | ⏳ | ⏳ | ⏳ | n/a |
| Trojan | ⏳ | ⏳ | n/a | `none`, `xtls-rprx-vision` |
| Shadowsocks (AEAD) | ⏳ | ⏳ | n/a | n/a |
| Shadowsocks 2022 | ⏳ | ⏳ | n/a | n/a |

## Outer TLS layer

| Outer | Status | Notes |
| --- | --- | --- |
| Plain TLS 1.3 | 🚧 | rustls 0.23 |
| Reality | 🚧 | uTLS-style forged hello incremental; primitives done |
| Anti-fingerprint TLS (`utls`-style: chrome/firefox/safari/ios) | ⏳ | tied to Reality |
| Post-quantum TLS (X25519-Kyber768) | ⏳ | gated behind feature flag |
| No-TLS | ✅ | for chained inbounds, debug |

## Transports

| Transport | Status | Notes |
| --- | --- | --- |
| Raw TCP | ✅ | TFO, keep-alive, optional bind-to-iface |
| XHTTP | 🚧 | Padding helpers + dial settings; HTTP/2 stream plumbing wires next |
| WebSocket | ⏳ | with `early_data` shortcut |
| HTTPUpgrade | ⏳ | |
| gRPC | ⏳ | with `multi_mode` |
| HTTP/3 (QUIC) | ⏳ | uses quinn; piggy-backs XHTTP `force_h3` |
| MASQUE | ⏳ | UDP-over-HTTP/3 with multipath |
| HY2 / TUIC | ❌ | use a dedicated client |

## Inbounds

| Inbound | Status | Notes |
| --- | --- | --- |
| SOCKS5 (TCP) | ✅ | no auth + user/pass |
| SOCKS5 (UDP ASSOCIATE) | ⏳ | |
| HTTP CONNECT | ⏳ | |
| Mixed (HTTP+SOCKS on same port) | ⏳ | |
| TUN (Linux, macOS, Windows, Android, iOS) | ⏳ | shared crate `mirage-tun` |
| Transparent (Linux TPROXY) | ⏳ | Linux-only |

## Routing matchers

| Matcher | Status |
| --- | --- |
| inbound_tag | ✅ |
| domain (exact/suffix/regex) | ✅ (exact, suffix; regex falls back to exact) |
| ip_cidr | 🚧 |
| port | ✅ |
| network (tcp/udp) | ✅ |
| geosite | ⏳ (loader for the v2fly dat files) |
| geoip | ⏳ |
| process_name | ⏳ |
| sniffed protocol (TLS/HTTP/QUIC) | ⏳ |
