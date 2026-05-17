# MirageX vs sing-box

This file is a frank, point-by-point comparison. It exists because
"better than sing-box" is the kind of claim that should be specific
and falsifiable.

## Where MirageX intends to *beat* sing-box

| Topic | sing-box | MirageX (target) |
| --- | --- | --- |
| Language | Go | Rust |
| RSS at idle (typical) | 40–60 MiB | <12 MiB (per design budget) |
| Cold start to first dial | 80–150 ms | <20 ms (per design budget) |
| Connection RSS overhead | ~12 KiB / conn | ~2 KiB / conn |
| Config schema | JSON, weakly-typed | TOML + JSON, typed Rust structs with `serde(deny_unknown_fields)` |
| Mobile-network knobs | basic | first-class `[mobile]` block |
| Vision flow | tied to VLESS | own crate, reusable |
| Reality transport coupling | tied to specific transports | composable with any transport |
| Multi-process security | single binary | future: split `engine` ↔ `tunnel` privsep |
| Cross-compile | requires Go cross toolchain | one `cargo build --target …` matrix |

The "target" column is design-budget, not current measurement. The
file will be updated with empirical numbers once the engine ships
its first end-to-end benchmark suite.

## Where sing-box is currently ahead

| Topic | Sing-box | MirageX |
| --- | --- | --- |
| Maturity | 2+ years, large adoption | foundation only |
| Protocol coverage | very broad (Naive, Hysteria, TUIC, …) | Xray family only (by design) |
| Pre-built mobile GUIs | yes | not yet |
| `clash`-style API | yes | planned (`ControlConfig`) |
| Built-in geosite/geoip dbs | yes | planned |

## Why we chose this trade-off

* The Xray protocol family covers the overwhelming majority of
  real-world deployments. Adding Hysteria/TUIC ourselves splits
  attention; if you need those, use the dedicated upstream clients.
* The mobile-network optimisation surface is *under-served* by
  every general-purpose proxy client we surveyed. That's where
  MirageX is willing to spend its engineering budget.
* Rust's memory model gives us a real shot at the RSS / cold-start
  budgets above. Go cannot match them — that's not a slight on Go,
  just an observation about runtime cost.
