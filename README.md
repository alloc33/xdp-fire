# xdp-fire

🔥 XDP-based firewall written in pure Rust 🦀. Filters packets at kernel level before they hit your network stack.

---

## Why

Block unwanted traffic at the **XDP layer** - the earliest point in Linux networking. Malicious packets get dropped at the NIC, not in userspace.

```
NIC → XDP (filter here) → Network Stack → Your App
```

Fast. Efficient. Zero CPU waste on attack traffic.

---

## Features

- IPv4/IPv6 filtering (allowlist/blocklist)
- Port-based rules (drop/pass/log)
- Per-IP rate limiting
- Real-time statistics
- Pure Rust (no C)

---

## Usage

```bash
# Start filtering
sudo xdp-fire --iface eth0

# Block port
xdp-fire add-rule -p 8080 -a Drop

# Rate limit (1000 pps per IP)
xdp-fire set-rate-limit -e true -l 1000 -w 1000

# Allowlist mode
xdp-fire set-ip-mode -m allowlist
xdp-fire add-ipv4 -i 192.168.1.100

# Stats
xdp-fire show-stats
```

---

## Project Structure

Standard [Aya](https://github.com/aya-rs/aya) workspace — three crates, one build.

```
xdp-fire/
├── xdp-fire-common/        # Shared types (kernel ↔ userspace)
│   └── src/lib.rs           #   Action, LogLevel, IpFilterMode, RateLimitState
│                            #   #![no_std] — must compile for both BPF and host targets
│
├── xdp-fire-ebpf/           # eBPF program (runs inside the Linux kernel)
│   └── src/main.rs          #   Packet parsing, map lookups, XDP_PASS/XDP_DROP verdicts
│                            #   #![no_std], #![no_main] — compiled to BPF bytecode
│
├── xdp-fire/                # Userspace binary (loads eBPF, CLI, map management)
│   ├── build.rs             #   Invokes aya_build to compile the eBPF crate
│   ├── src/main.rs          #   CLI (clap), map pinning, stats display, XDP attach
│   └── tests/               #   Integration tests — load eBPF, poke maps from userspace
│
└── scripts/
    └── benchmark.sh         # iperf3-based throughput comparison (baseline vs XDP)
```

**How they connect:** `cargo build` triggers `xdp-fire/build.rs`, which compiles `xdp-fire-ebpf` into BPF bytecode and embeds it into the final binary. At runtime, the userspace binary loads that bytecode into the kernel and communicates with it through eBPF maps pinned at `/sys/fs/bpf/xdp-fire/`.

---

## Build

```bash
# Requirements
rustup toolchain install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker

# Build
cargo build --release

# Run (requires root)
sudo ./target/release/xdp-fire --iface <interface>
```

---

## Testing

25 tests covering eBPF loading, maps, and filtering logic.

```bash
cargo test --release
```

---

## Limitations

Stateless filtering only. No connection tracking, no config persistence, no GeoIP. Add them if you need them.

---

## Stack

Built with [Aya](https://github.com/aya-rs/aya) - pure Rust eBPF framework.

Kernel and userspace code both in Rust. No C required.

---

## License

Userspace: MIT or Apache-2.0
eBPF: GPL-2 or MIT
