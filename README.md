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
