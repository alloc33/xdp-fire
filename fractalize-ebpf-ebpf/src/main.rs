#![no_std]
#![no_main]

use aya_ebpf::{
	bindings::xdp_action,
	macros::{map, xdp},
	maps::{Array, HashMap},
	programs::XdpContext,
};
use aya_log_ebpf::info;
use core::convert::TryFrom;
use core::mem;
use fractalize_ebpf_common::actions::*;
use network_types::{
	eth::{EthHdr, EtherType},
	ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
	tcp::TcpHdr,
	udp::UdpHdr,
};

/// Port-based filtering rules (runtime configurable from userspace)
/// Key: port number (u16)
/// Value: action (u8) - see Action enum (0=Pass, 1=Drop, 2=LogOnly)
#[map]
static PORT_RULES: HashMap<u16, u8> = HashMap::with_max_entries(100, 0);

/// Per-port packet statistics (runtime readable from userspace)
/// Key: port number (u16)
/// Value: packet count (u64)
#[map]
static PORT_STATS: HashMap<u16, u64> = HashMap::with_max_entries(100, 0);

// Statistics indices
const STAT_TOTAL_PACKETS: u32 = 0;
const STAT_TCP_PACKETS: u32 = 1;
const STAT_UDP_PACKETS: u32 = 2;
const STAT_SUBSTRATE_PACKETS: u32 = 3;
const STAT_NON_IP_PACKETS: u32 = 4;

/// Packet statistics map
/// - Index 0: Total packets processed
/// - Index 1: TCP packets
/// - Index 2: UDP packets
/// - Index 3: Substrate P2P packets (port 30333, TCP or UDP)
/// - Index 4: Non-IP packets (ARP, etc.)
#[map]
static STATS: Array<u64> = Array::with_max_entries(5, 0);

/// Helper function to increment a statistic counter with zero overhead
/// Uses get_ptr_mut for direct memory access without bounds checking in hot path
#[inline(always)]
fn inc_stat(index: u32) {
	if let Some(counter) = STATS.get_ptr_mut(index) {
		unsafe { *counter += 1 };
	}
}

/// Increment packet counter for a specific port
#[inline(always)]
fn inc_port_stat(port: u16) {
	unsafe {
		let count = PORT_STATS.get(&port).copied().unwrap_or(0);
		let _ = PORT_STATS.insert(&port, &(count + 1), 0);
	}
}

/// Check if packet port has a filtering rule and apply it
/// Returns Some(action) if rule exists, None if no rule (pass through)
#[inline(always)]
fn check_port_rule(
	ctx: &XdpContext,
	src_port: u16,
	dst_port: u16,
	proto_name: &str,
) -> Option<u32> {
	// Check destination port first (more common for server ports)
	if let Some(action_code) = unsafe { PORT_RULES.get(&dst_port) } {
		inc_stat(STAT_SUBSTRATE_PACKETS);
		inc_port_stat(dst_port);
		info!(ctx, "🔍 Filtered port {} ({}) - dst", dst_port, proto_name);

		match Action::try_from(*action_code) {
			Ok(Action::Drop) => {
				info!(ctx, "⛔ Dropping packet to port {}", dst_port);
				return Some(xdp_action::XDP_DROP);
			},
			Ok(Action::Pass) => {
				info!(ctx, "✅ Allowing packet to port {}", dst_port);
				return Some(xdp_action::XDP_PASS);
			},
			Ok(Action::LogOnly) => {
				info!(ctx, "📝 Logging packet to port {} (pass through)", dst_port);
				// Continue processing, don't return
			},
			Err(_) => {
				// Unknown action, pass through
			},
		}
	}

	// Check source port (for responses from monitored services)
	if let Some(action_code) = unsafe { PORT_RULES.get(&src_port) } {
		inc_stat(STAT_SUBSTRATE_PACKETS);
		inc_port_stat(src_port);
		info!(ctx, "🔍 Filtered port {} ({}) - src", src_port, proto_name);

		match Action::try_from(*action_code) {
			Ok(Action::Drop) => {
				info!(ctx, "⛔ Dropping packet from port {}", src_port);
				return Some(xdp_action::XDP_DROP);
			},
			Ok(Action::Pass) => {
				info!(ctx, "✅ Allowing packet from port {}", src_port);
				return Some(xdp_action::XDP_PASS);
			},
			Ok(Action::LogOnly) => {
				info!(ctx, "📝 Logging packet from port {} (pass through)", src_port);
				// Continue processing, don't return
			},
			Err(_) => {
				// Unknown action, pass through
			},
		}
	}

	None
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
	let start = ctx.data();
	let end = ctx.data_end();
	let len = mem::size_of::<T>();

	if start + offset + len > end {
		return Err(());
	}

	Ok((start + offset) as *const T)
}

#[xdp]
pub fn fractalize_ebpf(ctx: XdpContext) -> u32 {
	match try_fractalize_ebpf(ctx) {
		Ok(ret) => ret,
		Err(_) => xdp_action::XDP_ABORTED,
	}
}

fn try_fractalize_ebpf(ctx: XdpContext) -> Result<u32, ()> {
	// Count total packets processed
	inc_stat(STAT_TOTAL_PACKETS);

	// Parse Ethernet header - use offset_of! for efficiency (only validate the field we need)
	let ether_type: *const EtherType = ptr_at(&ctx, mem::offset_of!(EthHdr, ether_type))?;

	// Parse IP layer (IPv4 or IPv6) using EtherType enum
	let (ip_proto, tcp_offset) = match unsafe { *ether_type } {
		EtherType::Ipv4 => {
			// IPv4
			let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
			let src_addr = unsafe { (*ipv4hdr).src_addr };
			let dst_addr = unsafe { (*ipv4hdr).dst_addr };

			info!(
				&ctx,
				"IPv4: {}.{}.{}.{} → {}.{}.{}.{}",
				src_addr[0],
				src_addr[1],
				src_addr[2],
				src_addr[3],
				dst_addr[0],
				dst_addr[1],
				dst_addr[2],
				dst_addr[3]
			);

			let proto = unsafe { (*ipv4hdr).proto };
			(proto, EthHdr::LEN + Ipv4Hdr::LEN)
		},
		EtherType::Ipv6 => {
			// IPv6
			let ipv6hdr: *const Ipv6Hdr = ptr_at(&ctx, EthHdr::LEN)?;
			let src_addr = unsafe { (*ipv6hdr).src_addr };
			let dst_addr = unsafe { (*ipv6hdr).dst_addr };

			info!(
				&ctx,
				"IPv6: {:x}{:x}:{:x}{:x}:{:x}{:x}:{:x}{:x}... → {:x}{:x}:{:x}{:x}:{:x}{:x}:{:x}{:x}...",
				src_addr[0],
				src_addr[1],
				src_addr[2],
				src_addr[3],
				src_addr[4],
				src_addr[5],
				src_addr[6],
				src_addr[7],
				dst_addr[0],
				dst_addr[1],
				dst_addr[2],
				dst_addr[3],
				dst_addr[4],
				dst_addr[5],
				dst_addr[6],
				dst_addr[7]
			);

			let next_hdr = unsafe { (*ipv6hdr).next_hdr };
			(next_hdr, EthHdr::LEN + Ipv6Hdr::LEN)
		},
		_ => {
			// Not IP packet (ARP, etc.)
			inc_stat(STAT_NON_IP_PACKETS);
			return Ok(xdp_action::XDP_PASS);
		},
	};

	// Parse transport layer (TCP or UDP)
	match ip_proto {
		IpProto::Tcp => {
			inc_stat(STAT_TCP_PACKETS);
			let tcphdr: *const TcpHdr = ptr_at(&ctx, tcp_offset)?;
			let src_port = unsafe { u16::from_be_bytes((*tcphdr).source) };
			let dst_port = unsafe { u16::from_be_bytes((*tcphdr).dest) };

			info!(&ctx, "TCP: port {} → {}", src_port, dst_port);

			// Check for port-based filtering rules
			if let Some(action) = check_port_rule(&ctx, src_port, dst_port, "TCP") {
				return Ok(action);
			}
		},
		IpProto::Udp => {
			inc_stat(STAT_UDP_PACKETS);
			let udphdr: *const UdpHdr = ptr_at(&ctx, tcp_offset)?;
			let src_port = unsafe { u16::from_be_bytes((*udphdr).src) };
			let dst_port = unsafe { u16::from_be_bytes((*udphdr).dst) };

			info!(&ctx, "UDP: port {} → {}", src_port, dst_port);

			// Check for port-based filtering rules
			if let Some(action) = check_port_rule(&ctx, src_port, dst_port, "UDP/QUIC") {
				return Ok(action);
			}
		},
		_ => {
			// Other protocols (ICMP, SCTP, etc.) - just pass through
		},
	}

	Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
	loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
