#![no_std]
#![no_main]

use aya_ebpf::{
	bindings::xdp_action,
	helpers::bpf_ktime_get_ns,
	macros::{map, xdp},
	maps::{Array, HashMap},
	programs::XdpContext,
};
use aya_log_ebpf::info;
use core::{convert::TryFrom, mem};
use fractalize_ebpf_common::{actions::*, ip_filter::*, logging::*, rate_limit::*};
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

/// IP filter list (allowlist or blocklist, depending on mode)
/// Key: IPv4 address as u32 (network byte order)
/// Value: 1 = present in list
#[map]
static IP_FILTER_LIST: HashMap<u32, u8> = HashMap::with_max_entries(10000, 0);

/// Per-IP rate limiting state
/// Key: IPv4 address as u32 (network byte order)
/// Value: packed u64 (timestamp + packet count)
#[map]
static RATE_LIMIT_STATE: HashMap<u32, u64> = HashMap::with_max_entries(10000, 0);

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

/// Configuration map (runtime configurable from userspace)
/// Index 0: Log level (0=None, 1=DropsOnly, 2=Filtered, 3=All)
/// Index 1: IP filter mode (0=Disabled, 1=Blocklist, 2=Allowlist)
/// Index 2: Rate limit enabled (0=Disabled, 1=Enabled)
/// Index 3: Rate limit PPS (packets per second)
/// Index 4: Rate limit window (milliseconds)
#[map]
static CONFIG: Array<u32> = Array::with_max_entries(10, 0);

/// Get current log level from CONFIG map
#[inline(always)]
fn get_log_level() -> LogLevel {
	match CONFIG.get(CONFIG_LOG_LEVEL) {
		Some(level) => LogLevel::try_from(*level as u8).unwrap_or(LogLevel::Filtered),
		None => LogLevel::Filtered, // Default to filtered mode
	}
}

/// Get current IP filter mode from CONFIG map
#[inline(always)]
fn get_ip_filter_mode() -> IpFilterMode {
	match CONFIG.get(CONFIG_IP_FILTER_MODE) {
		Some(mode) => IpFilterMode::try_from(*mode as u8).unwrap_or(IpFilterMode::Disabled),
		None => IpFilterMode::Disabled, // Default to disabled
	}
}

/// Check if IP should be allowed based on filter mode
/// Returns true if packet should be allowed, false if it should be dropped
#[inline(always)]
fn check_ip_allowed(src_ip: u32, filter_mode: IpFilterMode) -> bool {
	match filter_mode {
		IpFilterMode::Disabled => true, // No filtering, allow all
		IpFilterMode::Blocklist => {
			// If IP is in list, block it
			unsafe { IP_FILTER_LIST.get(&src_ip).is_none() }
		},
		IpFilterMode::Allowlist => {
			// If IP is in list, allow it
			unsafe { IP_FILTER_LIST.get(&src_ip).is_some() }
		},
	}
}

/// Get current timestamp in milliseconds
#[inline(always)]
fn get_current_time_ms() -> u32 {
	// bpf_ktime_get_ns returns nanoseconds since boot
	// Convert to milliseconds, but keep only lower 32 bits (wraps every ~49 days)
	(unsafe { bpf_ktime_get_ns() } / 1_000_000) as u32
}

/// Check if IP is within rate limit
/// Returns true if packet should be allowed, false if rate limit exceeded
#[inline(always)]
fn check_rate_limit(src_ip: u32, pps_limit: u32, window_ms: u32) -> bool {
	let current_time_ms = get_current_time_ms();

	// Get current state for this IP
	let state = unsafe {
		match RATE_LIMIT_STATE.get(&src_ip) {
			Some(packed) => RateLimitState::unpack(*packed),
			None => RateLimitState::new(),
		}
	};

	// Check if we're in a new time window
	let time_elapsed = current_time_ms.wrapping_sub(state.last_seen_ms);

	let new_state = if time_elapsed >= window_ms {
		// New window - reset counter
		RateLimitState { last_seen_ms: current_time_ms, packet_count: 1 }
	} else {
		// Same window - increment counter
		RateLimitState { last_seen_ms: state.last_seen_ms, packet_count: state.packet_count + 1 }
	};

	// Update state in map
	let packed = new_state.pack();
	let _ = RATE_LIMIT_STATE.insert(&src_ip, &packed, 0);

	// Check if we're over the limit
	new_state.packet_count <= pps_limit
}

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
fn check_port_rule(ctx: &XdpContext, src_port: u16, dst_port: u16) -> Option<u32> {
	let log_level = get_log_level();

	// Check destination port first (more common for server ports)
	if let Some(action_code) = unsafe { PORT_RULES.get(&dst_port) } {
		inc_stat(STAT_SUBSTRATE_PACKETS);
		inc_port_stat(dst_port);

		match Action::try_from(*action_code) {
			Ok(Action::Drop) => {
				if log_level >= LogLevel::DropsOnly {
					info!(ctx, "⛔ Dropping packet to port {}", dst_port);
				}
				return Some(xdp_action::XDP_DROP);
			},
			Ok(Action::Pass) => {
				if log_level >= LogLevel::Filtered {
					info!(ctx, "✅ Allowing packet to port {}", dst_port);
				}
				return Some(xdp_action::XDP_PASS);
			},
			Ok(Action::LogOnly) => {
				if log_level >= LogLevel::Filtered {
					info!(ctx, "📝 Logging packet to port {} (pass through)", dst_port);
				}
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

		match Action::try_from(*action_code) {
			Ok(Action::Drop) => {
				if log_level >= LogLevel::DropsOnly {
					info!(ctx, "⛔ Dropping packet from port {}", src_port);
				}
				return Some(xdp_action::XDP_DROP);
			},
			Ok(Action::Pass) => {
				if log_level >= LogLevel::Filtered {
					info!(ctx, "✅ Allowing packet from port {}", src_port);
				}
				return Some(xdp_action::XDP_PASS);
			},
			Ok(Action::LogOnly) => {
				if log_level >= LogLevel::Filtered {
					info!(ctx, "📝 Logging packet from port {} (pass through)", src_port);
				}
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

	let log_level = get_log_level();
	let ip_filter_mode = get_ip_filter_mode();

	// Parse Ethernet header - use offset_of! for efficiency (only validate the field we need)
	let ether_type: *const EtherType = ptr_at(&ctx, mem::offset_of!(EthHdr, ether_type))?;

	// Parse IP layer (IPv4 or IPv6) using EtherType enum
	let (ip_proto, tcp_offset) = match unsafe { *ether_type } {
		EtherType::Ipv4 => {
			// IPv4
			let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
			let src_addr = unsafe { (*ipv4hdr).src_addr };
			let dst_addr = unsafe { (*ipv4hdr).dst_addr };

			// Convert source IP to u32 (already in network byte order)
			let src_ip = u32::from_be_bytes(src_addr);

			// Check IP filter
			if !check_ip_allowed(src_ip, ip_filter_mode) {
				if log_level >= LogLevel::DropsOnly {
					info!(
						&ctx,
						"⛔ Blocked IP: {}.{}.{}.{}",
						src_addr[0],
						src_addr[1],
						src_addr[2],
						src_addr[3]
					);
				}
				return Ok(xdp_action::XDP_DROP);
			}

			// Check rate limit
			let rate_limit_enabled = match CONFIG.get(CONFIG_RATE_LIMIT_ENABLED) {
				Some(enabled) => *enabled != 0,
				None => false,
			};

			if rate_limit_enabled {
				let pps_limit = CONFIG.get(CONFIG_RATE_LIMIT_PPS).copied().unwrap_or(1000);
				let window_ms = CONFIG.get(CONFIG_RATE_LIMIT_WINDOW_MS).copied().unwrap_or(1000);

				if !check_rate_limit(src_ip, pps_limit as u32, window_ms as u32) {
					if log_level >= LogLevel::DropsOnly {
						info!(
							&ctx,
							"⚠️  Rate limit exceeded: {}.{}.{}.{}",
							src_addr[0],
							src_addr[1],
							src_addr[2],
							src_addr[3]
						);
					}
					return Ok(xdp_action::XDP_DROP);
				}
			}

			if log_level == LogLevel::All {
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
			}

			let proto = unsafe { (*ipv4hdr).proto };
			(proto, EthHdr::LEN + Ipv4Hdr::LEN)
		},
		EtherType::Ipv6 => {
			// IPv6
			let ipv6hdr: *const Ipv6Hdr = ptr_at(&ctx, EthHdr::LEN)?;
			let src_addr = unsafe { (*ipv6hdr).src_addr };
			let dst_addr = unsafe { (*ipv6hdr).dst_addr };

			if log_level == LogLevel::All {
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
			}

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

			if log_level == LogLevel::All {
				info!(&ctx, "TCP: port {} → {}", src_port, dst_port);
			}

			// Check for port-based filtering rules
			if let Some(action) = check_port_rule(&ctx, src_port, dst_port) {
				return Ok(action);
			}
		},
		IpProto::Udp => {
			inc_stat(STAT_UDP_PACKETS);
			let udphdr: *const UdpHdr = ptr_at(&ctx, tcp_offset)?;
			let src_port = unsafe { u16::from_be_bytes((*udphdr).src) };
			let dst_port = unsafe { u16::from_be_bytes((*udphdr).dst) };

			if log_level == LogLevel::All {
				info!(&ctx, "UDP: port {} → {}", src_port, dst_port);
			}

			// Check for port-based filtering rules
			if let Some(action) = check_port_rule(&ctx, src_port, dst_port) {
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
