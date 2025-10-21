#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use core::mem;

// Ethernet header structure (14 bytes)
#[repr(C)]
#[derive(Copy, Clone)]
struct EthernetHeader {
	dst_mac: [u8; 6],
	src_mac: [u8; 6],
	ether_type: u16, // Network byte order (big-endian)
}

// IPv4 header structure (minimum 20 bytes)
#[repr(C)]
#[derive(Copy, Clone)]
struct Ipv4Header {
	version_ihl: u8, // Version (4 bits) + IHL (4 bits)
	tos: u8,         // Type of Service
	total_len: u16,  // Total length
	id: u16,         // Identification
	frag_off: u16,   // Fragment offset
	ttl: u8,         // Time to live
	protocol: u8,    // Protocol (TCP=6, UDP=17)
	checksum: u16,   // Header checksum
	src_addr: u32,   // Source IP address
	dst_addr: u32,   // Destination IP address
}

// IPv6 header structure (40 bytes)
#[repr(C)]
#[derive(Copy, Clone)]
struct Ipv6Header {
	version_traffic_flow: u32, // Version(4) + Traffic class(8) + Flow label(20)
	payload_len: u16,          // Payload length
	next_header: u8,           // Next header (same as IPv4 protocol: TCP=6)
	hop_limit: u8,             // Hop limit (TTL equivalent)
	src_addr: [u8; 16],        // Source address (128 bits)
	dst_addr: [u8; 16],        // Destination address (128 bits)
}

// TCP header structure (minimum 20 bytes)
#[repr(C)]
#[derive(Copy, Clone)]
struct TcpHeader {
	src_port: u16,     // Source port
	dst_port: u16,     // Destination port
	seq: u32,          // Sequence number
	ack: u32,          // Acknowledgment number
	offset_flags: u16, // Data offset(4 bits) + Reserved(3) + Flags(9)
	window: u16,       // Window size
	checksum: u16,     // Checksum
	urgent: u16,       // Urgent pointer
}

const ETH_P_IP: u16 = 0x0800; // IPv4 protocol
const ETH_P_IPV6: u16 = 0x86dd; // IPv6 protocol
const IPPROTO_TCP: u8 = 6; // TCP protocol

#[xdp]
pub fn fractalize_ebpf(ctx: XdpContext) -> u32 {
	match try_fractalize_ebpf(ctx) {
		Ok(ret) => ret,
		Err(_) => xdp_action::XDP_ABORTED,
	}
}

fn try_fractalize_ebpf(ctx: XdpContext) -> Result<u32, u32> {
	// Get packet data pointers
	let data_start = ctx.data();
	let data_end = ctx.data_end();

	// Check if we have enough data for Ethernet header (14 bytes)
	let eth_header_end = data_start + mem::size_of::<EthernetHeader>();
	if eth_header_end > data_end {
		return Ok(xdp_action::XDP_PASS);
	}

	// Parse Ethernet header
	let eth = unsafe { *(data_start as *const EthernetHeader) };
	let ether_type = u16::from_be(eth.ether_type);

	// Parse IP layer (both IPv4 and IPv6)
	let ip_header_start = data_start + mem::size_of::<EthernetHeader>();
	let (protocol, tcp_start) = match ether_type {
		ETH_P_IP => {
			// IPv4 packet
			let ip_header_end = ip_header_start + mem::size_of::<Ipv4Header>();
			if ip_header_end > data_end {
				return Ok(xdp_action::XDP_PASS);
			}

			let ip = unsafe { *(ip_header_start as *const Ipv4Header) };
			let src_ip = u32::from_be(ip.src_addr);
			let dst_ip = u32::from_be(ip.dst_addr);
			let src_bytes = src_ip.to_be_bytes();
			let dst_bytes = dst_ip.to_be_bytes();

			info!(
				&ctx,
				"IPv4: {}.{}.{}.{} → {}.{}.{}.{}",
				src_bytes[0],
				src_bytes[1],
				src_bytes[2],
				src_bytes[3],
				dst_bytes[0],
				dst_bytes[1],
				dst_bytes[2],
				dst_bytes[3]
			);

			(ip.protocol, ip_header_end)
		},
		ETH_P_IPV6 => {
			// IPv6 packet
			let ip_header_end = ip_header_start + mem::size_of::<Ipv6Header>();
			if ip_header_end > data_end {
				return Ok(xdp_action::XDP_PASS);
			}

			let ip6 = unsafe { *(ip_header_start as *const Ipv6Header) };

			info!(
				&ctx,
				"IPv6: {:x}{:x}:{:x}{:x}:{:x}{:x}:{:x}{:x}... → {:x}{:x}:{:x}{:x}:{:x}{:x}:{:x}{:x}...",
				ip6.src_addr[0],
				ip6.src_addr[1],
				ip6.src_addr[2],
				ip6.src_addr[3],
				ip6.src_addr[4],
				ip6.src_addr[5],
				ip6.src_addr[6],
				ip6.src_addr[7],
				ip6.dst_addr[0],
				ip6.dst_addr[1],
				ip6.dst_addr[2],
				ip6.dst_addr[3],
				ip6.dst_addr[4],
				ip6.dst_addr[5],
				ip6.dst_addr[6],
				ip6.dst_addr[7]
			);

			(ip6.next_header, ip_header_end)
		},
		_ => {
			// Not IP packet (ARP, etc.), pass through
			return Ok(xdp_action::XDP_PASS);
		},
	};

	// Parse TCP layer (same for both IPv4 and IPv6!)
	if protocol == IPPROTO_TCP {
		let tcp_header_end = tcp_start + mem::size_of::<TcpHeader>();
		if tcp_header_end > data_end {
			return Ok(xdp_action::XDP_PASS);
		}

		let tcp = unsafe { *(tcp_start as *const TcpHeader) };
		let src_port = u16::from_be(tcp.src_port);
		let dst_port = u16::from_be(tcp.dst_port);

		info!(&ctx, "TCP: port {} → {}", src_port, dst_port);

		// Check for Substrate P2P traffic (port 30333)
		if dst_port == 30333 || src_port == 30333 {
			info!(&ctx, "🔍 Substrate P2P traffic detected on port 30333!");
		}
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
