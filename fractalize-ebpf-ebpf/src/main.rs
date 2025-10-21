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

const ETH_P_IP: u16 = 0x0800; // IPv4 protocol (in network byte order: 0x0008)

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
		// Packet too small, pass it through
		return Ok(xdp_action::XDP_PASS);
	}

	// Parse Ethernet header (safe - bounds checked above)
	let eth = unsafe { *(data_start as *const EthernetHeader) };

	// Convert ether_type from network byte order to host byte order
	let ether_type = u16::from_be(eth.ether_type);

	// Log Ethernet information
	info!(&ctx, "Packet: EtherType=0x{:x}", ether_type);

	// Only process IPv4 packets for now
	if ether_type == ETH_P_IP {
		info!(&ctx, "IPv4 packet detected");
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
