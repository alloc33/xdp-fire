#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
	eth::{EthHdr, EtherType},
	ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
	tcp::TcpHdr,
};

// Substrate P2P port
const SUBSTRATE_PORT: u16 = 30333;

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
		_ => return Ok(xdp_action::XDP_PASS), // Not IP packet (ARP, etc.)
	};

	// Parse TCP layer using IpProto enum
	if ip_proto == IpProto::Tcp {
		let tcphdr: *const TcpHdr = ptr_at(&ctx, tcp_offset)?;
		let src_port = unsafe { u16::from_be_bytes((*tcphdr).source) };
		let dst_port = unsafe { u16::from_be_bytes((*tcphdr).dest) };

		info!(&ctx, "TCP: port {} → {}", src_port, dst_port);

		// Check for Substrate P2P traffic (port 30333)
		if dst_port == SUBSTRATE_PORT || src_port == SUBSTRATE_PORT {
			info!(&ctx, "🔍 Substrate P2P traffic detected on port 30333!");
			// TODO: Add filtering logic here (XDP_DROP or XDP_PASS)
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
