//! Integration tests for fractalize-ebpf
//!
//! These tests verify:
//! 1. eBPF program loads successfully
//! 2. Maps can be accessed and modified
//! 3. Configuration changes work correctly
//! 4. Statistics are tracked properly
//!
//! Run with: ./scripts/ubuntu-exec.sh "cd /root/fractalize-ebpf && cargo test"

use aya::{
	Ebpf,
	maps::{Array, HashMap},
};
use fractalize_ebpf_common::{actions::Action, ip_filter::IpFilterMode, logging::LogLevel};

// Config array indices (from fractalize-ebpf-ebpf/src/main.rs)
const CONFIG_LOG_LEVEL: u32 = 0;
const CONFIG_IP_FILTER_MODE: u32 = 1;
const CONFIG_RATE_LIMIT_ENABLED: u32 = 2;

/// Load the eBPF program without attaching it
fn load_ebpf() -> Result<Ebpf, Box<dyn std::error::Error>> {
	// Read the compiled eBPF bytecode using the same approach as main.rs
	let ebpf_bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/fractalize-ebpf"));

	// Load it into the kernel (but don't attach)
	let ebpf = Ebpf::load(ebpf_bytes)?;
	Ok(ebpf)
}

#[test]
fn test_load_program() {
	// This test verifies the eBPF program loads without errors
	let result = load_ebpf();
	assert!(result.is_ok(), "Failed to load eBPF program: {:?}", result.err());
}

#[test]
fn test_port_rules_map() {
	let mut ebpf = load_ebpf().expect("Failed to load eBPF program");

	// Get the PORT_RULES map
	let mut port_rules: HashMap<_, u16, u8> = ebpf
		.take_map("PORT_RULES")
		.expect("PORT_RULES map not found")
		.try_into()
		.expect("Failed to convert to HashMap");

	// Test: Add a drop rule for port 8080
	let port: u16 = 8080;
	let action = Action::Drop as u8;
	port_rules.insert(port, action, 0).expect("Failed to insert into PORT_RULES");

	// Verify we can read it back
	let retrieved = port_rules.get(&port, 0).expect("Failed to get from PORT_RULES");
	assert_eq!(retrieved, action, "Port rule mismatch");

	// Test: Update to Pass
	let new_action = Action::Pass as u8;
	port_rules.insert(port, new_action, 0).expect("Failed to update PORT_RULES");
	let retrieved = port_rules.get(&port, 0).expect("Failed to get updated rule");
	assert_eq!(retrieved, new_action, "Updated port rule mismatch");
}

#[test]
fn test_port_stats_map() {
	let mut ebpf = load_ebpf().expect("Failed to load eBPF program");

	// Get the PORT_STATS map
	let mut port_stats: HashMap<_, u16, u64> = ebpf
		.take_map("PORT_STATS")
		.expect("PORT_STATS map not found")
		.try_into()
		.expect("Failed to convert to HashMap");

	// Test: Initialize stats for port 30333
	let port: u16 = 30333;
	let count: u64 = 0;
	port_stats.insert(port, count, 0).expect("Failed to insert into PORT_STATS");

	// Simulate increment (in real XDP program, this would happen on packet processing)
	let retrieved = port_stats.get(&port, 0).expect("Failed to get from PORT_STATS");
	assert_eq!(retrieved, 0, "Initial stats should be 0");

	// Update stats
	port_stats.insert(port, 100, 0).expect("Failed to update PORT_STATS");
	let retrieved = port_stats.get(&port, 0).expect("Failed to get updated stats");
	assert_eq!(retrieved, 100, "Updated stats mismatch");
}

#[test]
fn test_config_array() {
	let mut ebpf = load_ebpf().expect("Failed to load eBPF program");

	// Get the CONFIG array
	let mut config: Array<_, u32> = ebpf
		.take_map("CONFIG")
		.expect("CONFIG map not found")
		.try_into()
		.expect("Failed to convert to Array");

	// Test: Set log level to DropsOnly
	let log_level = LogLevel::DropsOnly as u32;
	config.set(CONFIG_LOG_LEVEL, log_level, 0).expect("Failed to set log level");

	// Verify
	let retrieved = config.get(&CONFIG_LOG_LEVEL, 0).expect("Failed to get log level");
	assert_eq!(retrieved, log_level, "Log level mismatch");

	// Test: Set IP filter mode to Allowlist
	let filter_mode = IpFilterMode::Allowlist as u32;
	config
		.set(CONFIG_IP_FILTER_MODE, filter_mode, 0)
		.expect("Failed to set filter mode");

	// Verify
	let retrieved = config.get(&CONFIG_IP_FILTER_MODE, 0).expect("Failed to get filter mode");
	assert_eq!(retrieved, filter_mode, "Filter mode mismatch");

	// Test: Enable rate limiting
	let rate_limit_enabled: u32 = 1;
	config
		.set(CONFIG_RATE_LIMIT_ENABLED, rate_limit_enabled, 0)
		.expect("Failed to enable rate limiting");

	// Verify
	let retrieved = config
		.get(&CONFIG_RATE_LIMIT_ENABLED, 0)
		.expect("Failed to get rate limit config");
	assert_eq!(retrieved, rate_limit_enabled, "Rate limit config mismatch");
}

#[test]
fn test_ipv4_filter_map() {
	let mut ebpf = load_ebpf().expect("Failed to load eBPF program");

	// Get the IP_FILTER_LIST_V4 map
	let mut ip_filter: HashMap<_, u32, u8> = ebpf
		.take_map("IP_FILTER_LIST_V4")
		.expect("IP_FILTER_LIST_V4 map not found")
		.try_into()
		.expect("Failed to convert to HashMap");

	// Test: Add an IP to the filter list (e.g., 192.168.1.100)
	let ip: u32 = u32::from_be_bytes([192, 168, 1, 100]);
	let present: u8 = 1;
	ip_filter
		.insert(ip, present, 0)
		.expect("Failed to insert into IP_FILTER_LIST_V4");

	// Verify
	let retrieved = ip_filter.get(&ip, 0).expect("Failed to get from IP_FILTER_LIST_V4");
	assert_eq!(retrieved, present, "IP filter entry mismatch");
}

#[test]
fn test_ipv6_filter_map() {
	let mut ebpf = load_ebpf().expect("Failed to load eBPF program");

	// Get the IP_FILTER_LIST_V6 map
	let mut ip_filter: HashMap<_, [u32; 4], u8> = ebpf
		.take_map("IP_FILTER_LIST_V6")
		.expect("IP_FILTER_LIST_V6 map not found")
		.try_into()
		.expect("Failed to convert to HashMap");

	// Test: Add an IPv6 address to the filter list (2001:db8::1)
	let ip: [u32; 4] = [0x2001_0db8, 0x0000_0000, 0x0000_0000, 0x0000_0001];
	let present: u8 = 1;
	ip_filter
		.insert(ip, present, 0)
		.expect("Failed to insert into IP_FILTER_LIST_V6");

	// Verify
	let retrieved = ip_filter.get(&ip, 0).expect("Failed to get from IP_FILTER_LIST_V6");
	assert_eq!(retrieved, present, "IPv6 filter entry mismatch");
}

#[test]
fn test_rate_limit_state_v4_map() {
	let mut ebpf = load_ebpf().expect("Failed to load eBPF program");

	// Get the RATE_LIMIT_STATE_V4 map
	let mut rate_limit: HashMap<_, u32, u64> = ebpf
		.take_map("RATE_LIMIT_STATE_V4")
		.expect("RATE_LIMIT_STATE_V4 map not found")
		.try_into()
		.expect("Failed to convert to HashMap");

	// Test: Add rate limit state for an IP
	let ip: u32 = u32::from_be_bytes([10, 0, 0, 1]);

	// Pack state: timestamp=1000ms, packet_count=5
	let timestamp: u32 = 1000;
	let packet_count: u32 = 5;
	let packed: u64 = ((timestamp as u64) << 32) | (packet_count as u64);

	rate_limit
		.insert(ip, packed, 0)
		.expect("Failed to insert into RATE_LIMIT_STATE_V4");

	// Verify
	let retrieved = rate_limit.get(&ip, 0).expect("Failed to get from RATE_LIMIT_STATE_V4");
	assert_eq!(retrieved, packed, "Rate limit state mismatch");

	// Verify unpacking
	let retrieved_timestamp = (retrieved >> 32) as u32;
	let retrieved_packet_count = (retrieved & 0xFFFFFFFF) as u32;
	assert_eq!(retrieved_timestamp, timestamp, "Timestamp mismatch after unpack");
	assert_eq!(retrieved_packet_count, packet_count, "Packet count mismatch after unpack");
}

#[test]
fn test_stats_array() {
	let mut ebpf = load_ebpf().expect("Failed to load eBPF program");

	// Get the STATS array
	let mut stats: Array<_, u64> = ebpf
		.take_map("STATS")
		.expect("STATS map not found")
		.try_into()
		.expect("Failed to convert to Array");

	// Test: Set various statistics
	const STAT_TOTAL_PACKETS: u32 = 0;
	const STAT_TCP_PACKETS: u32 = 1;
	const STAT_UDP_PACKETS: u32 = 2;
	const STAT_SUBSTRATE_PACKETS: u32 = 3;

	stats.set(STAT_TOTAL_PACKETS, 1000, 0).expect("Failed to set total packets");
	stats.set(STAT_TCP_PACKETS, 600, 0).expect("Failed to set TCP packets");
	stats.set(STAT_UDP_PACKETS, 400, 0).expect("Failed to set UDP packets");
	stats
		.set(STAT_SUBSTRATE_PACKETS, 100, 0)
		.expect("Failed to set Substrate packets");

	// Verify all stats
	let total = stats.get(&STAT_TOTAL_PACKETS, 0).expect("Failed to get total packets");
	let tcp = stats.get(&STAT_TCP_PACKETS, 0).expect("Failed to get TCP packets");
	let udp = stats.get(&STAT_UDP_PACKETS, 0).expect("Failed to get UDP packets");
	let substrate = stats.get(&STAT_SUBSTRATE_PACKETS, 0).expect("Failed to get Substrate packets");

	assert_eq!(total, 1000, "Total packets mismatch");
	assert_eq!(tcp, 600, "TCP packets mismatch");
	assert_eq!(udp, 400, "UDP packets mismatch");
	assert_eq!(substrate, 100, "Substrate packets mismatch");
}
