use anyhow::Context as _;
use aya::{
	maps::{Array, HashMap, Map, MapData},
	programs::{Xdp, XdpFlags},
};
use clap::{Parser, Subcommand};
use core::convert::TryFrom;
use xdp_fire_common::{actions::*, ip_filter::*, logging::*};
#[rustfmt::skip]
use log::{debug, info, warn};
use std::{
	net::{IpAddr, Ipv4Addr, Ipv6Addr},
	path::Path,
};
use tokio::{
	signal,
	time::{Duration, sleep},
};

/// Convert Ipv6Addr to [u32; 4] for eBPF map key (network byte order)
#[inline]
fn ipv6_to_u32_array(ipv6: &Ipv6Addr) -> [u32; 4] {
	let octets = ipv6.octets();
	[
		u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]),
		u32::from_be_bytes([octets[4], octets[5], octets[6], octets[7]]),
		u32::from_be_bytes([octets[8], octets[9], octets[10], octets[11]]),
		u32::from_be_bytes([octets[12], octets[13], octets[14], octets[15]]),
	]
}

/// Convert [u32; 4] back to Ipv6Addr
#[inline]
fn u32_array_to_ipv6(ip_array: &[u32; 4]) -> Ipv6Addr {
	let mut octets = [0u8; 16];
	for (i, &word) in ip_array.iter().enumerate() {
		let bytes = word.to_be_bytes();
		octets[i * 4] = bytes[0];
		octets[i * 4 + 1] = bytes[1];
		octets[i * 4 + 2] = bytes[2];
		octets[i * 4 + 3] = bytes[3];
	}
	Ipv6Addr::from(octets)
}

/// Generic helper to open a pinned eBPF map
fn open_map<T>(map_name: &str) -> anyhow::Result<T>
where
	T: TryFrom<Map>,
	<T as TryFrom<Map>>::Error: std::error::Error + Send + Sync + 'static,
{
	let map_path = Path::new(MAP_PIN_PATH).join(map_name);
	let map_data = MapData::from_pin(&map_path)
		.context(format!("Failed to open pinned {} map. Is the XDP program running?", map_name))?;
	let map = Map::from_map_data(map_data)?;
	T::try_from(map).map_err(|e| anyhow::anyhow!("Map conversion error: {}", e))
}

#[derive(Debug, Parser)]
#[command(name = "xdp-fire")]
#[command(about = "XDP packet filter with runtime configuration")]
struct Opt {
	#[command(subcommand)]
	command: Option<Commands>,

	#[clap(short, long, default_value = "eth0")]
	iface: String,
}

#[derive(Debug, Subcommand)]
enum Commands {
	/// Add a port filtering rule
	AddRule {
		/// Port number to filter
		#[clap(short, long)]
		port: u16,

		/// Action code: 0=PASS, 1=DROP, 2=LOG_ONLY
		#[clap(short, long)]
		action: u8,
	},

	/// Remove a port filtering rule
	RemoveRule {
		/// Port number to remove
		#[clap(short, long)]
		port: u16,
	},

	/// List all configured port rules
	ListRules,

	/// Show per-port packet statistics
	ShowStats {
		/// Optional: show stats for specific port only
		#[clap(short, long)]
		port: Option<u16>,
	},

	/// Set log level (0=NONE, 1=DROPS_ONLY, 2=FILTERED, 3=ALL)
	SetLogLevel {
		/// Log level: 0=NONE, 1=DROPS_ONLY, 2=FILTERED, 3=ALL
		#[clap(short, long)]
		level: u8,
	},

	/// Get current log level
	GetLogLevel,

	/// Set IP filter mode (0=DISABLED, 1=BLOCKLIST, 2=ALLOWLIST)
	SetIpFilterMode {
		/// Filter mode: 0=DISABLED, 1=BLOCKLIST, 2=ALLOWLIST
		#[clap(short, long)]
		mode: u8,
	},

	/// Get current IP filter mode
	GetIpFilterMode,

	/// Add IP address to filter list (IPv4 or IPv6)
	AddIp {
		/// IP address (e.g., 192.168.1.100 or 2001:db8::1)
		#[clap(short, long)]
		ip: std::net::IpAddr,
	},

	/// Remove IP address from filter list (IPv4 or IPv6)
	RemoveIp {
		/// IP address (e.g., 192.168.1.100 or 2001:db8::1)
		#[clap(short, long)]
		ip: std::net::IpAddr,
	},

	/// List all IP addresses in filter list (both IPv4 and IPv6)
	ListIps,

	/// Enable rate limiting
	EnableRateLimit {
		/// Packets per second limit
		#[clap(short, long)]
		pps: u32,

		/// Time window in milliseconds (default: 1000ms = 1 second)
		#[clap(short, long, default_value = "1000")]
		window_ms: u32,
	},

	/// Disable rate limiting
	DisableRateLimit,

	/// Get rate limit configuration
	GetRateLimit,
}

const MAP_PIN_PATH: &str = "/sys/fs/bpf/xdp-fire";

async fn handle_command(command: &Commands) -> anyhow::Result<()> {
	match command {
		Commands::SetLogLevel { level } => {
			let mut config: Array<_, u32> = open_map("CONFIG")?;
			config.set(CONFIG_LOG_LEVEL, *level as u32, 0)?;
			let level_str =
				LogLevel::try_from(*level).ok().map(|l| l.as_str()).unwrap_or("UNKNOWN");
			info!("✅ Set log level to: {}", level_str);
		},
		Commands::GetLogLevel => {
			let config: Array<_, u32> = open_map("CONFIG")?;
			match config.get(&CONFIG_LOG_LEVEL, 0) {
				Ok(level) => {
					let level_str = LogLevel::try_from(level as u8)
						.ok()
						.map(|l| l.as_str())
						.unwrap_or("UNKNOWN");
					info!("📋 Current log level: {} ({})", level_str, level);
				},
				Err(_) => {
					info!("📋 Log level not set (default: FILTERED)");
				},
			}
		},
		Commands::SetIpFilterMode { mode } => {
			let mut config: Array<_, u32> = open_map("CONFIG")?;
			config.set(CONFIG_IP_FILTER_MODE, *mode as u32, 0)?;
			let mode_str =
				IpFilterMode::try_from(*mode).ok().map(|m| m.as_str()).unwrap_or("UNKNOWN");
			info!("✅ Set IP filter mode to: {}", mode_str);
		},
		Commands::GetIpFilterMode => {
			let config: Array<_, u32> = open_map("CONFIG")?;
			match config.get(&CONFIG_IP_FILTER_MODE, 0) {
				Ok(mode) => {
					let mode_str = IpFilterMode::try_from(mode as u8)
						.ok()
						.map(|m| m.as_str())
						.unwrap_or("UNKNOWN");
					info!("📋 Current IP filter mode: {} ({})", mode_str, mode);
				},
				Err(_) => {
					info!("📋 IP filter mode not set (default: DISABLED)");
				},
			}
		},
		Commands::AddIp { ip } => match ip {
			IpAddr::V4(ipv4) => {
				let mut ip_list: HashMap<_, u32, u8> = open_map("IP_FILTER_LIST_V4")?;
				ip_list.insert(u32::from(*ipv4), 1, 0)?;
				info!("✅ Added IPv4 to filter list: {}", ipv4);
			},
			IpAddr::V6(ipv6) => {
				let mut ip_list: HashMap<_, [u32; 4], u8> = open_map("IP_FILTER_LIST_V6")?;
				ip_list.insert(ipv6_to_u32_array(ipv6), 1, 0)?;
				info!("✅ Added IPv6 to filter list: {}", ipv6);
			},
		},
		Commands::RemoveIp { ip } => match ip {
			IpAddr::V4(ipv4) => {
				let mut ip_list: HashMap<_, u32, u8> = open_map("IP_FILTER_LIST_V4")?;
				ip_list.remove(&u32::from(*ipv4))?;
				info!("✅ Removed IPv4 from filter list: {}", ipv4);
			},
			IpAddr::V6(ipv6) => {
				let mut ip_list: HashMap<_, [u32; 4], u8> = open_map("IP_FILTER_LIST_V6")?;
				ip_list.remove(&ipv6_to_u32_array(ipv6))?;
				info!("✅ Removed IPv6 from filter list: {}", ipv6);
			},
		},
		Commands::ListIps => {
			info!("📋 IP filter list:");
			let mut found_any = false;

			// List IPv4 addresses
			if let Ok(ipv4_list) = open_map::<HashMap<_, u32, u8>>("IP_FILTER_LIST_V4") {
				for item in ipv4_list.iter() {
					if let Ok((ip_u32, _)) = item {
						info!("   {} (IPv4)", Ipv4Addr::from(ip_u32));
						found_any = true;
					}
				}
			}

			// List IPv6 addresses
			if let Ok(ipv6_list) = open_map::<HashMap<_, [u32; 4], u8>>("IP_FILTER_LIST_V6") {
				for item in ipv6_list.iter() {
					if let Ok((ip_array, _)) = item {
						info!("   {} (IPv6)", u32_array_to_ipv6(&ip_array));
						found_any = true;
					}
				}
			}

			if !found_any {
				info!("   (empty)");
			}
		},
		Commands::EnableRateLimit { pps, window_ms } => {
			let mut config: Array<_, u32> = open_map("CONFIG")?;
			config.set(CONFIG_RATE_LIMIT_ENABLED, 1, 0)?;
			config.set(CONFIG_RATE_LIMIT_PPS, *pps, 0)?;
			config.set(CONFIG_RATE_LIMIT_WINDOW_MS, *window_ms, 0)?;
			info!("✅ Enabled rate limiting: {} packets per {} ms", pps, window_ms);
		},
		Commands::DisableRateLimit => {
			let mut config: Array<_, u32> = open_map("CONFIG")?;
			config.set(CONFIG_RATE_LIMIT_ENABLED, 0, 0)?;
			info!("✅ Disabled rate limiting");
		},
		Commands::GetRateLimit => {
			let config: Array<_, u32> = open_map("CONFIG")?;
			match config.get(&CONFIG_RATE_LIMIT_ENABLED, 0) {
				Ok(enabled) if enabled != 0 => {
					let pps = config.get(&CONFIG_RATE_LIMIT_PPS, 0).unwrap_or(0);
					let window_ms = config.get(&CONFIG_RATE_LIMIT_WINDOW_MS, 0).unwrap_or(0);
					info!("📋 Rate limiting: ENABLED");
					info!("   Limit: {} packets per {} ms", pps, window_ms);
				},
				_ => {
					info!("📋 Rate limiting: DISABLED");
				},
			}
		},
		Commands::AddRule { port, action } => {
			let mut port_rules: HashMap<_, u16, u8> = open_map("PORT_RULES")?;
			port_rules.insert(*port, *action, 0)?;
			let action_str =
				Action::try_from(*action).ok().map(|a| a.as_str()).unwrap_or("UNKNOWN");
			info!("✅ Added rule: Port {} -> {}", port, action_str);
		},
		Commands::RemoveRule { port } => {
			let mut port_rules: HashMap<_, u16, u8> = open_map("PORT_RULES")?;
			port_rules.remove(port)?;
			info!("✅ Removed rule for port {}", port);
		},
		Commands::ListRules => {
			let port_rules: HashMap<_, u16, u8> = open_map("PORT_RULES")?;
			info!("📋 Configured port filtering rules:");
			for item in port_rules.iter() {
				if let Ok((port, action)) = item {
					let action_str =
						Action::try_from(action).ok().map(|a| a.as_str()).unwrap_or("UNKNOWN");
					info!("   Port {} -> {}", port, action_str);
				}
			}
		},
		Commands::ShowStats { port } => {
			let port_stats: HashMap<_, u16, u64> = open_map("PORT_STATS")?;
			if let Some(specific_port) = port {
				// Show stats for specific port
				match port_stats.get(specific_port, 0) {
					Ok(count) => {
						info!("📊 Port {} statistics: {} packets", specific_port, count);
					},
					Err(_) => {
						info!("📊 Port {} statistics: 0 packets (no data yet)", specific_port);
					},
				}
			} else {
				// Show stats for all ports
				info!("📊 Per-port packet statistics:");
				let mut found_any = false;
				for item in port_stats.iter() {
					if let Ok((port, count)) = item {
						if count > 0 {
							info!("   Port {}: {} packets", port, count);
							found_any = true;
						}
					}
				}
				if !found_any {
					info!("   No packet statistics collected yet");
				}
			}
		},
	}

	Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	let opt = Opt::parse();

	env_logger::init();

	// Handle configuration subcommands
	if let Some(command) = &opt.command {
		return handle_command(command).await;
	}

	// Bump the memlock rlimit. This is needed for older kernels that don't use the
	// new memcg based accounting, see https://lwn.net/Articles/837122/
	let rlim = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
	let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
	if ret != 0 {
		debug!("remove limit on locked memory failed, ret is: {ret}");
	}

	// This will include your eBPF object file as raw bytes at compile-time and load it at
	// runtime. This approach is recommended for most real-world use cases. If you would
	// like to specify the eBPF program at runtime rather than at compile-time, you can
	// reach for `Bpf::load_file` instead.
	let mut ebpf =
		aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp-fire")))?;
	match aya_log::EbpfLogger::init(&mut ebpf) {
		Err(e) => {
			// This can happen if you remove all log statements from your eBPF program.
			warn!("failed to initialize eBPF logger: {e}");
		},
		Ok(logger) => {
			let mut logger =
				tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
			tokio::task::spawn(async move {
				loop {
					let mut guard = logger.readable_mut().await.unwrap();
					guard.get_inner_mut().flush();
					guard.clear_ready();
				}
			});
		},
	}
	// Configure port filtering rules before attaching
	let mut port_rules: HashMap<_, u16, u8> = ebpf.map_mut("PORT_RULES").unwrap().try_into()?;

	// Default configuration: Monitor Substrate P2P port (30333) without dropping
	port_rules.insert(30333_u16, Action::LogOnly as u8, 0)?;

	// You can add more ports here:
	// port_rules.insert(9944_u16, Action::LogOnly as u8, 0)?;  // Substrate RPC WebSocket
	// port_rules.insert(9933_u16, Action::LogOnly as u8, 0)?;  // Substrate RPC HTTP

	// Pin the maps so they can be accessed by runtime configuration commands
	use std::path::Path;
	let map_pin_path = Path::new(MAP_PIN_PATH);
	std::fs::create_dir_all(map_pin_path).ok(); // Create directory if it doesn't exist
	port_rules.pin(map_pin_path.join("PORT_RULES"))?;

	// Also pin PORT_STATS for statistics access
	let port_stats: HashMap<_, u16, u64> = ebpf.map_mut("PORT_STATS").unwrap().try_into()?;
	port_stats.pin(map_pin_path.join("PORT_STATS"))?;

	// Pin CONFIG map for runtime log level, IP filter, and rate limit control
	let mut config: Array<_, u32> = ebpf.map_mut("CONFIG").unwrap().try_into()?;
	config.set(CONFIG_LOG_LEVEL, LogLevel::Filtered as u32, 0)?; // Default to Filtered mode
	config.set(CONFIG_IP_FILTER_MODE, IpFilterMode::Disabled as u32, 0)?; // Default to Disabled
	config.set(CONFIG_RATE_LIMIT_ENABLED, 0, 0)?; // Default to Disabled
	config.set(CONFIG_RATE_LIMIT_PPS, 1000, 0)?; // Default: 1000 packets per window
	config.set(CONFIG_RATE_LIMIT_WINDOW_MS, 1000, 0)?; // Default: 1000ms window (1000 pps)
	config.pin(map_pin_path.join("CONFIG"))?;

	// Pin IPv4 IP filter map for runtime IP filtering
	let ip_filter_list_v4: HashMap<_, u32, u8> =
		ebpf.map_mut("IP_FILTER_LIST_V4").unwrap().try_into()?;
	ip_filter_list_v4.pin(map_pin_path.join("IP_FILTER_LIST_V4"))?;

	// Pin IPv6 IP filter map for runtime IP filtering
	let ip_filter_list_v6: HashMap<_, [u32; 4], u8> =
		ebpf.map_mut("IP_FILTER_LIST_V6").unwrap().try_into()?;
	ip_filter_list_v6.pin(map_pin_path.join("IP_FILTER_LIST_V6"))?;

	// Pin IPv4 rate limit state map for per-IP rate limiting
	let rate_limit_state_v4: HashMap<_, u32, u64> =
		ebpf.map_mut("RATE_LIMIT_STATE_V4").unwrap().try_into()?;
	rate_limit_state_v4.pin(map_pin_path.join("RATE_LIMIT_STATE_V4"))?;

	// Pin IPv6 rate limit state map for per-IP rate limiting
	let rate_limit_state_v6: HashMap<_, [u32; 4], u64> =
		ebpf.map_mut("RATE_LIMIT_STATE_V6").unwrap().try_into()?;
	rate_limit_state_v6.pin(map_pin_path.join("RATE_LIMIT_STATE_V6"))?;

	info!("✅ Configured port filtering rules:");
	info!("   Port 30333 (Substrate P2P): LOG_ONLY");
	info!("📍 Pinned PORT_RULES map to {}/PORT_RULES", MAP_PIN_PATH);
	info!("📍 Pinned PORT_STATS map to {}/PORT_STATS", MAP_PIN_PATH);
	info!(
		"📍 Pinned CONFIG map to {}/CONFIG (log: FILTERED, IP filter: DISABLED, rate limit: DISABLED)",
		MAP_PIN_PATH
	);
	info!("📍 Pinned IP_FILTER_LIST_V4 map to {}/IP_FILTER_LIST_V4", MAP_PIN_PATH);
	info!("📍 Pinned IP_FILTER_LIST_V6 map to {}/IP_FILTER_LIST_V6", MAP_PIN_PATH);
	info!("📍 Pinned RATE_LIMIT_STATE_V4 map to {}/RATE_LIMIT_STATE_V4", MAP_PIN_PATH);
	info!("📍 Pinned RATE_LIMIT_STATE_V6 map to {}/RATE_LIMIT_STATE_V6", MAP_PIN_PATH);

	let Opt { iface, .. } = opt;
	let program: &mut Xdp = ebpf.program_mut("xdp_fire").unwrap().try_into()?;
	program.load()?;

	// Try native XDP first (driver mode), fall back to generic/SKB mode if not supported
	match program.attach(&iface, XdpFlags::DRV_MODE) {
		Ok(_) => {
			info!("✅ Attached XDP program in NATIVE mode (driver-level, best performance)");
		},
		Err(e) => {
			warn!("⚠️  Native XDP not supported: {}", e);
			info!("Falling back to GENERIC XDP mode (reduced performance)...");
			program
				.attach(&iface, XdpFlags::SKB_MODE)
				.context("Failed to attach XDP program even in generic/SKB mode")?;
			warn!("⚠️  Running in GENERIC XDP mode - expect 5-10x slower performance");
			warn!(
				"⚠️  For production, use hardware with native XDP support (Intel i40e/ixgbe, Mellanox mlx5)"
			);
		},
	}

	// Get reference to statistics map
	let stats_map: Array<_, u64> = ebpf.take_map("STATS").unwrap().try_into()?;

	// Spawn background task to display statistics every second
	tokio::task::spawn(async move {
		loop {
			sleep(Duration::from_secs(1)).await;

			// Read statistics from eBPF map
			let total = stats_map.get(&0, 0).unwrap_or(0);
			let tcp = stats_map.get(&1, 0).unwrap_or(0);
			let udp = stats_map.get(&2, 0).unwrap_or(0);
			let substrate = stats_map.get(&3, 0).unwrap_or(0);
			let non_ip = stats_map.get(&4, 0).unwrap_or(0);

			// Display statistics
			info!(
				"📊 Stats: Total={} TCP={} UDP={} Substrate={} Non-IP={}",
				total, tcp, udp, substrate, non_ip
			);
		}
	});

	let ctrl_c = signal::ctrl_c();
	println!("Waiting for Ctrl-C...");
	ctrl_c.await?;
	println!("Exiting...");

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	// IPv6 conversion tests - we store IPv6 as [u32; 4] in eBPF maps because
	// eBPF doesn't handle complex types well. Need to make sure conversion is lossless.

	#[test]
	fn test_ipv6_to_u32_array_simple() {
		// Simple address with :: notation
		let ipv6 = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
		let array = ipv6_to_u32_array(&ipv6);

		// 2001:0db8:0000:0000:0000:0000:0000:0001
		assert_eq!(array[0], 0x2001_0db8);
		assert_eq!(array[1], 0x0000_0000);
		assert_eq!(array[2], 0x0000_0000);
		assert_eq!(array[3], 0x0000_0001);
	}

	#[test]
	fn test_ipv6_to_u32_array_full() {
		// Full IPv6 address with all sections populated
		let ipv6 = "2001:db8:85a3::8a2e:370:7334".parse::<Ipv6Addr>().unwrap();
		let array = ipv6_to_u32_array(&ipv6);

		assert_eq!(array[0], 0x2001_0db8);
		assert_eq!(array[1], 0x85a3_0000);
		assert_eq!(array[2], 0x0000_8a2e);
		assert_eq!(array[3], 0x0370_7334);
	}

	#[test]
	fn test_ipv6_to_u32_array_loopback() {
		// Edge case: loopback address (::1)
		let ipv6 = "::1".parse::<Ipv6Addr>().unwrap();
		let array = ipv6_to_u32_array(&ipv6);

		assert_eq!(array[0], 0x0000_0000);
		assert_eq!(array[1], 0x0000_0000);
		assert_eq!(array[2], 0x0000_0000);
		assert_eq!(array[3], 0x0000_0001);
	}

	#[test]
	fn test_u32_array_to_ipv6_roundtrip() {
		// Most important test - make sure we don't lose any data during conversion
		// Test multiple addresses including edge cases
		let test_cases = [
			"2001:db8::1",
			"::1",     // Loopback
			"fe80::1", // Link-local
			"2001:db8:85a3::8a2e:370:7334",
			"::",                                      // All zeros
			"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", // All ones
		];

		for case in &test_cases {
			let original = case.parse::<Ipv6Addr>().unwrap();
			let array = ipv6_to_u32_array(&original);
			let converted = u32_array_to_ipv6(&array);
			assert_eq!(original, converted, "Roundtrip failed for {}", case);
		}
	}

	#[test]
	fn test_u32_array_to_ipv6_manual() {
		// Manually verify the reverse conversion works
		let array: [u32; 4] = [0x2001_0db8, 0x0000_0000, 0x0000_0000, 0x0000_0001];
		let ipv6 = u32_array_to_ipv6(&array);
		let expected = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
		assert_eq!(ipv6, expected);
	}

	#[test]
	fn test_ipv6_network_byte_order() {
		// Critical: IPv6 addresses must be in network byte order (big-endian)
		// for eBPF map lookups to work correctly
		let ipv6 = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
		let array = ipv6_to_u32_array(&ipv6);

		// First u32 should be 0x2001_0db8 in big-endian
		// If we were using little-endian (wrong!), it would be 0xb80d_0120
		assert_eq!(array[0], 0x2001_0db8, "Not using network byte order!");
	}
}
