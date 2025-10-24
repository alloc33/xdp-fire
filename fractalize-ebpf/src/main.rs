use anyhow::Context as _;
use aya::{
	maps::{Array, HashMap, Map, MapData},
	programs::{Xdp, XdpFlags},
};
use clap::{Parser, Subcommand};
use core::convert::TryFrom;
use fractalize_ebpf_common::{actions::*, ip_filter::*, logging::*};
#[rustfmt::skip]
use log::{debug, info, warn};
use std::net::Ipv4Addr;
use tokio::{
	signal,
	time::{Duration, sleep},
};

#[derive(Debug, Parser)]
#[command(name = "fractalize-ebpf")]
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

	/// Add IP to filter list
	AddIp {
		/// IPv4 address (e.g., 192.168.1.100)
		#[clap(short, long)]
		ip: Ipv4Addr,
	},

	/// Remove IP from filter list
	RemoveIp {
		/// IPv4 address (e.g., 192.168.1.100)
		#[clap(short, long)]
		ip: Ipv4Addr,
	},

	/// List all IPs in filter list
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

const MAP_PIN_PATH: &str = "/sys/fs/bpf/fractalize-ebpf";

async fn handle_command(command: &Commands) -> anyhow::Result<()> {
	use std::path::Path;

	match command {
		Commands::SetLogLevel { level } => {
			// Access CONFIG map for log level commands
			let config_path = Path::new(MAP_PIN_PATH).join("CONFIG");
			let config_data = MapData::from_pin(&config_path)
				.context("Failed to open pinned CONFIG map. Is the XDP program running?")?;

			let mut config_map = Map::from_map_data(config_data)?;
			let mut config: Array<_, u32> = Array::try_from(&mut config_map)?;

			config.set(CONFIG_LOG_LEVEL, *level as u32, 0)?;
			let level_str =
				LogLevel::try_from(*level).ok().map(|l| l.as_str()).unwrap_or("UNKNOWN");
			info!("✅ Set log level to: {}", level_str);
		},
		Commands::GetLogLevel => {
			// Access CONFIG map for log level commands
			let config_path = Path::new(MAP_PIN_PATH).join("CONFIG");
			let config_data = MapData::from_pin(&config_path)
				.context("Failed to open pinned CONFIG map. Is the XDP program running?")?;

			let mut config_map = Map::from_map_data(config_data)?;
			let config: Array<_, u32> = Array::try_from(&mut config_map)?;

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
			let config_path = Path::new(MAP_PIN_PATH).join("CONFIG");
			let config_data = MapData::from_pin(&config_path)
				.context("Failed to open pinned CONFIG map. Is the XDP program running?")?;

			let mut config_map = Map::from_map_data(config_data)?;
			let mut config: Array<_, u32> = Array::try_from(&mut config_map)?;

			config.set(CONFIG_IP_FILTER_MODE, *mode as u32, 0)?;
			let mode_str =
				IpFilterMode::try_from(*mode).ok().map(|m| m.as_str()).unwrap_or("UNKNOWN");
			info!("✅ Set IP filter mode to: {}", mode_str);
		},
		Commands::GetIpFilterMode => {
			let config_path = Path::new(MAP_PIN_PATH).join("CONFIG");
			let config_data = MapData::from_pin(&config_path)
				.context("Failed to open pinned CONFIG map. Is the XDP program running?")?;

			let mut config_map = Map::from_map_data(config_data)?;
			let config: Array<_, u32> = Array::try_from(&mut config_map)?;

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
		Commands::AddIp { ip } => {
			let ip_list_path = Path::new(MAP_PIN_PATH).join("IP_FILTER_LIST");
			let ip_list_data = MapData::from_pin(&ip_list_path)
				.context("Failed to open pinned IP_FILTER_LIST map. Is the XDP program running?")?;

			let mut ip_list_map = Map::from_map_data(ip_list_data)?;
			let mut ip_list: HashMap<_, u32, u8> = HashMap::try_from(&mut ip_list_map)?;

			let ip_u32 = u32::from(*ip);
			ip_list.insert(ip_u32, 1, 0)?;
			info!("✅ Added IP to filter list: {}", ip);
		},
		Commands::RemoveIp { ip } => {
			let ip_list_path = Path::new(MAP_PIN_PATH).join("IP_FILTER_LIST");
			let ip_list_data = MapData::from_pin(&ip_list_path)
				.context("Failed to open pinned IP_FILTER_LIST map. Is the XDP program running?")?;

			let mut ip_list_map = Map::from_map_data(ip_list_data)?;
			let mut ip_list: HashMap<_, u32, u8> = HashMap::try_from(&mut ip_list_map)?;

			let ip_u32 = u32::from(*ip);
			ip_list.remove(&ip_u32)?;
			info!("✅ Removed IP from filter list: {}", ip);
		},
		Commands::ListIps => {
			let ip_list_path = Path::new(MAP_PIN_PATH).join("IP_FILTER_LIST");
			let ip_list_data = MapData::from_pin(&ip_list_path)
				.context("Failed to open pinned IP_FILTER_LIST map. Is the XDP program running?")?;

			let mut ip_list_map = Map::from_map_data(ip_list_data)?;
			let ip_list: HashMap<_, u32, u8> = HashMap::try_from(&mut ip_list_map)?;

			info!("📋 IP filter list:");
			let mut found_any = false;
			for item in ip_list.iter() {
				if let Ok((ip_u32, _)) = item {
					let ip = Ipv4Addr::from(ip_u32);
					info!("   {}", ip);
					found_any = true;
				}
			}
			if !found_any {
				info!("   (empty)");
			}
		},
		Commands::EnableRateLimit { pps, window_ms } => {
			let config_path = Path::new(MAP_PIN_PATH).join("CONFIG");
			let config_data = MapData::from_pin(&config_path)
				.context("Failed to open pinned CONFIG map. Is the XDP program running?")?;

			let mut config_map = Map::from_map_data(config_data)?;
			let mut config: Array<_, u32> = Array::try_from(&mut config_map)?;

			// Enable rate limiting
			config.set(CONFIG_RATE_LIMIT_ENABLED, 1, 0)?;
			config.set(CONFIG_RATE_LIMIT_PPS, *pps, 0)?;
			config.set(CONFIG_RATE_LIMIT_WINDOW_MS, *window_ms, 0)?;

			info!("✅ Enabled rate limiting: {} packets per {} ms", pps, window_ms);
		},
		Commands::DisableRateLimit => {
			let config_path = Path::new(MAP_PIN_PATH).join("CONFIG");
			let config_data = MapData::from_pin(&config_path)
				.context("Failed to open pinned CONFIG map. Is the XDP program running?")?;

			let mut config_map = Map::from_map_data(config_data)?;
			let mut config: Array<_, u32> = Array::try_from(&mut config_map)?;

			config.set(CONFIG_RATE_LIMIT_ENABLED, 0, 0)?;
			info!("✅ Disabled rate limiting");
		},
		Commands::GetRateLimit => {
			let config_path = Path::new(MAP_PIN_PATH).join("CONFIG");
			let config_data = MapData::from_pin(&config_path)
				.context("Failed to open pinned CONFIG map. Is the XDP program running?")?;

			let mut config_map = Map::from_map_data(config_data)?;
			let config: Array<_, u32> = Array::try_from(&mut config_map)?;

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
		_ => {
			// Access PORT_RULES map for port-related commands
			let map_path = Path::new(MAP_PIN_PATH).join("PORT_RULES");
			let map_data = MapData::from_pin(&map_path)
				.context("Failed to open pinned PORT_RULES map. Is the XDP program running?")?;

			let mut map = Map::from_map_data(map_data)?;
			let mut port_rules: HashMap<_, u16, u8> = HashMap::try_from(&mut map)?;

			match command {
				Commands::AddRule { port, action } => {
					port_rules.insert(*port, *action, 0)?;
					let action_str =
						Action::try_from(*action).ok().map(|a| a.as_str()).unwrap_or("UNKNOWN");
					info!("✅ Added rule: Port {} -> {}", port, action_str);
				},
				Commands::RemoveRule { port } => {
					port_rules.remove(port)?;
					info!("✅ Removed rule for port {}", port);
				},
				Commands::ListRules => {
					info!("📋 Configured port filtering rules:");
					for item in port_rules.iter() {
						if let Ok((port, action)) = item {
							let action_str = Action::try_from(action)
								.ok()
								.map(|a| a.as_str())
								.unwrap_or("UNKNOWN");
							info!("   Port {} -> {}", port, action_str);
						}
					}
				},
				Commands::ShowStats { port } => {
					// Access the PORT_STATS map
					let stats_map_path = Path::new(MAP_PIN_PATH).join("PORT_STATS");
					let stats_map_data = MapData::from_pin(&stats_map_path).context(
						"Failed to open pinned PORT_STATS map. Is the XDP program running?",
					)?;

					let mut stats_map = Map::from_map_data(stats_map_data)?;
					let port_stats: HashMap<_, u16, u64> = HashMap::try_from(&mut stats_map)?;

					if let Some(specific_port) = port {
						// Show stats for specific port
						match port_stats.get(specific_port, 0) {
							Ok(count) => {
								info!("📊 Port {} statistics: {} packets", specific_port, count);
							},
							Err(_) => {
								info!(
									"📊 Port {} statistics: 0 packets (no data yet)",
									specific_port
								);
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
				_ => unreachable!(),
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
		aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/fractalize-ebpf")))?;
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

	// Pin IP_FILTER_LIST map for runtime IP filtering
	let ip_filter_list: HashMap<_, u32, u8> = ebpf.map_mut("IP_FILTER_LIST").unwrap().try_into()?;
	ip_filter_list.pin(map_pin_path.join("IP_FILTER_LIST"))?;

	// Pin RATE_LIMIT_STATE map for per-IP rate limiting
	let rate_limit_state: HashMap<_, u32, u64> =
		ebpf.map_mut("RATE_LIMIT_STATE").unwrap().try_into()?;
	rate_limit_state.pin(map_pin_path.join("RATE_LIMIT_STATE"))?;

	info!("✅ Configured port filtering rules:");
	info!("   Port 30333 (Substrate P2P): LOG_ONLY");
	info!("📍 Pinned PORT_RULES map to {}/PORT_RULES", MAP_PIN_PATH);
	info!("📍 Pinned PORT_STATS map to {}/PORT_STATS", MAP_PIN_PATH);
	info!(
		"📍 Pinned CONFIG map to {}/CONFIG (log: FILTERED, IP filter: DISABLED, rate limit: DISABLED)",
		MAP_PIN_PATH
	);
	info!("📍 Pinned IP_FILTER_LIST map to {}/IP_FILTER_LIST", MAP_PIN_PATH);
	info!("📍 Pinned RATE_LIMIT_STATE map to {}/RATE_LIMIT_STATE", MAP_PIN_PATH);

	let Opt { iface, .. } = opt;
	let program: &mut Xdp = ebpf.program_mut("fractalize_ebpf").unwrap().try_into()?;
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
