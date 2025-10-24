#![no_std]

use core::convert::TryFrom;

/// Port filtering action codes and display names
/// Single source of truth for both kernel and userspace
pub mod actions {
	use super::*;

	/// Port filtering actions
	#[repr(u8)]
	#[derive(Debug, Copy, Clone, PartialEq)]
	pub enum Action {
		/// Allow traffic through
		Pass, // 0
		/// Block/drop traffic
		Drop, // 1
		/// Log the traffic but allow it through
		LogOnly, // 2
	}

	impl Action {
		/// Get the action as a static string
		pub const fn as_str(&self) -> &'static str {
			match self {
				Self::Pass => "PASS",
				Self::Drop => "DROP",
				Self::LogOnly => "LOG_ONLY",
			}
		}
	}

	/// Convert u8 to Action (standard Rust trait)
	impl TryFrom<u8> for Action {
		type Error = ();

		fn try_from(val: u8) -> Result<Self, Self::Error> {
			match val {
				0 => Ok(Action::Pass),
				1 => Ok(Action::Drop),
				2 => Ok(Action::LogOnly),
				_ => Err(()),
			}
		}
	}
}

/// Logging control configuration
pub mod logging {
	use super::*;

	/// Log level for controlling verbosity
	#[repr(u8)]
	#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
	pub enum LogLevel {
		/// No logging (silent mode)
		None,
		/// Log only dropped packets
		DropsOnly,
		/// Log filtered packets (drops + matches)
		Filtered,
		/// Log all packets (very verbose)
		All,
	}

	impl LogLevel {
		/// Get the log level as a static string
		pub const fn as_str(&self) -> &'static str {
			match self {
				Self::None => "NONE",
				Self::DropsOnly => "DROPS_ONLY",
				Self::Filtered => "FILTERED",
				Self::All => "ALL",
			}
		}
	}

	/// Convert u8 to LogLevel (standard Rust trait)
	impl TryFrom<u8> for LogLevel {
		type Error = ();

		fn try_from(val: u8) -> Result<Self, Self::Error> {
			match val {
				0 => Ok(LogLevel::None),
				1 => Ok(LogLevel::DropsOnly),
				2 => Ok(LogLevel::Filtered),
				3 => Ok(LogLevel::All),
				_ => Err(()),
			}
		}
	}

	/// Configuration indices for CONFIG map
	pub const CONFIG_LOG_LEVEL: u32 = 0;
	pub const CONFIG_IP_FILTER_MODE: u32 = 1;
	pub const CONFIG_RATE_LIMIT_ENABLED: u32 = 2;
	pub const CONFIG_RATE_LIMIT_PPS: u32 = 3; // Packets per second threshold
	pub const CONFIG_RATE_LIMIT_WINDOW_MS: u32 = 4; // Time window in milliseconds
}

/// IP filtering configuration
pub mod ip_filter {
	use super::*;

	/// IP filter mode
	#[repr(u8)]
	#[derive(Debug, Copy, Clone, PartialEq, Eq)]
	pub enum IpFilterMode {
		/// IP filtering disabled (default)
		Disabled,
		/// Block specific IPs (blocklist mode)
		Blocklist,
		/// Only allow specific IPs (allowlist mode - most secure)
		Allowlist,
	}

	impl IpFilterMode {
		/// Get the filter mode as a static string
		pub const fn as_str(&self) -> &'static str {
			match self {
				Self::Disabled => "DISABLED",
				Self::Blocklist => "BLOCKLIST",
				Self::Allowlist => "ALLOWLIST",
			}
		}
	}

	/// Convert u8 to IpFilterMode
	impl TryFrom<u8> for IpFilterMode {
		type Error = ();

		fn try_from(val: u8) -> Result<Self, Self::Error> {
			match val {
				0 => Ok(IpFilterMode::Disabled),
				1 => Ok(IpFilterMode::Blocklist),
				2 => Ok(IpFilterMode::Allowlist),
				_ => Err(()),
			}
		}
	}
}

/// Rate limiting structures
pub mod rate_limit {
	/// Per-IP rate limit tracking state
	/// Stored in eBPF HashMap as a single u64 for efficiency
	/// Upper 32 bits: last_seen timestamp (milliseconds)
	/// Lower 32 bits: packet count in current window
	#[repr(C)]
	#[derive(Copy, Clone)]
	pub struct RateLimitState {
		pub last_seen_ms: u32,
		pub packet_count: u32,
	}

	impl RateLimitState {
		pub const fn new() -> Self {
			Self { last_seen_ms: 0, packet_count: 0 }
		}

		/// Pack into u64 for eBPF storage
		pub const fn pack(&self) -> u64 {
			((self.last_seen_ms as u64) << 32) | (self.packet_count as u64)
		}

		/// Unpack from u64
		pub const fn unpack(packed: u64) -> Self {
			Self { last_seen_ms: (packed >> 32) as u32, packet_count: (packed & 0xFFFFFFFF) as u32 }
		}
	}
}
