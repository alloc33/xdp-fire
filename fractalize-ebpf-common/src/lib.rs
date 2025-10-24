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
}
