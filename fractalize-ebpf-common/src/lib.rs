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
