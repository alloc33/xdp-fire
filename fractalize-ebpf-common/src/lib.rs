#![no_std]

/// Port filtering action codes
/// These constants must be kept in sync across kernel and userspace
pub mod actions {
	/// Allow traffic through
	pub const ACTION_PASS: u8 = 0;

	/// Block/drop traffic
	pub const ACTION_DROP: u8 = 1;

	/// Log the traffic but allow it through
	pub const ACTION_LOG_ONLY: u8 = 2;
}
