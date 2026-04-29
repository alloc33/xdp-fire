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
            Self {
                last_seen_ms: 0,
                packet_count: 0,
            }
        }

        /// Pack into u64 for eBPF storage
        pub const fn pack(&self) -> u64 {
            ((self.last_seen_ms as u64) << 32) | (self.packet_count as u64)
        }

        /// Unpack from u64
        pub const fn unpack(packed: u64) -> Self {
            Self {
                last_seen_ms: (packed >> 32) as u32,
                packet_count: (packed & 0xFFFFFFFF) as u32,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Action enum tests - these are stored as u8 in eBPF maps, so we need to make sure
    // the conversion from raw bytes works correctly
    #[test]
    fn test_action_try_from() {
        // Valid conversions
        assert_eq!(actions::Action::try_from(0), Ok(actions::Action::Pass));
        assert_eq!(actions::Action::try_from(1), Ok(actions::Action::Drop));
        assert_eq!(actions::Action::try_from(2), Ok(actions::Action::LogOnly));

        // Invalid values should fail - important for security
        assert_eq!(actions::Action::try_from(3), Err(()));
        assert_eq!(actions::Action::try_from(255), Err(()));
    }

    #[test]
    fn test_action_as_str() {
        // Used in CLI output, make sure strings are correct
        assert_eq!(actions::Action::Pass.as_str(), "PASS");
        assert_eq!(actions::Action::Drop.as_str(), "DROP");
        assert_eq!(actions::Action::LogOnly.as_str(), "LOG_ONLY");
    }

    // LogLevel tests - these control verbosity in the kernel logs
    #[test]
    fn test_loglevel_try_from() {
        // Make sure config values map correctly
        assert_eq!(logging::LogLevel::try_from(0), Ok(logging::LogLevel::None));
        assert_eq!(
            logging::LogLevel::try_from(1),
            Ok(logging::LogLevel::DropsOnly)
        );
        assert_eq!(
            logging::LogLevel::try_from(2),
            Ok(logging::LogLevel::Filtered)
        );
        assert_eq!(logging::LogLevel::try_from(3), Ok(logging::LogLevel::All));
        assert_eq!(logging::LogLevel::try_from(4), Err(())); // Out of range
    }

    #[test]
    fn test_loglevel_ordering() {
        // We use comparisons like `if log_level >= LogLevel::DropsOnly` in kernel code
        // so ordering must be correct
        assert!(logging::LogLevel::None < logging::LogLevel::DropsOnly);
        assert!(logging::LogLevel::DropsOnly < logging::LogLevel::Filtered);
        assert!(logging::LogLevel::Filtered < logging::LogLevel::All);
    }

    #[test]
    fn test_loglevel_as_str() {
        assert_eq!(logging::LogLevel::None.as_str(), "NONE");
        assert_eq!(logging::LogLevel::DropsOnly.as_str(), "DROPS_ONLY");
        assert_eq!(logging::LogLevel::Filtered.as_str(), "FILTERED");
        assert_eq!(logging::LogLevel::All.as_str(), "ALL");
    }

    // IpFilterMode tests - allowlist vs blocklist behavior is critical for security
    #[test]
    fn test_ipfiltermode_try_from() {
        assert_eq!(
            ip_filter::IpFilterMode::try_from(0),
            Ok(ip_filter::IpFilterMode::Disabled)
        );
        assert_eq!(
            ip_filter::IpFilterMode::try_from(1),
            Ok(ip_filter::IpFilterMode::Blocklist)
        );
        assert_eq!(
            ip_filter::IpFilterMode::try_from(2),
            Ok(ip_filter::IpFilterMode::Allowlist)
        );
        assert_eq!(ip_filter::IpFilterMode::try_from(3), Err(())); // Invalid mode
    }

    #[test]
    fn test_ipfiltermode_as_str() {
        assert_eq!(ip_filter::IpFilterMode::Disabled.as_str(), "DISABLED");
        assert_eq!(ip_filter::IpFilterMode::Blocklist.as_str(), "BLOCKLIST");
        assert_eq!(ip_filter::IpFilterMode::Allowlist.as_str(), "ALLOWLIST");
    }

    // RateLimitState pack/unpack - THIS IS CRITICAL
    // We pack two u32s into a single u64 to store in eBPF HashMap efficiently.
    // If this is wrong, rate limiting won't work at all.
    #[test]
    fn test_rate_limit_state_pack_unpack() {
        // Basic roundtrip with random values
        let state = rate_limit::RateLimitState {
            last_seen_ms: 12345,
            packet_count: 67890,
        };

        let packed = state.pack();
        let unpacked = rate_limit::RateLimitState::unpack(packed);

        assert_eq!(unpacked.last_seen_ms, 12345);
        assert_eq!(unpacked.packet_count, 67890);
    }

    #[test]
    fn test_rate_limit_state_pack_max_values() {
        // Edge case: make sure we don't lose bits with max values
        let state = rate_limit::RateLimitState {
            last_seen_ms: u32::MAX,
            packet_count: u32::MAX,
        };

        let packed = state.pack();
        let unpacked = rate_limit::RateLimitState::unpack(packed);

        assert_eq!(unpacked.last_seen_ms, u32::MAX);
        assert_eq!(unpacked.packet_count, u32::MAX);
    }

    #[test]
    fn test_rate_limit_state_pack_zero() {
        // Initial state should pack to 0
        let state = rate_limit::RateLimitState::new();
        assert_eq!(state.last_seen_ms, 0);
        assert_eq!(state.packet_count, 0);

        let packed = state.pack();
        assert_eq!(packed, 0);

        // And unpacking 0 should give us back zeros
        let unpacked = rate_limit::RateLimitState::unpack(0);
        assert_eq!(unpacked.last_seen_ms, 0);
        assert_eq!(unpacked.packet_count, 0);
    }

    #[test]
    fn test_rate_limit_state_pack_bit_layout() {
        // Manually verify the bit layout is correct (timestamp in upper 32, count in lower 32)
        // This is important because we're doing manual bit manipulation
        let state = rate_limit::RateLimitState {
            last_seen_ms: 0xABCD_1234,
            packet_count: 0x5678_9ABC,
        };

        let packed = state.pack();

        // Should be: timestamp << 32 | count
        assert_eq!(packed, 0xABCD_1234_5678_9ABC);

        // Double-check we can extract the parts
        let timestamp_part = (packed >> 32) as u32;
        let count_part = (packed & 0xFFFF_FFFF) as u32;

        assert_eq!(timestamp_part, 0xABCD_1234);
        assert_eq!(count_part, 0x5678_9ABC);
    }
}
