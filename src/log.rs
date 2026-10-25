//! Terminal and `systemd-journald` logging subsystem for the `synaptics-009a-tod` driver.
//!
//! Because `libfprint-2-tod1` plugins are dynamically loaded via `dlopen()` inside `/usr/libexec/fprintd`
//! (without a Rust `main()` entry point), standard `stderr` output with immediate line flushing
//! ensures real-time visibility both when running `/usr/libexec/fprintd -t` interactively in a terminal
//! and when monitoring `journalctl -u fprintd -f`.
//!
//! ## Runtime Configuration
//!
//! Verbose `DEBUG` logs (including USB Bulk/Interrupt packet lengths and TLS state transitions)
//! can be enabled at runtime by setting any of:
//! - `SYNAPTICS_009A_LOG=debug` (or `error`, `warn`, `info`, `off`)
//! - `SYNAPTICS_009A_DEBUG=1`
//! - `G_MESSAGES_DEBUG=all`

use std::fmt;
use std::io::Write;
use std::sync::OnceLock;

/// Log severity level for driver diagnostic messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// Suppress all log output (`SYNAPTICS_009A_LOG=off`).
    Off = 0,
    /// Critical hardware, USB, or TLS failures.
    Error = 1,
    /// Recoverable anomalies, scan quality retries, or session reconnects.
    Warn = 2,
    /// High-level lifecycle events (probe, open, LED transitions, match/enroll progress).
    Info = 3,
    /// Detailed packet-level USB Bulk/Interrupt transfers and internal state transitions.
    Debug = 4,
}

impl LogLevel {
    /// Fixed-width 5-character label printed inside the `[synaptics-009a <TAG>]` prefix.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Off => "OFF  ",
            Self::Error => "ERROR",
            Self::Warn => "WARN ",
            Self::Info => "INFO ",
            Self::Debug => "DEBUG",
        }
    }
}

/// Determine the configured maximum [`LogLevel`] from environment variables once per process.
/// Defaults to [`LogLevel::Info`].
pub fn max_log_level() -> LogLevel {
    static MAX_LEVEL: OnceLock<LogLevel> = OnceLock::new();
    *MAX_LEVEL.get_or_init(|| {
        if let Ok(val) = std::env::var("SYNAPTICS_009A_LOG") {
            match val.trim().to_ascii_lowercase().as_str() {
                "off" | "0" | "none" => return LogLevel::Off,
                "error" | "err" => return LogLevel::Error,
                "warn" | "warning" => return LogLevel::Warn,
                "info" => return LogLevel::Info,
                "debug" | "trace" | "1" | "true" => return LogLevel::Debug,
                _ => {}
            }
        }
        if let Ok(val) = std::env::var("SYNAPTICS_009A_DEBUG") {
            let v = val.trim();
            if v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("debug") {
                return LogLevel::Debug;
            }
        }
        if let Ok(val) = std::env::var("G_MESSAGES_DEBUG") {
            let v = val.trim();
            if v.eq_ignore_ascii_case("all") || v.contains("synaptics") || v.contains("fprintd") {
                return LogLevel::Debug;
            }
        }
        LogLevel::Info
    })
}

/// Format and emit a single log line to `stderr`, flushing immediately for real-time output
/// in `journalctl -u fprintd -f`.
pub fn emit_log(level: LogLevel, args: fmt::Arguments<'_>) {
    if level > max_log_level() || level == LogLevel::Off {
        return;
    }
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "[synaptics-009a {}] {}", level.tag(), args);
    let _ = stderr.flush();
}

/// Log an `ERROR`-level driver diagnostic message to `stderr` / `journalctl`.
#[macro_export]
macro_rules! drv_error {
    ($($arg:tt)*) => {
        $crate::log::emit_log($crate::log::LogLevel::Error, format_args!($($arg)*))
    };
}

/// Log a `WARN`-level driver diagnostic message to `stderr` / `journalctl`.
#[macro_export]
macro_rules! drv_warn {
    ($($arg:tt)*) => {
        $crate::log::emit_log($crate::log::LogLevel::Warn, format_args!($($arg)*))
    };
}

/// Log an `INFO`-level driver diagnostic message to `stderr` / `journalctl`.
#[macro_export]
macro_rules! drv_info {
    ($($arg:tt)*) => {
        $crate::log::emit_log($crate::log::LogLevel::Info, format_args!($($arg)*))
    };
}

/// Log a `DEBUG`-level driver diagnostic message to `stderr` / `journalctl`
/// (enabled when `SYNAPTICS_009A_LOG=debug` or `SYNAPTICS_009A_DEBUG=1`).
#[macro_export]
macro_rules! drv_debug {
    ($($arg:tt)*) => {
        $crate::log::emit_log($crate::log::LogLevel::Debug, format_args!($($arg)*))
    };
}
