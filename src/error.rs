//! Hardware status codes, driver error types, and `libfprint-2` error/retry code mappings.
//!
//! Every response packet sent by the Synaptics Metallica MIS (`06cb:009a`) sensor on Bulk IN
//! Endpoint `0x81` begins with a 16-bit little-endian status word ([`SensorStatus`]).
//! This module translates raw sensor status words, USB transport errors, TLS 1.2 record alerts,
//! and 2D capacitive scan quality codes into [`DriverError`], and maps them to `libfprint-2`'s
//! `FpDeviceRetry` and `FpDeviceError` C enums.

use std::ffi::c_int;
use thiserror::Error;

/// Known 16-bit status codes returned in the first 2 bytes (little-endian) of every
/// Synaptics Metallica MIS (`06cb:009a`) response on Bulk IN `0x81`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorStatus {
    /// `0x0000` - Command succeeded (`VCS_RESULT_OK`).
    Ok,
    /// `0x006E` - Generic internal firmware error (`VCS_RESULT_GEN_ERROR`).
    GenericError,
    /// `0x006F` - Invalid argument or malformed command packet (`VCS_RESULT_INVALID_PARAM`).
    InvalidParam,
    /// `0x0071` - Unimplemented or unsupported wire opcode (`VCS_RESULT_NOT_IMPLEMENTED`).
    NotImplemented,
    /// `0x00DB` - Sensor busy; caller should perform an immediate second Bulk IN read (`VCS_RESULT_BUSY`).
    BusyRetry,
    /// `0x0259` / `0x025A` - Out of memory or on-flash DB2 database full.
    OutOfMemory,
    /// `0x0491` - No dirty flash pages to commit during `0x1a` (`DbCleanup`).
    NothingToCommit,
    /// `0x04B3` - Requested DB2 object/user/template record does not exist.
    ObjectNotFound,
    /// `0x0400..=0x04FF` - Security, TLS state, or DB2 flash storage error (e.g. `0x0412` when idle).
    SecurityOrDbError(u16),
    /// Any other non-zero 16-bit sensor status code.
    Raw(u16),
}

impl From<u16> for SensorStatus {
    fn from(code: u16) -> Self {
        match code {
            0x0000 => Self::Ok,
            0x006e => Self::GenericError,
            0x006f => Self::InvalidParam,
            0x0071 => Self::NotImplemented,
            0x00db => Self::BusyRetry,
            0x0259 | 0x025a => Self::OutOfMemory,
            0x0491 => Self::NothingToCommit,
            0x04b3 => Self::ObjectNotFound,
            0x0400..=0x04ff => Self::SecurityOrDbError(code),
            other => Self::Raw(other),
        }
    }
}

impl SensorStatus {
    /// Return the numeric 16-bit status word.
    pub const fn code(self) -> u16 {
        match self {
            Self::Ok => 0x0000,
            Self::GenericError => 0x006e,
            Self::InvalidParam => 0x006f,
            Self::NotImplemented => 0x0071,
            Self::BusyRetry => 0x00db,
            Self::OutOfMemory => 0x025a,
            Self::NothingToCommit => 0x0491,
            Self::ObjectNotFound => 0x04b3,
            Self::SecurityOrDbError(c) | Self::Raw(c) => c,
        }
    }

    /// Return `true` if the status code is `0x0000` ([`SensorStatus::Ok`]).
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }
}

impl std::fmt::Display for SensorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "0x0000 (OK)"),
            Self::GenericError => write!(f, "0x006e (GenericError)"),
            Self::InvalidParam => write!(f, "0x006f (InvalidParam)"),
            Self::NotImplemented => write!(f, "0x0071 (NotImplemented)"),
            Self::BusyRetry => write!(f, "0x00db (BusyRetry)"),
            Self::OutOfMemory => write!(f, "0x025a (OutOfMemory)"),
            Self::NothingToCommit => write!(f, "0x0491 (NothingToCommit)"),
            Self::ObjectNotFound => write!(f, "0x04b3 (ObjectNotFound)"),
            Self::SecurityOrDbError(c) => write!(f, "0x{c:04x} (SecurityOrDbError)"),
            Self::Raw(c) => write!(f, "0x{c:04x}"),
        }
    }
}

/// Human-readable description of the 32-bit scan quality code returned at offset `+12`
/// of the `ProgramStatus` (`0x51 00 20 00 00`) response after a 2D frame capture.
pub const fn describe_scan_quality_error(code: u32) -> &'static str {
    match code {
        0x0000 => "ok",
        0x0001..=0x000f => "finger lifted too quickly or partial touch",
        0x0010..=0x00ff => "insufficient ridge coverage / off-center touch",
        _ => "poor image quality or sensor surface noise",
    }
}

/// Unified error type for the `synaptics-009a-tod` driver.
#[derive(Debug, Error)]
pub enum DriverError {
    /// Underlying `libusb` (`rusb`) transport error.
    #[error("USB transport error: {0}")]
    Usb(#[from] rusb::Error),

    /// Host filesystem I/O error (e.g. reading calibration or pairing cache files).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Sensor `06cb:009a` was not found on the USB bus.
    #[error("Synaptics sensor (06cb:009a) not found on USB bus")]
    DeviceNotFound,

    /// Sensor firmware returned a non-zero [`SensorStatus`] for a wire command.
    #[error("Sensor command 0x{opcode:02x} ({opcode_name}) failed with status {status}")]
    CommandFailed {
        opcode: u8,
        opcode_name: &'static str,
        status: SensorStatus,
    },

    /// Sensor response payload was shorter than required by the protocol structure.
    #[error("Response too short for {context}: expected at least {expected} bytes, got {actual}")]
    ShortResponse {
        context: &'static str,
        expected: usize,
        actual: usize,
    },

    /// TLS 1.2 handshake, Alert, or record layer MAC/padding error.
    #[error("TLS 1.2 session error: {0}")]
    Tls(String),

    /// ECDH, ECDSA P-256, AES-256-CBC, or HMAC-SHA256 cryptographic error.
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// High-level protocol invariant violation.
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Recoverable 2D capacitive scan quality rejection reported by `0x51`.
    #[error("Finger scan quality error 0x{code:04x} ({description})")]
    ScanQuality {
        code: u32,
        description: &'static str,
    },

    /// Recoverable transient capture anomaly (e.g. finger lifted before frame completion).
    #[error("Transient scan capture retry needed: {0}")]
    ScanRetry(String),

    /// Timed out while waiting for a specific sensor interrupt event.
    #[error("Timed out while waiting for {0}")]
    Timeout(&'static str),

    /// Operation was cancelled by `fprintd` (`dev_cancel` / `dev_suspend` / `dev_exit`).
    #[error("Operation cancelled by fprintd")]
    Cancelled,
}

impl DriverError {
    /// Returns `true` if this error represents a recoverable finger-touch / image-quality issue
    /// where the user should simply lift their finger and touch the sensor again.
    pub const fn is_scan_retryable(&self) -> bool {
        matches!(self, Self::ScanQuality { .. } | Self::ScanRetry(_))
    }

    /// Returns `true` if this error indicates that the underlying USB handle or TLS 1.2 session
    /// is out of sync or disconnected and must be re-established on the next operation.
    pub const fn is_session_fatal(&self) -> bool {
        matches!(
            self,
            Self::Usb(_) | Self::Tls(_) | Self::DeviceNotFound | Self::Timeout(_)
        )
    }

    /// Map a retryable scan error to a `libfprint-2` `FpDeviceRetry` code:
    /// - `0` = `FP_DEVICE_RETRY_GENERAL`
    /// - `1` = `FP_DEVICE_RETRY_TOO_SHORT`
    /// - `2` = `FP_DEVICE_RETRY_CENTER_FINGER`
    /// - `3` = `FP_DEVICE_RETRY_REMOVE_FINGER`
    pub const fn fp_device_retry_code(&self) -> c_int {
        match self {
            Self::ScanQuality { code, .. } => match *code {
                0x0001..=0x000f => 1, // FP_DEVICE_RETRY_TOO_SHORT
                0x0010..=0x00ff => 2, // FP_DEVICE_RETRY_CENTER_FINGER
                _ => 3,               // FP_DEVICE_RETRY_REMOVE_FINGER
            },
            Self::ScanRetry(_) => 3, // FP_DEVICE_RETRY_REMOVE_FINGER
            _ => 0,                  // FP_DEVICE_RETRY_GENERAL
        }
    }

    /// Map a fatal driver error to a `libfprint-2` `FpDeviceError` code:
    /// - `0` = `FP_DEVICE_ERROR_GENERAL`
    /// - `1` = `FP_DEVICE_ERROR_NOT_SUPPORTED`
    /// - `4` = `FP_DEVICE_ERROR_BUSY`
    /// - `5` = `FP_DEVICE_ERROR_PROTO`
    /// - `6` = `FP_DEVICE_ERROR_DATA_INVALID`
    /// - `7` = `FP_DEVICE_ERROR_DATA_NOT_FOUND`
    /// - `8` = `FP_DEVICE_ERROR_DATA_FULL`
    /// - `10` = `FP_DEVICE_ERROR_REMOVED`
    pub const fn fp_device_error_code(&self) -> c_int {
        match self {
            Self::DeviceNotFound | Self::Usb(rusb::Error::NoDevice) => 10, // FP_DEVICE_ERROR_REMOVED
            Self::Usb(rusb::Error::Busy) => 4,                             // FP_DEVICE_ERROR_BUSY
            Self::CommandFailed { status, .. } => match status {
                SensorStatus::BusyRetry => 4,      // FP_DEVICE_ERROR_BUSY
                SensorStatus::InvalidParam => 6,   // FP_DEVICE_ERROR_DATA_INVALID
                SensorStatus::NotImplemented => 1, // FP_DEVICE_ERROR_NOT_SUPPORTED
                SensorStatus::OutOfMemory => 8,    // FP_DEVICE_ERROR_DATA_FULL
                SensorStatus::ObjectNotFound => 7, // FP_DEVICE_ERROR_DATA_NOT_FOUND
                _ => 5,                            // FP_DEVICE_ERROR_PROTO
            },
            Self::Tls(_)
            | Self::Crypto(_)
            | Self::Protocol(_)
            | Self::ShortResponse { .. }
            | Self::Usb(_)
            | Self::Timeout(_) => 5, // FP_DEVICE_ERROR_PROTO
            Self::Io(_) | Self::ScanQuality { .. } | Self::ScanRetry(_) | Self::Cancelled => 0,
        }
    }
}

/// Alias for `std::result::Result<T, DriverError>`.
pub type Result<T> = std::result::Result<T, DriverError>;
