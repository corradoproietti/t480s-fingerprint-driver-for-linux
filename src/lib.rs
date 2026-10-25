//! # T480s Fingerprint Driver for Linux (`libfprint-2-tod1-synaptics009a`)
//!
//! Native Linux **`libfprint-2-tod1` (Touch OEM Driver)** shared library plugin written in Rust
//! for the **Lenovo ThinkPad T480s Synaptics Metallica MIS Touch Fingerprint Reader** (`06cb:009a`).
//!
//! ## Architecture Overview
//!
//! ```text
//! fprintd (D-Bus Biometric Daemon)
//!   └── libfprint-2.so.2 + libfprint-2-tod.so.1
//!         └── libfprint-2-tod1-synaptics009a.so (this crate)
//!               ├── tod.rs       : GObject FpDeviceClass vtable, pre-warming, suspend/resume
//!               ├── moc.rs       : 2D capacitive frame capture (0x02), QMatcher (0x5e..0x62), DB2 (0x45..0x4b)
//!               ├── protocol.rs  : SensorSession state machine, Metallica init (0x01/0x19/0x43/0x06), WireOpcode
//!               ├── tls.rs       : Custom Synaptics TLS 1.2 (ECDH_ECDSA_WITH_AES_256_CBC_SHA256) & Partition 1 parser
//!               ├── usb.rs       : libusb (rusb) Bulk OUT 0x01, Bulk IN 0x81, Interrupt IN 0x83 transport
//!               ├── error.rs     : Hardware status codes (SensorStatus) and libfprint retry/error mapping
//!               └── log.rs       : Real-time stderr / systemd-journald structured logger
//! ```

pub mod error;
pub mod log;
pub mod moc;
pub mod protocol;
pub mod tls;
pub mod tod;
pub mod usb;

pub use error::{DriverError, Result, SensorStatus};
pub use moc::{
    CaptureMode, Db2DatabaseInfo, Db2FingerEntry, Db2UserRecord, Db2UserStorage, MatchVerifyResult,
    build_cmd_02_0199, encode_sid_identity_for_uid, finger_subtype_name, parse_sid_identity,
};
pub use protocol::{SensorSession, SensorVersion, WireOpcode};
pub use tls::{PairingBundle, TlsHandshakeBuilder, TlsSession, TlsSessionKeys};
pub use usb::{
    METALLICA_MIS_PID, SYNAPTICS_VID, SensorInterruptEvent, SynapticsUsbTransport, Transport,
};
