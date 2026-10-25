//! Low-level USB transport layer (`libusb` / `rusb`) for Synaptics Metallica MIS (`06cb:009a`).
//!
//! ## USB Interface & Endpoint Layout (`palUsbProtocol.c` @ `0x180106680..0x180107380`)
//!
//! - **Interface `0`**: Vendor-Specific class (`0xFF`).
//! - **Endpoint `0x01` (Bulk OUT, 64B maxPacketSize)**: Host-to-sensor wire commands and TLS 1.2 `0x17` records.
//! - **Endpoint `0x81` (Bulk IN, 64B maxPacketSize)**: Sensor-to-host status word (2B LE) + response payload.
//!   If the sensor returns `0x00db` ([`SensorStatus::BusyRetry`]), the driver automatically issues a second
//!   Bulk IN read on `0x81` (`0x180106ee2`).
//! - **Endpoint `0x83` (Interrupt IN, 8B maxPacketSize)**: Asynchronous 7-byte sensor state notifications
//!   (`0x00` = armed, `0x02` = finger touch detected, `0x03` = 2D frame / QMatcher step completed).

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use rusb::{Context, DeviceHandle, UsbContext};

use crate::error::{DriverError, Result, SensorStatus};
use crate::{drv_debug, drv_error, drv_info, drv_warn};

/// USB Vendor ID for Synaptics Inc. (`0x06cb`).
pub const SYNAPTICS_VID: u16 = 0x06cb;
/// USB Product ID for Lenovo ThinkPad T480s Metallica MIS Touch Fingerprint Reader (`0x009a`).
pub const METALLICA_MIS_PID: u16 = 0x009a;

/// Bulk OUT command endpoint (`0x01`).
pub const EP_CMD_OUT: u8 = 0x01;
/// Bulk IN command response endpoint (`0x81`).
pub const EP_RESP_IN: u8 = 0x81;
/// Interrupt IN 7-byte sensor event endpoint (`0x83`).
pub const EP_INTR_EVENT: u8 = 0x83;

/// Default USB Bulk transfer timeout (`5000 ms`).
pub const DEFAULT_USB_TIMEOUT: Duration = Duration::from_millis(5000);

/// Parsed 7-byte interrupt event read from Endpoint `0x83` (`palUsbProtocol.c` @ `0x180107200`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensorInterruptEvent {
    /// Bytes `0..5`: 5-byte event header / status mask (`header[0]` = event phase, `header[2]` = completion bits).
    pub header: [u8; 5],
    /// Byte `5`: sequence / finger state byte.
    pub state: u8,
    /// Byte `6`: event type / flags byte.
    pub flags: u8,
}

impl SensorInterruptEvent {
    /// Parse a raw interrupt packet (up to 7 bytes) into a [`SensorInterruptEvent`].
    pub fn from_bytes(raw: &[u8]) -> Option<Self> {
        if raw.is_empty() {
            return None;
        }
        let mut header = [0u8; 5];
        let copy_len = raw.len().min(5);
        header[..copy_len].copy_from_slice(&raw[..copy_len]);
        Some(Self {
            header,
            state: raw.get(5).copied().unwrap_or(0),
            flags: raw.get(6).copied().unwrap_or(0),
        })
    }
}

/// Abstract transport trait implemented by [`SynapticsUsbTransport`] (real hardware)
/// and deterministic mock transports for offline unit testing.
pub trait Transport {
    /// Execute a raw Bulk OUT `0x01` + Bulk IN `0x81` transaction.
    /// Automatically retries reading `0x81` once if status `0x00db` (`BusyRetry`) is returned.
    fn transfer(&mut self, request: &[u8], expected_resp_len: usize) -> Result<Vec<u8>>;

    /// Wait for a 7-byte sensor interrupt event on Endpoint `0x83`.
    fn wait_interrupt_event(&mut self, timeout: Duration) -> Result<SensorInterruptEvent>;

    /// Drain any stale/residual interrupt packets queued on Endpoint `0x83`.
    fn flush_interrupt_events(&mut self) {}
}

/// Hardware USB transport for `06cb:009a` using `libusb` (`rusb`).
pub struct SynapticsUsbTransport {
    handle: DeviceHandle<Context>,
    interface_claimed: bool,
    timeout: Duration,
    cancel_flag: Arc<AtomicBool>,
}

impl SynapticsUsbTransport {
    /// Open the Synaptics Metallica MIS Fingerprint Reader (`06cb:009a`), detach any kernel
    /// driver if active, and claim USB interface `0`.
    pub fn open() -> Result<Self> {
        Self::open_with_vid_pid(SYNAPTICS_VID, METALLICA_MIS_PID)
    }

    /// Open a Synaptics USB fingerprint sensor by explicit `(vid, pid)`.
    pub fn open_with_vid_pid(vid: u16, pid: u16) -> Result<Self> {
        let context = Context::new()?;
        let devices = context.devices()?;

        for device in devices.iter() {
            let desc = match device.device_descriptor() {
                Ok(d) => d,
                Err(_) => continue,
            };
            if desc.vendor_id() == vid && desc.product_id() == pid {
                let bus = device.bus_number();
                let addr = device.address();
                let handle = device.open().map_err(|e| {
                    drv_error!(
                        "Failed to open USB device {vid:04x}:{pid:04x} (bus {bus:03} addr {addr:03}): {e}"
                    );
                    DriverError::Usb(e)
                })?;

                if handle.kernel_driver_active(0).unwrap_or(false) {
                    drv_warn!("Detaching active kernel driver from USB interface 0");
                    let _ = handle.detach_kernel_driver(0);
                }

                handle.claim_interface(0).map_err(|e| {
                    drv_error!("Failed to claim USB interface 0 on {vid:04x}:{pid:04x}: {e}");
                    DriverError::Usb(e)
                })?;

                drv_info!("Opened USB sensor {vid:04x}:{pid:04x} (bus {bus:03} addr {addr:03})");
                return Ok(Self {
                    handle,
                    interface_claimed: true,
                    timeout: DEFAULT_USB_TIMEOUT,
                    cancel_flag: Arc::new(AtomicBool::new(false)),
                });
            }
        }

        drv_error!("Synaptics USB sensor {vid:04x}:{pid:04x} not found on bus");
        Err(DriverError::DeviceNotFound)
    }

    /// Return a clone of the atomic cancellation flag used to interrupt [`Self::wait_interrupt_event`].
    pub fn cancel_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancel_flag)
    }

    /// Clear any pending cancellation state before starting a new operation.
    pub fn clear_cancel(&self) {
        self.cancel_flag.store(false, Ordering::SeqCst);
    }

    /// Perform a USB port reset when the sensor requires re-enumeration.
    pub fn reset_device(&mut self) -> Result<()> {
        drv_warn!("Performing USB port reset on sensor 06cb:009a");
        self.handle.reset()?;
        Ok(())
    }
}

impl Drop for SynapticsUsbTransport {
    fn drop(&mut self) {
        if self.interface_claimed {
            let _ = self.handle.release_interface(0);
        }
    }
}

impl Transport for SynapticsUsbTransport {
    fn transfer(&mut self, request: &[u8], expected_resp_len: usize) -> Result<Vec<u8>> {
        let opcode = request.first().copied().unwrap_or(0);
        drv_debug!(
            "USB Bulk OUT EP 0x{EP_CMD_OUT:02x}: len={} B, first_byte=0x{opcode:02x}",
            request.len()
        );

        let written = self
            .handle
            .write_bulk(EP_CMD_OUT, request, self.timeout)
            .map_err(|e| {
                drv_error!(
                    "USB Bulk OUT error on EP 0x{EP_CMD_OUT:02x} (len={} B, cmd=0x{opcode:02x}): {e}",
                    request.len()
                );
                DriverError::Usb(e)
            })?;

        if written != request.len() {
            drv_warn!(
                "Short write on USB Bulk OUT EP 0x{EP_CMD_OUT:02x}: wrote {written}/{} B",
                request.len()
            );
        }

        // Allocate a 64-byte aligned receive buffer large enough for any fragmented TLS response
        let alloc_len = (expected_resp_len.max(100 * 1024) + 63) & !63;
        let mut buf = vec![0u8; alloc_len];
        let mut n = self
            .handle
            .read_bulk(EP_RESP_IN, &mut buf, self.timeout)
            .map_err(|e| {
                drv_error!("USB Bulk IN error on EP 0x{EP_RESP_IN:02x} (cmd=0x{opcode:02x}): {e}");
                DriverError::Usb(e)
            })?;
        buf.truncate(n);

        // Retry once if the sensor returns 0x00db (BusyRetry) on EP 0x81 (`palUsbProtocol.c` @ `0x180106ee2`)
        if !buf.is_empty() {
            let status_u16 = if buf.len() >= 2 {
                u16::from_le_bytes([buf[0], buf[1]])
            } else {
                u16::from(buf[0])
            };
            if SensorStatus::from(status_u16) == SensorStatus::BusyRetry {
                drv_warn!("Sensor returned 0x00db (BusyRetry) on EP 0x81; retrying Bulk IN read");
                buf.resize(alloc_len, 0);
                n = self
                    .handle
                    .read_bulk(EP_RESP_IN, &mut buf, self.timeout)
                    .map_err(|e| {
                        drv_error!("USB Bulk IN retry error on EP 0x{EP_RESP_IN:02x}: {e}");
                        DriverError::Usb(e)
                    })?;
                buf.truncate(n);
            }
        }

        drv_debug!("USB Bulk IN  EP 0x{EP_RESP_IN:02x}: len={} B", buf.len());
        Ok(buf)
    }

    fn wait_interrupt_event(&mut self, timeout: Duration) -> Result<SensorInterruptEvent> {
        // Poll in 200ms slices so cancellation via `cancel_flag` takes effect promptly.
        // IMPORTANT: Never pass a timeout < 1ms to `read_interrupt`, because `rusb` truncates
        // sub-millisecond durations to `0 ms`, which `libusb` interprets as an INFINITE timeout!
        let deadline = Instant::now() + timeout;
        let slice_timeout = Duration::from_millis(200);
        let min_usb_timeout = Duration::from_millis(10);
        let mut buf = [0u8; 64];

        loop {
            if self.cancel_flag.load(Ordering::SeqCst) {
                self.cancel_flag.store(false, Ordering::SeqCst);
                drv_info!("Interrupt wait on EP 0x{EP_INTR_EVENT:02x} cancelled");
                return Err(DriverError::Cancelled);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(DriverError::Usb(rusb::Error::Timeout));
            }
            let remaining = deadline - now;
            if remaining < Duration::from_millis(1) {
                return Err(DriverError::Usb(rusb::Error::Timeout));
            }
            let wait = remaining.min(slice_timeout).max(min_usb_timeout);
            match self.handle.read_interrupt(EP_INTR_EVENT, &mut buf, wait) {
                Ok(n) => {
                    drv_debug!(
                        "USB Intr IN  EP 0x{EP_INTR_EVENT:02x}: len={n} B, data={}",
                        hex::encode(&buf[..n])
                    );
                    return SensorInterruptEvent::from_bytes(&buf[..n]).ok_or(
                        DriverError::ShortResponse {
                            context: "interrupt event EP 0x83",
                            expected: 1,
                            actual: n,
                        },
                    );
                }
                Err(rusb::Error::Timeout) => continue,
                Err(e) => {
                    drv_error!("USB Interrupt IN error on EP 0x{EP_INTR_EVENT:02x}: {e}");
                    return Err(DriverError::Usb(e));
                }
            }
        }
    }

    fn flush_interrupt_events(&mut self) {
        let mut buf = [0u8; 64];
        let flush_timeout = Duration::from_millis(25);
        for _ in 0..8 {
            match self.handle.read_interrupt(EP_INTR_EVENT, &mut buf, flush_timeout) {
                Ok(n) => {
                    drv_debug!(
                        "Flushed residual interrupt on EP 0x{EP_INTR_EVENT:02x}: len={n} B, data={}",
                        hex::encode(&buf[..n])
                    );
                }
                Err(_) => break,
            }
        }
    }
}
