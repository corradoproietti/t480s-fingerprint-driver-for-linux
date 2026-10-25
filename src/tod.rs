//! Native `libfprint-2-tod1` (Touch OEM Driver) shared library plugin for Ubuntu/Debian `fprintd`.
//!
//! Installed at:
//! `/usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/libfprint-2-tod1-synaptics009a.so`
//!
//! ## How `libfprint-2-tod.so.1` Loads This Plugin
//!
//! 1. At startup, `fprintd` initializes `libfprint-2.so.2`, which delegates Touch OEM Driver loading
//!    to `/usr/lib/x86_64-linux-gnu/libfprint-2-tod.so.1` (`tod-shared-loader.c`).
//! 2. `libfprint-2-tod.so.1` scans `/usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/*.so`, opens our
//!    shared library via `dlopen()`, and invokes [`fpi_tod_shared_driver_get_type`].
//! 3. [`fpi_tod_shared_driver_get_type`] registers the `FpiDeviceSynaptics009aTod` GObject subclass
//!    of `FpDevice` and populates the `FpDeviceClass` virtual method table in
//!    `fpi_device_synaptics_009a_tod_class_init`.
//! 4. All blocking USB/TLS/biometric operations (`open`, `enroll`, `verify`, `identify`, `delete`,
//!    `clear_storage`) execute on dedicated worker threads and marshal completion callbacks back
//!    onto the GLib main loop via `run_on_glib_main_loop` (`g_idle_add`), keeping `fprintd`'s
//!    D-Bus event loop responsive at all times.

use std::ffi::{CStr, c_char, c_int, c_uint, c_void};
use std::path::PathBuf;
use std::ptr;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};

use crate::error::{DriverError, Result};
use crate::moc::finger_subtype_name;
use crate::protocol::SensorSession;
use crate::tls::PairingBundle;
use crate::usb::SynapticsUsbTransport;
use crate::{drv_debug, drv_error, drv_info, drv_warn};

/// GLib `GType` (`gsize` / `usize` on 64-bit Linux).
pub type GType = usize;

/// Embedded 13,440-byte sensor calibration blob (`calib_06cb_009a.bin`) so the plugin works
/// out-of-the-box inside `fprintd.service`'s strict systemd filesystem sandbox.
const EMBEDDED_CALIB_009A: &[u8] = include_bytes!("../calib_06cb_009a.bin");

/// Driver ID registered with `libfprint-2` (`FpDeviceClass.id` @ `+0x88`).
pub const TOD_DRIVER_ID: &CStr = c"synaptics-009a-tod";
/// Human-readable device name (`FpDeviceClass.full_name` @ `+0x90`).
pub const TOD_FULL_NAME: &CStr = c"Synaptics Metallica MIS Touch Fingerprint Reader (06cb:009a)";
/// GObject type name for our `FpDevice` subclass.
const TOD_TYPE_NAME: &CStr = c"FpiDeviceSynaptics009aTod";
/// Number of enrollment touches required by the `06cb:009a` QMatcher firmware (`FpDeviceClass.nr_enroll_stages` @ `+0xa8`).
pub const TOD_NR_ENROLL_STAGES: c_int = 12;

/// `FpiDeviceAction` values from `libfprint-2-tod.so.1` (`fpi_device_action_get_type`).
const FPI_DEVICE_ACTION_VERIFY: c_int = 5;
const FPI_DEVICE_ACTION_IDENTIFY: c_int = 6;

/// `FpiMatchResult` values from `libfprint-2-tod.so.1` (`fpi_match_result_get_type`).
const FPI_MATCH_FAIL: c_int = 0;
const FPI_MATCH_SUCCESS: c_int = 1;

/// `FpIdEntry` USB table entry (`16` bytes on x86_64: `pid: u32, vid: u32, driver_data: u64`).
#[repr(C)]
pub struct FpIdEntry {
    pub pid: u32,
    pub vid: u32,
    pub driver_data: u64,
}

unsafe impl Sync for FpIdEntry {}

/// Null-terminated USB device ID table matching `06cb:009a`.
static ID_TABLE: [FpIdEntry; 2] = [
    FpIdEntry {
        pid: 0x009a,
        vid: 0x06cb,
        driver_data: 0,
    },
    FpIdEntry {
        pid: 0,
        vid: 0,
        driver_data: 0,
    },
];

/// GLib `GPtrArray` C layout used by `fpi_device_get_identify_data`.
#[repr(C)]
pub struct GPtrArray {
    pub pdata: *mut *mut c_void,
    pub len: c_uint,
}

unsafe extern "C" {
    fn atexit(cb: extern "C" fn()) -> c_int;

    // GLib / GObject FFI
    fn g_intern_static_string(string: *const c_char) -> *const c_char;
    fn g_type_register_static_simple(
        parent_type: GType,
        type_name: *const c_char,
        class_size: c_uint,
        class_init: extern "C" fn(*mut c_void, *mut c_void),
        instance_size: c_uint,
        instance_init: extern "C" fn(*mut c_void, *mut c_void),
        flags: c_uint,
    ) -> GType;
    fn g_type_class_peek_parent(g_class: *mut c_void) -> *mut c_void;
    fn g_type_check_class_cast(g_class: *mut c_void, is_a_type: GType) -> *mut c_void;
    fn g_object_ref(object: *mut c_void) -> *mut c_void;
    fn g_object_set(object: *mut c_void, first_property_name: *const c_char, ...);
    fn g_object_get(object: *mut c_void, first_property_name: *const c_char, ...);
    fn g_variant_new_fixed_array(
        element_type: *const c_char,
        elements: *const c_void,
        n_elements: usize,
        element_size: usize,
    ) -> *mut c_void;
    fn g_variant_get_fixed_array(
        value: *mut c_void,
        n_elements: *mut usize,
        element_size: usize,
    ) -> *const u8;
    fn g_variant_unref(value: *mut c_void);
    fn g_idle_add(function: extern "C" fn(*mut c_void) -> c_int, data: *mut c_void) -> c_uint;

    // libfprint-2.so.2 & libfprint-2-tod.so.1 FFI
    fn fp_device_get_type() -> GType;
    fn fp_print_get_finger(print: *mut c_void) -> c_uint;
    fn fp_print_get_username(print: *mut c_void) -> *const c_char;

    fn fpi_print_set_type(print: *mut c_void, print_type: c_uint);
    fn fpi_device_set_nr_enroll_stages(device: *mut c_void, enroll_stages: c_int);
    fn fpi_device_probe_complete(
        device: *mut c_void,
        device_id: *const c_char,
        device_name: *const c_char,
        error: *mut c_void,
    );
    fn fpi_device_open_complete(device: *mut c_void, error: *mut c_void);
    fn fpi_device_close_complete(device: *mut c_void, error: *mut c_void);
    fn fpi_device_get_current_action(device: *mut c_void) -> c_int;

    fn fpi_device_get_enroll_data(device: *mut c_void, print: *mut *mut c_void);
    fn fpi_device_enroll_progress(
        device: *mut c_void,
        completed_stages: c_int,
        print: *mut c_void,
        error: *mut c_void,
    );
    fn fpi_device_enroll_complete(device: *mut c_void, print: *mut c_void, error: *mut c_void);

    fn fpi_device_get_verify_data(device: *mut c_void, print: *mut *mut c_void);
    fn fpi_device_verify_report(
        device: *mut c_void,
        result: c_int,
        print: *mut c_void,
        error: *mut c_void,
    );
    fn fpi_device_verify_complete(device: *mut c_void, error: *mut c_void);

    fn fpi_device_get_identify_data(device: *mut c_void, prints: *mut *mut GPtrArray);
    fn fpi_device_identify_report(
        device: *mut c_void,
        match_print: *mut c_void,
        print: *mut c_void,
        error: *mut c_void,
    );
    fn fpi_device_identify_complete(device: *mut c_void, error: *mut c_void);

    fn fpi_device_get_delete_data(device: *mut c_void, print: *mut *mut c_void);
    fn fpi_device_delete_complete(device: *mut c_void, error: *mut c_void);
    fn fpi_device_clear_storage_complete(device: *mut c_void, error: *mut c_void);
    fn fpi_device_suspend_complete(device: *mut c_void, error: *mut c_void);
    fn fpi_device_resume_complete(device: *mut c_void, error: *mut c_void);

    fn fpi_device_retry_new(retry_code: c_int) -> *mut c_void;
    fn fpi_device_error_new(error_code: c_int) -> *mut c_void;
}

/// Convert `libfprint-2`'s `FpFinger` enum (`1..=10`) to Synaptics WINBIO subtype (`1..=10`).
///
/// - In `libfprint-2`: `1..=5` = `left-thumb` .. `left-little`, `6..=10` = `right-thumb` .. `right-little`.
/// - In Synaptics DB2 (`WINBIO`): `1..=5` = `right-thumb` .. `right-little`, `6..=10` = `left-thumb` .. `left-little`.
pub const fn fp_finger_to_synaptics_subtype(fp_finger: u32) -> u16 {
    match fp_finger {
        1..=5 => (fp_finger + 5) as u16,
        6..=10 => (fp_finger - 5) as u16,
        _ => 2,
    }
}

/// Resolve a Linux username (e.g. `"alice"`) to its numeric UID via `/etc/passwd` (defaulting to `1000`).
pub fn uid_from_username(username: &str) -> u32 {
    if username.is_empty() {
        return 1000;
    }
    if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let mut parts = line.split(':');
            let Some(name) = parts.next() else { continue };
            let _ = parts.next();
            let Some(uid_str) = parts.next() else {
                continue;
            };
            if name == username {
                if let Ok(uid) = uid_str.parse::<u32>() {
                    return uid;
                }
            }
        }
    }
    1000
}

/// Load the 13,440-byte sensor calibration blob (`calib_06cb_009a.bin`), falling back to the embedded calibration data.
pub fn load_calibration_blob() -> Vec<u8> {
    for candidate in [
        "/var/lib/fprint/.synaptics_06cb_009a_calib.bin",
        "/var/run/python-validity/calib-data.bin",
        "calib_06cb_009a.bin",
    ] {
        if let Ok(bytes) = std::fs::read(candidate) {
            if bytes.len() >= 13440 {
                return bytes;
            }
        }
    }
    EMBEDDED_CALIB_009A.to_vec()
}

/// Load the host-sensor TLS pairing bundle from disk cache, or read and decrypt it directly
/// from Flash Partition 1 (`0x40`) on the sensor and cache it to `/var/lib/fprint/.synaptics_06cb_009a_pairing.json`.
pub fn load_or_read_pairing_bundle(
    session: &mut SensorSession<SynapticsUsbTransport>,
) -> Result<PairingBundle> {
    const CACHE_PATH: &str = "/var/lib/fprint/.synaptics_06cb_009a_pairing.json";
    for candidate in [CACHE_PATH, "pairing_06cb_009a.json"] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            if let Ok(b) = PairingBundle::load_from_file(&p) {
                return Ok(b);
            }
        }
    }
    drv_info!("Reading TLS pairing credentials from Sensor Flash Partition 1 (0x40)...");
    let bundle = session.read_tls_flash_bundle()?;
    if let Err(e) = bundle.save_to_file(CACHE_PATH) {
        drv_debug!("Could not cache pairing bundle to {CACHE_PATH}: {e}");
    } else {
        drv_info!("Cached sensor TLS pairing bundle to {CACHE_PATH}");
    }
    Ok(bundle)
}

/// Global process-wide state holding the persistent TLS 1.2 [`SensorSession`] and active cancellation flag.
struct SharedSensorState {
    session: Mutex<Option<(SensorSession<SynapticsUsbTransport>, std::time::Instant)>>,
    cancel_flag: Mutex<Option<Arc<AtomicBool>>>,
    atexit_registered: AtomicBool,
}

static SENSOR_STATE: OnceLock<SharedSensorState> = OnceLock::new();

fn sensor_state() -> &'static SharedSensorState {
    SENSOR_STATE.get_or_init(|| SharedSensorState {
        session: Mutex::new(None),
        cancel_flag: Mutex::new(None),
        atexit_registered: AtomicBool::new(false),
    })
}

/// Process exit handler registered via `atexit()` so the sensor's TLS session slot is cleanly
/// released (`0x05 0x02 0x00`) if `fprintd` stops.
extern "C" fn tod_atexit_reboot() {
    request_cancel();
    if let Some(state) = SENSOR_STATE.get() {
        if let Ok(mut guard) = state.session.try_lock() {
            if let Some((mut session, _)) = guard.take() {
                let _ = session.reboot_sensor();
            }
        }
    }
}

/// Open or reuse the persistent TLS 1.2 session with `06cb:009a`.
///
/// - If an existing session has been idle for `>= 3s`, verifies liveness via [`SensorSession::ping_status`] (`0x01`).
/// - When establishing a new session, pre-caches the sensor's immutable OTP factory calibration values (`0x6f`)
///   so subsequent verify/enroll calls can arm the LED in ~5ms.
fn with_sensor_session<F, R>(f: F) -> Result<R>
where
    F: FnOnce(&mut SensorSession<SynapticsUsbTransport>) -> Result<R>,
{
    let state = sensor_state();
    let mut guard = state
        .session
        .lock()
        .map_err(|_| DriverError::Protocol("Sensor mutex poisoned".into()))?;

    let mut needs_open = guard.is_none();
    if let Some((sess, last_used)) = guard.as_mut() {
        sess.transport.clear_cancel();
        if last_used.elapsed() >= std::time::Duration::from_secs(3) {
            if let Err(e) = sess.ping_status() {
                drv_warn!("Existing TLS session unresponsive ({e}); reconnecting to sensor...");
                let _ = sess.reboot_sensor();
                needs_open = true;
            } else {
                *last_used = std::time::Instant::now();
            }
        }
    }

    if needs_open {
        *guard = None;
        let t_open = std::time::Instant::now();
        let mut session = {
            let transport = SynapticsUsbTransport::open()?;
            if let Ok(mut cf) = state.cancel_flag.lock() {
                *cf = Some(transport.cancel_handle());
            }
            let mut first_session = SensorSession::new(transport);
            if let Err(e) = first_session.initialize_metallica() {
                drv_warn!(
                    "Initial sensor handshake failed ({e}); resetting USB port and retrying..."
                );
                let _ = first_session.transport.reset_device();
                // Explicitly drop `first_session` so USB interface 0 is released before reopening
                drop(first_session);
                std::thread::sleep(std::time::Duration::from_millis(600));
                let retry_transport = SynapticsUsbTransport::open()?;
                if let Ok(mut cf) = state.cancel_flag.lock() {
                    *cf = Some(retry_transport.cancel_handle());
                }
                let mut retry_session = SensorSession::new(retry_transport);
                retry_session.initialize_metallica()?;
                retry_session
            } else {
                first_session
            }
        };
        let bundle = load_or_read_pairing_bundle(&mut session)?;
        session.establish_tls_session(&bundle)?;
        // Pre-cache immutable factory calibration values (0x6f) once during session setup
        let _ = session.get_factory_calibration_values()?;
        drv_info!(
            "Sensor TLS 1.2 session + factory calibration ready in {} ms",
            t_open.elapsed().as_millis()
        );

        if !state.atexit_registered.swap(true, Ordering::SeqCst) {
            unsafe {
                atexit(tod_atexit_reboot);
            }
        }
        *guard = Some((session, std::time::Instant::now()));
    }

    let (sess, last_used) = guard.as_mut().unwrap();
    sess.transport.clear_cancel();
    let result = f(sess);
    match &result {
        Ok(_) => {
            *last_used = std::time::Instant::now();
        }
        Err(err) if err.is_session_fatal() => {
            drv_warn!("Dropping cached TLS session after fatal transport/session error: {err}");
            *guard = None;
        }
        Err(_) => {}
    }
    result
}

/// Trigger cooperative cancellation of any active interrupt wait on `EP 0x83`.
fn request_cancel() {
    let state = sensor_state();
    if let Ok(guard) = state.cancel_flag.lock() {
        if let Some(flag) = guard.as_ref() {
            flag.store(true, Ordering::SeqCst);
        }
    }
}

/// Schedule a Rust closure to execute on the GLib main context thread via `g_idle_add`.
fn run_on_glib_main_loop<F>(func: F)
where
    F: FnOnce() + Send + 'static,
{
    extern "C" fn trampoline(data: *mut c_void) -> c_int {
        let boxed: Box<Box<dyn FnOnce() + Send>> = unsafe { Box::from_raw(data as *mut _) };
        boxed();
        0 // G_SOURCE_REMOVE
    }

    let boxed: Box<Box<dyn FnOnce() + Send>> = Box::new(Box::new(func));
    unsafe {
        g_idle_add(trampoline, Box::into_raw(boxed) as *mut c_void);
    }
}

/// Attach a 16-byte `"fpi-data"` GVariant byte array (`b"SYN9" || uid || user_dbid || template_dbid || subtype || fp_finger`)
/// and set `fpi_print_set_type(print, 1 /* FPI_PRINT_RAW */)` on a `FpPrint *` object so `fprintd`
/// persists the hardware DB2 metadata in `/var/lib/fprint/<user>/synaptics-009a-tod/0/`.
pub unsafe fn attach_synaptics_fpi_data(
    print: *mut c_void,
    uid: u32,
    user_dbid: u16,
    template_dbid: u16,
    synaptics_subtype: u16,
    fp_finger: u32,
) {
    let mut payload = [0u8; 16];
    payload[0..4].copy_from_slice(b"SYN9");
    payload[4..8].copy_from_slice(&uid.to_le_bytes());
    payload[8..10].copy_from_slice(&user_dbid.to_le_bytes());
    payload[10..12].copy_from_slice(&template_dbid.to_le_bytes());
    payload[12..14].copy_from_slice(&synaptics_subtype.to_le_bytes());
    payload[14..16].copy_from_slice(&(fp_finger as u16).to_le_bytes());

    unsafe {
        fpi_print_set_type(print, 1); // FPI_PRINT_RAW = 1
        let variant = g_variant_new_fixed_array(
            c"y".as_ptr(),
            payload.as_ptr() as *const c_void,
            payload.len(),
            1,
        );
        g_object_set(
            print,
            c"fpi-data".as_ptr(),
            variant,
            ptr::null::<c_char>(),
        );
    }
}

/// Extract `(uid, user_dbid, template_dbid, synaptics_subtype, fp_finger)` from a `FpPrint *`'s `"fpi-data"`.
pub unsafe fn extract_synaptics_fpi_data(print: *mut c_void) -> Option<(u32, u16, u16, u16, u16)> {
    if print.is_null() {
        return None;
    }
    unsafe {
        let mut variant: *mut c_void = ptr::null_mut();
        g_object_get(
            print,
            c"fpi-data".as_ptr(),
            &mut variant as *mut *mut c_void,
            ptr::null::<c_char>(),
        );
        if variant.is_null() {
            return None;
        }
        let mut n_elem: usize = 0;
        let ptr_bytes = g_variant_get_fixed_array(variant, &mut n_elem, 1);
        let res = if !ptr_bytes.is_null() && n_elem >= 16 {
            let slice = std::slice::from_raw_parts(ptr_bytes, n_elem);
            if &slice[0..4] == b"SYN9" {
                let uid = u32::from_le_bytes([slice[4], slice[5], slice[6], slice[7]]);
                let user_dbid = u16::from_le_bytes([slice[8], slice[9]]);
                let template_dbid = u16::from_le_bytes([slice[10], slice[11]]);
                let syn_subtype = u16::from_le_bytes([slice[12], slice[13]]);
                let fp_finger = u16::from_le_bytes([slice[14], slice[15]]);
                Some((uid, user_dbid, template_dbid, syn_subtype, fp_finger))
            } else {
                None
            }
        } else {
            None
        };
        g_variant_unref(variant);
        res
    }
}

/// `FpDeviceClass.usb_discover` (`+0xb0`): return a positive priority score (`51`) to claim `06cb:009a`
/// over `libfprint-2`'s built-in non-MoC `synaptics` driver.
extern "C" fn dev_usb_discover(_usb_device: *mut c_void) -> c_int {
    51
}

/// `FpDeviceClass.probe` (`+0xb8`): report device metadata to `fprintd` and immediately spawn
/// background TLS 1.2 + OTP factory calibration pre-warming.
extern "C" fn dev_probe(device: *mut c_void) {
    drv_info!("Probing USB device 06cb:009a (enroll_stages={TOD_NR_ENROLL_STAGES})");
    // Start warming up the USB + TLS 1.2 session in the background while fprintd
    // finishes D-Bus registration, Polkit checks, and template loading (~380 ms head start).
    std::thread::spawn(|| {
        if let Err(e) = with_sensor_session(|_| Ok(())) {
            drv_warn!("Background TLS pre-warm on probe failed: {e}");
        }
    });
    unsafe {
        fpi_device_set_nr_enroll_stages(device, TOD_NR_ENROLL_STAGES);
        fpi_device_probe_complete(
            device,
            TOD_DRIVER_ID.as_ptr(),
            TOD_FULL_NAME.as_ptr(),
            ptr::null_mut(),
        );
    }
}

/// `FpDeviceClass.open` (`+0xc0`): wait for the pre-warmed TLS 1.2 session to be ready before
/// completing `open`, so `fprintd` only prompts the user to touch the sensor when the LED can
/// turn on immediately (~5ms).
extern "C" fn dev_init(device: *mut c_void) {
    drv_debug!("Device opened by fprintd");
    let dev_addr = device as usize;
    std::thread::spawn(move || {
        let _ = with_sensor_session(|_| Ok(()));
        run_on_glib_main_loop(move || unsafe {
            let dev_ptr = dev_addr as *mut c_void;
            fpi_device_set_nr_enroll_stages(dev_ptr, TOD_NR_ENROLL_STAGES);
            fpi_device_open_complete(dev_ptr, ptr::null_mut());
        });
    });
}

/// `FpDeviceClass.close` (`+0xc8`): cancel any pending interrupt wait and complete device close.
extern "C" fn dev_exit(device: *mut c_void) {
    drv_debug!("Device closed by fprintd");
    request_cancel();
    unsafe {
        fpi_device_close_complete(device, ptr::null_mut());
    }
}

/// `FpDeviceClass.cancel` (`+0x100`): signal cooperative cancellation to the worker thread.
extern "C" fn dev_cancel(_device: *mut c_void) {
    drv_info!("Cancellation requested by fprintd");
    request_cancel();
}

/// `FpDeviceClass.suspend` (`+0x120`): abort any active scan cleanly before system suspend.
extern "C" fn dev_suspend(device: *mut c_void) {
    drv_info!("System suspend notified by fprintd — cancelling active scan");
    request_cancel();
    unsafe {
        fpi_device_suspend_complete(device, ptr::null_mut());
    }
}

/// `FpDeviceClass.resume` (`+0x128`): re-warm the TLS 1.2 session in the background after system wake.
extern "C" fn dev_resume(device: *mut c_void) {
    drv_info!("System resume notified by fprintd — re-warming sensor session in background");
    std::thread::spawn(|| {
        if let Err(e) = with_sensor_session(|_| Ok(())) {
            drv_warn!("Post-resume TLS session warm-up failed: {e}");
        }
    });
    unsafe {
        fpi_device_resume_complete(device, ptr::null_mut());
    }
}

/// `FpDeviceClass.enroll` (`+0xd0`): run a 12-stage on-chip enrollment and commit the resulting
/// template both to the sensor's DB2 flash and to `fprintd`'s host storage.
extern "C" fn dev_enroll(device: *mut c_void) {
    let mut print: *mut c_void = ptr::null_mut();
    unsafe {
        fpi_device_get_enroll_data(device, &mut print);
    }
    if print.is_null() {
        drv_error!("dev_enroll: fpi_device_get_enroll_data returned NULL print");
        unsafe {
            let err = fpi_device_error_new(6); // FP_DEVICE_ERROR_DATA_INVALID
            fpi_device_enroll_complete(device, ptr::null_mut(), err);
        }
        return;
    }

    let (username, fp_finger) = unsafe {
        let uname_ptr = fp_print_get_username(print);
        let uname = if uname_ptr.is_null() {
            String::new()
        } else {
            CStr::from_ptr(uname_ptr).to_string_lossy().into_owned()
        };
        let finger = fp_print_get_finger(print);
        (uname, finger)
    };

    let uid = uid_from_username(&username);
    let syn_subtype = fp_finger_to_synaptics_subtype(fp_finger);
    let dev_addr = device as usize;
    let print_addr = print as usize;

    drv_info!(
        "Starting ENROLL for user '{}' (uid={uid}), fp_finger={fp_finger} -> subtype={syn_subtype} ({})",
        if username.is_empty() {
            "<default>"
        } else {
            &username
        },
        finger_subtype_name(syn_subtype)
    );

    std::thread::spawn(move || {
        let calib_data = load_calibration_blob();
        let mut last_reported_stage: c_int = 0;

        let res = with_sensor_session(|session| {
            let template_dbid = session.enroll_finger_009a(
                uid,
                syn_subtype,
                &calib_data,
                |stage_count, _header, retry_err| {
                    if let Some(err) = retry_err {
                        let retry_code = err.fp_device_retry_code();
                        let stage_now = last_reported_stage;
                        run_on_glib_main_loop(move || unsafe {
                            let gerr = fpi_device_retry_new(retry_code);
                            fpi_device_enroll_progress(
                                dev_addr as *mut c_void,
                                stage_now,
                                ptr::null_mut(),
                                gerr,
                            );
                        });
                    } else {
                        let reported = (stage_count as c_int).min(TOD_NR_ENROLL_STAGES - 1);
                        last_reported_stage = reported;
                        run_on_glib_main_loop(move || unsafe {
                            fpi_device_enroll_progress(
                                dev_addr as *mut c_void,
                                reported,
                                ptr::null_mut(),
                                ptr::null_mut(),
                            );
                        });
                    }
                },
            )?;
            let (user_dbid, _) = session.db2_lookup_or_create_user(uid)?;
            Ok((user_dbid, template_dbid))
        });

        run_on_glib_main_loop(move || unsafe {
            let dev_ptr = dev_addr as *mut c_void;
            let prt_ptr = print_addr as *mut c_void;
            match res {
                Ok((user_dbid, template_dbid)) => {
                    drv_info!(
                        "ENROLL SUCCESS: subtype={syn_subtype} ({}), user_dbid=0x{user_dbid:04x}, template_dbid=0x{template_dbid:04x}",
                        finger_subtype_name(syn_subtype)
                    );
                    fpi_device_enroll_progress(
                        dev_ptr,
                        TOD_NR_ENROLL_STAGES,
                        ptr::null_mut(),
                        ptr::null_mut(),
                    );
                    attach_synaptics_fpi_data(
                        prt_ptr,
                        uid,
                        user_dbid,
                        template_dbid,
                        syn_subtype,
                        fp_finger,
                    );
                    let ref_print = g_object_ref(prt_ptr);
                    fpi_device_enroll_complete(dev_ptr, ref_print, ptr::null_mut());
                }
                Err(e) => {
                    let code = e.fp_device_error_code();
                    drv_error!("ENROLL FAILED: {e} (fp_device_error={code})");
                    let err = fpi_device_error_new(code);
                    fpi_device_enroll_complete(dev_ptr, ptr::null_mut(), err);
                }
            }
        });
    });
}

/// Candidate `FpPrint` entry passed by `fprintd` during `verify` (1:1) or `identify` (1:N).
#[derive(Clone)]
struct GalleryCandidate {
    print_addr: usize,
    syn_subtype: u16,
}

/// `FpDeviceClass.verify` (`+0xd8`) and `FpDeviceClass.identify` (`+0xe0`): perform on-chip
/// QMatcher identification and match the resulting finger subtype against `fprintd`'s candidate list.
extern "C" fn dev_verify(device: *mut c_void) {
    let action = unsafe { fpi_device_get_current_action(device) };
    let mut candidates = Vec::new();

    if action == FPI_DEVICE_ACTION_IDENTIFY {
        let mut prints_arr: *mut GPtrArray = ptr::null_mut();
        unsafe {
            fpi_device_get_identify_data(device, &mut prints_arr);
            if !prints_arr.is_null() {
                let len = (*prints_arr).len as usize;
                let pdata = (*prints_arr).pdata;
                if !pdata.is_null() {
                    for i in 0..len {
                        let prt = *pdata.add(i);
                        if !prt.is_null() {
                            if let Some((_, _, _, syn_sub, _)) = extract_synaptics_fpi_data(prt) {
                                candidates.push(GalleryCandidate {
                                    print_addr: prt as usize,
                                    syn_subtype: syn_sub,
                                });
                            } else {
                                let fp_f = fp_print_get_finger(prt);
                                candidates.push(GalleryCandidate {
                                    print_addr: prt as usize,
                                    syn_subtype: fp_finger_to_synaptics_subtype(fp_f),
                                });
                            }
                        }
                    }
                }
            }
        }
    } else if action == FPI_DEVICE_ACTION_VERIFY {
        let mut prt: *mut c_void = ptr::null_mut();
        unsafe {
            fpi_device_get_verify_data(device, &mut prt);
            if !prt.is_null() {
                if let Some((_, _, _, syn_sub, _)) = extract_synaptics_fpi_data(prt) {
                    candidates.push(GalleryCandidate {
                        print_addr: prt as usize,
                        syn_subtype: syn_sub,
                    });
                } else {
                    let fp_f = fp_print_get_finger(prt);
                    candidates.push(GalleryCandidate {
                        print_addr: prt as usize,
                        syn_subtype: fp_finger_to_synaptics_subtype(fp_f),
                    });
                }
            }
        }
    }

    let action_name = if action == FPI_DEVICE_ACTION_IDENTIFY {
        "IDENTIFY"
    } else {
        "VERIFY"
    };
    drv_info!(
        "Starting {action_name} (fprintd gallery={} candidate(s)) — waiting for finger touch...",
        candidates.len()
    );

    let dev_addr = device as usize;

    std::thread::spawn(move || {
        let calib_data = load_calibration_blob();
        let res = with_sensor_session(|session| {
            let m = session.identify_finger_009a_with_retry(&calib_data, |_err| {})?;
            if m.matched {
                let found = candidates
                    .iter()
                    .find(|c| c.syn_subtype == m.matched_finger_id)
                    .cloned();
                if found.is_some() {
                    drv_info!(
                        "{action_name} MATCH SUCCESS: user_dbid=0x{:04x}, subtype={} ({})",
                        m.matched_user_id,
                        m.matched_finger_id,
                        finger_subtype_name(m.matched_finger_id)
                    );
                } else {
                    drv_info!(
                        "{action_name}: on-chip matched subtype={} ({}) is not in fprintd candidate list -> reporting NO MATCH",
                        m.matched_finger_id,
                        finger_subtype_name(m.matched_finger_id)
                    );
                }
                Ok(found)
            } else {
                drv_info!("{action_name} NO MATCH: finger did not match any enrolled template");
                Ok(None)
            }
        });

        run_on_glib_main_loop(move || unsafe {
            let dev_ptr = dev_addr as *mut c_void;
            let cur_action = fpi_device_get_current_action(dev_ptr);
            match res {
                Ok(Some(matched_cand)) => {
                    if cur_action == FPI_DEVICE_ACTION_IDENTIFY {
                        let ref_prt = g_object_ref(matched_cand.print_addr as *mut c_void);
                        fpi_device_identify_report(
                            dev_ptr,
                            ref_prt,
                            ptr::null_mut(),
                            ptr::null_mut(),
                        );
                        fpi_device_identify_complete(dev_ptr, ptr::null_mut());
                    } else if cur_action == FPI_DEVICE_ACTION_VERIFY {
                        fpi_device_verify_report(
                            dev_ptr,
                            FPI_MATCH_SUCCESS,
                            ptr::null_mut(),
                            ptr::null_mut(),
                        );
                        fpi_device_verify_complete(dev_ptr, ptr::null_mut());
                    }
                }
                Ok(None) => {
                    if cur_action == FPI_DEVICE_ACTION_IDENTIFY {
                        fpi_device_identify_report(
                            dev_ptr,
                            ptr::null_mut(),
                            ptr::null_mut(),
                            ptr::null_mut(),
                        );
                        fpi_device_identify_complete(dev_ptr, ptr::null_mut());
                    } else if cur_action == FPI_DEVICE_ACTION_VERIFY {
                        fpi_device_verify_report(
                            dev_ptr,
                            FPI_MATCH_FAIL,
                            ptr::null_mut(),
                            ptr::null_mut(),
                        );
                        fpi_device_verify_complete(dev_ptr, ptr::null_mut());
                    }
                }
                Err(e) => {
                    let code = e.fp_device_error_code();
                    drv_error!("{action_name} FAILED: {e} (fp_device_error={code})");
                    let err = fpi_device_error_new(code);
                    if cur_action == FPI_DEVICE_ACTION_IDENTIFY {
                        fpi_device_identify_complete(dev_ptr, err);
                    } else if cur_action == FPI_DEVICE_ACTION_VERIFY {
                        fpi_device_verify_complete(dev_ptr, err);
                    }
                }
            }
        });
    });
}

/// `FpDeviceClass.delete` (`+0xf8`): delete a specific enrolled template record from the sensor's
/// DB2 flash database (`0x48`).
extern "C" fn dev_delete(device: *mut c_void) {
    let mut print: *mut c_void = ptr::null_mut();
    unsafe {
        fpi_device_get_delete_data(device, &mut print);
    }

    let extracted = unsafe { extract_synaptics_fpi_data(print) };
    let fallback_info = if extracted.is_none() && !print.is_null() {
        unsafe {
            let uname_ptr = fp_print_get_username(print);
            let uname = if uname_ptr.is_null() {
                String::new()
            } else {
                CStr::from_ptr(uname_ptr).to_string_lossy().into_owned()
            };
            let fp_f = fp_print_get_finger(print);
            Some((
                uid_from_username(&uname),
                fp_finger_to_synaptics_subtype(fp_f),
            ))
        }
    } else {
        None
    };

    let dev_addr = device as usize;
    std::thread::spawn(move || {
        let res = with_sensor_session(|session| {
            if let Some((uid, _user_dbid, template_dbid, syn_sub, _)) = extracted {
                drv_info!(
                    "Deleting enrolled template dbid=0x{template_dbid:04x}, subtype={syn_sub} ({}) for UID {uid}",
                    finger_subtype_name(syn_sub)
                );
                session.db2_delete_object(template_dbid)?;
                let target_sid = format!("S-1-5-21-111111111-1111111111-1111111111-{uid}");
                if let Ok(stg) = session.db2_get_user_storage(0, "StgWindsor") {
                    for (u_dbid, _) in &stg.users {
                        if let Ok(usr) = session.db2_get_user(*u_dbid) {
                            if usr.sid_string.as_deref() == Some(target_sid.as_str()) {
                                for f in usr.fingers.iter().filter(|f| f.subtype == syn_sub) {
                                    session.db2_delete_object(f.dbid)?;
                                }
                            }
                        }
                    }
                }
            } else if let Some((uid, syn_sub)) = fallback_info {
                drv_info!(
                    "Deleting enrolled finger subtype={syn_sub} ({}) for UID {uid}",
                    finger_subtype_name(syn_sub)
                );
                let target_sid = format!("S-1-5-21-111111111-1111111111-1111111111-{uid}");
                let stg = session.db2_get_user_storage(0, "StgWindsor")?;
                for (u_dbid, _) in &stg.users {
                    if let Ok(usr) = session.db2_get_user(*u_dbid) {
                        if usr.sid_string.as_deref() == Some(target_sid.as_str()) {
                            for f in usr.fingers.iter().filter(|f| f.subtype == syn_sub) {
                                session.db2_delete_object(f.dbid)?;
                            }
                        }
                    }
                }
            }
            Ok(())
        });

        run_on_glib_main_loop(move || unsafe {
            match res {
                Ok(()) => {
                    fpi_device_delete_complete(dev_addr as *mut c_void, ptr::null_mut());
                }
                Err(e) => {
                    let code = e.fp_device_error_code();
                    drv_error!("DELETE FAILED: {e} (fp_device_error={code})");
                    let err = fpi_device_error_new(code);
                    fpi_device_delete_complete(dev_addr as *mut c_void, err);
                }
            }
        });
    });
}

/// `FpDeviceClass.clear_storage` (`+0x118`): delete all user and template records inside `StgWindsor`.
extern "C" fn dev_clear_storage(device: *mut c_void) {
    drv_info!("Clearing all enrolled user records in StgWindsor");
    let dev_addr = device as usize;
    std::thread::spawn(move || {
        let res = with_sensor_session(|session| {
            let stg = session.db2_get_user_storage(0, "StgWindsor")?;
            for (u_dbid, _) in &stg.users {
                session.db2_delete_object(*u_dbid)?;
            }
            Ok(())
        });

        run_on_glib_main_loop(move || unsafe {
            match res {
                Ok(()) => {
                    fpi_device_clear_storage_complete(dev_addr as *mut c_void, ptr::null_mut());
                }
                Err(e) => {
                    let code = e.fp_device_error_code();
                    drv_error!("CLEAR STORAGE FAILED: {e} (fp_device_error={code})");
                    let err = fpi_device_error_new(code);
                    fpi_device_clear_storage_complete(dev_addr as *mut c_void, err);
                }
            }
        });
    });
}

extern "C" fn fpi_device_synaptics_009a_tod_init(_instance: *mut c_void, _g_class: *mut c_void) {}

/// Populate the `FpDeviceClass` virtual method table (`0x208` bytes on x86_64).
///
/// Field offsets verified against `libfprint-2-tod1-elan.so` (`fpi_device_efd_tod_class_intern_init` @ `0x8460`)
/// and `libfprint-2-tod.so.1` (`fpi_device_class_auto_initialize_features` @ `0xef30`):
/// - `0x88`: `id` (`*const c_char`)
/// - `0x90`: `full_name` (`*const c_char`)
/// - `0x98`: `type` (`FpDeviceType` = `1` `FP_DEVICE_TYPE_USB`)
/// - `0xa0`: `id_table` (`*const FpIdEntry`)
/// - `0xa8`: `nr_enroll_stages` (`c_int` = `12`)
/// - `0xac`: `scan_type` (`FpScanType` = `1` `FP_SCAN_TYPE_PRESS`)
/// - `0xb0`: `usb_discover`
/// - `0xb8`: `probe`
/// - `0xc0`: `open`
/// - `0xc8`: `close`
/// - `0xd0`: `enroll`
/// - `0xd8`: `verify`
/// - `0xe0`: `identify`
/// - `0xf8`: `delete`
/// - `0x100`: `cancel`
/// - `0x10c`: `temp_hot_seconds` (`-1` = disable thermal throttling)
/// - `0x118`: `clear_storage`
/// - `0x120`: `suspend`
/// - `0x128`: `resume`
extern "C" fn fpi_device_synaptics_009a_tod_class_init(
    klass: *mut c_void,
    _class_data: *mut c_void,
) {
    unsafe {
        let _ = g_type_class_peek_parent(klass);
        let fp_dev_type = fp_device_get_type();
        let dev_class = g_type_check_class_cast(klass, fp_dev_type) as *mut u8;

        *(dev_class.add(0x88) as *mut *const c_char) = TOD_DRIVER_ID.as_ptr();
        *(dev_class.add(0x90) as *mut *const c_char) = TOD_FULL_NAME.as_ptr();
        *(dev_class.add(0x98) as *mut u32) = 1; // FP_DEVICE_TYPE_USB = 1
        *(dev_class.add(0xa0) as *mut *const FpIdEntry) = ID_TABLE.as_ptr();
        *(dev_class.add(0xa8) as *mut c_int) = TOD_NR_ENROLL_STAGES;
        *(dev_class.add(0xac) as *mut u32) = 1; // FP_SCAN_TYPE_PRESS = 1

        *(dev_class.add(0xb0) as *mut extern "C" fn(*mut c_void) -> c_int) = dev_usb_discover;
        *(dev_class.add(0xb8) as *mut extern "C" fn(*mut c_void)) = dev_probe;
        *(dev_class.add(0xc0) as *mut extern "C" fn(*mut c_void)) = dev_init;
        *(dev_class.add(0xc8) as *mut extern "C" fn(*mut c_void)) = dev_exit;
        *(dev_class.add(0xd0) as *mut extern "C" fn(*mut c_void)) = dev_enroll;
        *(dev_class.add(0xd8) as *mut extern "C" fn(*mut c_void)) = dev_verify;
        *(dev_class.add(0xe0) as *mut extern "C" fn(*mut c_void)) = dev_verify;
        *(dev_class.add(0xf8) as *mut extern "C" fn(*mut c_void)) = dev_delete;
        *(dev_class.add(0x100) as *mut extern "C" fn(*mut c_void)) = dev_cancel;
        *(dev_class.add(0x10c) as *mut c_int) = -1; // temp_hot_seconds = -1
        *(dev_class.add(0x118) as *mut extern "C" fn(*mut c_void)) = dev_clear_storage;
        *(dev_class.add(0x120) as *mut extern "C" fn(*mut c_void)) = dev_suspend;
        *(dev_class.add(0x128) as *mut extern "C" fn(*mut c_void)) = dev_resume;
    }
}

static REGISTERED_GTYPE: OnceLock<GType> = OnceLock::new();

/// Entry point symbol looked up by `/usr/lib/x86_64-linux-gnu/libfprint-2-tod.so.1`
/// (`tod-shared-loader.c`: `fpi_tod_shared_driver_get_type`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fpi_tod_shared_driver_get_type() -> GType {
    *REGISTERED_GTYPE.get_or_init(|| unsafe {
        drv_info!(
            "Registering libfprint-2-tod1 driver GType (FpiDeviceSynaptics009aTod, 06cb:009a)"
        );
        let name = g_intern_static_string(TOD_TYPE_NAME.as_ptr());
        let parent = fp_device_get_type();
        g_type_register_static_simple(
            parent,
            name,
            0x208,
            fpi_device_synaptics_009a_tod_class_init,
            0x38,
            fpi_device_synaptics_009a_tod_init,
            0,
        )
    })
}
