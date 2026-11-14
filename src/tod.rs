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
//!    of `FpDevice` and populates the [`FpDeviceClass`] virtual method table in
//!    `fpi_device_synaptics_009a_tod_class_init`.
//! 4. All blocking USB/TLS/biometric operations (`open`, `enroll`, `verify`, `identify`, `delete`,
//!    `clear_storage`) execute on dedicated worker threads and marshal completion callbacks back
//!    onto the GLib main loop via `run_on_glib_main_loop` (`g_idle_add`), keeping `fprintd`'s
//!    D-Bus event loop responsive at all times.

use std::ffi::{CStr, c_char, c_int, c_uint, c_void};
use std::mem::{offset_of, size_of};
use std::path::PathBuf;
use std::ptr;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};

use crate::error::{DriverError, Result};
use crate::moc::{STG_WINDSOR_NAME, finger_subtype_name};
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

/// `FpDeviceType` enum value for USB fingerprint readers (`1` on Debian/Ubuntu TOD-1, `2` on Fedora libfprint >= 1.94.100).
#[cfg(not(fedora_libfprint))]
const FP_DEVICE_TYPE_USB: u32 = 1;
#[cfg(fedora_libfprint)]
const FP_DEVICE_TYPE_USB: u32 = 2;

/// `FpScanType` enum value for press-type capacitive touch sensors (`FP_SCAN_TYPE_PRESS = 1`).
const FP_SCAN_TYPE_PRESS: u32 = 1;

/// `FpiDeviceAction` values (`fpi_device_action_get_type`).
const FPI_DEVICE_ACTION_VERIFY: c_int = 5;
const FPI_DEVICE_ACTION_IDENTIFY: c_int = 6;

/// `FpiMatchResult` values (`fpi_match_result_get_type`).
const FPI_MATCH_FAIL: c_int = 0;
const FPI_MATCH_SUCCESS: c_int = 1;

/// `FpIdEntry` USB table entry (`16` bytes on Debian/Ubuntu TOD-1, `32` bytes on Fedora libfprint >= 1.94.100).
#[cfg(not(fedora_libfprint))]
#[repr(C)]
pub struct FpIdEntry {
    pub pid: u32,
    pub vid: u32,
    pub driver_data: u64,
}

#[cfg(fedora_libfprint)]
#[repr(C)]
pub struct FpIdEntry {
    pub pid: u32,
    pub vid: u32,
    pub driver_data: u64,
    pub _pad: [u64; 2],
}

unsafe impl Sync for FpIdEntry {}

/// Null-terminated USB device ID table matching `06cb:009a`.
#[cfg(not(fedora_libfprint))]
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

#[cfg(fedora_libfprint)]
static ID_TABLE: [FpIdEntry; 2] = [
    FpIdEntry {
        pid: 0x009a,
        vid: 0x06cb,
        driver_data: 0,
        _pad: [0; 2],
    },
    FpIdEntry {
        pid: 0,
        vid: 0,
        driver_data: 0,
        _pad: [0; 2],
    },
];

/// GLib `GPtrArray` C layout used by `fpi_device_get_identify_data`.
#[repr(C)]
pub struct GPtrArray {
    pub pdata: *mut *mut c_void,
    pub len: c_uint,
}

/// Strongly typed `FpDeviceClass` C vtable layout (`0x208` bytes on x86_64) matching
/// Debian/Ubuntu `libfprint-2-tod.so.1` (`fpi-device.h`).
#[cfg(not(fedora_libfprint))]
#[repr(C)]
pub struct FpDeviceClass {
    pub parent_class: [u8; 0x88],
    pub id: *const c_char,
    pub full_name: *const c_char,
    pub device_type: u32,
    pub features: u32,
    pub id_table: *const FpIdEntry,
    pub nr_enroll_stages: c_int,
    pub scan_type: u32,
    pub usb_discover: Option<extern "C" fn(*mut c_void) -> c_int>,
    pub probe: Option<extern "C" fn(*mut c_void)>,
    pub open: Option<extern "C" fn(*mut c_void)>,
    pub close: Option<extern "C" fn(*mut c_void)>,
    pub enroll: Option<extern "C" fn(*mut c_void)>,
    pub verify: Option<extern "C" fn(*mut c_void)>,
    pub identify: Option<extern "C" fn(*mut c_void)>,
    pub capture: Option<extern "C" fn(*mut c_void)>,
    pub list: Option<extern "C" fn(*mut c_void)>,
    pub delete: Option<extern "C" fn(*mut c_void)>,
    pub cancel: Option<extern "C" fn(*mut c_void)>,
    pub temp_warm_seconds: c_int,
    pub temp_hot_seconds: c_int,
    pub temp_cold_seconds: c_int,
    pub _pad_114: c_int,
    pub clear_storage: Option<extern "C" fn(*mut c_void)>,
    pub suspend: Option<extern "C" fn(*mut c_void)>,
    pub resume: Option<extern "C" fn(*mut c_void)>,
    pub _reserved: [u8; 0xd8],
}

#[cfg(not(fedora_libfprint))]
const _: () = {
    assert!(size_of::<FpDeviceClass>() == 0x208);
    assert!(offset_of!(FpDeviceClass, id) == 0x88);
    assert!(offset_of!(FpDeviceClass, full_name) == 0x90);
    assert!(offset_of!(FpDeviceClass, device_type) == 0x98);
    assert!(offset_of!(FpDeviceClass, features) == 0x9c);
    assert!(offset_of!(FpDeviceClass, id_table) == 0xa0);
    assert!(offset_of!(FpDeviceClass, nr_enroll_stages) == 0xa8);
    assert!(offset_of!(FpDeviceClass, scan_type) == 0xac);
    assert!(offset_of!(FpDeviceClass, usb_discover) == 0xb0);
    assert!(offset_of!(FpDeviceClass, probe) == 0xb8);
    assert!(offset_of!(FpDeviceClass, open) == 0xc0);
    assert!(offset_of!(FpDeviceClass, close) == 0xc8);
    assert!(offset_of!(FpDeviceClass, enroll) == 0xd0);
    assert!(offset_of!(FpDeviceClass, verify) == 0xd8);
    assert!(offset_of!(FpDeviceClass, identify) == 0xe0);
    assert!(offset_of!(FpDeviceClass, delete) == 0xf8);
    assert!(offset_of!(FpDeviceClass, cancel) == 0x100);
    assert!(offset_of!(FpDeviceClass, temp_warm_seconds) == 0x108);
    assert!(offset_of!(FpDeviceClass, clear_storage) == 0x118);
    assert!(offset_of!(FpDeviceClass, suspend) == 0x120);
    assert!(offset_of!(FpDeviceClass, resume) == 0x128);
};

/// Strongly typed `FpDeviceClass` C vtable layout (`0x130` bytes on x86_64) matching
/// Fedora `libfprint-2.so.2.0.0` (`libfprint-1.94.100`).
#[cfg(fedora_libfprint)]
#[repr(C)]
pub struct FpDeviceClass {
    pub parent_class: [u8; 0x88],
    pub id: *const c_char,
    pub full_name: *const c_char,
    pub device_type: u32,
    pub _pad_9c: u32,
    pub id_table: *const FpIdEntry,
    pub features: u32,
    pub nr_enroll_stages: c_int,
    pub scan_type: u32,
    pub temp_hot_seconds: c_int,
    pub temp_cold_seconds: c_int,
    pub _pad_bc: c_int,
    pub usb_discover: Option<extern "C" fn(*mut c_void) -> c_int>,
    pub probe: Option<extern "C" fn(*mut c_void)>,
    pub open: Option<extern "C" fn(*mut c_void)>,
    pub close: Option<extern "C" fn(*mut c_void)>,
    pub enroll: Option<extern "C" fn(*mut c_void)>,
    pub verify: Option<extern "C" fn(*mut c_void)>,
    pub identify: Option<extern "C" fn(*mut c_void)>,
    pub capture: Option<extern "C" fn(*mut c_void)>,
    pub list: Option<extern "C" fn(*mut c_void)>,
    pub delete: Option<extern "C" fn(*mut c_void)>,
    pub clear_storage: Option<extern "C" fn(*mut c_void)>,
    pub cancel: Option<extern "C" fn(*mut c_void)>,
    pub suspend: Option<extern "C" fn(*mut c_void)>,
    pub resume: Option<extern "C" fn(*mut c_void)>,
}

#[cfg(fedora_libfprint)]
const _: () = {
    assert!(size_of::<FpIdEntry>() == 0x20);
    assert!(size_of::<FpDeviceClass>() == 0x130);
    assert!(offset_of!(FpDeviceClass, id) == 0x88);
    assert!(offset_of!(FpDeviceClass, full_name) == 0x90);
    assert!(offset_of!(FpDeviceClass, device_type) == 0x98);
    assert!(offset_of!(FpDeviceClass, id_table) == 0xa0);
    assert!(offset_of!(FpDeviceClass, features) == 0xa8);
    assert!(offset_of!(FpDeviceClass, nr_enroll_stages) == 0xac);
    assert!(offset_of!(FpDeviceClass, scan_type) == 0xb0);
    assert!(offset_of!(FpDeviceClass, temp_hot_seconds) == 0xb4);
    assert!(offset_of!(FpDeviceClass, usb_discover) == 0xc0);
    assert!(offset_of!(FpDeviceClass, probe) == 0xc8);
    assert!(offset_of!(FpDeviceClass, open) == 0xd0);
    assert!(offset_of!(FpDeviceClass, close) == 0xd8);
    assert!(offset_of!(FpDeviceClass, enroll) == 0xe0);
    assert!(offset_of!(FpDeviceClass, verify) == 0xe8);
    assert!(offset_of!(FpDeviceClass, identify) == 0xf0);
    assert!(offset_of!(FpDeviceClass, delete) == 0x108);
    assert!(offset_of!(FpDeviceClass, clear_storage) == 0x110);
    assert!(offset_of!(FpDeviceClass, cancel) == 0x118);
    assert!(offset_of!(FpDeviceClass, suspend) == 0x120);
    assert!(offset_of!(FpDeviceClass, resume) == 0x128);
};

/// Hardware DB2 template metadata stored inside an `FpPrint`'s 16-byte `"fpi-data"` GVariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynapticsPrintMetadata {
    pub uid: u32,
    pub user_dbid: u16,
    pub template_dbid: u16,
    pub synaptics_subtype: u16,
    pub fp_finger: u16,
}

impl SynapticsPrintMetadata {
    const MAGIC: &'static [u8; 4] = b"SYN9";

    /// Encode into the 16-byte `"SYN9"` binary header stored in `fprintd`'s host print file.
    ///
    /// # Arguments
    /// * `self` - [`SynapticsPrintMetadata`] value to serialize.
    pub fn to_bytes(self) -> [u8; 16] {
        let mut payload = [0u8; 16];
        payload[0..4].copy_from_slice(Self::MAGIC);
        payload[4..8].copy_from_slice(&self.uid.to_le_bytes());
        payload[8..10].copy_from_slice(&self.user_dbid.to_le_bytes());
        payload[10..12].copy_from_slice(&self.template_dbid.to_le_bytes());
        payload[12..14].copy_from_slice(&self.synaptics_subtype.to_le_bytes());
        payload[14..16].copy_from_slice(&self.fp_finger.to_le_bytes());
        payload
    }

    /// Decode from a `"fpi-data"` GVariant byte slice if it starts with `"SYN9"`.
    ///
    /// # Arguments
    /// * `slice` - Raw byte slice extracted from the `FpPrint`'s `"fpi-data"` property.
    pub fn from_bytes(slice: &[u8]) -> Option<Self> {
        if slice.len() < 16 || &slice[0..4] != Self::MAGIC {
            return None;
        }
        Some(Self {
            uid: u32::from_le_bytes([slice[4], slice[5], slice[6], slice[7]]),
            user_dbid: u16::from_le_bytes([slice[8], slice[9]]),
            template_dbid: u16::from_le_bytes([slice[10], slice[11]]),
            synaptics_subtype: u16::from_le_bytes([slice[12], slice[13]]),
            fp_finger: u16::from_le_bytes([slice[14], slice[15]]),
        })
    }
}

unsafe extern "C" {
    fn atexit(cb: extern "C" fn()) -> c_int;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;

    // GLib / GObject FFI
    fn g_intern_static_string(string: *const c_char) -> *const c_char;
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

    // Public exported symbols in libfprint-2.so.2
    fn fp_device_get_type() -> GType;
    fn fp_print_get_finger(print: *mut c_void) -> c_uint;
    fn fp_print_get_username(print: *mut c_void) -> *const c_char;
}

#[cfg(not(fedora_libfprint))]
unsafe extern "C" {
    fn g_type_register_static_simple(
        parent_type: GType,
        type_name: *const c_char,
        class_size: c_uint,
        class_init: extern "C" fn(*mut c_void, *mut c_void),
        instance_size: c_uint,
        instance_init: extern "C" fn(*mut c_void, *mut c_void),
        flags: c_uint,
    ) -> GType;

    // libfprint-2-tod.so.1 exported internal driver API
    fn fpi_device_class_auto_initialize_features(device_class: *mut c_void);
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

#[cfg(not(fedora_libfprint))]
unsafe fn real_g_type_register_static_simple(
    parent_type: GType,
    type_name: *const c_char,
    class_size: c_uint,
    class_init: extern "C" fn(*mut c_void, *mut c_void),
    instance_size: c_uint,
    instance_init: extern "C" fn(*mut c_void, *mut c_void),
    flags: c_uint,
) -> GType {
    unsafe {
        g_type_register_static_simple(
            parent_type,
            type_name,
            class_size,
            class_init,
            instance_size,
            instance_init,
            flags,
        )
    }
}

#[cfg(fedora_libfprint)]
const RTLD_DEFAULT: *mut c_void = ptr::null_mut();
#[cfg(fedora_libfprint)]
const RTLD_NEXT: *mut c_void = (-1isize) as *mut c_void;

#[cfg(fedora_libfprint)]
static LIBFPRINT_BASE: OnceLock<usize> = OnceLock::new();

/// Compute the runtime load base address of `/usr/lib64/libfprint-2.so.2.0.0` from `fp_device_get_type` (`+0x4f300`).
#[cfg(fedora_libfprint)]
fn libfprint_base() -> usize {
    *LIBFPRINT_BASE.get_or_init(|| unsafe {
        let sym = dlsym(RTLD_DEFAULT, c"fp_device_get_type".as_ptr());
        assert!(!sym.is_null(), "dlsym(fp_device_get_type) returned NULL");
        (sym as usize) - 0x4f300
    })
}

#[cfg(fedora_libfprint)]
unsafe fn real_g_type_register_static_simple(
    parent_type: GType,
    type_name: *const c_char,
    class_size: c_uint,
    class_init: extern "C" fn(*mut c_void, *mut c_void),
    instance_size: c_uint,
    instance_init: extern "C" fn(*mut c_void, *mut c_void),
    flags: c_uint,
) -> GType {
    static REAL_FN: OnceLock<usize> = OnceLock::new();
    let addr = *REAL_FN.get_or_init(|| unsafe {
        let mut p = dlsym(RTLD_NEXT, c"g_type_register_static_simple".as_ptr());
        if p.is_null() {
            p = dlsym(RTLD_DEFAULT, c"g_type_register_static_simple".as_ptr());
        }
        assert!(!p.is_null(), "dlsym(g_type_register_static_simple) failed");
        p as usize
    });
    let f: unsafe extern "C" fn(
        GType,
        *const c_char,
        c_uint,
        extern "C" fn(*mut c_void, *mut c_void),
        c_uint,
        extern "C" fn(*mut c_void, *mut c_void),
        c_uint,
    ) -> GType = unsafe { std::mem::transmute(addr) };
    unsafe {
        f(
            parent_type,
            type_name,
            class_size,
            class_init,
            instance_size,
            instance_init,
            flags,
        )
    }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_device_class_auto_initialize_features(device_class: *mut c_void) {
    let f: unsafe extern "C" fn(*mut c_void) =
        unsafe { std::mem::transmute(libfprint_base() + 0xa8b10) };
    unsafe { f(device_class) }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_print_set_type(print: *mut c_void, print_type: c_uint) {
    let f: unsafe extern "C" fn(*mut c_void, c_uint) =
        unsafe { std::mem::transmute(libfprint_base() + 0xab550) };
    unsafe { f(print, print_type) }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_device_set_nr_enroll_stages(device: *mut c_void, enroll_stages: c_int) {
    let f: unsafe extern "C" fn(*mut c_void, c_int) =
        unsafe { std::mem::transmute(libfprint_base() + 0xa8c10) };
    unsafe { f(device, enroll_stages) }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_device_probe_complete(
    device: *mut c_void,
    device_id: *const c_char,
    device_name: *const c_char,
    error: *mut c_void,
) {
    let f: unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char, *mut c_void) =
        unsafe { std::mem::transmute(libfprint_base() + 0xab7f0) };
    unsafe { f(device, device_id, device_name, error) }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_device_open_complete(device: *mut c_void, error: *mut c_void) {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void) =
        unsafe { std::mem::transmute(libfprint_base() + 0xab9d0) };
    unsafe { f(device, error) }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_device_close_complete(device: *mut c_void, error: *mut c_void) {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void) =
        unsafe { std::mem::transmute(libfprint_base() + 0xabb10) };
    unsafe { f(device, error) }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_device_get_current_action(device: *mut c_void) -> c_int {
    let f: unsafe extern "C" fn(*mut c_void) -> c_int =
        unsafe { std::mem::transmute(libfprint_base() + 0xa9640) };
    unsafe { f(device) }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_device_get_enroll_data(device: *mut c_void, print: *mut *mut c_void) {
    let f: unsafe extern "C" fn(*mut c_void, *mut *mut c_void) =
        unsafe { std::mem::transmute(libfprint_base() + 0xa9820) };
    unsafe { f(device, print) }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_device_enroll_progress(
    device: *mut c_void,
    completed_stages: c_int,
    print: *mut c_void,
    error: *mut c_void,
) {
    let f: unsafe extern "C" fn(*mut c_void, c_int, *mut c_void, *mut c_void) =
        unsafe { std::mem::transmute(libfprint_base() + 0xaaa70) };
    unsafe { f(device, completed_stages, print, error) }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_device_enroll_complete(device: *mut c_void, print: *mut c_void, error: *mut c_void) {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) =
        unsafe { std::mem::transmute(libfprint_base() + 0xabd20) };
    unsafe { f(device, print, error) }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_device_get_verify_data(device: *mut c_void, print: *mut *mut c_void) {
    let f: unsafe extern "C" fn(*mut c_void, *mut *mut c_void) =
        unsafe { std::mem::transmute(libfprint_base() + 0xa9900) };
    unsafe { f(device, print) }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_device_verify_report(
    device: *mut c_void,
    result: c_int,
    print: *mut c_void,
    error: *mut c_void,
) {
    let f: unsafe extern "C" fn(*mut c_void, c_int, *mut c_void, *mut c_void) =
        unsafe { std::mem::transmute(libfprint_base() + 0xaae50) };
    unsafe { f(device, result, print, error) }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_device_verify_complete(device: *mut c_void, error: *mut c_void) {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void) =
        unsafe { std::mem::transmute(libfprint_base() + 0xac080) };
    unsafe { f(device, error) }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_device_get_identify_data(device: *mut c_void, prints: *mut *mut GPtrArray) {
    let f: unsafe extern "C" fn(*mut c_void, *mut *mut GPtrArray) =
        unsafe { std::mem::transmute(libfprint_base() + 0xa99e0) };
    unsafe { f(device, prints) }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_device_identify_report(
    device: *mut c_void,
    match_print: *mut c_void,
    print: *mut c_void,
    error: *mut c_void,
) {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) =
        unsafe { std::mem::transmute(libfprint_base() + 0xab200) };
    unsafe { f(device, match_print, print, error) }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_device_identify_complete(device: *mut c_void, error: *mut c_void) {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void) =
        unsafe { std::mem::transmute(libfprint_base() + 0xac2c0) };
    unsafe { f(device, error) }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_device_get_delete_data(device: *mut c_void, print: *mut *mut c_void) {
    let f: unsafe extern "C" fn(*mut c_void, *mut *mut c_void) =
        unsafe { std::mem::transmute(libfprint_base() + 0xa9ac0) };
    unsafe { f(device, print) }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_device_delete_complete(device: *mut c_void, error: *mut c_void) {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void) =
        unsafe { std::mem::transmute(libfprint_base() + 0xac6c0) };
    unsafe { f(device, error) }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_device_clear_storage_complete(device: *mut c_void, error: *mut c_void) {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void) =
        unsafe { std::mem::transmute(libfprint_base() + 0xac9b0) };
    unsafe { f(device, error) }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_device_suspend_complete(device: *mut c_void, error: *mut c_void) {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void) =
        unsafe { std::mem::transmute(libfprint_base() + 0xaa470) };
    unsafe { f(device, error) }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_device_resume_complete(device: *mut c_void, error: *mut c_void) {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_void) =
        unsafe { std::mem::transmute(libfprint_base() + 0xaa730) };
    unsafe { f(device, error) }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_device_retry_new(retry_code: c_int) -> *mut c_void {
    let f: unsafe extern "C" fn(c_int) -> *mut c_void =
        unsafe { std::mem::transmute(libfprint_base() + 0xa8990) };
    unsafe { f(retry_code) }
}

#[cfg(fedora_libfprint)]
unsafe fn fpi_device_error_new(error_code: c_int) -> *mut c_void {
    let f: unsafe extern "C" fn(c_int) -> *mut c_void =
        unsafe { std::mem::transmute(libfprint_base() + 0xa8390) };
    unsafe { f(error_code) }
}

/// Convert `libfprint-2`'s `FpFinger` enum (`1..=10`) to Synaptics WINBIO subtype (`1..=10`).
///
/// - In `libfprint-2`: `1..=5` = `left-thumb` .. `left-little`, `6..=10` = `right-thumb` .. `right-little`.
/// - In Synaptics DB2 (`WINBIO`): `1..=5` = `right-thumb` .. `right-little`, `6..=10` = `left-thumb` .. `left-little`.
///
/// # Arguments
/// * `fp_finger` - `FpFinger` enum value (`1..=10`) from `libfprint-2`.
pub const fn fp_finger_to_synaptics_subtype(fp_finger: u32) -> u16 {
    match fp_finger {
        1..=5 => (fp_finger + 5) as u16,
        6..=10 => (fp_finger - 5) as u16,
        _ => 2,
    }
}

/// Resolve a Linux username (e.g. `"alice"`) to its numeric UID via `/etc/passwd` (defaulting to `1000`).
///
/// # Arguments
/// * `username` - Account username string from `FpPrint`.
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
            if name == username
                && let Ok(uid) = uid_str.parse::<u32>()
            {
                return uid;
            }
        }
    }
    1000
}

static CALIB_MEM_CACHE: OnceLock<Mutex<Option<Vec<u8>>>> = OnceLock::new();

fn calib_mem_cache() -> &'static Mutex<Option<Vec<u8>>> {
    CALIB_MEM_CACHE.get_or_init(|| Mutex::new(None))
}

/// Load the 13,440-byte sensor calibration blob (`calib_06cb_009a.bin`), falling back to the embedded calibration data.
///
/// # Arguments
/// *(none)*
pub fn load_calibration_blob() -> Vec<u8> {
    if let Ok(guard) = calib_mem_cache().lock()
        && let Some(ref cached) = *guard
    {
        return cached.clone();
    }
    for candidate in [
        "/var/lib/fprint/.synaptics_06cb_009a_calib.bin",
        "/var/run/python-validity/calib-data.bin",
        "calib_06cb_009a.bin",
    ] {
        if let Ok(bytes) = std::fs::read(candidate)
            && bytes.len() >= 13440
        {
            return bytes;
        }
    }
    EMBEDDED_CALIB_009A.to_vec()
}

/// Ensure this specific physical `06cb:009a` sensor has its own 13,440-byte 2D calibration table
/// on disk (`/var/lib/fprint/.synaptics_06cb_009a_calib.bin`) AND a matching `0x5002` clean-slate
/// baseline image in Flash Partition 6.
pub fn ensure_sensor_calibrated(
    session: &mut SensorSession<SynapticsUsbTransport>,
) -> Result<Vec<u8>> {
    const CALIB_CACHE_PATH: &str = "/var/lib/fprint/.synaptics_06cb_009a_calib.bin";
    if let Ok(bytes) = std::fs::read(CALIB_CACHE_PATH)
        && bytes.len() >= 13440
        && session.check_clean_slate().unwrap_or(false)
    {
        if let Ok(mut guard) = calib_mem_cache().lock() {
            *guard = Some(bytes.clone());
        }
        return Ok(bytes);
    }

    drv_info!(
        "Sensor calibration missing or Flash Partition 6 clean-slate invalid — running 2D calibration now..."
    );
    let calib_data = session.calibrate_sensor()?;
    if let Err(e) = std::fs::write(CALIB_CACHE_PATH, &calib_data) {
        drv_warn!("Could not write calibration file to {CALIB_CACHE_PATH}: {e}");
    } else {
        drv_info!("Saved sensor-specific 2D calibration table to {CALIB_CACHE_PATH}");
    }
    if let Ok(mut guard) = calib_mem_cache().lock() {
        *guard = Some(calib_data.clone());
    }
    Ok(calib_data)
}

/// Load the host-sensor TLS pairing bundle from disk cache, or read and decrypt it directly
/// from Flash Partition 1 (`0x40`) on the sensor and cache it to `/var/lib/fprint/.synaptics_06cb_009a_pairing.json`.
///
/// # Arguments
/// * `session` - Active pre-TLS [`SensorSession`] used to read Flash Partition 1 (`0x40`) on cache miss.
pub fn load_or_read_pairing_bundle(
    session: &mut SensorSession<SynapticsUsbTransport>,
) -> Result<PairingBundle> {
    const CACHE_PATH: &str = "/var/lib/fprint/.synaptics_06cb_009a_pairing.json";
    for candidate in [CACHE_PATH, "pairing_06cb_009a.json"] {
        let p = PathBuf::from(candidate);
        if p.exists()
            && let Ok(b) = PairingBundle::load_from_file(&p)
        {
            return Ok(b);
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

/// Access or lazily initialize the process-wide [`SharedSensorState`].
///
/// # Arguments
/// *(none)*
fn sensor_state() -> &'static SharedSensorState {
    SENSOR_STATE.get_or_init(|| SharedSensorState {
        session: Mutex::new(None),
        cancel_flag: Mutex::new(None),
        atexit_registered: AtomicBool::new(false),
    })
}

/// Process exit handler registered via `atexit()` so the sensor's TLS session slot is cleanly
/// released (`0x05 0x02 0x00`) if `fprintd` stops.
///
/// # Arguments
/// *(none)*
extern "C" fn tod_atexit_reboot() {
    request_cancel();
    if let Some(state) = SENSOR_STATE.get()
        && let Ok(mut guard) = state.session.try_lock()
        && let Some((mut session, _)) = guard.take()
    {
        let _ = session.reboot_sensor();
    }
}

/// Open a fresh USB transport to `06cb:009a`, run Metallica pre-TLS initialization (resetting the
/// USB port once if the sensor is in a leftover state), and establish the TLS 1.2 + OTP calibration session.
///
/// # Arguments
/// * `state` - Process-wide [`SharedSensorState`] where the active USB cancellation handle is stored.
fn connect_and_initialize_session(
    state: &SharedSensorState,
) -> Result<SensorSession<SynapticsUsbTransport>> {
    let mut session = {
        let transport = SynapticsUsbTransport::open()?;
        if let Ok(mut cf) = state.cancel_flag.lock() {
            *cf = Some(transport.cancel_handle());
        }
        let mut first_session = SensorSession::new(transport);
        if let Err(e) = first_session.initialize_metallica() {
            drv_warn!("Initial sensor handshake failed ({e}); resetting USB port and retrying...");
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
    let _ = ensure_sensor_calibrated(&mut session)?;
    Ok(session)
}

/// Open or reuse the persistent TLS 1.2 session with `06cb:009a`.
///
/// - If an existing session has been idle for `>= 3s`, verifies liveness via [`SensorSession::ping_status`] (`0x01`).
/// - When establishing a new session, pre-caches the sensor's immutable OTP factory calibration values (`0x6f`)
///   so subsequent verify/enroll calls can arm the LED in ~5ms.
///
/// # Arguments
/// * `f` - Closure executed with exclusive access to the active [`SensorSession`].
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
        let session = connect_and_initialize_session(state)?;
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
///
/// # Arguments
/// *(none)*
fn request_cancel() {
    let state = sensor_state();
    if let Ok(guard) = state.cancel_flag.lock()
        && let Some(flag) = guard.as_ref()
    {
        flag.store(true, Ordering::SeqCst);
    }
}

/// Schedule a Rust closure to execute on the GLib main context thread via `g_idle_add`.
///
/// # Arguments
/// * `func` - One-shot closure to execute on the GLib main loop thread.
fn run_on_glib_main_loop<F>(func: F)
where
    F: FnOnce() + Send + 'static,
{
    /// C callback trampoline passed to `g_idle_add` that unboxes and invokes the Rust closure once.
    ///
    /// # Arguments
    /// * `data` - Heap pointer created via `Box::into_raw` containing the boxed closure.
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

/// Read the username and `FpFinger` enum value from an `FpPrint *` pointer.
///
/// # Arguments
/// * `print` - Non-null `FpPrint *` GObject pointer.
///
/// # Safety
/// `print` must be a valid `FpPrint *` instance allocated by `libfprint-2`.
unsafe fn read_print_user_and_finger(print: *mut c_void) -> (String, u32) {
    unsafe {
        let uname_ptr = fp_print_get_username(print);
        let uname = if uname_ptr.is_null() {
            String::new()
        } else {
            CStr::from_ptr(uname_ptr).to_string_lossy().into_owned()
        };
        let finger = fp_print_get_finger(print);
        (uname, finger)
    }
}

/// Attach a 16-byte `"fpi-data"` GVariant byte array ([`SynapticsPrintMetadata`])
/// and set `fpi_print_set_type(print, 1 /* FPI_PRINT_RAW */)` on a `FpPrint *` object so `fprintd`
/// persists the hardware DB2 metadata in `/var/lib/fprint/<user>/synaptics-009a-tod/0/`.
///
/// # Arguments
/// * `print` - Non-null `FpPrint *` GObject pointer to populate.
/// * `meta` - [`SynapticsPrintMetadata`] containing the enrolled DB2 record IDs and subtype.
///
/// # Safety
/// `print` must be a valid, writable `FpPrint *` GObject pointer owned by `libfprint-2`.
pub unsafe fn attach_synaptics_fpi_data(print: *mut c_void, meta: SynapticsPrintMetadata) {
    let payload = meta.to_bytes();
    unsafe {
        fpi_print_set_type(print, 1); // FPI_PRINT_RAW = 1
        let variant = g_variant_new_fixed_array(
            c"y".as_ptr(),
            payload.as_ptr() as *const c_void,
            payload.len(),
            1,
        );
        g_object_set(print, c"fpi-data".as_ptr(), variant, ptr::null::<c_char>());
    }
}

/// Extract [`SynapticsPrintMetadata`] from a `FpPrint *`'s `"fpi-data"` GVariant property.
///
/// # Arguments
/// * `print` - `FpPrint *` GObject pointer (may be null, in which case `None` is returned).
///
/// # Safety
/// If non-null, `print` must be a valid `FpPrint *` GObject pointer allocated by `libfprint-2`.
pub unsafe fn extract_synaptics_fpi_data(print: *mut c_void) -> Option<SynapticsPrintMetadata> {
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
            SynapticsPrintMetadata::from_bytes(slice)
        } else {
            None
        };
        g_variant_unref(variant);
        res
    }
}

/// `FpDeviceClass.usb_discover` (`+0xb0`): return a positive priority score (`51`) to claim `06cb:009a`
/// over `libfprint-2`'s built-in non-MoC `synaptics` driver.
///
/// # Arguments
/// * `_usb_device` - `GUsbDevice *` pointer passed by `libfprint-2` during USB discovery.
extern "C" fn dev_usb_discover(_usb_device: *mut c_void) -> c_int {
    51
}

/// `FpDeviceClass.probe` (`+0xb8`): report device metadata to `fprintd` and immediately spawn
/// background TLS 1.2 + OTP factory calibration pre-warming.
///
/// # Arguments
/// * `device` - `FpDevice *` instance pointer being probed.
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
///
/// # Arguments
/// * `device` - `FpDevice *` instance pointer being opened.
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
///
/// # Arguments
/// * `device` - `FpDevice *` instance pointer being closed.
extern "C" fn dev_exit(device: *mut c_void) {
    drv_debug!("Device closed by fprintd");
    request_cancel();
    unsafe {
        fpi_device_close_complete(device, ptr::null_mut());
    }
}

/// `FpDeviceClass.cancel` (`+0x100`): signal cooperative cancellation to the worker thread.
///
/// # Arguments
/// * `_device` - `FpDevice *` instance pointer requesting cancellation.
extern "C" fn dev_cancel(_device: *mut c_void) {
    drv_info!("Cancellation requested by fprintd");
    request_cancel();
}

/// `FpDeviceClass.suspend` (`+0x120`): abort any active scan cleanly before system suspend.
///
/// # Arguments
/// * `device` - `FpDevice *` instance pointer entering system suspend.
extern "C" fn dev_suspend(device: *mut c_void) {
    drv_info!("System suspend notified by fprintd — cancelling active scan");
    request_cancel();
    unsafe {
        fpi_device_suspend_complete(device, ptr::null_mut());
    }
}

/// `FpDeviceClass.resume` (`+0x128`): re-warm the TLS 1.2 session in the background after system wake.
///
/// # Arguments
/// * `device` - `FpDevice *` instance pointer resuming from system suspend.
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
///
/// # Arguments
/// * `device` - `FpDevice *` instance pointer starting an enrollment action.
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

    let (username, fp_finger) = unsafe { read_print_user_and_finger(print) };
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
                        SynapticsPrintMetadata {
                            uid,
                            user_dbid,
                            template_dbid,
                            synaptics_subtype: syn_subtype,
                            fp_finger: fp_finger as u16,
                        },
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

impl GalleryCandidate {
    /// Extract a [`GalleryCandidate`] from a `FpPrint *` pointer in `fprintd`'s gallery.
    ///
    /// # Arguments
    /// * `prt` - `FpPrint *` GObject pointer from `fpi_device_get_verify_data` or `fpi_device_get_identify_data`.
    ///
    /// # Safety
    /// If non-null, `prt` must be a valid `FpPrint *` GObject pointer owned by `libfprint-2`.
    unsafe fn from_print_ptr(prt: *mut c_void) -> Option<Self> {
        if prt.is_null() {
            return None;
        }
        let syn_subtype = unsafe {
            if let Some(meta) = extract_synaptics_fpi_data(prt) {
                meta.synaptics_subtype
            } else {
                fp_finger_to_synaptics_subtype(fp_print_get_finger(prt))
            }
        };
        Some(Self {
            print_addr: prt as usize,
            syn_subtype,
        })
    }
}

/// `FpDeviceClass.verify` (`+0xd8`) and `FpDeviceClass.identify` (`+0xe0`): perform on-chip
/// QMatcher identification and match the resulting finger subtype against `fprintd`'s candidate list.
///
/// # Arguments
/// * `device` - `FpDevice *` instance pointer executing `verify` or `identify`.
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
                        if let Some(cand) = GalleryCandidate::from_print_ptr(*pdata.add(i)) {
                            candidates.push(cand);
                        }
                    }
                }
            }
        }
    } else if action == FPI_DEVICE_ACTION_VERIFY {
        let mut prt: *mut c_void = ptr::null_mut();
        unsafe {
            fpi_device_get_verify_data(device, &mut prt);
            if let Some(cand) = GalleryCandidate::from_print_ptr(prt) {
                candidates.push(cand);
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
///
/// # Arguments
/// * `device` - `FpDevice *` instance pointer executing `delete_print`.
extern "C" fn dev_delete(device: *mut c_void) {
    let mut print: *mut c_void = ptr::null_mut();
    unsafe {
        fpi_device_get_delete_data(device, &mut print);
    }

    let extracted = unsafe { extract_synaptics_fpi_data(print) };
    let fallback_info = if extracted.is_none() && !print.is_null() {
        let (uname, fp_f) = unsafe { read_print_user_and_finger(print) };
        Some((
            uid_from_username(&uname),
            fp_finger_to_synaptics_subtype(fp_f),
        ))
    } else {
        None
    };

    let dev_addr = device as usize;
    std::thread::spawn(move || {
        let res = with_sensor_session(|session| {
            if let Some(meta) = extracted {
                drv_info!(
                    "Deleting enrolled template dbid=0x{:04x}, subtype={} ({}) for UID {}",
                    meta.template_dbid,
                    meta.synaptics_subtype,
                    finger_subtype_name(meta.synaptics_subtype),
                    meta.uid
                );
                session.db2_delete_object(meta.template_dbid)?;
                let _ = session.db2_delete_user_finger(meta.uid, meta.synaptics_subtype);
            } else if let Some((uid, syn_sub)) = fallback_info {
                drv_info!(
                    "Deleting enrolled finger subtype={syn_sub} ({}) for UID {uid}",
                    finger_subtype_name(syn_sub)
                );
                session.db2_delete_user_finger(uid, syn_sub)?;
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
///
/// # Arguments
/// * `device` - `FpDevice *` instance pointer executing `clear_storage`.
extern "C" fn dev_clear_storage(device: *mut c_void) {
    drv_info!("Clearing all enrolled user records in StgWindsor");
    let dev_addr = device as usize;
    std::thread::spawn(move || {
        let res = with_sensor_session(|session| {
            let stg = session.db2_get_user_storage(0, STG_WINDSOR_NAME)?;
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

/// GObject instance initializer (`GInstanceInitFunc`) for `FpiDeviceSynaptics009aTod`.
///
/// # Arguments
/// * `_instance` - Newly allocated `FpiDeviceSynaptics009aTod` instance pointer.
/// * `_g_class` - `FpDeviceClass *` class structure pointer.
extern "C" fn fpi_device_synaptics_009a_tod_init(_instance: *mut c_void, _g_class: *mut c_void) {}

/// Populate the [`FpDeviceClass`] virtual method table (`0x208` bytes on x86_64).
///
/// # Arguments
/// * `klass` - Uninitialized `FpDeviceClass *` class structure pointer passed by GObject.
/// * `_class_data` - Optional user data pointer passed to `g_type_register_static_simple` (unused).
extern "C" fn fpi_device_synaptics_009a_tod_class_init(
    klass: *mut c_void,
    _class_data: *mut c_void,
) {
    unsafe {
        let _ = g_type_class_peek_parent(klass);
        let fp_dev_type = fp_device_get_type();
        let dev_class = &mut *(g_type_check_class_cast(klass, fp_dev_type) as *mut FpDeviceClass);

        dev_class.id = TOD_DRIVER_ID.as_ptr();
        dev_class.full_name = TOD_FULL_NAME.as_ptr();
        dev_class.device_type = FP_DEVICE_TYPE_USB;
        dev_class.id_table = ID_TABLE.as_ptr();
        dev_class.nr_enroll_stages = TOD_NR_ENROLL_STAGES;
        dev_class.scan_type = FP_SCAN_TYPE_PRESS;

        dev_class.usb_discover = Some(dev_usb_discover);
        dev_class.probe = Some(dev_probe);
        dev_class.open = Some(dev_init);
        dev_class.close = Some(dev_exit);
        dev_class.enroll = Some(dev_enroll);
        dev_class.verify = Some(dev_verify);
        dev_class.identify = Some(dev_verify);
        dev_class.delete = Some(dev_delete);
        dev_class.cancel = Some(dev_cancel);
        #[cfg(not(fedora_libfprint))]
        {
            dev_class.temp_warm_seconds = -1; // disable thermal throttling
        }
        #[cfg(fedora_libfprint)]
        {
            dev_class.temp_hot_seconds = -1; // disable thermal throttling
        }
        dev_class.clear_storage = Some(dev_clear_storage);
        dev_class.suspend = Some(dev_suspend);
        dev_class.resume = Some(dev_resume);

        fpi_device_class_auto_initialize_features(klass);
    }
}

static REGISTERED_GTYPE: OnceLock<GType> = OnceLock::new();

/// LD_PRELOAD hook for `g_type_register_static_simple` so Fedora's unmodified
/// `/usr/lib64/libfprint-2.so.2` binds `FpiDeviceSynaptics` directly to our
/// native Rust `06cb:009a` Match-on-Chip driver vtable.
#[cfg(fedora_libfprint)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn g_type_register_static_simple(
    parent_type: GType,
    type_name: *const c_char,
    class_size: c_uint,
    class_init: extern "C" fn(*mut c_void, *mut c_void),
    instance_size: c_uint,
    instance_init: extern "C" fn(*mut c_void, *mut c_void),
    flags: c_uint,
) -> GType {
    unsafe {
        if !type_name.is_null() && CStr::from_ptr(type_name).to_bytes() == b"FpiDeviceSynaptics" {
            drv_info!(
                "Intercepted FpiDeviceSynaptics in Fedora libfprint-2.so.2 -> registering native Rust 06cb:009a MoC driver"
            );
            return real_g_type_register_static_simple(
                parent_type,
                type_name,
                size_of::<FpDeviceClass>() as c_uint,
                fpi_device_synaptics_009a_tod_class_init,
                0x38,
                fpi_device_synaptics_009a_tod_init,
                flags,
            );
        }
        real_g_type_register_static_simple(
            parent_type,
            type_name,
            class_size,
            class_init,
            instance_size,
            instance_init,
            flags,
        )
    }
}

/// Entry point symbol looked up by `libfprint-2-tod.so.1`
/// (`tod-shared-loader.c`: `fpi_tod_shared_driver_get_type`).
///
/// # Arguments
/// *(none)*
///
/// # Safety
/// Must be called from a process with GLib/GObject and `libfprint-2` initialized.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fpi_tod_shared_driver_get_type() -> GType {
    *REGISTERED_GTYPE.get_or_init(|| unsafe {
        drv_info!(
            "Registering libfprint-2-tod1 driver GType (FpiDeviceSynaptics009aTod, 06cb:009a)"
        );
        let name = g_intern_static_string(TOD_TYPE_NAME.as_ptr());
        let parent = fp_device_get_type();
        real_g_type_register_static_simple(
            parent,
            name,
            size_of::<FpDeviceClass>() as c_uint,
            fpi_device_synaptics_009a_tod_class_init,
            0x38,
            fpi_device_synaptics_009a_tod_init,
            0,
        )
    })
}
