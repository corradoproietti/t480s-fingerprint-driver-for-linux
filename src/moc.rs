//! Match-on-Chip (MoC) QMatcher biometric engine, 2D capacitive sensor timeslot compiler,
//! and on-flash DB2 database operations for Synaptics Metallica MIS (`06cb:009a`).
//!
//! ## Subsystems Implemented in This Module
//!
//! 1. **On-Flash DB2 Biometric Database (`0x45..0x4b`)**:
//!    - Queries storage containers (`StgWindsor`, `0x4b`), user records (`0x4a`), and enrolled finger
//!      templates (`Db2FingerEntry`).
//!    - Encodes and decodes Windows Biometric Framework (`WINBIO`) Security Identifiers (`SID`s)
//!      mapped to Linux numeric UIDs (`S-1-5-21-111111111-1111111111-1111111111-<uid>`).
//!    - Creates (`0x47`) and deletes (`0x48`) user and template records wrapped with RSA-signed
//!      `db_write_enable` (`0x06 0x02 ...`) and flash page cleanup (`0x1a`).
//! 2. **2D Capacitive Frame Acquisition (`0x02`, Sensor Type `0x0199`)**:
//!    - Decodes and patches the sensor's 2D timeslot bytecode table (`patch_timeslot_table`,
//!      `patch_timeslot_again`), packs OTP factory calibration (`0x6f`) and 13,440-byte baseline
//!      calibration (`calib_06cb_009a.bin`), and builds the 13,801-byte `AcqStart` (`0x02`) program.
//!    - Drives the 3-step Interrupt `0x83` state machine (`0x00` armed -> `0x02` finger touch ->
//!      `0x03` frame ready) and verifies image quality via `ProgramStatus` (`0x51 00 20 00 00`).
//! 3. **On-Chip QMatcher Verification (`0x5e` / `0x60` / `0x62`) & 12-Stage Enrollment (`0x68` / `0x69` / `0x6b`)**:
//!    - Executes 1:N / 1:1 template matching directly inside the sensor's `qmatcher` firmware extension.
//!    - Runs multi-stage template construction on the sensor processor and commits the final encrypted
//!      template to Partition 4 (`DB2`).

use std::time::Duration;

use crate::error::{DriverError, Result, SensorStatus, describe_scan_quality_error};
use crate::protocol::{SensorSession, WireOpcode};
use crate::usb::Transport;
use crate::{drv_debug, drv_error, drv_info, drv_warn};

/// Summary of the on-flash DB2 biometric database (`WireOpcode::Db2GetDbInfo` = `0x45`, 66-byte response).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Db2DatabaseInfo {
    pub version_major: u32,
    pub version_minor: u32,
    pub total_bytes: u32,
    pub used_bytes: u32,
    pub free_bytes: u32,
    pub total_objects: u16,
    pub root_ids: Vec<u16>,
}

impl Db2DatabaseInfo {
    pub fn from_response_payload(payload: &[u8]) -> Result<Self> {
        if payload.len() < 24 {
            return Err(DriverError::ShortResponse {
                context: "Db2GetDbInfo (0x45)",
                expected: 24,
                actual: payload.len(),
            });
        }
        let version_major = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let version_minor = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let total_bytes = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let used_bytes = u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]);
        let free_bytes = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
        let total_objects = u16::from_le_bytes([payload[20], payload[21]]);
        let nroots = u16::from_le_bytes([payload[22], payload[23]]) as usize;

        let mut root_ids = Vec::with_capacity(nroots);
        for chunk in payload[24..].chunks_exact(2).take(nroots) {
            root_ids.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }

        Ok(Self {
            version_major,
            version_minor,
            total_bytes,
            used_bytes,
            free_bytes,
            total_objects,
            root_ids,
        })
    }
}

/// Enrolled finger entry inside a DB2 user record (`0x4a`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Db2FingerEntry {
    pub dbid: u16,
    pub subtype: u16,
    pub storage_id: u16,
    pub value_size: u16,
}

impl Db2FingerEntry {
    pub fn finger_name(&self) -> &'static str {
        finger_subtype_name(self.subtype)
    }
}

/// User record and enrolled fingers returned by `db2_get_user` (`0x4a`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Db2UserRecord {
    pub record_id: u16,
    pub sid_string: Option<String>,
    pub identity_bytes: Vec<u8>,
    pub fingers: Vec<Db2FingerEntry>,
}

/// Storage container (`StgWindsor`) returned by `0x4b`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Db2UserStorage {
    pub record_id: u16,
    pub name: String,
    pub users: Vec<(u16, u16)>,
}

/// Sensor 2D imaging acquisition mode (`0x02`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    Calibrate = 1,
    Identify = 2,
    Enroll = 3,
}

/// Map a finger subtype ID (`1..=10` or `0xf5..=0xfe`) to its fprintd/WINBIO human-readable name.
pub fn finger_subtype_name(subtype: u16) -> &'static str {
    match subtype {
        1 => "right-thumb",
        2 => "right-index-finger",
        3 => "right-middle-finger",
        4 => "right-ring-finger",
        5 => "right-little-finger",
        6 => "left-thumb",
        7 => "left-index-finger",
        8 => "left-middle-finger",
        9 => "left-ring-finger",
        10 => "left-little-finger",
        0xf5 => "WINBIO_FINGER_UNSPECIFIED_POS_01",
        0xf6 => "WINBIO_FINGER_UNSPECIFIED_POS_02",
        0xf7 => "WINBIO_FINGER_UNSPECIFIED_POS_03",
        0xf8 => "WINBIO_FINGER_UNSPECIFIED_POS_04",
        0xf9 => "WINBIO_FINGER_UNSPECIFIED_POS_05",
        0xfa => "WINBIO_FINGER_UNSPECIFIED_POS_06",
        0xfb => "WINBIO_FINGER_UNSPECIFIED_POS_07",
        0xfc => "WINBIO_FINGER_UNSPECIFIED_POS_08",
        0xfd => "WINBIO_FINGER_UNSPECIFIED_POS_09",
        0xfe => "WINBIO_FINGER_UNSPECIFIED_POS_10",
        _ => "unknown-finger",
    }
}

/// Parse a DB2 identity byte blob (`[3u32, len: u32, sid_bytes...]`) into a `S-1-5-21-...` string.
pub fn parse_sid_identity(b: &[u8]) -> Option<String> {
    if b.len() < 16 {
        return None;
    }
    let typ = u32::from_le_bytes(b[0..4].try_into().ok()?);
    if typ != 3 {
        return None;
    }
    let len = u32::from_le_bytes(b[4..8].try_into().ok()?) as usize;
    if b.len() < 8 + len || len < 8 {
        return None;
    }
    let sid = &b[8..8 + len];
    let revision = sid[0];
    let subcnt = sid[1] as usize;
    if sid.len() < 8 + 4 * subcnt {
        return None;
    }
    let mut auth: u64 = 0;
    for &byte in &sid[2..8] {
        auth = (auth << 8) | (byte as u64);
    }
    let mut parts = Vec::with_capacity(subcnt);
    for chunk in sid[8..8 + 4 * subcnt].chunks_exact(4) {
        parts.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]).to_string());
    }
    Some(format!("S-{revision}-{auth}-{}", parts.join("-")))
}

/// Encode a Linux numeric `uid` into the 76-byte (`0x4c`) padded DB2 SID identity blob
/// (`S-1-5-21-111111111-1111111111-1111111111-<uid>`).
pub fn encode_sid_identity_for_uid(uid: u32) -> Vec<u8> {
    let subauth: [u32; 5] = [21, 111_111_111, 1_111_111_111, 1_111_111_111, uid];
    let mut sid = Vec::with_capacity(8 + subauth.len() * 4);
    sid.push(1u8); // revision = 1
    sid.push(subauth.len() as u8);
    sid.extend_from_slice(&[0, 0, 0, 0, 0, 5]); // authority = 5 (big-endian 48-bit)
    for &sa in &subauth {
        sid.extend_from_slice(&sa.to_le_bytes());
    }
    let mut out = Vec::with_capacity(0x4c);
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&(sid.len() as u32).to_le_bytes());
    out.extend_from_slice(&sid);
    if out.len() < 0x4c {
        out.resize(0x4c, 0);
    }
    out
}

/// Baseline 112-byte register calibration table for sensor type `0x0199` (`06cb:009a`).
const CALIBRATION_BLOB_0199: [u8; 112] = [
    0x9b, 0x9a, 0x99, 0x97, 0x96, 0x95, 0x93, 0x92, 0x91, 0x8f, 0x8e, 0x8d, 0x8b, 0x8a, 0x89, 0x87,
    0x86, 0x85, 0x83, 0x82, 0x81, 0x7f, 0x7e, 0x7d, 0x7b, 0x7a, 0x79, 0x77, 0x76, 0x75, 0x73, 0x72,
    0x71, 0x6f, 0x6e, 0x6d, 0x6b, 0x6a, 0x69, 0x67, 0x66, 0x65, 0x63, 0x62, 0x61, 0x5f, 0x5e, 0x5d,
    0x5b, 0x5a, 0x59, 0x57, 0x56, 0x55, 0x52, 0x51, 0x50, 0x4e, 0x4d, 0x4c, 0x4a, 0x49, 0x48, 0x46,
    0x45, 0x44, 0x42, 0x41, 0x40, 0x3e, 0x3d, 0x3c, 0x3a, 0x39, 0x38, 0x36, 0x35, 0x34, 0x32, 0x31,
    0x30, 0x2e, 0x2d, 0x2c, 0x2a, 0x29, 0x28, 0x26, 0x25, 0x24, 0x22, 0x21, 0x20, 0x1e, 0x1d, 0x1c,
    0x1a, 0x19, 0x18, 0x16, 0x15, 0x14, 0x12, 0x11, 0x10, 0x0e, 0x0d, 0x0c, 0x0a, 0x09, 0x08, 0x06,
];

const HARDCODED_PROG_0199_HEX: &str = "23000000200008000020008000000100320074000000008020200400242000005020773628200100302001003c208000082138000c210000482107004c210000582000005c20000060200000682005006c20014970200141742001887820018084202000942001809c200902a0200b19b4200300b8203b04bc201400c0200200c4200100c82002003300100000000080cc200000f503d0200000a1013200440000000080dc20e803e0206401e420d002e8200001f0200500f8200500fc200000b8203a00000804001408000008080000080800001408300008080000140831001c081a0032000c0000000080501101004c111e00340078010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010221710221710221610221610221601065010250101000007c8078c06ff0000000000004f80006d0300280307030990098db00b90880991858e08c1810b9190910ac1b8928a0993878a890b9388898908c88191890ac8889289099a818a890b9a88898908d08191890ad08892890802818a095a810a0288890b5a8808d98189890ad9908989095e8289890b5e88898908e18189890ae190898909648289890b648889096e8108e981890b6e880ae99091b9096f828a8f0b6f88918908f0818a890af090898909768289910b76b8918a08f88792910af8888a92097c81898a0b7c09018089890b01888991097f8189920b7f09088089920b088889920c07030307200402000000002f0004007000000029000400700000003500040080000000";

/// `0x39` LED configuration command to turn the sensor scan LED ON (`state = 0x01`, brightness `0x99`).
const GLOW_START_SCAN_HEX: &str = "3920bf0200ffff0000019900200000000099990000000000000000000000000020000000000000000000000000ffff000000990020000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/// `0x39` LED configuration command to turn the sensor scan LED OFF when cancelling an untouched scan.
/// Note: Phase 1 pulses `state = 0x01` (`0xff`) for `500 ms` (`0x01f4`) before transitioning to `state = 0x00`,
/// so this command must **only** be sent when the LED is still lit (`!finger_touched`).
const GLOW_END_SCAN_HEX: &str = "39f4010000f401000001ff002000000000ffff0000000000000000000000000020000000000000000000000000f401000000ff0020000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/// Decode a single instruction from the sensor's 2D timeslot bytecode table (`tag 0x34`),
/// returning `(opcode, byte_len, operand0, operand1)`.
fn decode_timeslot_insn(b: &[u8]) -> (u8, usize, u32, u32) {
    let b0 = b[0];
    if b0 <= 4 {
        (b0, 1, 0, 0)
    } else if b0 == 5 || b0 == 6 {
        (b0, 2, b.get(1).copied().unwrap_or(0) as u32, 0)
    } else if b0 == 7 {
        let b1 = b.get(1).copied().unwrap_or(0);
        (7, 2, if b1 == 0 { 0x100 } else { b1 as u32 }, 0)
    } else if (b0 & 0xfe) == 8 {
        let b1 = b.get(1).copied().unwrap_or(0);
        (8, 2, (((b0 & 1) as u32) << 8) | (b1 as u32), 0)
    } else if (b0 & 0xfe) == 0x0a {
        let b1 = b.get(1).copied().unwrap_or(0);
        (9, 2, (((b0 & 1) as u32) << 8) | (b1 as u32), 0)
    } else if (b0 & 0xfc) == 0x0c {
        (10, 1, (b0 & 3) as u32, 0)
    } else if (b0 & 0xf8) == 0x10 {
        let b1 = b.get(1).copied().unwrap_or(0);
        (11, 3, (b0 & 7) as u32, (b1 as u32) << 2)
    } else if (b0 & 0xe0) == 0x20 {
        (12, 1, (b0 & 0x1f) as u32, 0)
    } else if (b0 & 0xc0) == 0x40 {
        let addr = ((b0 & 0x3f) as u32) * 4 + 0x8000_2000;
        let b1 = b.get(1).copied().unwrap_or(0) as u32;
        let b2 = b.get(2).copied().unwrap_or(0) as u32;
        let val = b1 | (b2 << 8);
        (13, 3, addr, val)
    } else if (b0 & 0xc0) == 0x80 {
        (14, 1, ((b0 & 0x38) >> 3) as u32, (b0 & 7) as u32)
    } else if (b0 & 0xc0) == 0xc0 {
        (15, 2, ((b0 & 0x38) >> 3) as u32, (b0 & 7) as u32)
    } else {
        (0, 1, 0, 0)
    }
}

/// Locate the byte offset (`PC`) of the `n`-th instruction with `opcode` in a timeslot bytecode buffer.
fn find_nth_insn(b: &[u8], opcode: u8, mut n: usize) -> usize {
    let mut pc = 0usize;
    while pc < b.len() {
        let (op, sz, _, _) = decode_timeslot_insn(&b[pc..]);
        if op == opcode {
            n -= 1;
            if n == 0 {
                return pc;
            }
        }
        pc += sz;
    }
    0
}

/// Locate the byte offset (`PC`) of the `n`-th register-write instruction (`opcode == 13`)
/// targeting hardware register `reg_addr` (e.g. `0x8000_203c`).
fn find_nth_regwrite(b: &[u8], reg_addr: u32, mut n: usize) -> usize {
    let mut pc = 0usize;
    while pc < b.len() {
        let (op, sz, addr, _) = decode_timeslot_insn(&b[pc..]);
        if op == 13 && addr == reg_addr {
            n -= 1;
            if n == 0 {
                return pc;
            }
        }
        pc += sz;
    }
    0
}

/// First-pass timeslot bytecode patcher (`table_types.py`: `patch_timeslot_table`),
/// scaling loop repeat counts (`opcode 11`) by `mult` (`2` for 224 lines) and optionally incrementing call addresses.
fn patch_timeslot_table(b: &[u8], inc_address: bool, mult: u8) -> Vec<u8> {
    let mut out = b.to_vec();
    let mut i = 0usize;
    while i + 3 < out.len() {
        if (out[i] & 0xf8) == 0x10 {
            if out[i + 2] > 1 {
                out[i + 2] = out[i + 2].wrapping_mul(mult);
                if inc_address {
                    out[i + 1] = out[i + 1].wrapping_add(1);
                }
            }
            i += 3;
            continue;
        }
        if out[i] == 0 {
            i += 1;
            continue;
        }
        if out[i] == 7 {
            i += 2;
            continue;
        }
        break;
    }
    out
}

/// Second-pass timeslot bytecode patcher (`sensor.py`: `patch_timeslot_again`),
/// injecting the OTP factory calibration value (`key_calib_val` at line `0x38`) into the
/// register write to `0x8000_203c`.
fn patch_timeslot_again(b: &[u8], key_calib_val: u8) -> Vec<u8> {
    let mut out = b.to_vec();
    let mut pc = 0usize;
    let mut match_call: Option<usize> = None;
    while pc < out.len() {
        let (opcode, l, _, op1) = decode_timeslot_insn(&out[pc..]);
        if opcode == 1 || opcode == 2 || opcode == 4 {
            break;
        }
        if opcode == 11 {
            match_call = Some(op1 as usize);
        }
        pc += l;
    }
    let Some(mut pc) = match_call else {
        return out;
    };
    let mut match_reg: Option<usize> = None;
    while pc < out.len() {
        let (opcode, l, op0, _) = decode_timeslot_insn(&out[pc..]);
        if opcode == 1 || opcode == 2 || opcode == 4 {
            break;
        }
        if opcode == 13 && op0 == 0x8000_203c {
            match_reg = Some(pc);
        }
        pc += l;
    }
    if let Some(reg_pc) = match_reg {
        if reg_pc + 1 < out.len() {
            out[reg_pc + 1] = key_calib_val;
        }
    }
    out
}

/// Delta-bitpack a slice of per-line calibration bytes into `(bits_per_entry, min_value, packed_bytes)`.
fn bitpack(b: &[u8]) -> (u8, u8, Vec<u8>) {
    let l = b.len();
    let m = *b.iter().min().unwrap_or(&0);
    let max_val = *b.iter().max().unwrap_or(&0);
    let mut x = max_val - m;
    let mut u = 0usize;
    while x > 0 {
        x >>= 1;
        u += 1;
    }
    let out_len = (u * l + 7) / 8;
    let mut out = vec![0u8; out_len];
    for (idx, &val) in b.iter().enumerate() {
        let delta = val - m;
        for bit in 0..u {
            if ((delta >> bit) & 1) != 0 {
                let total_bit = idx * u + bit;
                out[total_bit / 8] |= 1 << (total_bit % 8);
            }
        }
    }
    (u as u8, m, out)
}

/// Build the exact `0x02` (`AcqStart`) 2D imaging command packet for `06cb:009a` (`sensor_type = 0x0199`).
pub fn build_cmd_02_0199(
    mode: CaptureMode,
    factory_calibration_values: &[u8],
    calib_data: &[u8],
) -> Vec<u8> {
    let prog = hex::decode(HARDCODED_PROG_0199_HEX).expect("valid hex");
    let mut chunks: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut pos = 0usize;
    while pos + 4 <= prog.len() {
        let typ = u16::from_le_bytes([prog[pos], prog[pos + 1]]);
        let sz = u16::from_le_bytes([prog[pos + 2], prog[pos + 3]]) as usize;
        if pos + 4 + sz > prog.len() {
            break;
        }
        chunks.push((typ, prog[pos + 4..pos + 4 + sz].to_vec()));
        pos += 4 + sz;
    }

    let key_line: Vec<u8> = if calib_data.len() >= 13440 {
        let bytes_per_calib_line = calib_data.len() / 112;
        let key_line_offset = 8 + bytes_per_calib_line * 0x38;
        calib_data[key_line_offset..key_line_offset + 112]
            .iter()
            .map(|&v| if v == 5 { v - 1 } else { v })
            .collect()
    } else {
        vec![0u8; 112]
    };

    let key_calib_val = factory_calibration_values.get(0x38).copied().unwrap_or(0);
    let mut tst = Vec::new();
    for (typ, val) in &mut chunks {
        if *typ == 0x34 {
            let mut patched = patch_timeslot_table(val, true, 2);
            if mode != CaptureMode::Calibrate {
                patched = patch_timeslot_again(&patched, key_calib_val);
            }
            tst = patched.clone();
            let mut new_val = key_line.clone();
            if patched.len() > 112 {
                new_val.extend_from_slice(&patched[112..]);
            }
            *val = new_val;
        }
    }

    chunks.push((0x17, Vec::new()));
    match mode {
        CaptureMode::Identify => {
            chunks.push((
                0x4e,
                hex::decode(
                    "fbb20f0000000f00300000008700020067000a00018000000a0200000b1900008813b80b01091000",
                )
                .expect("valid hex"),
            ));
            chunks.push((
                0x2e,
                hex::decode("0200180002000000700070004d010000a0008c003c32321e3c0a0202")
                    .expect("valid hex"),
            ));
        }
        CaptureMode::Enroll => {
            chunks.push((
                0x26,
                hex::decode(
                    "fbb20f0000000f00300000008700020067000a00018000000a0200000b19000050c360ea01091000",
                )
                .expect("valid hex"),
            ));
            chunks.push((
                0x2e,
                hex::decode("0200180023000000700070004d010000a0008c003c32321e3c0a0202")
                    .expect("valid hex"),
            ));
        }
        CaptureMode::Calibrate => {}
    }

    chunks.push((0x44, 1u32.to_le_bytes().to_vec()));

    struct LineUpdateEntry {
        mask: u32,
        flags: u32,
        v0: u8,
        v1: u8,
        v2: u16,
        data: Vec<u8>,
    }

    let mut lines: Vec<LineUpdateEntry> = Vec::new();
    let pc0 = find_nth_insn(&tst, 6, 2) as u32;
    lines.push(LineUpdateEntry {
        mask: 0xff,
        flags: (pc0 + 1) | (2 << 20) | 0x0700_0000,
        v0: 0x0f,
        v1: 0,
        v2: 0,
        data: CALIBRATION_BLOB_0199.to_vec(),
    });

    let pc1 = find_nth_regwrite(&tst, 0x8000_203c, 1) as u32;
    let (u, m, packed_data) = bitpack(factory_calibration_values);
    lines.push(LineUpdateEntry {
        mask: 0xff,
        flags: (pc1 + 1) | (3 << 20) | 0x0700_0000,
        v0: (u.saturating_sub(1)) | 8,
        v1: m,
        v2: 0,
        data: packed_data,
    });

    if calib_data.len() >= 13440 {
        let bytes_per_calib_line = calib_data.len() / 112;
        for i in (0..112).step_by(4) {
            let mut data = Vec::with_capacity(112 * 4);
            for j in 0..112 {
                let p = 8 + j * bytes_per_calib_line + i;
                data.extend_from_slice(&calib_data[p..p + 4]);
            }
            lines.push(LineUpdateEntry {
                mask: 0xffff_ffff,
                flags: (i as u32) | (0x85 << 24),
                v0: 0,
                v1: 0,
                v2: 0,
                data,
            });
        }
    }

    for l in &mut lines {
        let pad = l.data.len() % 4;
        if pad > 0 {
            l.data.resize(l.data.len() + (4 - pad), 0);
        }
    }

    let mut line_update = Vec::new();
    line_update.extend_from_slice(&(lines.len() as u32).to_le_bytes());
    for l in &lines {
        line_update.extend_from_slice(&l.mask.to_le_bytes());
        line_update.extend_from_slice(&l.flags.to_le_bytes());
    }
    for l in &lines {
        if ((l.flags & 0x00f0_0000) >> 20) <= 1 {
            line_update.extend_from_slice(&l.data);
        }
    }
    chunks.push((0x30, line_update));

    let mut update_transform = Vec::new();
    for l in &lines {
        if ((l.flags & 0x00f0_0000) >> 20) > 1 {
            update_transform.push(l.v0);
            update_transform.push(l.v1);
            update_transform.extend_from_slice(&l.v2.to_le_bytes());
            update_transform.extend_from_slice(&l.data);
        }
    }
    chunks.push((0x43, update_transform));

    let req_lines: u16 = if mode == CaptureMode::Calibrate {
        3 * 224 + 1
    } else {
        0
    };

    let mut out = Vec::new();
    out.push(0x02);
    out.extend_from_slice(&0x0078u16.to_le_bytes());
    out.extend_from_slice(&req_lines.to_le_bytes());
    for (k, v) in chunks {
        out.extend_from_slice(&k.to_le_bytes());
        out.extend_from_slice(&(v.len() as u16).to_le_bytes());
        out.extend_from_slice(&v);
    }
    out
}

/// Match-on-Chip verification / identification result returned by `0x5e`/`0x60`/`0x62`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchVerifyResult {
    pub matched: bool,
    pub matched_object_id: u16,
    pub matched_user_id: u16,
    pub matched_finger_id: u16,
    pub match_score: u32,
}

impl<T: Transport> SensorSession<T> {
    /// Query the sensor's on-flash DB2 biometric database statistics (`WireOpcode::Db2GetDbInfo` = `0x45`).
    pub fn db2_get_info(&mut self) -> Result<Db2DatabaseInfo> {
        let payload = self.execute_cmd(&[WireOpcode::Db2GetDbInfo as u8], 0x42)?;
        Db2DatabaseInfo::from_response_payload(&payload)
    }

    /// Query a user record (`type = 5`) and its enrolled fingers (`0x4a`, 7B req `[0x4a, dbid_lo, dbid_hi, 0, 0, 0, 0]`).
    pub fn db2_get_user(&mut self, user_dbid: u16) -> Result<Db2UserRecord> {
        let mut req = [0u8; 7];
        req[0] = WireOpcode::Db2GetObjectInfo as u8;
        req[1..3].copy_from_slice(&user_dbid.to_le_bytes());

        let payload = self.execute_cmd(&req, 256)?;
        if payload.len() < 8 {
            return Err(DriverError::ShortResponse {
                context: "Db2GetObjectInfo (0x4a)",
                expected: 8,
                actual: payload.len(),
            });
        }
        let record_id = u16::from_le_bytes([payload[0], payload[1]]);
        let fingercnt = u16::from_le_bytes([payload[2], payload[3]]) as usize;
        let identitysz = u16::from_le_bytes([payload[6], payload[7]]) as usize;

        let ftab_end = (8 + 8 * fingercnt).min(payload.len());
        let mut fingers = Vec::with_capacity(fingercnt);
        for chunk in payload[8..ftab_end].chunks_exact(8) {
            let dbid = u16::from_le_bytes([chunk[0], chunk[1]]);
            let subtype = u16::from_le_bytes([chunk[2], chunk[3]]);
            let storage_id = u16::from_le_bytes([chunk[4], chunk[5]]);
            let value_size = u16::from_le_bytes([chunk[6], chunk[7]]);
            fingers.push(Db2FingerEntry {
                dbid,
                subtype,
                storage_id,
                value_size,
            });
        }
        let id_end = (ftab_end + identitysz).min(payload.len());
        let identity_bytes = payload[ftab_end..id_end].to_vec();
        let sid_string = parse_sid_identity(&identity_bytes);

        Ok(Db2UserRecord {
            record_id,
            sid_string,
            identity_bytes,
            fingers,
        })
    }

    /// Query a DB2 user storage container (e.g. `"StgWindsor"`, opcode `0x4b`).
    pub fn db2_get_user_storage(&mut self, dbid: u16, name: &str) -> Result<Db2UserStorage> {
        let mut name_bytes = name.as_bytes().to_vec();
        if !name_bytes.is_empty() {
            name_bytes.push(0);
        }
        let mut req = Vec::with_capacity(5 + name_bytes.len());
        req.push(WireOpcode::Db2GetStorage as u8);
        req.extend_from_slice(&dbid.to_le_bytes());
        req.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        req.extend_from_slice(&name_bytes);

        let payload = self.execute_cmd(&req, 256)?;
        if payload.len() < 8 {
            return Err(DriverError::ShortResponse {
                context: "Db2GetStorage (0x4b)",
                expected: 8,
                actual: payload.len(),
            });
        }
        let record_id = u16::from_le_bytes([payload[0], payload[1]]);
        let usercnt = u16::from_le_bytes([payload[2], payload[3]]) as usize;
        let namesz = u16::from_le_bytes([payload[4], payload[5]]) as usize;

        let utab_end = (8 + 4 * usercnt).min(payload.len());
        let mut users = Vec::with_capacity(usercnt);
        for chunk in payload[8..utab_end].chunks_exact(4) {
            let uid = u16::from_le_bytes([chunk[0], chunk[1]]);
            let vsz = u16::from_le_bytes([chunk[2], chunk[3]]);
            users.push((uid, vsz));
        }
        let name_end = (utab_end + namesz).min(payload.len());
        let parsed_name = String::from_utf8_lossy(&payload[utab_end..name_end])
            .trim_end_matches('\0')
            .to_string();

        Ok(Db2UserStorage {
            record_id,
            name: parsed_name,
            users,
        })
    }

    /// Delete an object from the on-flash DB2 database (`WireOpcode::Db2DeleteObject` = `0x48`,
    /// 3B req `[0x48, obj_id_lo, obj_id_hi]` -> 2B resp).
    pub fn db2_delete_object(&mut self, obj_id: u16) -> Result<()> {
        let mut req = [0u8; 3];
        req[0] = WireOpcode::Db2DeleteObject as u8;
        req[1..3].copy_from_slice(&obj_id.to_le_bytes());
        match self.execute_cmd(&req, 2) {
            Ok(_) => {
                drv_info!("Deleted DB2 object dbid=0x{obj_id:04x} ({obj_id}) from sensor flash");
                Ok(())
            }
            Err(DriverError::CommandFailed {
                status: SensorStatus::ObjectNotFound,
                ..
            }) => {
                drv_debug!("DB2 object dbid=0x{obj_id:04x} already absent (0x04b3)");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Read factory calibration values from sensor ROM/OTP (`0x6f` with `tag = 0x0e00`, `subtag = 3`),
    /// caching the immutable OTP values on the session for subsequent operations.
    pub fn get_factory_calibration_values(&mut self) -> Result<Vec<u8>> {
        if let Some(ref cached) = self.factory_calib {
            return Ok(cached.clone());
        }
        let req = [
            WireOpcode::SpotCheck as u8,
            0x00,
            0x0e,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ];
        let payload = self.execute_cmd(&req, 4096)?;
        if payload.len() < 8 {
            return Err(DriverError::ShortResponse {
                context: "SpotCheck factory calibration (0x6f)",
                expected: 8,
                actual: payload.len(),
            });
        }
        let entries = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
        let mut pos = 8usize;
        for _ in 0..entries {
            if pos + 12 > payload.len() {
                break;
            }
            let len = u16::from_le_bytes([payload[pos + 4], payload[pos + 5]]) as usize;
            let subtag = u16::from_le_bytes([payload[pos + 8], payload[pos + 9]]);
            pos += 12;
            if pos + len > payload.len() {
                break;
            }
            if subtag == 3 && len > 4 {
                let vals = payload[pos + 4..pos + len].to_vec();
                self.factory_calib = Some(vals.clone());
                return Ok(vals);
            }
            pos += len;
        }
        Err(DriverError::Protocol(
            "Factory calibration subtag 3 not found in 0x6f response".to_string(),
        ))
    }

    /// Start the sensor LED scan glow pattern (`0x39`).
    pub fn glow_start_scan(&mut self) -> Result<()> {
        drv_info!("[LED] Turning sensor LED ON (glow_start_scan 0x39)");
        let cmd = hex::decode(GLOW_START_SCAN_HEX).expect("valid hex");
        let _ = self.execute_cmd(&cmd, 2)?;
        Ok(())
    }

    /// End the sensor LED scan glow pattern (`0x39`).
    pub fn glow_end_scan(&mut self) -> Result<()> {
        drv_info!("[LED] Turning sensor LED OFF (glow_end_scan 0x39)");
        let cmd = hex::decode(GLOW_END_SCAN_HEX).expect("valid hex");
        let _ = self.execute_cmd(&cmd, 2)?;
        Ok(())
    }

    /// Arm the 2D capacitive sensor (`0x02`), wait for a finger touch and frame capture on Interrupt IN `0x83`,
    /// verify scan quality via `0x51 00 20 00 00`, and stop acquisition (`0x04`).
    pub fn capture_finger_frame(
        &mut self,
        mode: CaptureMode,
        factory_calibration_values: &[u8],
        calib_data: &[u8],
    ) -> Result<()> {
        let t_start = std::time::Instant::now();
        self.transport.flush_interrupt_events();
        let cmd_02 = build_cmd_02_0199(mode, factory_calibration_values, calib_data);
        drv_info!(
            "[CAPTURE] Sending AcqStart (0x02, mode={mode:?}, len={} B)",
            cmd_02.len()
        );
        let _ = self.execute_cmd(&cmd_02, 2)?;

        let mut finger_touched = false;
        let res = (|| -> Result<()> {
            // 1. Wait for scan-start interrupt (b[0] == 0, or b[0] == 2 if finger is already touching)
            let evt = self
                .transport
                .wait_interrupt_event(Duration::from_secs(10))
                .map_err(|e| match e {
                    DriverError::Usb(rusb::Error::Timeout) => {
                        DriverError::Timeout("sensor scan-start interrupt (0x00)")
                    }
                    other => other,
                })?;

            let mut already_touched = false;
            if evt.header[0] == 0 {
                drv_info!(
                    "[CAPTURE] Interrupt 1/3 (armed): header={} (+{} ms) — waiting for finger touch...",
                    hex::encode(evt.header),
                    t_start.elapsed().as_millis()
                );
            } else if evt.header[0] == 2 {
                drv_info!(
                    "[CAPTURE] Interrupt 1/3 (finger already touching, sensor turns LED off): header={} (+{} ms)",
                    hex::encode(evt.header),
                    t_start.elapsed().as_millis()
                );
                already_touched = true;
                finger_touched = true;
            } else {
                return Err(DriverError::ScanRetry(format!(
                    "Unexpected scan-start interrupt header {:02x?}",
                    evt.header
                )));
            }

            // 2. Wait for finger touch on sensor (b[0] == 2)
            let mut already_captured = false;
            if !already_touched {
                loop {
                    let evt = self
                        .transport
                        .wait_interrupt_event(Duration::from_secs(120))
                        .map_err(|e| match e {
                            DriverError::Usb(rusb::Error::Timeout) => {
                                DriverError::Timeout("finger touch on sensor (120s)")
                            }
                            other => other,
                        })?;
                    if evt.header[0] == 2 {
                        finger_touched = true;
                        drv_info!(
                            "[CAPTURE] Interrupt 2/3 (finger touch detected, sensor turns LED off): header={} (+{} ms)",
                            hex::encode(evt.header),
                            t_start.elapsed().as_millis()
                        );
                        break;
                    } else if evt.header[0] == 3 && (evt.header[2] & 4) != 0 {
                        finger_touched = true;
                        already_captured = true;
                        drv_info!(
                            "[CAPTURE] Interrupt 2+3/3 (touch & frame capture completed): header={} (+{} ms)",
                            hex::encode(evt.header),
                            t_start.elapsed().as_millis()
                        );
                        break;
                    } else {
                        drv_info!(
                            "[CAPTURE] Ignoring pre-touch interrupt: header={} (+{} ms)",
                            hex::encode(evt.header),
                            t_start.elapsed().as_millis()
                        );
                    }
                }
            }

            // 3. Wait for capture completion (b[0] == 3 && (b[2] & 4) != 0)
            let t_touch = std::time::Instant::now();
            if !already_captured {
                loop {
                    let evt = self
                        .transport
                        .wait_interrupt_event(Duration::from_secs(5))
                        .map_err(|e| match e {
                            DriverError::Usb(rusb::Error::Timeout) => DriverError::ScanRetry(
                                "Finger lifted too quickly before frame capture completed".to_string(),
                            ),
                            other => other,
                        })?;
                    if evt.header[0] == 2 {
                        drv_debug!(
                            "[CAPTURE] Additional touch interrupt while capturing: header={}",
                            hex::encode(evt.header)
                        );
                        continue;
                    }
                    if evt.header[0] != 3 {
                        return Err(DriverError::ScanRetry(format!(
                            "Unexpected capture interrupt header 0x{:02x}",
                            evt.header[0]
                        )));
                    }
                    if (evt.header[2] & 4) != 0 {
                        drv_info!(
                            "[CAPTURE] Interrupt 3/3 (2D frame captured): header={} (capture_time={} ms)",
                            hex::encode(evt.header),
                            t_touch.elapsed().as_millis()
                        );
                        break;
                    } else {
                        drv_debug!(
                            "[CAPTURE] Intermediate 0x03 interrupt (waiting for bit 2): header={}",
                            hex::encode(evt.header)
                        );
                    }
                }
            }

            // 4. Query program status (`0x51 00 20 00 00`)
            let status_payload =
                self.execute_cmd(&[WireOpcode::ProgramStatus as u8, 0x00, 0x20, 0x00, 0x00], 64)?;
            if status_payload.len() < 16 {
                return Err(DriverError::ShortResponse {
                    context: "ProgramStatus (0x51)",
                    expected: 16,
                    actual: status_payload.len(),
                });
            }
            let x = u16::from_le_bytes([status_payload[4], status_payload[5]]);
            let y = u16::from_le_bytes([status_payload[6], status_payload[7]]);
            let w1 = u16::from_le_bytes([status_payload[8], status_payload[9]]);
            let w2 = u16::from_le_bytes([status_payload[10], status_payload[11]]);
            let scan_error = u32::from_le_bytes([
                status_payload[12],
                status_payload[13],
                status_payload[14],
                status_payload[15],
            ]);
            if scan_error != 0 {
                let description = describe_scan_quality_error(scan_error);
                drv_warn!(
                    "[CAPTURE] ProgramStatus (0x51) scan quality FAILED: x={x}, y={y}, w1={w1}, w2={w2}, error=0x{scan_error:04x} ({description})"
                );
                return Err(DriverError::ScanQuality {
                    code: scan_error,
                    description,
                });
            }
            drv_info!(
                "[CAPTURE] ProgramStatus (0x51) OK: x={x}, y={y}, w1={w1}, w2={w2}, error=0x0000"
            );
            Ok(())
        })();

        // Stop acquisition (`0x04` cleanup); ignore `0x0412` when acquisition already completed
        let _ = self.execute_raw(&[WireOpcode::NoopStatus as u8], 2);
        if res.is_err() {
            self.transport.flush_interrupt_events();
            // Only send `glow_end_scan` if the finger never touched the sensor (e.g. cancelled while waiting),
            // because once the finger touches the sensor, the hardware turns the LED off automatically,
            // and `GLOW_END_SCAN_HEX` (`39 f4010000 ... 01 ff00 ...`) would pulse the LED back ON for 500ms!
            if !finger_touched {
                let _ = self.glow_end_scan();
            }
        }
        res
    }

    /// Perform on-chip 1:N fingerprint identification on `06cb:009a`, invoking `on_retry` whenever
    /// a retryable finger scan quality error requires another touch.
    pub fn identify_finger_009a_with_retry<F>(
        &mut self,
        calib_data: &[u8],
        mut on_retry: F,
    ) -> Result<MatchVerifyResult>
    where
        F: FnMut(&DriverError),
    {
        let factory_calib = self.get_factory_calibration_values()?;
        let mut attempt = 0usize;
        loop {
            attempt += 1;
            drv_info!("[VERIFY] Capture attempt #{attempt}: arming sensor...");
            self.glow_start_scan()?;
            match self.capture_finger_frame(CaptureMode::Identify, &factory_calib, calib_data) {
                Ok(()) => break,
                Err(e) if e.is_scan_retryable() => {
                    drv_warn!(
                        "[VERIFY] Attempt #{attempt} scan retry needed ({e}) — waiting 400ms before re-arming LED..."
                    );
                    on_retry(&e);
                    std::thread::sleep(Duration::from_millis(400));
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        let t_match = std::time::Instant::now();
        let res = (|| -> Result<MatchVerifyResult> {
            drv_info!("[MATCH] Sending QmIdentifyStart (0x5e) for on-chip 1:N matching...");
            let req_5e = [
                WireOpcode::QmIdentifyStart as u8,
                0x02,
                0xff,
                0x00,
                0x00,
                0x00,
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
            ];
            let _ = self.execute_cmd(&req_5e, 16)?;

            let evt = self
                .transport
                .wait_interrupt_event(Duration::from_secs(10))
                .map_err(|e| match e {
                    DriverError::Usb(rusb::Error::Timeout) => {
                        DriverError::Timeout("QMatcher identify interrupt (0x5e)")
                    }
                    other => other,
                })?;
            drv_info!(
                "[MATCH] QMatcher interrupt on EP 0x83: header={} (+{} ms)",
                hex::encode(evt.header),
                t_match.elapsed().as_millis()
            );
            if evt.header[0] != 3 {
                drv_warn!(
                    "[MATCH] QMatcher interrupt header[0]=0x{:02x} != 0x03 -> finger not recognized",
                    evt.header[0]
                );
                return Ok(MatchVerifyResult {
                    matched: false,
                    matched_object_id: 0,
                    matched_user_id: 0,
                    matched_finger_id: 0,
                    match_score: 0,
                });
            }

            let payload = match self.execute_cmd(
                &[WireOpcode::QmIdentifyResult as u8, 0x00, 0x00, 0x00, 0x00],
                256,
            ) {
                Ok(p) => p,
                Err(DriverError::CommandFailed { status, .. }) => {
                    drv_info!(
                        "[MATCH] QmIdentifyResult (0x60) returned {status} -> no template matched (+{} ms)",
                        t_match.elapsed().as_millis()
                    );
                    return Ok(MatchVerifyResult {
                        matched: false,
                        matched_object_id: 0,
                        matched_user_id: 0,
                        matched_finger_id: 0,
                        match_score: 0,
                    });
                }
                Err(e) => return Err(e),
            };
            if payload.len() < 2 {
                return Err(DriverError::ShortResponse {
                    context: "QmIdentifyResult (0x60)",
                    expected: 2,
                    actual: payload.len(),
                });
            }
            let dict_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
            let mut pos = 2usize;
            let end = (2 + dict_len).min(payload.len());

            let mut matched_user_id = 0u16;
            let mut matched_finger_id = 0u16;
            while pos + 4 <= end {
                let tag = u16::from_le_bytes([payload[pos], payload[pos + 1]]);
                let tlen = u16::from_le_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
                pos += 4;
                if pos + tlen > end {
                    break;
                }
                let val = &payload[pos..pos + tlen];
                if tag == 1 && val.len() >= 4 {
                    matched_user_id =
                        u32::from_le_bytes([val[0], val[1], val[2], val[3]]) as u16;
                } else if tag == 3 && val.len() >= 2 {
                    matched_finger_id = u16::from_le_bytes([val[0], val[1]]);
                }
                pos += tlen;
            }

            drv_info!(
                "[MATCH] QmIdentifyResult (0x60) parsed in {} ms: matched={}, user_dbid=0x{matched_user_id:04x}, subtype={matched_finger_id} ({})",
                t_match.elapsed().as_millis(),
                matched_user_id != 0,
                finger_subtype_name(matched_finger_id)
            );

            Ok(MatchVerifyResult {
                matched: matched_user_id != 0,
                matched_object_id: matched_user_id,
                matched_user_id,
                matched_finger_id,
                match_score: 100,
            })
        })();

        // End QMatcher session (`0x62`). Do NOT call `glow_end_scan()` here because the sensor hardware
        // already turned the LED off when the finger touched it; calling `glow_end_scan()` (`39 f4010000 ... 01 ff00`)
        // would turn the LED back ON for 500ms before turning it off!
        let _ = self.execute_raw(&[WireOpcode::QmSessionEnd as u8, 0x00, 0x00, 0x00, 0x00], 16);
        res
    }

    /// Send the 3,621-byte RSA-signed `db_write_enable` (`0x06 0x02 ...`) command required before
    /// modifying DB2 flash records or running `0x6b` enrollment updates on `06cb:009a`.
    pub fn db_write_enable(&mut self) -> Result<()> {
        const DB_WRITE_ENABLE_009A_HEX: &str = "0602000001f48001074892b6c57deb7889b5ebf86bc3040f6d91ff1f68765f046591184be08cf36c154b7ec5368139d0f9532382214379aff3ffbfe4659e2f274e864bd0ad660f99e21da2bab677dbfa907a66ce110c180d2ddc5dfe40b8ed975cbedffc11631f12f8bd646a0ee82d44d2a6c1ec9cfbd40f485cb3d9124376b97b4a3349b0a730adda626d8ac28ec20e886aab1b8851deee3431c4d89c8bb3e787eaa9c0323dfe583d5424d36436e4435043e04fd4ea46b1fb2507ca6f0eb03baf27c84b819cbc96cec31a78045eb648339e2aa4789e7672d933936005f4720c8ffdc1ea23a4f30a1cdc8f6e87775c241b9ab1566f7771857cc4703d571f1106c526f95232925a6a93ec8e919022fbe303a515f9aaa8ca215072069311dd3f97d9a4f56259bab3a1b7a8582d6dc2f92d49f023d6f25a05837e1536a633e252ef645225f4293955041a0d54dcb1d1dd7e097b7839de5fde2a6ce999966d712b4cb2fd9d7830031da55d9faa99f866fbb7e520566efba43c2509286bf28e1a20c6a836db8a1fa4cb9b8d193780aab592d41653839670129066ac56f1268e6f761337f768555e13c5d68137c60f83dba8dc3863e00e73fd3af21e23a566daa67f3f14dd934e323651167021ca6b82a6103cb30be849446e2f54dde64a05377052b57332e9bf08a18cf52da2a13ebbd55e60333f8bc319e1457f38ec5d4839ec0ecd034825bdeaf64926858c6e8c2df418717b5f67135abc038835d3e4e1aa809546fd0d7f01066a71537f96bd1ecec3687583e1b511bf48c2776f4670158e56164c62da20f671764c785c352fc3cce22cefa20760acff8f45efb54a934f9834d54f9701dedacd4d383ac01f8cca92562eec774a58da6f55da252c491ee2ab58ff769f89a9649d3956682ca7d06bbf33f9a935b781dfc21b123b16694424e72d6a3e6781dcf195effd36470a4eab0fdc74e87102879ec81fea6549920cce454ac7813997b82d51e7b8c1ee24fad389904478f847654ec3a63bc595b9a7dde798db5c0b6f244901f239e7674c98eebb42b66e8956a733c3796586280a19a1df8a69224acd2556f7ec2e27cae37c69b332b2c0ec85991ae48722f988935f658b9cf32f46dfc6d96a5a36f18b6bf9f657b59b3da42414e4d56c0a24485aa298d2d0d1b177e7d0dafe602a4fb4f423def4bdb010fdc626c947587e19e7e4b0e6f9f2da41c29a8f1903d0d2803365fe0a113abba19220141d1ac7cec683962030d3f6591f98ea3dd09162715e5c12f40332b47c53164532827e5596fb2cc0aa8f31683cc63ec14c034c6f3d2c70b8c47611b4c5cb5348a2559fb162a780a2b403b0120a6846e27d6057a3ab9e1b18915ae2039e81cc6c50d2a14d5913617bacae78fe9b91e9e49d2e82def47565c12ff938b182f8ce941d2781b773479538c76ed9f7d4469f6fe5ba7f6e3ad98871b2866f0ef4f36277daa76c1042c83f77df0ff2e2639540bb355ea84273411c453081bd1e1035c402c53190d0bd905e8d01fc3787c65b69172cca5b234e92e358463bbb8d23e38c74a3a8e2735542b996ba5ec22c5095a777b6775a728df59c3560c7f36b83d55f819f196573f8fd356379fe9a5e7cecb376395e01309e2005b29e3b160cb74c6a5856093480dd06aea5fb3fbe23e004f8d7a38fd07866cdf24161391cc756f6ff71ff072e308b35e259435111bee09ddf2b8df99d0f2c2e8edaa4ecaabc6975a58f23bb6bfc94ebcbbba0d581f16be9d043c4e410b321c6df424ecaeea94edbe5801eb786199124222b091e5b33bad6761445a8a6606d0e781c07a6f91cd5fe188ddb9f9e17f5e07b0cba319c52e5fb03f53df570f82ddb603d305b72a2406bc7c1a37f920405f8f14d3ddf5d836ba68d83c1a8d7f1a41d148cc34b1ef996ddfb43ef19d2fbf0adcad301a473497739eaa10bbce85e15c32f1d90c8ab8605d0ae941eb914086592d087a521fde33a676cdfb94a4247f60f51edd37294511e92ec71a9a54bab68a0edaabdcb2c1a3adea778f416e39200af4c517dd7152bb72476c5d1413f04704615d795300f3a091214f4e4ac2ef41969c81f8fc08610864907b2e6edfa5fdb0926b6f064b2a1c3b8c7b631cc75663cedad5e71868abc9bac678e430144613cb0e51982b9e019099026b069bb7a4dc376cdd6a3c59566317976213672754fac87df85953cdc0de276fb8742f48ba218d4202fe6f865834152979d6da9b473e5d476c0aaa68491f545091b879c01986078d64fa5f49f60e615cb865f154f48b45173a1dc85f2eb1128652290bd383cdedcd8f280117e60be034ce224f92673934ed9e0077d5f7899f4e0eee097933a35e40f205d84a10733f492da619802ff70d9b949ca0c2bcb9ba68c290f2ef9a20a3bf496834c66956a8ec4179266999d9f87bdfc14aea865f0487e2be10a64becba69547d01658935e63703986a56d6ce38fe66dbf61d754ba9a1a278353913422e4f2e4100c5962999a3eaa3e1672bc73edcfcc7525a2d3dbe95683b4bf38f7444ac0f470f0e98079916e4e1fba3fcd5b082fc2772e63b5e0663f87638a163858f590845240a8c22dacf6f7999c431a2ab5204a7da7839c9a932608c7f83a87d1d73d7d8b2fec65abb95221fada44365fe21061dbcde52cb84cbfe9f061c4dab3be86002e7683eed16c23c687ce61c5d923ffbab40bee6ae93ed7f857f304e5eb16ec6d088563524e90d916e41a3a8c7777e29731f0f45c125082c423a5c02704c07c6fc19b1c4838ee3eabe12562829e67581d312c720b792a41744dec1e157426ab75136d31ee2f208147039091453c0b0e3970c5624d7a53df8076e9d1625d2c8e693e0e9a81e23862dca78921b66ca4c3c5ed35b0b5ed2e24622eb216ba0ba6e0c0eaf97c754eeb3db4a506d5854a3edc92d0111af3d2135a998729123f03d0f9366bb0d2c681cfc62c59bcd75c6b410d8e6997cca55c989f010393d6c242f7ce1ea71c6f262e498855584347b04ce26cce2e822b8c6b7b4937148a45c947073b300f7c72b6e78c4231078d80531b7f9317c1bb4d6070f299e9a97731b1befeeec2dae0a1a0364568acbebab069a4b90147776ff7e7f79c1cc98b2fe6214792501554f4195783b0f9188ccfe96ad8cd29f5463409c2054e4a2496ee65eaa1fcda3d7764cd3e8431e44a2b05e64aa2f9fb0d13456bfea9c91ec2d90d0099e7e395dce818650dcaf8bdfe23b4c6443f5c690b18ead221a6c2bcd34572ffb83b3332eafde6e25b37ff3ac6da0c3cc697b996265caa5a53ce44570303d7d111f44c635119595c247e86a32083f2865501752f93e3024b2e2b6d82d0c03b745bfd809af7e8e1349d1a79bed51bba415064701a2a7890e8f39937c6d2f563b0747bd94f1b698624b4fd17dfdf68ffdc0450c26d771f8ff4fb01a26ff8f64eb5b6d9153f5ce29d9dfcf84ca230a4c212401b437d1137f83a44f7a98a9fd1bc3d883e6227ce369ed32a960550aa863f3d014de7494dead34fced1d7b4eab651d499033589446fb5a1564557d63e724941e77ae3f46b79703d06277d87356999b51f61893d31c7231b0c635f1d83ab38a0dce544f5f6803861d6e3d7e70d617ecc593920b1ab9006bdc7bff34a8b36a7601eb170a040156b4567ab37f55fdf2d466fca9374277322f21811d02c7bc599c9ed5c2b1fe7b6baa19b1b0a30f79f8641b97bf66491dca0b4c0341367aa5acec1398bb37c037d81ac2368db49c5d5720bbfb7466ba616c70c7d834286303047357da0e9a34fc14b00c17a0a02f6a62a5b52976b00ed67bb2d0aa1b4a8a93100b799e1839695bdae9b98e75c8df5d8340d158be60379a6f626af052ad55c5cea01f806048e937f87e01e725e67620364e511afd288b25953e9ade343b596068608190fa5c4df114c93d3c8deca929c066d8bae5ac2d607e3f94d68a5d3554827a64735a43c462bc3682cc1664411f592c9456f53da1026f51459a0cf20cc171b9b6bede47ce57d845dffe1025c6eb240615da151106a5601b75c24c673d6ea818d60c31f414aeaa55597b40cc4f2ed2b3850d366084a52513420b013695e2bfcb0dbfad0014975c67471a3807528d15730802a4428842c6368c72650b3161265d6b86007264cf093a317fee4ee388e7721a02434c514324cbf85cb57f709b53fdf69624adc29b85518f1a051f2473ad9384d7ac57c2a780ab72506ba925fa39992dd2d0b00ffd8c38645d55c2ca2ae94cf4ffa372284a28a13797e25eb0d950c08371656a889e6189f83b9c0c8e06952b34fe13ccb5c3b2c82f2d988f6d9a233f1a9e64de97218be12ee7a8e8463d82131624ce167e744a3ca3915c78e6e76362d06090e2a7ed60ea7437c84838d8aa75f096c9a928e403e2428550c98de8c43bd25e24520aef6ee534ee1d4702175e6b25d030b87941845cefc1dc289cee33c72139f29839af81cb6a097d114311a01736f479bdae32a59398fc4a7494d034fc8dc5f2ba8af93fc4c576b703967ae593780413b44b98f4baba9d3fd7b55715ad5e5c41f9361a42a757d9a6d7220a9467e19f739877076164c142d40bbae9501312c394dc0233dc5868814162bfc1f10bd4663b285dd2d005f3bc3dad2ff023f7e81b799b1b323b37e82fc99dc81291cf93cc04a0e05aa674bcfd3bc0d930a10d0957ec7712b8cc78375dd904eb5a468296015dab1babb076786f305c8ad90ca3947b150da79cb94037e970e9180437ea34c72771d673000826741fe759fcdc2b03558331fdf5b89d6e3f25a05241f32f139e898126aec8b1715cac0208831fb1205f9efb75538755b2d83931c7ad9e252c88c8af3c5df62fb99653aff99e6c6c051a9a1241381cd5ce1307261f866575caea0a3e847286ecc67d7d9aa18f48ef2a5e5f183286127f8b9aa2caa0869ec5e474a70e5427dc2f0488b134d201241dae68ed3996869453247bb50d8bc3d3c909951e5a47b1e899610347ea8d7193346bfe754c289ad1ca454b9c92a07527b95a1fe508d0b7c8da5b9047d277508ff615c9dc9ab11596aa88d0c9734a45d81f0393219bead587d3a6f9d07c470f2abf8d7c6992228bf0ab6ef79e46599bb0a60";
        let blob = hex::decode(DB_WRITE_ENABLE_009A_HEX).expect("valid hex");
        let _ = self.execute_cmd(&blob, 16)?;
        Ok(())
    }

    /// Send flash cleanup/commit command `0x1a` (ignoring `0x0491` `NothingToCommit`).
    pub fn db_call_cleanups(&mut self) -> Result<()> {
        let raw = self.execute_raw(&[WireOpcode::DbCleanup as u8], 16)?;
        if raw.len() >= 2 {
            let status = SensorStatus::from(u16::from_le_bytes([raw[0], raw[1]]));
            if status.is_ok() || status == SensorStatus::NothingToCommit {
                return Ok(());
            }
            return Err(DriverError::CommandFailed {
                opcode: WireOpcode::DbCleanup as u8,
                opcode_name: "DbCleanup",
                status,
            });
        }
        Ok(())
    }

    /// Create a new DB2 record (`0x47`) wrapped with `db_write_enable` (`0x06`) and `db_call_cleanups` (`0x1a`).
    pub fn db2_new_record(
        &mut self,
        parent_id: u16,
        typ: u16,
        storage_id: u16,
        data: &[u8],
    ) -> Result<u16> {
        let _ = self.db2_get_info()?;
        self.db_write_enable()?;
        let res = (|| -> Result<u16> {
            let mut req = Vec::with_capacity(9 + data.len());
            req.push(WireOpcode::Db2WriteObject as u8);
            req.extend_from_slice(&parent_id.to_le_bytes());
            req.extend_from_slice(&typ.to_le_bytes());
            req.extend_from_slice(&storage_id.to_le_bytes());
            req.extend_from_slice(&(data.len() as u16).to_le_bytes());
            req.extend_from_slice(data);
            let payload = self.execute_cmd(&req, 16)?;
            if payload.len() < 2 {
                return Err(DriverError::ShortResponse {
                    context: "Db2WriteObject (0x47)",
                    expected: 2,
                    actual: payload.len(),
                });
            }
            Ok(u16::from_le_bytes([payload[0], payload[1]]))
        })();
        let _ = self.db_call_cleanups();
        res
    }

    /// Look up the DB2 user record (`type = 5`) for `uid` in `StgWindsor`, or create it if absent.
    pub fn db2_lookup_or_create_user(&mut self, uid: u32) -> Result<(u16, u16)> {
        let stg = self.db2_get_user_storage(0, "StgWindsor")?;
        let id_data = encode_sid_identity_for_uid(uid);

        let mut req = Vec::with_capacity(7 + id_data.len());
        req.push(WireOpcode::Db2GetObjectInfo as u8);
        req.extend_from_slice(&0u16.to_le_bytes());
        req.extend_from_slice(&stg.record_id.to_le_bytes());
        req.extend_from_slice(&(id_data.len() as u16).to_le_bytes());
        req.extend_from_slice(&id_data);

        let raw = self.execute_raw(&req, 256)?;
        if raw.len() >= 2 {
            let status = SensorStatus::from(u16::from_le_bytes([raw[0], raw[1]]));
            if status == SensorStatus::ObjectNotFound {
                drv_info!("Creating new DB2 user record in StgWindsor for UID {uid}");
                let user_dbid = self.db2_new_record(stg.record_id, 5, stg.record_id, &id_data)?;
                return Ok((user_dbid, stg.record_id));
            } else if status.is_ok() && raw.len() >= 4 {
                let user_dbid = u16::from_le_bytes([raw[2], raw[3]]);
                return Ok((user_dbid, stg.record_id));
            } else {
                return Err(DriverError::CommandFailed {
                    opcode: WireOpcode::Db2GetObjectInfo as u8,
                    opcode_name: "Db2GetObjectInfo",
                    status,
                });
            }
        }
        Err(DriverError::ShortResponse {
            context: "db2_lookup_or_create_user (0x4a)",
            expected: 4,
            actual: raw.len(),
        })
    }

    /// Run a complete interactive Match-on-Chip fingerprint enrollment on `06cb:009a`.
    ///
    /// - `uid`: Linux user ID (e.g. `1000` -> `S-1-5-21-111111111-1111111111-1111111111-1000`)
    /// - `subtype`: Finger subtype (`1..=10`)
    /// - `calib_data`: 13,440-byte sensor calibration blob (`calib_06cb_009a.bin`)
    /// - `on_stage`: callback `(completed_stages, header_bytes, retry_err)` invoked after each valid touch or retry
    pub fn enroll_finger_009a<F>(
        &mut self,
        uid: u32,
        subtype: u16,
        calib_data: &[u8],
        mut on_stage: F,
    ) -> Result<u16>
    where
        F: FnMut(usize, &[u8], Option<&DriverError>),
    {
        // Remove any pre-existing template with the same (uid, subtype) in StgWindsor before starting
        let target_sid = format!("S-1-5-21-111111111-1111111111-1111111111-{uid}");
        if let Ok(stg) = self.db2_get_user_storage(0, "StgWindsor") {
            for (user_dbid, _) in &stg.users {
                if let Ok(usr) = self.db2_get_user(*user_dbid) {
                    if usr.sid_string.as_deref() == Some(target_sid.as_str()) {
                        for f in usr.fingers.iter().filter(|f| f.subtype == subtype) {
                            drv_warn!(
                                "Removing existing DB2 template dbid=0x{:04x} for subtype={} ({}) before enrollment",
                                f.dbid,
                                subtype,
                                finger_subtype_name(subtype)
                            );
                            let _ = self.db2_delete_object(f.dbid);
                        }
                    }
                }
            }
        }

        let factory_calib = self.get_factory_calibration_values()?;

        // create_enrollment: pack('<BL', 0x69, 1)
        let create_req = [WireOpcode::OtaEnrollStep as u8, 0x01, 0x00, 0x00, 0x00];
        let end_req = [WireOpcode::OtaEnrollStep as u8, 0x00, 0x00, 0x00, 0x00];
        if self.execute_cmd(&create_req, 16).is_err() {
            drv_warn!("Resetting stale enrollment state (0x69 0x00) and retrying 0x69 0x01...");
            let _ = self.execute_raw(&end_req, 16);
            let _ = self.execute_cmd(&create_req, 16)?;
        }

        let enroll_res = (|| -> Result<u16> {
            let mut key: u32 = 0;
            let mut template: Vec<u8> = Vec::new();
            let mut stage_count: usize = 0;
            let mut consecutive_retries: usize = 0;
            let final_tid: Vec<u8>;

            loop {
                drv_info!("Enroll stage {}: waiting for finger touch...", stage_count + 1);
                let step_res = (|| -> Result<(Vec<u8>, Vec<u8>, Option<Vec<u8>>)> {
                    self.glow_start_scan()?;
                    self.capture_finger_frame(CaptureMode::Enroll, &factory_calib, calib_data)?;

                    // enrollment_update_start(key): pack('<BLL', 0x68, key, 0)
                    let mut req_68 = [0u8; 9];
                    req_68[0] = WireOpcode::OtaSessionInit as u8;
                    req_68[1..5].copy_from_slice(&key.to_le_bytes());
                    let resp_68 = self.execute_cmd(&req_68, 16)?;
                    if resp_68.len() < 4 {
                        return Err(DriverError::ShortResponse {
                            context: "OtaSessionInit (0x68)",
                            expected: 4,
                            actual: resp_68.len(),
                        });
                    }
                    key = u32::from_le_bytes([resp_68[0], resp_68[1], resp_68[2], resp_68[3]]);
                    let _ = self
                        .transport
                        .wait_interrupt_event(Duration::from_secs(10))
                        .map_err(|e| match e {
                            DriverError::Usb(rusb::Error::Timeout) => {
                                DriverError::Timeout("OtaSessionInit interrupt (0x68)")
                            }
                            other => other,
                        })?;

                    // append_new_image(template): two 0x6b calls separated by an interrupt
                    let mut req_6b = Vec::with_capacity(1 + template.len());
                    req_6b.push(WireOpcode::OtaReadData as u8);
                    req_6b.extend_from_slice(&template);

                    self.db_write_enable()?;
                    let first_6b = self.execute_cmd(&req_6b, 65536);
                    let _ = self.db_call_cleanups();
                    first_6b?;

                    let _ = self
                        .transport
                        .wait_interrupt_event(Duration::from_secs(10))
                        .map_err(|e| match e {
                            DriverError::Usb(rusb::Error::Timeout) => {
                                DriverError::Timeout("OtaReadData interrupt (0x6b)")
                            }
                            other => other,
                        })?;

                    self.db_write_enable()?;
                    let second_6b = self.execute_cmd(&req_6b, 65536);
                    let _ = self.db_call_cleanups();
                    let res_6b = second_6b?;

                    if res_6b.len() < 2 {
                        return Err(DriverError::ShortResponse {
                            context: "OtaReadData (0x6b)",
                            expected: 2,
                            actual: res_6b.len(),
                        });
                    }
                    let total_len = u16::from_le_bytes([res_6b[0], res_6b[1]]) as usize;
                    let mut slice = &res_6b[2..(2 + total_len).min(res_6b.len())];
                    let magic_len = 0x38usize;

                    let mut new_template = Vec::new();
                    let mut header = Vec::new();
                    let mut tid = None;

                    while slice.len() >= 4 {
                        let tag = u16::from_le_bytes([slice[0], slice[1]]);
                        let clen = u16::from_le_bytes([slice[2], slice[3]]) as usize;
                        let step = magic_len + clen;
                        if slice.len() < step {
                            break;
                        }
                        match tag {
                            0 => new_template = slice[..step].to_vec(),
                            1 => header = slice[magic_len..step].to_vec(),
                            3 => tid = Some(slice[magic_len..step].to_vec()),
                            _ => {}
                        }
                        slice = &slice[step..];
                    }

                    Ok((header, new_template, tid))
                })();

                // finally: enrollment_update_end() -> pack('<BL', 0x69, 0)
                let _ = self.execute_raw(&end_req, 16);

                match step_res {
                    Ok((header, new_template, tid)) => {
                        consecutive_retries = 0;
                        template = new_template;
                        stage_count += 1;
                        drv_info!(
                            "Enroll stage {stage_count} captured successfully (template={} B)",
                            template.len()
                        );
                        on_stage(stage_count, &header, None);
                        if let Some(t) = tid {
                            drv_info!(
                                "All enrollment stages completed after {stage_count} touches; committing template to DB2 flash..."
                            );
                            final_tid = t;
                            break;
                        }
                        // Brief pause so the user can lift their finger before the next stage arms the sensor
                        std::thread::sleep(Duration::from_millis(300));
                    }
                    Err(e)
                        if !matches!(e, DriverError::Cancelled | DriverError::Usb(_))
                            && (e.is_scan_retryable() || consecutive_retries < 8) =>
                    {
                        consecutive_retries += 1;
                        drv_warn!(
                            "Enroll stage {}: scan retry needed ({e}) — lift finger and touch again",
                            stage_count + 1
                        );
                        on_stage(stage_count, &[], Some(&e));
                        std::thread::sleep(Duration::from_millis(700));
                    }
                    Err(e) => {
                        drv_error!("Enroll stage {} aborted due to error: {e}", stage_count + 1);
                        return Err(e);
                    }
                }
            }

            // enrollment_update_end() called a second time as in sensor.py line 853
            let _ = self.execute_raw(&end_req, 16);

            // make_finger_data(subtype, template, tid)
            let mut inner = Vec::with_capacity(8 + template.len() + final_tid.len());
            inner.extend_from_slice(&1u16.to_le_bytes());
            inner.extend_from_slice(&(template.len() as u16).to_le_bytes());
            inner.extend_from_slice(&template);
            inner.extend_from_slice(&2u16.to_le_bytes());
            inner.extend_from_slice(&(final_tid.len() as u16).to_le_bytes());
            inner.extend_from_slice(&final_tid);

            let mut tinfo = Vec::with_capacity(8 + inner.len() + 0x20);
            tinfo.extend_from_slice(&subtype.to_le_bytes());
            tinfo.extend_from_slice(&3u16.to_le_bytes());
            tinfo.extend_from_slice(&(inner.len() as u16).to_le_bytes());
            tinfo.extend_from_slice(&0x0020u16.to_le_bytes());
            tinfo.extend_from_slice(&inner);
            tinfo.extend_from_slice(&[0u8; 0x20]);

            let (user_dbid, stg_dbid) = self.db2_lookup_or_create_user(uid)?;
            let recid = self.db2_new_record(user_dbid, 0x000b, stg_dbid, &tinfo)?;
            let _ = self
                .transport
                .wait_interrupt_event(Duration::from_secs(10));
            drv_info!(
                "Committed template dbid=0x{recid:04x} under user_dbid=0x{user_dbid:04x} for subtype={subtype} ({})",
                finger_subtype_name(subtype)
            );
            Ok(recid)
        })();

        if enroll_res.is_err() {
            let _ = self.execute_raw(&end_req, 16);
        }
        enroll_res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb::SensorInterruptEvent;
    use std::collections::VecDeque;

    struct MockTransport {
        requests: Vec<Vec<u8>>,
        responses: VecDeque<Vec<u8>>,
        interrupts: VecDeque<Result<SensorInterruptEvent>>,
    }

    impl MockTransport {
        fn new(responses: Vec<Vec<u8>>, interrupts: Vec<Result<SensorInterruptEvent>>) -> Self {
            Self {
                requests: Vec::new(),
                responses: responses.into(),
                interrupts: interrupts.into(),
            }
        }
    }

    impl Transport for MockTransport {
        fn transfer(&mut self, request: &[u8], _expected_resp_len: usize) -> Result<Vec<u8>> {
            self.requests.push(request.to_vec());
            Ok(self.responses.pop_front().unwrap_or_else(|| vec![0x00, 0x00]))
        }

        fn wait_interrupt_event(&mut self, _timeout: Duration) -> Result<SensorInterruptEvent> {
            self.interrupts
                .pop_front()
                .unwrap_or_else(|| Err(DriverError::Usb(rusb::Error::Timeout)))
        }
    }

    #[test]
    fn test_db2_delete_object_ignores_04b3() {
        let mock = MockTransport::new(
            vec![
                vec![0x00, 0x00], // first delete succeeds
                vec![0xb3, 0x04], // second delete returns 0x04b3 (ObjectNotFound)
            ],
            vec![],
        );
        let mut session = SensorSession::new(mock);
        session
            .db2_delete_object(0x0007)
            .expect("delete should succeed");
        session
            .db2_delete_object(0x0007)
            .expect("delete of already-removed object (0x04b3) should be treated as Ok");
    }

    #[test]
    fn test_build_cmd_02_0199_matches_reference() {
        use sha2::{Digest, Sha256};
        let calib_path = std::path::Path::new("calib_06cb_009a.bin");
        if !calib_path.exists() {
            return;
        }
        let calib_data = std::fs::read(calib_path).unwrap();
        let factory_calib: Vec<u8> = (10u8..10 + 144).collect();
        let cmd = build_cmd_02_0199(CaptureMode::Identify, &factory_calib, &calib_data);
        assert_eq!(cmd.len(), 13801);
        let digest = hex::encode(Sha256::digest(&cmd));
        assert_eq!(
            digest,
            "f90f19659dc9899c5d1894f3607fbdd85ac78f52b4625e37986a6d2a9cfbce61"
        );
    }

    #[test]
    fn test_sid_identity_roundtrip() {
        let blob = encode_sid_identity_for_uid(1000);
        assert_eq!(blob.len(), 0x4c);
        let sid = parse_sid_identity(&blob).expect("should parse SID");
        assert_eq!(sid, "S-1-5-21-111111111-1111111111-1111111111-1000");
    }
}
