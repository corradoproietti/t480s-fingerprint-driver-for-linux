//! 2D capacitive sensor timeslot bytecode compiler (`0x02`), factory OTP calibration reader (`0x6f`),
//! LED glow controller (`0x39`), and 3-step `EP 0x83` frame capture state machine for `06cb:009a`.

use std::time::Duration;

use crate::error::{DriverError, Result, describe_scan_quality_error};
use crate::protocol::{ByteReader, SensorSession, WireOpcode, decode_hex_const};
use crate::usb::Transport;
use crate::{drv_debug, drv_info, drv_warn};

/// Sensor 2D imaging acquisition mode (`0x02`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    Calibrate = 1,
    Identify = 2,
    Enroll = 3,
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

/// Base 648-byte 2D imaging program for sensor `0x0199` (`06cb:009a`), decoded at compile time.
const HARDCODED_PROG_0199: [u8; 648] = decode_hex_const(
    "23000000200008000020008000000100320074000000008020200400242000005020773628200100302001003c208000082138000c210000482107004c210000582000005c20000060200000682005006c20014970200141742001887820018084202000942001809c200902a0200b19b4200300b8203b04bc201400c0200200c4200100c82002003300100000000080cc200000f503d0200000a1013200440000000080dc20e803e0206401e420d002e8200001f0200500f8200500fc200000b8203a00000804001408000008080000080800001408300008080000140831001c081a0032000c0000000080501101004c111e00340078010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010221710221710221610221610221601065010250101000007c8078c06ff0000000000004f80006d0300280307030990098db00b90880991858e08c1810b9190910ac1b8928a0993878a890b9388898908c88191890ac8889289099a818a890b9a88898908d08191890ad08892890802818a095a810a0288890b5a8808d98189890ad9908989095e8289890b5e88898908e18189890ae190898909648289890b648889096e8108e981890b6e880ae99091b9096f828a8f0b6f88918908f0818a890af090898909768289910b76b8918a08f88792910af8888a92097c81898a0b7c09018089890b01888991097f8189920b7f09088089920b088889920c07030307200402000000002f0004007000000029000400700000003500040080000000",
);

/// `0x39` LED configuration command to turn the sensor scan LED ON (`state = 0x01`, brightness `0x99`).
const GLOW_START_SCAN: [u8; 125] = decode_hex_const(
    "3920bf0200ffff0000019900200000000099990000000000000000000000000020000000000000000000000000ffff000000990020000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
);

/// `0x39` LED configuration command to turn the sensor scan LED OFF when cancelling an untouched scan.
/// Note: Phase 1 pulses `state = 0x01` (`0xff`) for `500 ms` (`0x01f4`) before transitioning to `state = 0x00`,
/// so this command must **only** be sent when the LED is still lit (`!finger_touched`).
const GLOW_END_SCAN: [u8; 125] = decode_hex_const(
    "39f4010000f401000001ff002000000000ffff0000000000000000000000000020000000000000000000000000f401000000ff0020000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
);

const IDENTIFY_CHUNK_4E: [u8; 40] = decode_hex_const(
    "fbb20f0000000f00300000008700020067000a00018000000a0200000b1900008813b80b01091000",
);
const IDENTIFY_CHUNK_2E: [u8; 28] =
    decode_hex_const("0200180002000000700070004d010000a0008c003c32321e3c0a0202");
const ENROLL_CHUNK_26: [u8; 40] = decode_hex_const(
    "fbb20f0000000f00300000008700020067000a00018000000a0200000b19000050c360ea01091000",
);
const ENROLL_CHUNK_2E: [u8; 28] =
    decode_hex_const("0200180023000000700070004d010000a0008c003c32321e3c0a0202");

/// Decoded instruction from the sensor's 2D timeslot bytecode table (`tag 0x34`).
#[derive(Debug, Clone, Copy)]
struct TimeslotInsn {
    opcode: u8,
    byte_len: usize,
    operand0: u32,
    operand1: u32,
}

/// Decode a single instruction from the sensor's 2D timeslot bytecode table (`tag 0x34`).
///
/// # Arguments
/// * `b` - Byte slice starting at the current timeslot bytecode program counter (`PC`).
fn decode_timeslot_insn(b: &[u8]) -> TimeslotInsn {
    let b0 = b[0];
    if b0 <= 4 {
        TimeslotInsn {
            opcode: b0,
            byte_len: 1,
            operand0: 0,
            operand1: 0,
        }
    } else if b0 == 5 || b0 == 6 {
        TimeslotInsn {
            opcode: b0,
            byte_len: 2,
            operand0: b.get(1).copied().unwrap_or(0) as u32,
            operand1: 0,
        }
    } else if b0 == 7 {
        let b1 = b.get(1).copied().unwrap_or(0);
        TimeslotInsn {
            opcode: 7,
            byte_len: 2,
            operand0: if b1 == 0 { 0x100 } else { b1 as u32 },
            operand1: 0,
        }
    } else if (b0 & 0xfe) == 8 {
        let b1 = b.get(1).copied().unwrap_or(0);
        TimeslotInsn {
            opcode: 8,
            byte_len: 2,
            operand0: (((b0 & 1) as u32) << 8) | (b1 as u32),
            operand1: 0,
        }
    } else if (b0 & 0xfe) == 0x0a {
        let b1 = b.get(1).copied().unwrap_or(0);
        TimeslotInsn {
            opcode: 9,
            byte_len: 2,
            operand0: (((b0 & 1) as u32) << 8) | (b1 as u32),
            operand1: 0,
        }
    } else if (b0 & 0xfc) == 0x0c {
        TimeslotInsn {
            opcode: 10,
            byte_len: 1,
            operand0: (b0 & 3) as u32,
            operand1: 0,
        }
    } else if (b0 & 0xf8) == 0x10 {
        let b1 = b.get(1).copied().unwrap_or(0);
        TimeslotInsn {
            opcode: 11,
            byte_len: 3,
            operand0: (b0 & 7) as u32,
            operand1: (b1 as u32) << 2,
        }
    } else if (b0 & 0xe0) == 0x20 {
        TimeslotInsn {
            opcode: 12,
            byte_len: 1,
            operand0: (b0 & 0x1f) as u32,
            operand1: 0,
        }
    } else if (b0 & 0xc0) == 0x40 {
        let addr = ((b0 & 0x3f) as u32) * 4 + 0x8000_2000;
        let b1 = b.get(1).copied().unwrap_or(0) as u32;
        let b2 = b.get(2).copied().unwrap_or(0) as u32;
        TimeslotInsn {
            opcode: 13,
            byte_len: 3,
            operand0: addr,
            operand1: b1 | (b2 << 8),
        }
    } else if (b0 & 0xc0) == 0x80 {
        TimeslotInsn {
            opcode: 14,
            byte_len: 1,
            operand0: ((b0 & 0x38) >> 3) as u32,
            operand1: (b0 & 7) as u32,
        }
    } else if (b0 & 0xc0) == 0xc0 {
        TimeslotInsn {
            opcode: 15,
            byte_len: 2,
            operand0: ((b0 & 0x38) >> 3) as u32,
            operand1: (b0 & 7) as u32,
        }
    } else {
        TimeslotInsn {
            opcode: 0,
            byte_len: 1,
            operand0: 0,
            operand1: 0,
        }
    }
}

/// Locate the byte offset (`PC`) of the `n`-th instruction with `opcode` in a timeslot bytecode buffer.
///
/// # Arguments
/// * `b` - Complete timeslot bytecode slice (`tag 0x34`).
/// * `opcode` - Decoded instruction opcode (`0..=15`) to search for.
/// * `n` - 1-based occurrence index to match.
fn find_nth_insn(b: &[u8], opcode: u8, mut n: usize) -> usize {
    let mut pc = 0usize;
    while pc < b.len() {
        let insn = decode_timeslot_insn(&b[pc..]);
        if insn.opcode == opcode {
            n -= 1;
            if n == 0 {
                return pc;
            }
        }
        pc += insn.byte_len;
    }
    0
}

/// Locate the byte offset (`PC`) of the `n`-th register-write instruction (`opcode == 13`)
/// targeting hardware register `reg_addr` (e.g. `0x8000_203c`).
///
/// # Arguments
/// * `b` - Complete timeslot bytecode slice (`tag 0x34`).
/// * `reg_addr` - 32-bit MMIO register address (`0x8000_2000 + offset`) to match.
/// * `n` - 1-based occurrence index to match.
fn find_nth_regwrite(b: &[u8], reg_addr: u32, mut n: usize) -> usize {
    let mut pc = 0usize;
    while pc < b.len() {
        let insn = decode_timeslot_insn(&b[pc..]);
        if insn.opcode == 13 && insn.operand0 == reg_addr {
            n -= 1;
            if n == 0 {
                return pc;
            }
        }
        pc += insn.byte_len;
    }
    0
}

/// First-pass timeslot bytecode patcher (`table_types.py`: `patch_timeslot_table`),
/// scaling loop repeat counts (`opcode 11`) by `mult` (`2` for 224 lines) and optionally incrementing call addresses.
///
/// # Arguments
/// * `b` - Raw timeslot bytecode table (`tag 0x34`).
/// * `inc_address` - Whether to increment the target call address byte (`out[i + 1]`) when scaling.
/// * `mult` - Loop count multiplier (`2` for `06cb:009a`).
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
///
/// # Arguments
/// * `b` - First-pass patched timeslot bytecode buffer.
/// * `key_calib_val` - Factory OTP calibration byte for reference line `0x38`.
fn patch_timeslot_again(b: &[u8], key_calib_val: u8) -> Vec<u8> {
    let mut out = b.to_vec();
    let mut pc = 0usize;
    let mut match_call: Option<usize> = None;
    while pc < out.len() {
        let insn = decode_timeslot_insn(&out[pc..]);
        if insn.opcode == 1 || insn.opcode == 2 || insn.opcode == 4 {
            break;
        }
        if insn.opcode == 11 {
            match_call = Some(insn.operand1 as usize);
        }
        pc += insn.byte_len;
    }
    let Some(mut pc) = match_call else {
        return out;
    };
    let mut match_reg: Option<usize> = None;
    while pc < out.len() {
        let insn = decode_timeslot_insn(&out[pc..]);
        if insn.opcode == 1 || insn.opcode == 2 || insn.opcode == 4 {
            break;
        }
        if insn.opcode == 13 && insn.operand0 == 0x8000_203c {
            match_reg = Some(pc);
        }
        pc += insn.byte_len;
    }
    if let Some(reg_pc) = match_reg
        && reg_pc + 1 < out.len()
    {
        out[reg_pc + 1] = key_calib_val;
    }
    out
}

/// Delta-bitpack a slice of per-line calibration bytes into `(bits_per_entry, min_value, packed_bytes)`.
///
/// # Arguments
/// * `b` - Slice of per-line factory OTP calibration values read from `0x6f`.
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
    let out_len = (u * l).div_ceil(8);
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
///
/// # Arguments
/// * `mode` - Target 2D acquisition mode ([`CaptureMode::Calibrate`], [`CaptureMode::Identify`], or [`CaptureMode::Enroll`]).
/// * `factory_calibration_values` - Per-line factory OTP calibration bytes read from `0x6f` (`subtag = 3`).
/// * `calib_data` - 13,440-byte host calibration table (`calib_06cb_009a.bin`).
pub fn build_cmd_02_0199(
    mode: CaptureMode,
    factory_calibration_values: &[u8],
    calib_data: &[u8],
) -> Vec<u8> {
    let mut chunks: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut pos = 0usize;
    while pos + 4 <= HARDCODED_PROG_0199.len() {
        let typ = u16::from_le_bytes([HARDCODED_PROG_0199[pos], HARDCODED_PROG_0199[pos + 1]]);
        let sz = u16::from_le_bytes([HARDCODED_PROG_0199[pos + 2], HARDCODED_PROG_0199[pos + 3]])
            as usize;
        if pos + 4 + sz > HARDCODED_PROG_0199.len() {
            break;
        }
        chunks.push((typ, HARDCODED_PROG_0199[pos + 4..pos + 4 + sz].to_vec()));
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
            chunks.push((0x4e, IDENTIFY_CHUNK_4E.to_vec()));
            chunks.push((0x2e, IDENTIFY_CHUNK_2E.to_vec()));
        }
        CaptureMode::Enroll => {
            chunks.push((0x26, ENROLL_CHUNK_26.to_vec()));
            chunks.push((0x2e, ENROLL_CHUNK_2E.to_vec()));
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

impl<T: Transport> SensorSession<T> {
    /// Read factory calibration values from sensor ROM/OTP (`0x6f` with `tag = 0x0e00`, `subtag = 3`),
    /// caching the immutable OTP values on the session for subsequent operations.
    ///
    /// # Arguments
    /// * `&mut self` - Active [`SensorSession`].
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
        let mut r = ByteReader::new(&payload, "SpotCheck factory calibration (0x6f)");
        let _header = r.read_u32_le()?;
        let entries = r.read_u32_le()? as usize;

        for _ in 0..entries {
            if r.remaining_len() < 12 {
                break;
            }
            let hdr = r.read_slice(12)?;
            let len = u16::from_le_bytes([hdr[4], hdr[5]]) as usize;
            let subtag = u16::from_le_bytes([hdr[8], hdr[9]]);
            if r.remaining_len() < len {
                break;
            }
            let body = r.read_slice(len)?;
            if subtag == 3 && len > 4 {
                let vals = body[4..].to_vec();
                self.factory_calib = Some(vals.clone());
                return Ok(vals);
            }
        }
        Err(DriverError::Protocol(
            "Factory calibration subtag 3 not found in 0x6f response".to_string(),
        ))
    }

    /// Start the sensor LED scan glow pattern (`0x39`).
    ///
    /// # Arguments
    /// * `&mut self` - Active [`SensorSession`].
    pub fn glow_start_scan(&mut self) -> Result<()> {
        drv_info!("[LED] Turning sensor LED ON (glow_start_scan 0x39)");
        let _ = self.execute_cmd(&GLOW_START_SCAN, 2)?;
        Ok(())
    }

    /// End the sensor LED scan glow pattern (`0x39`).
    ///
    /// # Arguments
    /// * `&mut self` - Active [`SensorSession`].
    pub fn glow_end_scan(&mut self) -> Result<()> {
        drv_info!("[LED] Turning sensor LED OFF (glow_end_scan 0x39)");
        let _ = self.execute_cmd(&GLOW_END_SCAN, 2)?;
        Ok(())
    }

    /// Arm the 2D capacitive sensor (`0x02`), wait for a finger touch and frame capture on Interrupt IN `0x83`,
    /// verify scan quality via `0x51 00 20 00 00`, and stop acquisition (`0x04`).
    ///
    /// # Arguments
    /// * `&mut self` - Active [`SensorSession`].
    /// * `mode` - Target 2D acquisition mode ([`CaptureMode::Identify`] or [`CaptureMode::Enroll`]).
    /// * `factory_calibration_values` - Per-line factory OTP calibration bytes read from `0x6f`.
    /// * `calib_data` - 13,440-byte host calibration table (`calib_06cb_009a.bin`).
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
                                "Finger lifted too quickly before frame capture completed"
                                    .to_string(),
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
            let status_payload = self.execute_cmd(
                &[WireOpcode::ProgramStatus as u8, 0x00, 0x20, 0x00, 0x00],
                64,
            )?;
            let mut r = ByteReader::new(&status_payload, "ProgramStatus (0x51)");
            let _reserved = r.read_u32_le()?;
            let x = r.read_u16_le()?;
            let y = r.read_u16_le()?;
            let w1 = r.read_u16_le()?;
            let w2 = r.read_u16_le()?;
            let scan_error = r.read_u32_le()?;
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
            // and `GLOW_END_SCAN` (`39 f4010000 ... 01 ff00 ...`) would pulse the LED back ON for 500ms!
            if !finger_touched {
                let _ = self.glow_end_scan();
            }
        }
        res
    }

    /// Verify whether Flash Partition 6 contains a valid `0x5002` clean-slate calibration baseline image.
    pub fn check_clean_slate(&mut self) -> Result<bool> {
        let start = self.read_partition_chunk(6, 1, 0, 0x44)?;
        if start.len() < 0x44 {
            return Ok(false);
        }
        let magic = u16::from_le_bytes([start[0], start[1]]);
        let len = u16::from_le_bytes([start[2], start[3]]) as usize;
        if magic != 0x5002 || len == 0 {
            return Ok(false);
        }
        let hs = &start[4..0x24];
        let zeroes = &start[0x24..0x44];
        if zeroes.iter().any(|&b| b != 0) {
            drv_warn!("[CALIBRATE] Unexpected non-zero padding in Flash Partition 6 header");
            return Ok(false);
        }
        let img = self.read_partition_all(6, 0x44, len)?;
        if img.len() != len {
            return Ok(false);
        }
        let digest = <sha2::Sha256 as sha2::Digest>::digest(&img);
        if hs != digest.as_slice() {
            drv_warn!("[CALIBRATE] Flash Partition 6 clean-slate SHA-256 mismatch");
            return Ok(false);
        }
        Ok(true)
    }

    /// Persist a `0x5002` clean-slate reference image into Flash Partition 6 (`sensor.py`: `persist_clean_slate`).
    pub fn persist_clean_slate(&mut self, clean_slate: &[u8]) -> Result<()> {
        if clean_slate.len() < 0x44 {
            return Err(DriverError::Protocol(
                "clean_slate buffer smaller than 0x44 header".into(),
            ));
        }
        let start = self.read_partition_chunk(6, 1, 0, 0x44)?;
        if start.len() >= 0x44 && start.iter().any(|&b| b != 0xff) {
            if start[..0x44] == clean_slate[..0x44] {
                drv_info!("[CALIBRATE] Clean-slate header already matches Flash Partition 6.");
                return Ok(());
            }
            drv_info!("[CALIBRATE] Erasing existing Flash Partition 6 before writing new clean slate...");
            self.erase_partition(6)?;
        }
        drv_info!(
            "[CALIBRATE] Writing {} B clean-slate baseline to Flash Partition 6...",
            clean_slate.len()
        );
        self.write_partition_all(6, 0, clean_slate)?;
        Ok(())
    }

    /// Run the full 3-iteration 2D capacitive calibration + Flash Partition 6 clean-slate capture
    /// for this exact physical `06cb:009a` sensor (`sensor.py`: `calibrate()`), returning the
    /// 13,440-byte `calib_data` table.
    pub fn calibrate_sensor(&mut self) -> Result<Vec<u8>> {
        const BYTES_PER_LINE: usize = 120;
        const LINES_PER_FRAME: usize = 224;
        const FRAME_SIZE: usize = LINES_PER_FRAME * BYTES_PER_LINE; // 26,880 B

        let factory_calib = self.get_factory_calibration_values()?;
        let mut calib_data: Vec<u8> = Vec::new();

        for iter in 0..3 {
            drv_info!(
                "[CALIBRATE] Iteration {}/3: capturing 2D baseline frames on EP 0x82...",
                iter + 1
            );
            let cmd = build_cmd_02_0199(CaptureMode::Calibrate, &factory_calib, &calib_data);
            let _ = self.execute_cmd(&cmd, 2)?;
            let raw_82 = self
                .transport
                .read_image_data(2 * FRAME_SIZE, Duration::from_secs(10))?;
            let cooked = average_calibration_frames_0199(&raw_82)?;
            process_calibration_results_0199(&mut calib_data, &cooked);
        }

        drv_info!("[CALIBRATE] Capturing blank reference image (clean slate) on EP 0x82...");
        let cmd = build_cmd_02_0199(CaptureMode::Calibrate, &factory_calib, &calib_data);
        let _ = self.execute_cmd(&cmd, 2)?;
        let raw_82 = self
            .transport
            .read_image_data(2 * FRAME_SIZE, Duration::from_secs(10))?;
        let avg_blank = average_calibration_frames_0199(&raw_82)?;

        let mut inner = Vec::with_capacity(4 + avg_blank.len());
        inner.extend_from_slice(&(avg_blank.len() as u16).to_le_bytes());
        inner.extend_from_slice(&avg_blank);
        inner.extend_from_slice(&0u16.to_le_bytes());

        let digest = <sha2::Sha256 as sha2::Digest>::digest(&inner);
        let mut clean_slate = Vec::with_capacity(0x44 + inner.len());
        clean_slate.extend_from_slice(&0x5002u16.to_le_bytes());
        clean_slate.extend_from_slice(&(inner.len() as u16).to_le_bytes());
        clean_slate.extend_from_slice(&digest);
        clean_slate.extend_from_slice(&[0u8; 0x20]);
        clean_slate.extend_from_slice(&inner);

        self.persist_clean_slate(&clean_slate)?;
        self.transport.flush_interrupt_events();
        drv_info!(
            "[CALIBRATE] Sensor 2D calibration complete (calib_data={} B, clean_slate={} B)",
            calib_data.len(),
            clean_slate.len()
        );
        Ok(calib_data)
    }
}

fn calib_clip(x: i32) -> u8 {
    let clamped = x.clamp(-128, 127);
    (clamped as i8) as u8
}

fn calib_scale(x: u8) -> u8 {
    let diff = (x as i32) - 0x80;
    calib_clip((diff * 10) / 0x22)
}

fn calib_add(l: u8, r: u8) -> u8 {
    let ls = (l as i8) as i32;
    let rs = (r as i8) as i32;
    calib_clip(ls + rs)
}

/// Average the second 224-line frame across 2 interleaved lines per calibration row (`sensor.py`: `average`),
/// producing a 13,440-byte (`112 * 120`) cooked frame.
pub(crate) fn average_calibration_frames_0199(raw_calib_data: &[u8]) -> Result<Vec<u8>> {
    const BYTES_PER_LINE: usize = 120;
    const LINES_PER_FRAME: usize = 224;
    const INTERLEAVE_LINES: usize = 2;
    const FRAME_SIZE: usize = LINES_PER_FRAME * BYTES_PER_LINE; // 26,880 B

    if raw_calib_data.len() < 2 * FRAME_SIZE {
        return Err(DriverError::ShortResponse {
            context: "EP 0x82 calibration frame stream",
            expected: 2 * FRAME_SIZE,
            actual: raw_calib_data.len(),
        });
    }
    let frame = &raw_calib_data[FRAME_SIZE..2 * FRAME_SIZE];
    let group_len = INTERLEAVE_LINES * BYTES_PER_LINE;
    let mut out = Vec::with_capacity(112 * BYTES_PER_LINE);
    for group in frame.chunks_exact(group_len) {
        let line0 = &group[..BYTES_PER_LINE];
        let line1 = &group[BYTES_PER_LINE..2 * BYTES_PER_LINE];
        for c in 0..BYTES_PER_LINE {
            let avg = ((line0[c] as u16) + (line1[c] as u16)) / 2;
            out.push(avg as u8);
        }
    }
    Ok(out)
}

/// Scale and accumulate a 13,440-byte cooked calibration frame into `calib_data` (`sensor.py`: `process_calibration_results`).
pub(crate) fn process_calibration_results_0199(calib_data: &mut Vec<u8>, cooked_data: &[u8]) {
    const BYTES_PER_LINE: usize = 120;
    let mut scaled_frame = Vec::with_capacity(cooked_data.len());
    for line in cooked_data.chunks_exact(BYTES_PER_LINE) {
        scaled_frame.extend_from_slice(&line[..8]);
        for &b in &line[8..] {
            scaled_frame.push(calib_scale(b));
        }
    }

    if calib_data.len() == scaled_frame.len() {
        for (ll, rr) in calib_data
            .chunks_exact_mut(BYTES_PER_LINE)
            .zip(scaled_frame.chunks_exact(BYTES_PER_LINE))
        {
            for (l_byte, &r_byte) in ll[8..].iter_mut().zip(rr[8..].iter()) {
                *l_byte = calib_add(*l_byte, r_byte);
            }
        }
    } else {
        *calib_data = scaled_frame;
    }
}
