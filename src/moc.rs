//! Match-on-Chip (MoC) QMatcher biometric verification (`0x5e..0x62`) and 12-stage enrollment
//! (`0x68..0x6b`) for Synaptics Metallica MIS (`06cb:009a`).
//!
//! Lower-level 2D capacitive timeslot compilation (`0x02`) and on-flash DB2 database records
//! (`0x45..0x4b`) live in [`crate::capture`] and [`crate::db2`] respectively and are re-exported
//! here for ergonomic access.

use std::time::Duration;

pub use crate::capture::{CaptureMode, build_cmd_02_0199};
pub use crate::db2::{
    Db2DatabaseInfo, Db2FingerEntry, Db2UserRecord, Db2UserStorage, STG_WINDSOR_NAME,
    encode_db2_template_record, encode_sid_identity_for_uid, finger_subtype_name,
    format_sid_for_uid, parse_sid_identity,
};
use crate::error::{DriverError, Result};
use crate::protocol::{ByteReader, SensorSession, WireOpcode};
use crate::usb::Transport;
use crate::{drv_error, drv_info, drv_warn};

/// Match-on-Chip verification / identification result returned by `0x5e`/`0x60`/`0x62`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchVerifyResult {
    pub matched: bool,
    pub matched_object_id: u16,
    pub matched_user_id: u16,
    pub matched_finger_id: u16,
    pub match_score: u32,
}

impl MatchVerifyResult {
    /// Construct a negative (`matched = false`) verification result.
    ///
    /// # Arguments
    /// *(none)*
    pub const fn no_match() -> Self {
        Self {
            matched: false,
            matched_object_id: 0,
            matched_user_id: 0,
            matched_finger_id: 0,
            match_score: 0,
        }
    }
}

/// Parsed response from the second `0x6b` (`OtaReadData` / `append_new_image`) enrollment call.
struct EnrollmentStepOutput {
    header: Vec<u8>,
    new_template: Vec<u8>,
    final_tid: Option<Vec<u8>>,
}

/// Parse the TLV sub-blocks (`0x38`-byte crypto header + payload) returned by `0x6b` (`OtaReadData`).
///
/// # Arguments
/// * `res_6b` - Decrypted payload bytes returned by the second `0x6b` command in an enrollment step.
fn parse_enrollment_step_response(res_6b: &[u8]) -> Result<EnrollmentStepOutput> {
    const MAGIC_HEADER_LEN: usize = 0x38;

    let mut r = ByteReader::new(res_6b, "OtaReadData (0x6b)");
    let total_len = r.read_u16_le()? as usize;
    let mut slice = r.read_slice(total_len.min(r.remaining_len()))?;

    let mut new_template = Vec::new();
    let mut header = Vec::new();
    let mut final_tid = None;

    while slice.len() >= 4 {
        let tag = u16::from_le_bytes([slice[0], slice[1]]);
        let clen = u16::from_le_bytes([slice[2], slice[3]]) as usize;
        let step = MAGIC_HEADER_LEN + clen;
        if slice.len() < step {
            break;
        }
        match tag {
            0 => new_template = slice[..step].to_vec(),
            1 => header = slice[MAGIC_HEADER_LEN..step].to_vec(),
            3 => final_tid = Some(slice[MAGIC_HEADER_LEN..step].to_vec()),
            _ => {}
        }
        slice = &slice[step..];
    }

    Ok(EnrollmentStepOutput {
        header,
        new_template,
        final_tid,
    })
}

impl<T: Transport> SensorSession<T> {
    /// Perform on-chip 1:N fingerprint identification on `06cb:009a`, invoking `on_retry` whenever
    /// a retryable finger scan quality error requires another touch.
    ///
    /// # Arguments
    /// * `&mut self` - Active [`SensorSession`].
    /// * `calib_data` - 13,440-byte sensor calibration table (`calib_06cb_009a.bin`).
    /// * `on_retry` - Callback invoked with the retryable [`DriverError`] before re-arming the sensor.
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
                Err(e) => return Err(e),
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
                return Ok(MatchVerifyResult::no_match());
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
                    return Ok(MatchVerifyResult::no_match());
                }
                Err(e) => return Err(e),
            };

            let mut r = ByteReader::new(&payload, "QmIdentifyResult (0x60)");
            let dict_len = r.read_u16_le()? as usize;
            let dict_slice = r.read_slice(dict_len.min(r.remaining_len()))?;

            let mut matched_user_id = 0u16;
            let mut matched_finger_id = 0u16;
            let mut d = ByteReader::new(dict_slice, "QmIdentifyResult TLV");
            while d.remaining_len() >= 4 {
                let tag = d.read_u16_le()?;
                let tlen = d.read_u16_le()? as usize;
                if d.remaining_len() < tlen {
                    break;
                }
                let val = d.read_slice(tlen)?;
                if tag == 1 && val.len() >= 4 {
                    matched_user_id = u32::from_le_bytes([val[0], val[1], val[2], val[3]]) as u16;
                } else if tag == 3 && val.len() >= 2 {
                    matched_finger_id = u16::from_le_bytes([val[0], val[1]]);
                }
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
        let _ = self.execute_raw(
            &[WireOpcode::QmSessionEnd as u8, 0x00, 0x00, 0x00, 0x00],
            16,
        );
        res
    }

    /// Run a complete interactive Match-on-Chip fingerprint enrollment on `06cb:009a`.
    ///
    /// # Arguments
    /// * `&mut self` - Active [`SensorSession`].
    /// * `uid` - Linux user ID (e.g. `1000` -> `S-1-5-21-111111111-1111111111-1111111111-1000`).
    /// * `subtype` - Finger subtype (`1..=10`).
    /// * `calib_data` - 13,440-byte sensor calibration blob (`calib_06cb_009a.bin`).
    /// * `on_stage` - Callback `(completed_stages, header_bytes, retry_err)` invoked after each valid touch or retry.
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
        let _ = self.db2_delete_user_finger(uid, subtype);

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
                drv_info!(
                    "Enroll stage {}: waiting for finger touch...",
                    stage_count + 1
                );
                let step_res = (|| -> Result<EnrollmentStepOutput> {
                    self.glow_start_scan()?;
                    self.capture_finger_frame(CaptureMode::Enroll, &factory_calib, calib_data)?;

                    // enrollment_update_start(key): pack('<BLL', 0x68, key, 0)
                    let mut req_68 = [0u8; 9];
                    req_68[0] = WireOpcode::OtaSessionInit as u8;
                    req_68[1..5].copy_from_slice(&key.to_le_bytes());
                    let resp_68 = self.execute_cmd(&req_68, 16)?;
                    let mut r68 = ByteReader::new(&resp_68, "OtaSessionInit (0x68)");
                    key = r68.read_u32_le()?;

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

                    parse_enrollment_step_response(&res_6b)
                })();

                // finally: enrollment_update_end() -> pack('<BL', 0x69, 0)
                let _ = self.execute_raw(&end_req, 16);

                match step_res {
                    Ok(step_out) => {
                        consecutive_retries = 0;
                        template = step_out.new_template;
                        stage_count += 1;
                        drv_info!(
                            "Enroll stage {stage_count} captured successfully (template={} B)",
                            template.len()
                        );
                        on_stage(stage_count, &step_out.header, None);
                        if let Some(t) = step_out.final_tid {
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

            let tinfo = encode_db2_template_record(subtype, &template, &final_tid);
            let (user_dbid, stg_dbid) = self.db2_lookup_or_create_user(uid)?;
            let recid = self.db2_new_record(user_dbid, 0x000b, stg_dbid, &tinfo)?;
            let _ = self.transport.wait_interrupt_event(Duration::from_secs(10));
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
        /// Create a new [`MockTransport`] preloaded with canned bulk `responses` and `interrupts`.
        ///
        /// # Arguments
        /// * `responses` - Queue of raw response payloads returned by [`Transport::transfer`].
        /// * `interrupts` - Queue of interrupt events returned by [`Transport::wait_interrupt_event`].
        fn new(responses: Vec<Vec<u8>>, interrupts: Vec<Result<SensorInterruptEvent>>) -> Self {
            Self {
                requests: Vec::new(),
                responses: responses.into(),
                interrupts: interrupts.into(),
            }
        }
    }

    impl Transport for MockTransport {
        /// Record `request` and pop the next canned response payload (or `[0x00, 0x00]` if empty).
        ///
        /// # Arguments
        /// * `&mut self` - Mutable [`MockTransport`] state.
        /// * `request` - Outgoing command frame bytes.
        /// * `_expected_resp_len` - Ignored in mock transport.
        fn transfer(&mut self, request: &[u8], _expected_resp_len: usize) -> Result<Vec<u8>> {
            self.requests.push(request.to_vec());
            Ok(self
                .responses
                .pop_front()
                .unwrap_or_else(|| vec![0x00, 0x00]))
        }

        /// Pop the next canned interrupt event (or return `Timeout` if empty).
        ///
        /// # Arguments
        /// * `&mut self` - Mutable [`MockTransport`] state.
        /// * `_timeout` - Ignored in mock transport.
        fn wait_interrupt_event(&mut self, _timeout: Duration) -> Result<SensorInterruptEvent> {
            self.interrupts
                .pop_front()
                .unwrap_or(Err(DriverError::Usb(rusb::Error::Timeout)))
        }
    }

    /// Verify that [`SensorSession::db2_delete_object`] treats `0x04b3` (`ObjectNotFound`) as idempotent success.
    ///
    /// # Arguments
    /// *(none)*
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

    /// Verify that [`build_cmd_02_0199`] produces the exact 13,801-byte SHA-256 reference payload.
    ///
    /// # Arguments
    /// *(none)*
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

    /// Verify that [`encode_sid_identity_for_uid`] and [`parse_sid_identity`] round-trip cleanly.
    ///
    /// # Arguments
    /// *(none)*
    #[test]
    fn test_sid_identity_roundtrip() {
        let blob = encode_sid_identity_for_uid(1000);
        assert_eq!(blob.len(), 0x4c);
        let sid = parse_sid_identity(&blob).expect("should parse SID");
        assert_eq!(sid, "S-1-5-21-111111111-1111111111-1111111111-1000");
    }

    /// Verify that [`SynapticsPrintMetadata::to_bytes`] and [`SynapticsPrintMetadata::from_bytes`] round-trip cleanly.
    ///
    /// # Arguments
    /// *(none)*
    #[test]
    fn test_synaptics_print_metadata_roundtrip() {
        use crate::tod::SynapticsPrintMetadata;
        let orig = SynapticsPrintMetadata {
            uid: 1000,
            user_dbid: 0x0003,
            template_dbid: 0x0007,
            synaptics_subtype: 2,
            fp_finger: 7,
        };
        let bytes = orig.to_bytes();
        assert_eq!(&bytes[0..4], b"SYN9");
        let parsed = SynapticsPrintMetadata::from_bytes(&bytes).expect("valid SYN9 metadata");
        assert_eq!(parsed, orig);
        assert!(SynapticsPrintMetadata::from_bytes(b"BAD!0123456789ab").is_none());
    }

    /// Verify that [`ByteReader`] returns [`DriverError::ShortResponse`] when reading past buffer bounds.
    ///
    /// # Arguments
    /// *(none)*
    #[test]
    fn test_byte_reader_bounds_checking() {
        let mut r = ByteReader::new(&[0x34, 0x12, 0x78], "test");
        assert_eq!(r.read_u16_le().unwrap(), 0x1234);
        assert_eq!(r.remaining_len(), 1);
        assert!(matches!(
            r.read_u16_le(),
            Err(DriverError::ShortResponse {
                context: "test",
                expected: 4,
                actual: 3
            })
        ));
    }

    /// Verify 2D capacitive calibration frame averaging and signed-clipped accumulation for sensor `0x0199`.
    #[test]
    fn test_calibration_frame_averaging_and_scaling() {
        use crate::capture::{average_calibration_frames_0199, process_calibration_results_0199};
        let mut raw = vec![0x80u8; 2 * 224 * 120];
        // Set second frame (offset 26880) first interleaved pair to 100 and 140 -> avg = 120
        raw[26880 + 8] = 100;
        raw[26880 + 120 + 8] = 140;
        let avg = average_calibration_frames_0199(&raw).expect("averaging should succeed");
        assert_eq!(avg.len(), 13440);
        assert_eq!(avg[8], 120);

        let mut calib = Vec::new();
        process_calibration_results_0199(&mut calib, &avg);
        assert_eq!(calib.len(), 13440);
        // (120 - 128) * 10 / 34 = -80 / 34 = -2 -> 0xfe (254)
        assert_eq!(calib[8], 0xfe);
        // Neutral 0x80 bytes scale to 0
        assert_eq!(calib[9], 0x00);

        // Second iteration accumulates signed values (-2 + -2 = -4 -> 0xfc)
        process_calibration_results_0199(&mut calib, &avg);
        assert_eq!(calib[8], 0xfc);
    }
}
