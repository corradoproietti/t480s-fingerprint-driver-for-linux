//! Wire protocol opcodes, pre-TLS Metallica initialization sequence, and encrypted
//! [`SensorSession`] command dispatcher (`scsCommand.c` @ `0x180116960`).

use crate::error::{DriverError, Result, SensorStatus};
use crate::tls::{TLS_CONTENT_APPLICATION_DATA, TlsHandshakeBuilder, TlsSession};
use crate::usb::Transport;
use crate::{drv_debug, drv_error, drv_info, drv_warn};

/// Wire opcodes used by the Synaptics Metallica MIS (`06cb:009a`) driver (`scsCommand.c` @ `0x180116960`).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireOpcode {
    /// `0x01`: Query 38-byte firmware & hardware version (`VCSFW_CMD_GET_VERSION`).
    GetVersion = 0x01,
    /// `0x02`: Start 2D capacitive frame acquisition (`VCSFW_CMD_ACQ_START`).
    AcqStart = 0x02,
    /// `0x04`: Stop active 2D acquisition (`VCSFW_CMD_NOOP` / `AcqStop`).
    NoopStatus = 0x04,
    /// `0x05`: Sensor microcontroller reset (`VCSFW_CMD_RESET`).
    Reset = 0x05,
    /// `0x06`: RSA-signed security root init or DB2 flash write-enable command.
    SecurityInitOrWriteEnable = 0x06,
    /// `0x19`: Get 68-byte device configuration (`VCSFW_CMD_GET_CONFIG`).
    GetConfig = 0x19,
    /// `0x1a`: DB2 flash cleanup / commit (`VCSFW_CMD_DB_CLEANUP`).
    DbCleanup = 0x1a,
    /// `0x39`: Configure sensor LED scan glow / acquisition (`VCSFW_CMD_CONFIG_ACQ`).
    ConfigureAcquisition = 0x39,
    /// `0x40`: Read flash partition chunk (`VCSFW_CMD_STORAGE_PART_READ`).
    StoragePartRead = 0x40,
    /// `0x43`: Get firmware extension partition status (`VCSFW_CMD_GET_FWEXT_INFO`).
    GetFwextInfo = 0x43,
    /// `0x44`: Tunnel TLS 1.2 handshake flight (`[0x44, 0x00, 0x00, 0x00] || tls_records`).
    TlsHandshakeData = 0x44,
    /// `0x45`: DB2 get biometric database info (`DB2_GET_DB_INFO`).
    Db2GetDbInfo = 0x45,
    /// `0x47`: DB2 write object / template record (`DB2_WRITE_OBJECT`).
    Db2WriteObject = 0x47,
    /// `0x48`: DB2 delete object / template record (`DB2_DELETE_OBJECT`).
    Db2DeleteObject = 0x48,
    /// `0x4a`: DB2 get user record metadata and enrolled finger list (`DB2_GET_OBJECT_INFO`).
    Db2GetObjectInfo = 0x4a,
    /// `0x4b`: DB2 get storage container (`StgWindsor`).
    Db2GetStorage = 0x4b,
    /// `0x51`: Query 2D acquisition program status / scan quality.
    ProgramStatus = 0x51,
    /// `0x5e`: QMatcher Match-on-Chip identify start.
    QmIdentifyStart = 0x5e,
    /// `0x60`: QMatcher Match-on-Chip identify result read.
    QmIdentifyResult = 0x60,
    /// `0x62`: QMatcher Match-on-Chip session end.
    QmSessionEnd = 0x62,
    /// `0x68`: Enrollment update start (`enrollment_update_start`).
    OtaSessionInit = 0x68,
    /// `0x69`: Enrollment create / finish (`create_enrollment` / `enrollment_update_end`).
    OtaEnrollStep = 0x69,
    /// `0x6b`: Enrollment append image & extract template (`append_new_image`).
    OtaReadData = 0x6b,
    /// `0x6f`: Read factory calibration / OTP spot check.
    SpotCheck = 0x6f,
}

impl WireOpcode {
    /// Human-readable name for any wire opcode byte, used in structured error and log messages.
    pub const fn name(opcode: u8) -> &'static str {
        match opcode {
            0x01 => "GetVersion",
            0x02 => "AcqStart",
            0x04 => "NoopStatus",
            0x05 => "Reset",
            0x06 => "SecurityInitOrWriteEnable",
            0x19 => "GetConfig",
            0x1a => "DbCleanup",
            0x39 => "ConfigureAcquisition",
            0x40 => "StoragePartRead",
            0x43 => "GetFwextInfo",
            0x44 => "TlsHandshakeData",
            0x45 => "Db2GetDbInfo",
            0x47 => "Db2WriteObject",
            0x48 => "Db2DeleteObject",
            0x4a => "Db2GetObjectInfo",
            0x4b => "Db2GetStorage",
            0x51 => "ProgramStatus",
            0x5e => "QmIdentifyStart",
            0x60 => "QmIdentifyResult",
            0x62 => "QmSessionEnd",
            0x68 => "OtaSessionInit",
            0x69 => "OtaEnrollStep",
            0x6b => "OtaReadData",
            0x6f => "SpotCheck",
            _ => "UnknownOpcode",
        }
    }
}

/// Parsed 38-byte response from [`WireOpcode::GetVersion`] (`0x01`, `0x180083110`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorVersion {
    pub build_time: u32,
    pub build_num: u32,
    pub version_major: u8,
    pub version_minor: u8,
    pub target: u8,
    /// Product ID: `0x30` (48) = Synaptics Metallica MIS.
    pub product: u8,
    pub silicon_rev: u8,
    pub formal_release: u8,
    pub platform: u8,
    pub patch: u8,
    pub serial_number: [u8; 6],
    pub security_flags: u16,
    pub iface_type: u8,
}

impl SensorVersion {
    /// Parse from the 36-byte payload following the 2-byte status word in the 38-byte response.
    pub fn from_response_payload(payload: &[u8]) -> Result<Self> {
        if payload.len() < 27 {
            return Err(DriverError::ShortResponse {
                context: "GetVersion (0x01)",
                expected: 27,
                actual: payload.len(),
            });
        }
        let mut serial_number = [0u8; 6];
        serial_number.copy_from_slice(&payload[16..22]);
        Ok(Self {
            build_time: u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]),
            build_num: u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]),
            version_major: payload[8],
            version_minor: payload[9],
            target: payload[10],
            product: payload[11],
            silicon_rev: payload[12],
            formal_release: payload[13],
            platform: payload[14],
            patch: payload[15],
            serial_number,
            security_flags: u16::from_le_bytes([payload[22], payload[23]]),
            iface_type: payload[24],
        })
    }

    /// Format firmware version as `"<major>.<minor>.<build> (patch <patch>)"`.
    pub fn formatted_version(&self) -> String {
        format!(
            "{}.{:02}.{:04} (patch {})",
            self.version_major, self.version_minor, self.build_num, self.patch
        )
    }

    /// Return the 6-byte hardware serial number as a 12-character hex string.
    pub fn serial_hex(&self) -> String {
        hex::encode(self.serial_number)
    }
}

/// High-level session wrapping a [`Transport`] and an optional active [`TlsSession`].
///
/// - When `tls` is `None`, requests are sent in plaintext over USB Bulk `0x01`/`0x81`.
/// - When `tls` is `Some(session)` and `session.active == true`, every request is wrapped in a
///   TLS 1.2 `0x17` (`ApplicationData`) record and every response is unwrapped and MAC-verified.
pub struct SensorSession<T: Transport> {
    pub transport: T,
    pub tls: Option<TlsSession>,
    pub factory_calib: Option<Vec<u8>>,
}

impl<T: Transport> SensorSession<T> {
    /// 632-byte initialization security blob (`0x06 0x02 ...`) for `06cb:009a` (Metallica MIS),
    /// required before starting the TLS 1.2 handshake so the sensor loads its TLS root state.
    pub const INIT_HARDCODED_009A_HEX: &str = concat!(
        "06020000014a231406e5542fc6dc3b1aedebe68f55596ad3ca13f6e019994c6f71672fff756fbde0511d09d45978b12ba415b3694a0e763",
        "48c8cfe9dbb9abf86813fc0c67c1005519a6f87360c2fb3e12bd0a9e012b06d9f5c9b44ccc6645b0fbd47afe45c8c874fcb88fbfd18fb7a",
        "9b3241351f256acce689f9586a52b01f8fdcb66cdf3b340b1f9f386d58ca24fdfcdfbcebefb5f3a3c2a08357721040235a20ce1ee2f4f78",
        "56e0d9c27b92cd9b975c86f2c8cab1179868f795da674004b93c15e6ac8aa825a1907f2003cb9e6df096423167b2cabae98c0cd3fd200d1",
        "1c7e0ee1ba5a725f7f2022886f3caa5f68b688ba61bc5cb0190db569efa0a57aa9d76ecdc7440c8920ea02768734221260d083bebb39c17",
        "6d129c01d1a0f1388497171402ba041afd925d71e76ce4905e44fa5fd528759a2c9f12895864b5aa394dc71a4a17161dd82197a10742fa5",
        "f3135c5e78820e36653fa3db535f57c71897242939d7da50f81070ce9ab81c61af6ac29a6c6c4a5df73ffd08542fb540e417939ed117298",
        "051d27736c2faf1c5577a2133b6f60ea7484c692faae2a49c51c8e6f69af77774bad51a9adeea3109d3611d6a437cdc0c356e46a8f9a6d3",
        "054c5519c17c986e54f61f8329006ce184c275984799dbdf5512188fa8ff10aa2ddc25eb697ebdcb156509309ade5d7909a734bf35ec69e",
        "062cb941c2ea4af0958110da93bd2b5f17fc9b1ebdbd8020a3c36f22a68f707226cec716126d6a830219521669bd59fa0e4bd35db6ef0aa",
        "2999d1c0e7acf67e598696cd58cc4bdb1b7c037ee9a085f784c4"
    );

    pub fn new(transport: T) -> Self {
        Self {
            transport,
            tls: None,
            factory_calib: None,
        }
    }

    /// Execute a command and verify the 2-byte status word at the start of the response,
    /// returning the remaining payload bytes.
    pub fn execute_cmd(&mut self, request: &[u8], expected_resp_len: usize) -> Result<Vec<u8>> {
        let opcode = request.first().copied().unwrap_or(0);
        let opcode_name = WireOpcode::name(opcode);
        let raw_resp = self.execute_raw(request, expected_resp_len)?;
        if raw_resp.len() < 2 {
            drv_error!(
                "Short response for 0x{opcode:02x} ({opcode_name}): got {} B, expected >= 2 B",
                raw_resp.len()
            );
            return Err(DriverError::ShortResponse {
                context: opcode_name,
                expected: 2,
                actual: raw_resp.len(),
            });
        }
        let status = SensorStatus::from(u16::from_le_bytes([raw_resp[0], raw_resp[1]]));
        if !status.is_ok() {
            drv_warn!(
                "Sensor command 0x{opcode:02x} ({opcode_name}) returned non-OK status {status}"
            );
            return Err(DriverError::CommandFailed {
                opcode,
                opcode_name,
                status,
            });
        }
        Ok(raw_resp[2..].to_vec())
    }

    /// Execute a raw command (automatically wrapping/unwrapping TLS 1.2 `0x17` records if active,
    /// except for `0x44` handshake tunnel packets).
    pub fn execute_raw(&mut self, request: &[u8], expected_resp_len: usize) -> Result<Vec<u8>> {
        let is_handshake_tunnel =
            request.first().copied() == Some(WireOpcode::TlsHandshakeData as u8);

        if !is_handshake_tunnel {
            if let Some(tls) = self.tls.as_mut().filter(|s| s.active) {
                let wrapped = tls.wrap_record(TLS_CONTENT_APPLICATION_DATA, request)?;
                let rx_wrapped = self.transport.transfer(&wrapped, expected_resp_len + 0x45)?;
                let (ct, unwrapped) = tls.unwrap_record(&rx_wrapped)?;
                if ct != TLS_CONTENT_APPLICATION_DATA {
                    let msg = format!(
                        "Expected TLS ApplicationData (0x17), got content_type=0x{ct:02x}"
                    );
                    drv_error!("{msg}");
                    return Err(DriverError::Tls(msg));
                }
                return Ok(unwrapped);
            }
        }

        self.transport.transfer(request, expected_resp_len)
    }

    /// Verify that the sensor session is alive by querying [`WireOpcode::GetVersion`] (`0x01`, 38B resp).
    ///
    /// Note: `0x04` (`NoopStatus` / `AcqStop`) cannot be used as an idle keepalive ping because
    /// it returns `0x0412` (`SecurityOrDbError`) when no 2D acquisition is running.
    pub fn ping_status(&mut self) -> Result<()> {
        let _ = self.get_version()?;
        Ok(())
    }

    /// Query sensor firmware and hardware version (`WireOpcode::GetVersion` = `0x01`, 38B resp).
    pub fn get_version(&mut self) -> Result<SensorVersion> {
        let payload = self.execute_cmd(&[WireOpcode::GetVersion as u8], 38)?;
        SensorVersion::from_response_payload(&payload)
    }

    /// Query 68-byte sensor hardware configuration (`WireOpcode::GetConfig` = `0x19`).
    pub fn get_config(&mut self) -> Result<Vec<u8>> {
        self.execute_cmd(&[WireOpcode::GetConfig as u8], 68)
    }

    /// Read a chunk from a flash partition (`WireOpcode::StoragePartRead` = `0x40`,
    /// 13B req `[0x40, part_id, sub_id, 0, 0, offset_le32, size_le32]` -> `2B status + 4B len + 2B pad + data`).
    pub fn read_partition_chunk(
        &mut self,
        part_id: u8,
        sub_id: u8,
        offset: u32,
        len: u32,
    ) -> Result<Vec<u8>> {
        let mut req = [0u8; 13];
        req[0] = WireOpcode::StoragePartRead as u8;
        req[1] = part_id;
        req[2] = sub_id;
        req[3..5].copy_from_slice(&0u16.to_le_bytes());
        req[5..9].copy_from_slice(&offset.to_le_bytes());
        req[9..13].copy_from_slice(&len.to_le_bytes());

        let payload = self.execute_cmd(&req, (len as usize) + 16)?;
        if payload.len() < 6 {
            return Err(DriverError::ShortResponse {
                context: "StoragePartRead (0x40)",
                expected: 6,
                actual: payload.len(),
            });
        }
        let actual_len = (u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize)
            .min(payload.len().saturating_sub(6));
        Ok(payload[6..6 + actual_len].to_vec())
    }

    /// Read Flash Partition 1 (`0x1000` bytes) and extract the host-sensor [`crate::tls::PairingBundle`].
    pub fn read_tls_flash_bundle(&mut self) -> Result<crate::tls::PairingBundle> {
        let flash_data = self.read_partition_chunk(0x01, 0x01, 0, 0x1000)?;
        crate::tls::PairingBundle::from_tls_flash_partition(&flash_data)
    }

    /// Reboot the sensor (`WireOpcode::Reset` = `0x05`, `[0x05, 0x02, 0x00]`) to release active TLS state.
    pub fn reboot_sensor(&mut self) -> Result<()> {
        drv_debug!("Rebooting sensor (0x05 0x02 0x00) to release TLS session");
        let _ = self.execute_cmd(&[WireOpcode::Reset as u8, 0x02, 0x00], 2)?;
        self.tls = None;
        Ok(())
    }

    /// Run the full Metallica (`product == 0x30`) pre-TLS initialization sequence:
    /// 1. Send `0x01` (`GetVersion`)
    /// 2. Send `0x19` (`GetConfig`)
    /// 3. Send `0x43 0x02` (`GetFwextInfo` on Partition 2)
    /// 4. Send `0x06 0x02 ...` (`INIT_HARDCODED_009A`)
    pub fn initialize_metallica(&mut self) -> Result<SensorVersion> {
        drv_debug!("Init step 1/4: Querying SensorVersion (0x01)");
        let version = self.get_version()?;
        drv_info!(
            "Sensor initialized: FW {}, product=0x{:02x}, serial={}, sec_flags=0x{:04x}",
            version.formatted_version(),
            version.product,
            version.serial_hex(),
            version.security_flags
        );

        drv_debug!("Init step 2/4: Querying SensorConfig (0x19)");
        let _ = self.get_config()?;

        drv_debug!("Init step 3/4: Querying Partition 2 FwextInfo (0x43 0x02)");
        let _ = self.execute_cmd(&[WireOpcode::GetFwextInfo as u8, 0x02], 0xf0);

        drv_debug!("Init step 4/4: Sending Metallica security init blob (0x06 0x02)");
        let init_blob = hex::decode(Self::INIT_HARDCODED_009A_HEX).expect("valid hex constant");
        let _ = self.execute_cmd(&init_blob, 64)?;

        Ok(version)
    }

    /// Establish an encrypted TLS 1.2 session with the sensor using a [`crate::tls::PairingBundle`].
    pub fn establish_tls_session(&mut self, bundle: &crate::tls::PairingBundle) -> Result<()> {
        let host_priv_bytes = hex::decode(&bundle.host_private_key_hex)
            .map_err(|e| DriverError::Crypto(format!("Invalid host_private_key_hex: {e}")))?;
        let signing_key = p256::ecdsa::SigningKey::from_slice(&host_priv_bytes)
            .map_err(|e| DriverError::Crypto(format!("Invalid P-256 signing key: {e}")))?;
        let host_cert = hex::decode(&bundle.host_cert_hex)
            .map_err(|e| DriverError::Crypto(format!("Invalid host_cert_hex: {e}")))?;
        let sensor_pub = hex::decode(&bundle.sensor_public_key_hex)
            .map_err(|e| DriverError::Crypto(format!("Invalid sensor_public_key_hex: {e}")))?;

        let mut hs = TlsHandshakeBuilder::new();
        drv_debug!("TLS 1.2: Sending Flight 1 (ClientHello over 0x44)");
        let flight1 = hs.build_client_hello_flight();
        let resp1 = self.execute_raw(&flight1, 2048)?;
        hs.process_server_flight(&resp1)?;

        drv_debug!(
            "TLS 1.2: Sending Flight 2 (cipher_suite=0x{:04x})",
            hs.selected_cipher_suite
        );
        let (flight2, mut session) =
            hs.build_client_second_flight(&host_cert, &signing_key, &sensor_pub)?;
        let resp2 = self.execute_raw(&flight2, 2048)?;
        hs.process_server_finished(&resp2, &mut session)?;

        // Reset sequence numbers to 0 for ApplicationData traffic (`0x18007b3c0`)
        session.client_seq_num = 0;
        session.server_seq_num = 0;
        self.tls = Some(session);

        drv_info!("TLS 1.2 session established (cipher=0xC005 ECDH_ECDSA_WITH_AES_256_CBC_SHA256)");
        Ok(())
    }
}
