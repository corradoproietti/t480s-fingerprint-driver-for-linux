//! Custom Synaptics TLS 1.2 cryptographic engine and Flash Partition 1 pairing parser
//! (`scsTLS.c` @ `0x180078f90..0x18007ef8c`, `scsSecMgmt.c` @ `0x18006ad90..0x180073350`).
//!
//! ## Protocol Overview
//!
//! Once the Synaptics Metallica MIS (`06cb:009a`) sensor completes its 4-step pre-TLS
//! initialization ([`crate::protocol::SensorSession::initialize_metallica`]), all subsequent
//! biometric and database commands must be encrypted inside a TLS 1.2 session using cipher suite
//! `TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA256` (`0xC005`).
//!
//! ### Key Synaptics TLS 1.2 Quirks (Reverse-Engineered from `synaWudfBioUsb.dll`)
//! 1. **Handshake Tunneling (`0x44`)**: Both client handshake flights (`ClientHello` and
//!    `Certificate + ClientKeyExchange + CertificateVerify + ChangeCipherSpec + Finished`) are
//!    prefixed with the 4-byte wire header `[0x44, 0x00, 0x00, 0x00]`.
//! 2. **`ClientHello` Extensions Length**: The 2-byte extensions total length field in `ClientHello`
//!    is encoded as `extensions.len() - 2` (`0x000a` for 12 bytes of extensions).
//! 3. **Key Expansion Seed Order**: Both `"master secret"` and `"key expansion"` calls to
//!    `PRF_SHA256` use `seed = client_random || server_random` in the exact same order.
//! 4. **Custom Record MAC (`0x18007a350`)**: The 32-byte `HMAC-SHA256` inside encrypted TLS records
//!    is computed over `ContentType(1B) || 0x0303(2B) || PlaintextLen_BE16(2B) || Plaintext`,
//!    **omitting** the 64-bit sequence number from the MAC input.
//! 5. **Transcript before `ServerFinished`**: The client `Finished` message (`0x14`) is **not**
//!    appended to the handshake transcript before verifying the sensor's `ServerFinished` MAC.

use std::fs;
use std::path::Path;

use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use p256::SecretKey;
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{DriverError, Result};
use crate::{drv_debug, drv_error, drv_info};

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// Wire command prefix used to tunnel TLS 1.2 handshake flights (`scsTLS.c` @ `0x18007af90`):
/// `[0x44, 0x00, 0x00, 0x00]`.
pub const TLS_HANDSHAKE_TUNNEL_PREFIX: [u8; 4] = [0x44, 0x00, 0x00, 0x00];

/// Hardcoded pre-TLS `GWK` derivation seed from `synaWudfBioUsb.dll` used to decrypt Partition 1 Block 4.
pub const PASSWORD_HARDCODED: [u8; 32] = [
    0x71, 0x7c, 0xd7, 0x2d, 0x09, 0x62, 0xbc, 0x4a, 0x28, 0x46, 0x13, 0x8d, 0xbb, 0x2c, 0x24, 0x19,
    0x25, 0x12, 0xa7, 0x64, 0x07, 0x06, 0x5f, 0x38, 0x38, 0x46, 0x13, 0x9d, 0x4b, 0xec, 0x20, 0x33,
];

/// Hardcoded pre-TLS `GWK_SIGN` derivation seed from `synaWudfBioUsb.dll` used to verify Partition 1 Block 4.
pub const GWK_SIGN_HARDCODED: [u8; 32] = [
    0x3a, 0x4c, 0x76, 0xb7, 0x6a, 0x97, 0x98, 0x1d, 0x12, 0x74, 0x24, 0x7e, 0x16, 0x66, 0x10, 0xe7,
    0x7f, 0x4d, 0x9c, 0x9d, 0x07, 0xd3, 0xc7, 0x28, 0xe5, 0x32, 0x91, 0x6b, 0xdd, 0x28, 0xb4, 0x54,
];

/// TLS 1.2 ContentType: `ChangeCipherSpec` (`0x14`).
pub const TLS_CONTENT_CHANGE_CIPHER_SPEC: u8 = 0x14;
/// TLS 1.2 ContentType: `Alert` (`0x15`).
pub const TLS_CONTENT_ALERT: u8 = 0x15;
/// TLS 1.2 ContentType: `Handshake` (`0x16`).
pub const TLS_CONTENT_HANDSHAKE: u8 = 0x16;
/// TLS 1.2 ContentType: `ApplicationData` (`0x17`).
pub const TLS_CONTENT_APPLICATION_DATA: u8 = 0x17;

/// TLS 1.2 version bytes (`0x03, 0x03`).
pub const TLS_VERSION_1_2: [u8; 2] = [0x03, 0x03];

/// Negotiated cipher suite on `06cb:009a` (`TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA256`).
pub const CIPHER_SUITE_ECDH_ECDSA_AES256_CBC_SHA256: u16 = 0xC005;

/// Persistent host-sensor pairing credentials (`scsSecMgmt.c` @ `0x18006ad90..0x180073350`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingBundle {
    /// Host P-256 private key scalar in big-endian (32 bytes, hex-encoded).
    pub host_private_key_hex: String,
    /// Host TLS certificate blob (TLV Block ID 3 on Flash Partition 1, hex-encoded).
    pub host_cert_hex: String,
    /// Sensor static ECDH P-256 public key (65 bytes uncompressed SEC1 `04 || X_be || Y_be`, hex-encoded).
    pub sensor_public_key_hex: String,
}

impl PairingBundle {
    /// Load a cached [`PairingBundle`] JSON file from disk.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        serde_json::from_str(&content)
            .map_err(|e| DriverError::Crypto(format!("Invalid pairing JSON: {e}")))
    }

    /// Save this [`PairingBundle`] to a JSON file on disk.
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| DriverError::Crypto(format!("Serialize pairing JSON failed: {e}")))?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Parse Flash Partition 1 (`0x1000` bytes read in plaintext via opcode `0x40`) and decrypt
    /// the host private key using the machine's DMI `product_name` and `product_serial`
    /// (or fallback `("VirtualBox", "0")`).
    ///
    /// ### Partition 1 TLV Layout
    /// Each block has a 36-byte header `[id: u16, sz: u16, sha256: [u8; 32]]` followed by `body[sz]`:
    /// - **Block `id = 3`** (`184` B): Host TLS certificate (`tls_cert`).
    /// - **Block `id = 4`** (`161` B): AES-256-CBC encrypted + HMAC-SHA256 authenticated host P-256 private key.
    /// - **Block `id = 6`** (`400` B): Sensor static ECDH P-256 public key (`X_le` at `0x08..0x28`, `Y_le` at `0x4c..0x6c`).
    pub fn from_tls_flash_partition(flash_data: &[u8]) -> Result<Self> {
        let mut tls_cert: Option<Vec<u8>> = None;
        let mut priv_blob: Option<Vec<u8>> = None;
        let mut sensor_pub_sec1: Option<Vec<u8>> = None;

        let mut pos = 0usize;
        while pos + 36 <= flash_data.len() {
            let id = u16::from_le_bytes([flash_data[pos], flash_data[pos + 1]]);
            let sz = u16::from_le_bytes([flash_data[pos + 2], flash_data[pos + 3]]) as usize;
            if id == 0xffff {
                break;
            }
            let expected_hash = &flash_data[pos + 4..pos + 36];
            pos += 36;
            if pos + sz > flash_data.len() {
                return Err(DriverError::Tls(format!(
                    "Truncated TLV block id=0x{id:04x} (size={sz}) in Partition 1"
                )));
            }
            let body = &flash_data[pos..pos + sz];
            pos += sz;

            let actual_hash = Sha256::digest(body);
            if actual_hash.as_slice() != expected_hash {
                return Err(DriverError::Tls(format!(
                    "SHA-256 mismatch on Partition 1 TLV block id=0x{id:04x}"
                )));
            }

            drv_debug!("Parsed Partition 1 TLS flash TLV block id={id} (size={sz} B)");
            match id {
                3 => {
                    tls_cert = Some(body.to_vec());
                }
                4 => {
                    priv_blob = Some(body.to_vec());
                }
                6 => {
                    if body.len() < 0x90 {
                        return Err(DriverError::Tls(
                            "Block 6 (ECDH) shorter than 0x90 bytes".into(),
                        ));
                    }
                    // Convert little-endian coordinates X (0x08..0x28) and Y (0x4c..0x6c) to big-endian SEC1
                    let mut x_be = [0u8; 32];
                    let mut y_be = [0u8; 32];
                    x_be.copy_from_slice(&body[0x08..0x28]);
                    y_be.copy_from_slice(&body[0x4c..0x6c]);
                    x_be.reverse();
                    y_be.reverse();

                    let mut sec1 = Vec::with_capacity(65);
                    sec1.push(0x04);
                    sec1.extend_from_slice(&x_be);
                    sec1.extend_from_slice(&y_be);
                    p256::PublicKey::from_sec1_bytes(&sec1).map_err(|e| {
                        DriverError::Crypto(format!("Block 6 ECDH public key not on P-256: {e}"))
                    })?;
                    sensor_pub_sec1 = Some(sec1);
                }
                _ => {}
            }
        }

        let tls_cert = tls_cert
            .ok_or_else(|| DriverError::Tls("Missing Block 3 (tls_cert) in Partition 1".into()))?;
        let priv_blob = priv_blob
            .ok_or_else(|| DriverError::Tls("Missing Block 4 (priv_blob) in Partition 1".into()))?;
        let sensor_pub_sec1 = sensor_pub_sec1
            .ok_or_else(|| DriverError::Tls("Missing Block 6 (ecdh_blob) in Partition 1".into()))?;

        let host_priv_d_be = decrypt_host_priv_blob(&priv_blob)?;

        Ok(Self {
            host_private_key_hex: hex::encode(host_priv_d_be),
            host_cert_hex: hex::encode(tls_cert),
            sensor_public_key_hex: hex::encode(sensor_pub_sec1),
        })
    }
}

/// Derive `(psk_encryption_key, psk_validation_key)` from DMI `product_name` and `product_serial`.
pub fn derive_host_psk_keys(product_name: &str, product_serial: &str) -> ([u8; 32], [u8; 32]) {
    let mut hw_key = Vec::with_capacity(product_name.len() + product_serial.len() + 2);
    hw_key.extend_from_slice(product_name.as_bytes());
    hw_key.push(0);
    hw_key.extend_from_slice(product_serial.as_bytes());
    hw_key.push(0);

    let enc_vec = tls12_prf_sha256(&PASSWORD_HARDCODED, b"GWK", &hw_key, 32);
    let mut enc_key = [0u8; 32];
    enc_key.copy_from_slice(&enc_vec);

    let val_vec = tls12_prf_sha256(&enc_key, b"GWK_SIGN", &GWK_SIGN_HARDCODED, 32);
    let mut val_key = [0u8; 32];
    val_key.copy_from_slice(&val_vec);

    (enc_key, val_key)
}

/// Decrypt Block 4 (`priv_blob`) from Partition 1, trying the host DMI `product_name`/`product_serial`
/// and falling back to `("VirtualBox", "0")` if the sensor was paired without DMI access.
fn decrypt_host_priv_blob(body: &[u8]) -> Result<[u8; 32]> {
    if body.len() < 1 + 16 + 32 + 32 || body[0] != 0x02 {
        return Err(DriverError::Tls(
            "Invalid Block 4 private key blob header".into(),
        ));
    }
    let c = &body[1..body.len() - 32];
    let hs = &body[body.len() - 32..];

    let mut candidates = Vec::new();
    let dmi_name = fs::read_to_string("/sys/devices/virtual/dmi/id/product_name")
        .or_else(|_| fs::read_to_string("/sys/class/dmi/id/product_name"))
        .ok()
        .map(|s| s.trim().to_string());
    let dmi_serial = fs::read_to_string("/sys/devices/virtual/dmi/id/product_serial")
        .or_else(|_| fs::read_to_string("/sys/class/dmi/id/product_serial"))
        .ok()
        .map(|s| s.trim().to_string())
        .or_else(|| std::env::var("T480S_PRODUCT_SERIAL").ok());

    if let (Some(name), Some(serial)) = (&dmi_name, &dmi_serial) {
        candidates.push((name.clone(), serial.clone()));
    }
    candidates.push(("VirtualBox".to_string(), "0".to_string()));

    for (prod_name, prod_serial) in &candidates {
        let (enc_key, val_key) = derive_host_psk_keys(prod_name, prod_serial);
        let expected_sig = hmac_sha256(&val_key, c);
        if expected_sig == hs {
            drv_info!(
                "Verified Partition 1 host private key blob HMAC-SHA256 (DMI product_name='{prod_name}')"
            );
            let iv = &c[0..16];
            let mut decrypted = c[16..].to_vec();
            Aes256CbcDec::new((&enc_key).into(), iv.into())
                .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut decrypted)
                .map_err(|e| DriverError::Crypto(format!("Decrypt Block 4 failed: {e}")))?;

            let pad_len = *decrypted.last().unwrap() as usize;
            if pad_len == 0 || pad_len > 16 || decrypted.len() < 0x60 + pad_len {
                return Err(DriverError::Tls("Invalid PKCS#7 padding in Block 4".into()));
            }
            // Plaintext layout: X_le (0x00..0x20) || Y_le (0x20..0x40) || d_le (0x40..0x60)
            let mut d_be = [0u8; 32];
            d_be.copy_from_slice(&decrypted[0x40..0x60]);
            d_be.reverse();
            return Ok(d_be);
        }
    }

    Err(DriverError::Tls(
        "Partition 1 Block 4 HMAC mismatch: reading /sys/class/dmi/id/product_serial requires root"
            .into(),
    ))
}

/// TLS 1.2 PRF based on `P_SHA256` (`scsTLS.c` / `palCrypto.c` @ `0x180047830`):
/// `PRF(secret, label, seed) = P_SHA256(secret, label || seed)`.
pub fn tls12_prf_sha256(secret: &[u8], label: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut label_and_seed = Vec::with_capacity(label.len() + seed.len());
    label_and_seed.extend_from_slice(label);
    label_and_seed.extend_from_slice(seed);

    let mut a_i = hmac_sha256(secret, &label_and_seed);
    let mut output = Vec::with_capacity(out_len + 32);

    while output.len() < out_len {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(secret).expect("HMAC accepts any key size");
        mac.update(&a_i);
        mac.update(&label_and_seed);
        let block = mac.finalize().into_bytes();
        output.extend_from_slice(&block);

        if output.len() < out_len {
            a_i = hmac_sha256(secret, &a_i);
        }
    }

    output.truncate(out_len);
    output
}

/// Compute standard 32-byte `HMAC-SHA256(key, data)`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Derived TLS 1.2 session keys (`scsTLS.c` @ `0x18007a4c0` and `0x18007a650`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSessionKeys {
    /// 48-byte TLS 1.2 `master_secret`.
    pub master_secret: [u8; 48],
    /// 32-byte HMAC-SHA256 key for host-to-sensor records.
    pub client_write_mac_key: [u8; 32],
    /// 32-byte HMAC-SHA256 key for sensor-to-host records.
    pub server_write_mac_key: [u8; 32],
    /// 32-byte AES-256-CBC key for host-to-sensor records.
    pub client_write_key: [u8; 32],
    /// 32-byte AES-256-CBC key for sensor-to-host records.
    pub server_write_key: [u8; 32],
}

impl TlsSessionKeys {
    /// Derive the 48-byte `master_secret` and 128-byte `key_block` from `pre_master_secret`,
    /// `client_random` (32 B), and `server_random` (32 B), matching `scsTLS.c` (`0x18007a4c0`, `0x18007a650`).
    /// Note that Synaptics uses `seed = client_random || server_random` for **both** `"master secret"`
    /// and `"key expansion"`.
    pub fn derive(
        pre_master_secret: &[u8],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
    ) -> Self {
        let mut seed = [0u8; 64];
        seed[0..32].copy_from_slice(client_random);
        seed[32..64].copy_from_slice(server_random);

        let ms_vec = tls12_prf_sha256(pre_master_secret, b"master secret", &seed, 48);
        let mut master_secret = [0u8; 48];
        master_secret.copy_from_slice(&ms_vec);

        let kb = tls12_prf_sha256(&master_secret, b"key expansion", &seed, 128);

        let mut client_write_mac_key = [0u8; 32];
        let mut server_write_mac_key = [0u8; 32];
        let mut client_write_key = [0u8; 32];
        let mut server_write_key = [0u8; 32];

        client_write_mac_key.copy_from_slice(&kb[0x00..0x20]);
        server_write_mac_key.copy_from_slice(&kb[0x20..0x40]);
        client_write_key.copy_from_slice(&kb[0x40..0x60]);
        server_write_key.copy_from_slice(&kb[0x60..0x80]);

        Self {
            master_secret,
            client_write_mac_key,
            server_write_mac_key,
            client_write_key,
            server_write_key,
        }
    }

    /// Compute the 12-byte TLS 1.2 `Finished` verify_data (`0x18007a9c0` / `0x18007bee0`).
    pub fn compute_finished_verify_data(
        &self,
        is_client: bool,
        handshake_transcript: &[u8],
    ) -> [u8; 12] {
        let transcript_hash = Sha256::digest(handshake_transcript);
        let label: &[u8] = if is_client {
            b"client finished"
        } else {
            b"server finished"
        };
        let vd = tls12_prf_sha256(&self.master_secret, label, &transcript_hash, 12);
        let mut out = [0u8; 12];
        out.copy_from_slice(&vd);
        out
    }
}

/// Active TLS 1.2 record-layer session state (`scsTLS.c` @ `0x1800790a0..0x18007bc30`).
#[derive(Debug, Clone)]
pub struct TlsSession {
    pub keys: TlsSessionKeys,
    pub client_seq_num: u64,
    pub server_seq_num: u64,
    pub active: bool,
}

impl TlsSession {
    pub fn new(keys: TlsSessionKeys) -> Self {
        Self {
            keys,
            client_seq_num: 0,
            server_seq_num: 0,
            active: true,
        }
    }

    /// Compute Synaptics custom TLS 1.2 record MAC (`scsTLS.c` @ `0x18007a350`):
    /// `HMAC-SHA256(mac_key, content_type(1B) || 0x0303(2B) || pt_len_be16(2B) || plaintext)`
    /// without including the 64-bit sequence number in the HMAC input.
    pub fn compute_synaptics_record_mac(
        mac_key: &[u8; 32],
        content_type: u8,
        plaintext: &[u8],
    ) -> [u8; 32] {
        let pt_len = plaintext.len() as u16;
        let header = [
            content_type,
            TLS_VERSION_1_2[0],
            TLS_VERSION_1_2[1],
            (pt_len >> 8) as u8,
            (pt_len & 0xff) as u8,
        ];
        let mut mac = <HmacSha256 as Mac>::new_from_slice(mac_key).expect("HMAC key size valid");
        mac.update(&header);
        mac.update(plaintext);
        let bytes = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    /// Encrypt a plaintext command into a TLS 1.2 record (`0x18007ac80` / `0x18007bd70`)
    /// using a fresh random 16-byte IV.
    pub fn wrap_record(&mut self, content_type: u8, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);
        self.wrap_record_with_iv(content_type, plaintext, &iv)
    }

    /// Deterministic variant of [`Self::wrap_record`] accepting an explicit 16-byte IV.
    pub fn wrap_record_with_iv(
        &mut self,
        content_type: u8,
        plaintext: &[u8],
        iv: &[u8; 16],
    ) -> Result<Vec<u8>> {
        let mac = Self::compute_synaptics_record_mac(
            &self.keys.client_write_mac_key,
            content_type,
            plaintext,
        );
        self.client_seq_num = self.client_seq_num.wrapping_add(1);

        let unpadded_len = plaintext.len() + 32;
        let pad_len = 16 - (unpadded_len & 0x0f);
        let pad_byte = (pad_len - 1) as u8;
        let encrypted_len = unpadded_len + pad_len;

        let mut block_buf = Vec::with_capacity(encrypted_len);
        block_buf.extend_from_slice(plaintext);
        block_buf.extend_from_slice(&mac);
        block_buf.resize(encrypted_len, pad_byte);

        Aes256CbcEnc::new((&self.keys.client_write_key).into(), iv.into())
            .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(
                &mut block_buf,
                encrypted_len,
            )
            .map_err(|e| DriverError::Crypto(format!("AES-256-CBC encrypt failed: {e}")))?;

        let record_body_len = (16 + encrypted_len) as u16;
        let mut record = Vec::with_capacity(5 + 16 + encrypted_len);
        record.push(content_type);
        record.extend_from_slice(&TLS_VERSION_1_2);
        record.extend_from_slice(&record_body_len.to_be_bytes());
        record.extend_from_slice(iv);
        record.extend_from_slice(&block_buf);

        Ok(record)
    }

    /// Decrypt and authenticate a TLS 1.2 record received from the sensor (`0x1800792a0` / `0x18007bc30`).
    pub fn unwrap_record(&mut self, record: &[u8]) -> Result<(u8, Vec<u8>)> {
        if record.len() >= 7 && record[0] == TLS_CONTENT_ALERT {
            let msg = format!(
                "Sensor sent TLS Alert: level=0x{:02x}, description=0x{:02x}",
                record[5], record[6]
            );
            drv_error!("{msg}");
            return Err(DriverError::Tls(msg));
        }

        if record.len() < 0x36 {
            return Err(DriverError::Tls(format!(
                "TLS record too short: {} bytes (minimum 54)",
                record.len()
            )));
        }

        let content_type = record[0];
        if record[1..3] != TLS_VERSION_1_2 {
            return Err(DriverError::Tls(format!(
                "Unexpected TLS record version: {:02x} {:02x}",
                record[1], record[2]
            )));
        }

        let body_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        if record.len() < 5 + body_len || body_len < 16 + 32 {
            return Err(DriverError::Tls(format!(
                "TLS record length mismatch: header says {body_len} bytes, buffer has {}",
                record.len().saturating_sub(5)
            )));
        }

        let ciphertext_len = body_len - 16;
        if ciphertext_len % 16 != 0 {
            return Err(DriverError::Tls(format!(
                "TLS ciphertext length ({ciphertext_len}) is not a multiple of 16"
            )));
        }

        let mut iv = [0u8; 16];
        iv.copy_from_slice(&record[5..21]);
        let mut decrypted = record[21..21 + ciphertext_len].to_vec();

        Aes256CbcDec::new((&self.keys.server_write_key).into(), (&iv).into())
            .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut decrypted)
            .map_err(|e| DriverError::Crypto(format!("AES-256-CBC decrypt failed: {e}")))?;

        let pad_val = *decrypted.last().unwrap() as usize;
        let pad_len = pad_val + 1;
        if pad_len > 16 || decrypted.len() < 32 + pad_len {
            return Err(DriverError::Tls(format!(
                "Invalid TLS CBC padding length: {pad_len}"
            )));
        }

        let pt_len = decrypted.len() - 32 - pad_len;
        let plaintext = decrypted[..pt_len].to_vec();
        let rx_mac = &decrypted[pt_len..pt_len + 32];

        let expected_mac = Self::compute_synaptics_record_mac(
            &self.keys.server_write_mac_key,
            content_type,
            &plaintext,
        );
        self.server_seq_num = self.server_seq_num.wrapping_add(1);

        if rx_mac != expected_mac {
            drv_error!("TLS record HMAC-SHA256 verification failed");
            return Err(DriverError::Tls(
                "TLS record HMAC-SHA256 verification failed".to_string(),
            ));
        }

        Ok((content_type, plaintext))
    }
}

/// Builder for the TLS 1.2 `ECDH_ECDSA` handshake flights (`scsTLS.c` @ `0x180079580..0x18007a240`).
pub struct TlsHandshakeBuilder {
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
    pub session_id: Vec<u8>,
    pub selected_cipher_suite: u16,
    pub transcript: Vec<u8>,
}

impl Default for TlsHandshakeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsHandshakeBuilder {
    pub fn new() -> Self {
        let mut client_random = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut client_random);
        Self {
            client_random,
            server_random: [0u8; 32],
            session_id: vec![0u8; 7],
            selected_cipher_suite: CIPHER_SUITE_ECDH_ECDSA_AES256_CBC_SHA256,
            transcript: Vec::new(),
        }
    }

    /// Build Flight 1 (`0x44 00 00 00` + TLS Record `0x16` containing `ClientHello`),
    /// matching `scsTLS.c` (`0x180079580` and `0x18007af90`).
    pub fn build_client_hello_flight(&mut self) -> Vec<u8> {
        let extensions: [u8; 12] = [
            0x00, 0x04, 0x00, 0x02, 0x00, 0x17, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
        ];
        let cipher_suites: [u8; 6] = [0xc0, 0x05, 0x00, 0x3d, 0x00, 0x8d];

        let mut body = Vec::with_capacity(64);
        body.extend_from_slice(&TLS_VERSION_1_2);
        body.extend_from_slice(&self.client_random);
        body.push(self.session_id.len() as u8);
        body.extend_from_slice(&self.session_id);
        body.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
        body.extend_from_slice(&cipher_suites);
        body.push(0x00);
        // Synaptics encodes the extensions total length field as `len(exts) - 2`
        body.extend_from_slice(&((extensions.len() - 2) as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let body_len = body.len();
        let mut hs_msg = Vec::with_capacity(4 + body_len);
        hs_msg.push(0x01);
        hs_msg.push(((body_len >> 16) & 0xff) as u8);
        hs_msg.push(((body_len >> 8) & 0xff) as u8);
        hs_msg.push((body_len & 0xff) as u8);
        hs_msg.extend_from_slice(&body);

        self.transcript.extend_from_slice(&hs_msg);

        let mut packet = Vec::with_capacity(4 + 5 + hs_msg.len());
        packet.extend_from_slice(&TLS_HANDSHAKE_TUNNEL_PREFIX);
        packet.push(TLS_CONTENT_HANDSHAKE);
        packet.extend_from_slice(&TLS_VERSION_1_2);
        packet.extend_from_slice(&(hs_msg.len() as u16).to_be_bytes());
        packet.extend_from_slice(&hs_msg);
        packet
    }

    /// Parse the sensor's Flight 1 response (`ServerHello`, `CertificateRequest`, `ServerHelloDone`)
    /// as implemented in `scsTLS.c` (`0x18007b5d0..0x18007ba90`).
    pub fn process_server_flight(&mut self, raw_resp: &[u8]) -> Result<()> {
        let mut pos = if raw_resp.len() >= 7
            && raw_resp[0] == 0
            && raw_resp[1] == 0
            && raw_resp[2] == TLS_CONTENT_HANDSHAKE
        {
            2
        } else {
            0
        };

        while pos + 5 <= raw_resp.len() {
            let content_type = raw_resp[pos];
            let rec_len = u16::from_be_bytes([raw_resp[pos + 3], raw_resp[pos + 4]]) as usize;
            pos += 5;
            if pos + rec_len > raw_resp.len() {
                return Err(DriverError::Tls(
                    "Truncated TLS record in ServerHello flight".into(),
                ));
            }
            let rec_body = &raw_resp[pos..pos + rec_len];
            pos += rec_len;

            if content_type == TLS_CONTENT_ALERT && rec_body.len() >= 2 {
                let msg = format!(
                    "Sensor rejected ClientHello with Alert: level=0x{:02x}, desc=0x{:02x}",
                    rec_body[0], rec_body[1]
                );
                drv_error!("{msg}");
                return Err(DriverError::Tls(msg));
            }
            if content_type != TLS_CONTENT_HANDSHAKE {
                continue;
            }

            let mut hpos = 0;
            while hpos + 4 <= rec_body.len() {
                let msg_type = rec_body[hpos];
                let msg_len = ((rec_body[hpos + 1] as usize) << 16)
                    | ((rec_body[hpos + 2] as usize) << 8)
                    | (rec_body[hpos + 3] as usize);
                if hpos + 4 + msg_len > rec_body.len() {
                    return Err(DriverError::Tls("Truncated TLS handshake message".into()));
                }
                let full_msg = &rec_body[hpos..hpos + 4 + msg_len];
                let msg_body = &rec_body[hpos + 4..hpos + 4 + msg_len];
                self.transcript.extend_from_slice(full_msg);

                if msg_type == 0x02 {
                    if msg_body.len() < 38 {
                        return Err(DriverError::Tls("ServerHello body too short".into()));
                    }
                    self.server_random.copy_from_slice(&msg_body[2..34]);
                    let sid_len = msg_body[34] as usize;
                    if msg_body.len() < 35 + sid_len + 3 {
                        return Err(DriverError::Tls("ServerHello session_id overflow".into()));
                    }
                    self.session_id = msg_body[35..35 + sid_len].to_vec();
                    let cs_off = 35 + sid_len;
                    self.selected_cipher_suite =
                        u16::from_be_bytes([msg_body[cs_off], msg_body[cs_off + 1]]);
                }
                hpos += 4 + msg_len;
            }
        }
        Ok(())
    }

    /// Build Client Flight 2 (`Certificate` + `ClientKeyExchange` + `CertificateVerify` +
    /// `ChangeCipherSpec` + encrypted `Finished`) prefixed with `0x44 00 00 00`.
    pub fn build_client_second_flight(
        &mut self,
        host_cert: &[u8],
        host_signing_key: &SigningKey,
        sensor_pub_sec1: &[u8],
    ) -> Result<(Vec<u8>, TlsSession)> {
        let eph_secret = SecretKey::random(&mut rand::thread_rng());
        let eph_pub_sec1 = eph_secret.public_key().to_encoded_point(false);

        let sensor_pub = p256::PublicKey::from_sec1_bytes(sensor_pub_sec1)
            .map_err(|e| DriverError::Crypto(format!("Invalid sensor P-256 public key: {e}")))?;
        let shared = p256::ecdh::diffie_hellman(
            eph_secret.to_nonzero_scalar(),
            sensor_pub.as_affine(),
        );
        let pre_master_secret = shared.raw_secret_bytes();

        let keys = TlsSessionKeys::derive(
            pre_master_secret.as_slice(),
            &self.client_random,
            &self.server_random,
        );

        let mut hs_records_payload = Vec::new();

        // Handshake msg 0x0b: Certificate (`pack(">BH", 0, len) + pack(">BH", 0, len) + b"\xac\x16" + host_cert`)
        let raw_cert_len = host_cert.len() as u16;
        let mut cert_body = Vec::with_capacity(8 + host_cert.len());
        cert_body.push(0x00);
        cert_body.extend_from_slice(&raw_cert_len.to_be_bytes());
        cert_body.push(0x00);
        cert_body.extend_from_slice(&raw_cert_len.to_be_bytes());
        cert_body.extend_from_slice(&[0xac, 0x16]);
        cert_body.extend_from_slice(host_cert);

        let cert_msg_len = cert_body.len();
        let mut cert_msg = Vec::with_capacity(4 + cert_msg_len);
        cert_msg.push(0x0b);
        cert_msg.push(((cert_msg_len >> 16) & 0xff) as u8);
        cert_msg.push(((cert_msg_len >> 8) & 0xff) as u8);
        cert_msg.push((cert_msg_len & 0xff) as u8);
        cert_msg.extend_from_slice(&cert_body);
        self.transcript.extend_from_slice(&cert_msg);
        hs_records_payload.extend_from_slice(&cert_msg);

        // Handshake msg 0x10: ClientKeyExchange (65-byte uncompressed SEC1 point without 1B length prefix)
        let cke_body = eph_pub_sec1.as_bytes();
        let cke_body_len = cke_body.len();
        let mut cke_msg = Vec::with_capacity(4 + cke_body_len);
        cke_msg.push(0x10);
        cke_msg.push(((cke_body_len >> 16) & 0xff) as u8);
        cke_msg.push(((cke_body_len >> 8) & 0xff) as u8);
        cke_msg.push((cke_body_len & 0xff) as u8);
        cke_msg.extend_from_slice(cke_body);
        self.transcript.extend_from_slice(&cke_msg);
        hs_records_payload.extend_from_slice(&cke_msg);

        // Handshake msg 0x0f: CertificateVerify (raw DER ECDSA signature over SHA-256(transcript))
        let transcript_hash = Sha256::digest(&self.transcript);
        let sig: Signature = host_signing_key
            .sign_prehash(&transcript_hash)
            .map_err(|e| DriverError::Crypto(format!("ECDSA sign_prehash failed: {e}")))?;
        let sig_der = sig.to_der();
        let sig_bytes = sig_der.as_bytes();
        let cv_body_len = sig_bytes.len();
        let mut cv_msg = Vec::with_capacity(4 + cv_body_len);
        cv_msg.push(0x0f);
        cv_msg.push(((cv_body_len >> 16) & 0xff) as u8);
        cv_msg.push(((cv_body_len >> 8) & 0xff) as u8);
        cv_msg.push((cv_body_len & 0xff) as u8);
        cv_msg.extend_from_slice(sig_bytes);
        self.transcript.extend_from_slice(&cv_msg);
        hs_records_payload.extend_from_slice(&cv_msg);

        // Handshake msg 0x14: Finished (NOTE: not appended to `self.transcript` before verifying ServerFinished)
        let verify_data = keys.compute_finished_verify_data(true, &self.transcript);
        let mut fin_plain = Vec::with_capacity(16);
        fin_plain.push(0x14);
        fin_plain.extend_from_slice(&[0x00, 0x00, 0x0c]);
        fin_plain.extend_from_slice(&verify_data);

        let mut session = TlsSession::new(keys);
        let encrypted_finished_record = session.wrap_record(TLS_CONTENT_HANDSHAKE, &fin_plain)?;

        let mut flight = Vec::with_capacity(
            4 + 5 + hs_records_payload.len() + 6 + encrypted_finished_record.len(),
        );
        flight.extend_from_slice(&TLS_HANDSHAKE_TUNNEL_PREFIX);
        flight.push(TLS_CONTENT_HANDSHAKE);
        flight.extend_from_slice(&TLS_VERSION_1_2);
        flight.extend_from_slice(&(hs_records_payload.len() as u16).to_be_bytes());
        flight.extend_from_slice(&hs_records_payload);

        flight.extend_from_slice(&[TLS_CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01]);
        flight.extend_from_slice(&encrypted_finished_record);

        Ok((flight, session))
    }

    /// Process the sensor's Flight 2 response (`ChangeCipherSpec` + encrypted `Finished`)
    /// and verify the 12-byte `server finished` verify_data (`0x18007bee0`).
    pub fn process_server_finished(
        &mut self,
        raw_resp: &[u8],
        session: &mut TlsSession,
    ) -> Result<()> {
        let mut pos = 0usize;
        let mut saw_ccs = false;
        let mut saw_finished = false;

        while pos + 5 <= raw_resp.len() {
            let content_type = raw_resp[pos];
            let rec_len = u16::from_be_bytes([raw_resp[pos + 3], raw_resp[pos + 4]]) as usize;
            if pos + 5 + rec_len > raw_resp.len() {
                return Err(DriverError::Tls(
                    "Truncated TLS record in ServerFinished".into(),
                ));
            }
            let full_rec = &raw_resp[pos..pos + 5 + rec_len];
            let rec_body = &raw_resp[pos + 5..pos + 5 + rec_len];
            pos += 5 + rec_len;

            match content_type {
                TLS_CONTENT_ALERT if rec_body.len() >= 2 => {
                    let msg = format!(
                        "Sensor sent TLS Alert during Flight 2: level=0x{:02x}, desc=0x{:02x}",
                        rec_body[0], rec_body[1]
                    );
                    drv_error!("{msg}");
                    return Err(DriverError::Tls(msg));
                }
                TLS_CONTENT_CHANGE_CIPHER_SPEC => {
                    saw_ccs = true;
                }
                TLS_CONTENT_HANDSHAKE if saw_ccs => {
                    let (_, pt) = session.unwrap_record(full_rec)?;
                    if pt.len() < 16 || pt[0] != 0x14 {
                        return Err(DriverError::Tls(
                            "Invalid decrypted ServerFinished msg".into(),
                        ));
                    }
                    let expected_vd = session
                        .keys
                        .compute_finished_verify_data(false, &self.transcript);
                    if pt[4..16] != expected_vd {
                        drv_error!("TLS ServerFinished verify_data mismatch");
                        return Err(DriverError::Tls(
                            "ServerFinished verify_data mismatch".into(),
                        ));
                    }
                    self.transcript.extend_from_slice(&pt[..16]);
                    saw_finished = true;
                }
                _ => {}
            }
        }

        if !saw_finished {
            return Err(DriverError::Tls(
                "Did not receive encrypted ServerFinished record from sensor".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls12_prf_sha256_deterministic() {
        let secret = [0x42u8; 32];
        let client_random = [0x11u8; 32];
        let server_random = [0x22u8; 32];
        let keys1 = TlsSessionKeys::derive(&secret, &client_random, &server_random);
        let keys2 = TlsSessionKeys::derive(&secret, &client_random, &server_random);
        assert_eq!(keys1, keys2);
        assert_ne!(keys1.client_write_key, keys1.server_write_key);
        assert_ne!(keys1.client_write_mac_key, keys1.server_write_mac_key);
    }

    #[test]
    fn test_synaptics_record_wrap_unwrap_roundtrip() {
        let raw_keys = TlsSessionKeys::derive(&[0x55; 32], &[0xaa; 32], &[0xbb; 32]);
        let peer_keys = TlsSessionKeys {
            master_secret: raw_keys.master_secret,
            client_write_mac_key: raw_keys.server_write_mac_key,
            server_write_mac_key: raw_keys.client_write_mac_key,
            client_write_key: raw_keys.server_write_key,
            server_write_key: raw_keys.client_write_key,
        };

        let mut client_tls = TlsSession::new(raw_keys);
        let mut server_tls = TlsSession::new(peer_keys);

        let iv = [0x10u8; 16];
        let record = client_tls
            .wrap_record_with_iv(TLS_CONTENT_APPLICATION_DATA, &[0x01], &iv)
            .expect("wrap should succeed");

        assert_eq!(record.len(), 0x45);
        assert_eq!(&record[0..5], &[0x17, 0x03, 0x03, 0x00, 0x40]);

        let (ct, pt) = server_tls
            .unwrap_record(&record)
            .expect("unwrap should succeed");
        assert_eq!(ct, TLS_CONTENT_APPLICATION_DATA);
        assert_eq!(pt, vec![0x01]);
        assert_eq!(client_tls.client_seq_num, 1);
        assert_eq!(server_tls.server_seq_num, 1);
    }
}
