use t480s_fingerprint_v2::{SensorSession, SynapticsUsbTransport};

fn main() {
    println!("=== Synaptics Metallica MIS (06cb:009a) Hardware Probe ===");
    let transport = match SynapticsUsbTransport::open() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ERROR opening USB device 06cb:009a: {e}");
            std::process::exit(1);
        }
    };
    let mut session = SensorSession::new(transport);
    let version = match session.initialize_metallica() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("First initialize_metallica failed ({e}), resetting USB device and retrying...");
            let _ = session.transport.reset_device();
            drop(session);
            std::thread::sleep(std::time::Duration::from_millis(600));
            let retry_transport = SynapticsUsbTransport::open().expect("Reopen USB failed");
            session = SensorSession::new(retry_transport);
            session.initialize_metallica().expect("Retry initialize_metallica failed")
        }
    };
    println!(
        "SUCCESS: Sensor initialized! Firmware={}, Product=0x{:02x}, Serial={}, SecFlags=0x{:04x}",
        version.formatted_version(),
        version.product,
        version.serial_hex(),
        version.security_flags
    );

    match session.read_tls_flash_bundle() {
        Ok(bundle) => {
            println!("SUCCESS: Extracted and decrypted TLS pairing bundle from Flash Partition 1!");
            match session.establish_tls_session(&bundle) {
                Ok(()) => {
                    println!("SUCCESS: Hardware TLS 1.2 session established with 06cb:009a!");
                    println!("Calibrating 2D capacitive sensor (DO NOT touch the sensor for 2 seconds)...");
                    match session.calibrate_sensor() {
                        Ok(calib_data) => {
                            let _ = std::fs::create_dir_all("/var/lib/fprint");
                            let calib_path = "/var/lib/fprint/.synaptics_06cb_009a_calib.bin";
                            std::fs::write(calib_path, &calib_data)
                                .expect("Failed to write calibration file");
                            let clean_ok = session.check_clean_slate().unwrap_or(false);
                            println!(
                                "SUCCESS: Sensor calibrated! Saved {} B to {calib_path} (Flash Partition 6 clean_slate valid: {clean_ok})",
                                calib_data.len()
                            );
                        }
                        Err(e) => {
                            eprintln!("ERROR calibrating sensor: {e}");
                            let _ = session.reboot_sensor();
                            std::process::exit(4);
                        }
                    }
                    let _ = session.reboot_sensor();
                }
                Err(e) => {
                    eprintln!("ERROR establishing TLS 1.2 session: {e}");
                    let _ = session.reboot_sensor();
                    std::process::exit(2);
                }
            }
        }
        Err(e) => {
            eprintln!("ERROR reading/decrypting TLS pairing bundle from Partition 1: {e}");
            std::process::exit(3);
        }
    }
}
