# T480s Fingerprint Driver for Linux

Native **Rust** Linux driver (**Touch OEM Driver** `libfprint-2-tod1`) with full **Match-on-Chip (MoC)** support for the **Synaptics Metallica MIS Touch Fingerprint Reader (`06cb:009a`)** integrated into **Lenovo ThinkPad T480s**, **T480**, **X280**, and **P52s** laptops.

Unlike legacy Python wrappers (`python3-validity` / `open-fprintd`), this driver compiles into a single native C-ABI shared library (`libfprint-2-tod1-synaptics009a.so`) loaded directly by the official Ubuntu/Debian **`fprintd`** daemon via `libfprint-2-tod.so.1`.

---

## Key Features

- **Native `libfprint-2-tod1` / `fprintd` Integration**:
  - Works out of the box with `fprintd-enroll`, `fprintd-verify`, `fprintd-list`, `fprintd-delete`, **PAM** (`sudo`, GDM/LightDM login, lock screen), **GNOME Settings**, and **Fingwit**.
  - No background Python daemon and no custom `fprintd` replacement required.
- **Hardware Match-on-Chip (MoC) QMatcher & DB2 Storage**:
  - **On-chip 1:N / 1:1 verification** (`0x5e` / `0x60` / `0x62`): biometric matching is performed entirely inside the sensor's secure processor.
  - **12-stage enrollment** (`0x69` / `0x68` / `0x6b` / `0x47`) stored directly in the sensor's internal **DB2** (`StgWindsor`) flash storage bound to the Linux UID (`S-1-5-21-...-<UID>`).
  - **Single template deletion and database reset** (`0x48` `Db2DeleteObject` / `clear_storage`).
- **Hardware Encrypted TLS 1.2 Channel (`TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA256`)**:
  - Automatic extraction and decryption of host pairing credentials from the sensor's **Flash Partition 1** (`0x40`) using host DMI (`product_name` / `product_serial`) with automatic caching in `/var/lib/fprint/.synaptics_06cb_009a_pairing.json`.
  - Every USB command and response travels encrypted inside TLS 1.2 `0x17` Application Data records (`AES-256-CBC` + `HMAC-SHA256`).
- **Instant Sensor Activation (~5 ms) & Lifecycle Management**:
  - **Background pre-warming** (`dev_probe` / `dev_init`): the TLS 1.2 handshake and factory OTP calibration (`0x6f`) are initialized when `fprintd` starts. When `sudo` or the login screen prompts for a fingerprint, the sensor LED turns on in **~5 ms**.
  - **`--no-timeout` mode included in the `.deb` package**: keeps the TLS session alive, preventing USB device resets after 30 seconds of inactivity (eliminating repeated **USBGuard** notifications).
  - **Suspend / Resume support (`suspend` / `resume`)**: cleanly closes the active session before system sleep and automatically reconnects upon wakeup.

---

## Driver Architecture

```
fprintd (D-Bus Daemon)
  └── libfprint-2.so.2 / libfprint-2-tod.so.1
        └── libfprint-2-tod1-synaptics009a.so (This Rust driver)
              ├── src/tod.rs       → GObject FpDeviceClass subclass (TOD-1 vtable)
              ├── src/moc.rs       → 2D Capacitive Capture (0x02), QMatcher (0x5e..0x62) & DB2 (0x45..0x4b) pipeline
              ├── src/protocol.rs  → Sensor session, Metallica init (0x01/0x19/0x43/0x06) & Wire Opcodes
              ├── src/tls.rs       → TLS 1.2 ECDH_ECDSA P-256 + AES-256-CBC + HMAC-SHA256 Handshake & Record Layer
              ├── src/usb.rs       → libusb transport (EP 0x01 Bulk OUT, 0x81/0x82 Bulk IN, 0x83 Interrupt IN)
              ├── src/error.rs     → Sensor status codes & scan quality mapping to FpDeviceRetry
              └── src/log.rs       → Structured logging to journalctl (SYNAPTICS_009A_LOG)
```

---

## Prerequisites: Removing `python3-validity` / `open-fprintd`

If you previously installed the `python3-validity` / `open-fprintd` PPA, disable it and restore the official `fprintd` and `libfprint-2-tod1` packages:

```bash
sudo systemctl disable --now python3-validity.service open-fprintd.service fprintd-resume.service || true
sudo systemctl mask python3-validity.service
sudo apt update
sudo apt install -y fprintd libfprint-2-2 libfprint-2-tod1 libpam-fprintd
```

> **Note on Sensor Firmware**: the `06cb:009a` sensor must have Partition 2 flashed with the Synaptics QMatcher firmware (`6_07f_lenovo_mis_qm.xpfwext`, v6.07.0164) and factory host pairing data in Partition 1 (already present if the sensor was initialized at least once under Windows or via `validity-sensors-firmware`).

---

## Installation from `.deb` Package (Recommended)

Download `libfprint-2-tod1-synaptics009a_0.1.0-1_amd64.deb` from the [**Releases**](https://github.com/corradoproietti/t480s-fingerprint-driver-for-linux/releases) page and install it with `dpkg`:

```bash
sudo dpkg -i libfprint-2-tod1-synaptics009a_0.1.0-1_amd64.deb
```

The `.deb` package automatically:
1. Installs `/usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/libfprint-2-tod1-synaptics009a.so` (native `libfprint-2-tod1` plugin).
2. Installs `/lib/systemd/system/fprintd.service.d/synaptics009a-no-timeout.conf` (`fprintd -t` / `--no-timeout` override to keep the TLS session warm in RAM and avoid periodic USB resets).
3. Reloads `systemd` and restarts `fprintd.service`.

---

## Building from Source

### 1. Build Dependencies

On Ubuntu / Debian / Linux Mint:

```bash
sudo apt update
sudo apt install -y build-essential cargo rustc pkg-config libusb-1.0-0-dev libfprint-2-tod1
```

### 2. Compile and Install

```bash
cargo build --release
sudo install -D -m 0644 target/release/libt480s_fingerprint_v2.so \
    /usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/libfprint-2-tod1-synaptics009a.so
sudo systemctl restart fprintd
```

---

## Usage & PAM Configuration

### Enrolling, Verifying, and Deleting Fingerprints via CLI

```bash
# Enroll the right index finger (12 touches on the sensor)
fprintd-enroll -f right-index-finger

# List enrolled fingerprints
fprintd-list "$USER"

# Verify an enrolled fingerprint
fprintd-verify

# Delete all fingerprints for the current user (both from fprintd and from the sensor's DB2 flash)
fprintd-delete "$USER"
```

You can also manage fingerprints graphically via **GNOME Settings → Users → Fingerprint Login** or **Fingwit**.

### Enabling Fingerprint Authentication for `sudo`, Login, and Lock Screen

Run:

```bash
sudo pam-auth-update
```

Make sure **`[*] Fingerprint authentication`** is checked (using the spacebar) and press **Enter**.

---

## Diagnostics & Logging (`journalctl`)

The driver includes a structured logging subsystem that writes directly to the `fprintd` systemd journal:

```bash
journalctl -u fprintd -f
```

To enable verbose `DEBUG` logs (USB Bulk/Interrupt transfer timings, `0x51` sensor status events, and TLS handshake details), add the `SYNAPTICS_009A_LOG=debug` environment variable to `fprintd.service`:

```bash
sudo systemctl edit fprintd.service
```

Add:

```ini
[Service]
Environment="SYNAPTICS_009A_LOG=debug"
```

Then restart the daemon:

```bash
sudo systemctl restart fprintd
```

Supported `SYNAPTICS_009A_LOG` levels: `error`, `warn`, `info` (default), `debug`, `off`.

---

## Project Structure

| File | Description |
| :--- | :--- |
| [`Cargo.toml`](Cargo.toml) | Rust crate manifest (`cdylib` + `rlib`) |
| [`build.rs`](build.rs) | Build script for linking against `libfprint-2-tod.so.1` and `libglib-2.0.so.0` |
| [`calib_06cb_009a.bin`](calib_06cb_009a.bin) | 2D capacitive calibration blob (`13,440` bytes) for sensor `0x0199` |
| [`src/lib.rs`](src/lib.rs) | Library entrypoint and public exports |
| [`src/tod.rs`](src/tod.rs) | `libfprint-2-tod1` GObject plugin (`FpDeviceClass` vtable, pre-warming, suspend/resume) |
| [`src/moc.rs`](src/moc.rs) | 2D frame acquisition (`0x02`), QMatcher engine (`0x5e..0x62`), enrollment (`0x68..0x6b`), and DB2 (`0x45..0x4b`) |
| [`src/protocol.rs`](src/protocol.rs) | Sensor session, Metallica init sequence, and `WireOpcode` definitions |
| [`src/tls.rs`](src/tls.rs) | Custom Synaptics TLS 1.2 stack (`ECDH_ECDSA_AES256_CBC_SHA256`) and Partition 1 (`0x40`) parser |
| [`src/usb.rs`](src/usb.rs) | `rusb` (`libusb`) USB transport with cooperative cancellation on Interrupt `0x83` |
| [`src/error.rs`](src/error.rs) | Hardware status codes (`SensorStatus`) and scan error mapping |
| [`src/log.rs`](src/log.rs) | Lightweight thread-safe logger configurable via `SYNAPTICS_009A_LOG` |

---

## License

Dual-licensed under **MIT** or **LGPL-2.1-or-later**.
