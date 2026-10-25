# T480s Fingerprint Driver for Linux

Driver nativo Linux in **Rust** (**Touch OEM Driver** `libfprint-2-tod1`) con supporto completo **Match-on-Chip (MoC)** per il lettore di impronte digitali **Synaptics Metallica MIS Touch Fingerprint Reader (`06cb:009a`)** integrato nei laptop **Lenovo ThinkPad T480s**, **T480**, **X280** e **P52s**.

A differenza dei wrapper Python legacy (`python3-validity` / `open-fprintd`), questo driver compila in una singola libreria condivisa nativa C-ABI (`libfprint-2-tod1-synaptics009a.so`) caricata direttamente dal demone ufficiale **`fprintd`** di Ubuntu/Debian tramite `libfprint-2-tod.so.1`.

---

## Caratteristiche Principali

- **Integrazione Nativa `libfprint-2-tod1` / `fprintd`**:
  - Funziona nativamente con `fprintd-enroll`, `fprintd-verify`, `fprintd-list`, `fprintd-delete`, **PAM** (`sudo`, login GDM/LightDM, blocco schermo), **Impostazioni di GNOME** e **Fingwit**.
  - Nessun demone Python in background e nessuna sostituzione di `fprintd`.
- **Match-on-Chip (MoC) QMatcher & DB2 Hardware**:
  - **Verifica 1:N / 1:1 on-chip** (`0x5e` / `0x60` / `0x62`): il confronto biometrico avviene interamente all'interno del processore sicuro del sensore.
  - **Registrazione (Enroll) in 12 stadi** (`0x69` / `0x68` / `0x6b` / `0x47`) con salvataggio diretto nella memoria flash interna **DB2** (`StgWindsor`) del sensore associata all'UID Linux (`S-1-5-21-...-<UID>`).
  - **Cancellazione singola e reset database** (`0x48` `Db2DeleteObject` / `clear_storage`).
- **Canale Cifrato TLS 1.2 Hardware (`TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA256`)**:
  - Estrazione e decifrazione automatica delle credenziali di pairing dalla **Partizione Flash 1** (`0x40`) del sensore tramite DMI (`product_name` / `product_serial`) con caching automatico in `/var/lib/fprint/.synaptics_06cb_009a_pairing.json`.
  - Ogni comando e risposta USB viaggia cifrato in record TLS 1.2 `0x17` (`AES-256-CBC` + `HMAC-SHA256`).
- **Attivazione Istantanea (~5 ms) & Gestione Ciclo di Vita**:
  - **Pre-warming in background** (`dev_probe` / `dev_init`): l'handshake TLS 1.2 e la calibrazione di fabbrica OTP (`0x6f`) vengono inizializzati all'avvio di `fprintd`. Quando `sudo` o il login chiedono l'impronta, il LED si accende in **~5 ms**.
  - **Modalità `--no-timeout` inclusa nel pacchetto `.deb`**: mantiene attiva la sessione TLS evitando riavvii USB del sensore dopo 30 secondi di inattività (zero notifiche ripetute su **USBGuard**).
  - **Supporto Sospensione / Ripristino (`suspend` / `resume`)**: chiusura pulita della sessione prima dello standby del laptop e riconnessione automatica al risveglio.

---

## Architettura del Driver

```
fprintd (D-Bus Daemon)
  └── libfprint-2.so.2 / libfprint-2-tod.so.1
        └── libfprint-2-tod1-synaptics009a.so (Questo driver Rust)
              ├── src/tod.rs       → Sottoclasse GObject FpDeviceClass (vtable TOD-1)
              ├── src/moc.rs       → Pipeline 2D Capacitive Capture (0x02), QMatcher (0x5e..0x62) e DB2 (0x45..0x4b)
              ├── src/protocol.rs  → Sessione sensore, init Metallica (0x01/0x19/0x43/0x06) e Opcodes Wire
              ├── src/tls.rs       → Handshake e Record Layer TLS 1.2 ECDH_ECDSA P-256 + AES-256-CBC + HMAC-SHA256
              ├── src/usb.rs       → Trasporto libusb (EP 0x01 Bulk OUT, 0x81/0x82 Bulk IN, 0x83 Interrupt IN)
              ├── src/error.rs     → Mappatura codici stato sensore e qualità scansione verso FpDeviceRetry
              └── src/log.rs       → Logging strutturato su journalctl (SYNAPTICS_009A_LOG)
```

---

## Requisiti preliminare: Rimozione di `python3-validity` / `open-fprintd`

Se in precedenza avevi installato il PPA `python3-validity` / `open-fprintd`, disattivalo e ripristina i pacchetti ufficiali `fprintd` e `libfprint-2-tod1`:

```bash
sudo systemctl disable --now python3-validity.service open-fprintd.service fprintd-resume.service || true
sudo systemctl mask python3-validity.service
sudo apt update
sudo apt install -y fprintd libfprint-2-2 libfprint-2-tod1 libpam-fprintd
```

> **Nota sul Firmware del Sensore**: il sensore `06cb:009a` deve avere la Partizione 2 inizializzata con il firmware Synaptics QMatcher (`6_07f_lenovo_mis_qm.xpfwext`, v6.07.0164) e il pairing di fabbrica nella Partizione 1 (già presenti se il sensore è stato inizializzato almeno una volta sotto Windows o con `validity-sensors-firmware`).

---

## Installazione da Pacchetto `.deb` (Consigliata)

Scarica il pacchetto `.deb` dalla sezione **Releases** (oppure generato con `./build_deb.sh`) e installalo con `dpkg` o `apt`:

```bash
sudo dpkg -i libfprint-2-tod1-synaptics009a_0.1.0-1_amd64.deb
```

Il pacchetto `.deb` installa automaticamente:
1. `/usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/libfprint-2-tod1-synaptics009a.so`: plugin nativo `libfprint-2-tod1`.
2. `/lib/systemd/system/fprintd.service.d/synaptics009a-no-timeout.conf`: configurazione `fprintd -t` (`--no-timeout`) per mantenere la sessione TLS pronta in RAM ed evitare reset USB periodici.
3. Ricarica `systemd` e riavvia `fprintd.service`.

---

## Compilazione e Creazione del `.deb` dai Sorgenti

### 1. Dipendenze di compilazione

Su Ubuntu / Debian / Linux Mint:

```bash
sudo apt update
sudo apt install -y build-essential cargo rustc pkg-config libusb-1.0-0-dev libfprint-2-tod1 dpkg-dev
```

### 2. Generazione del pacchetto `.deb`

Dalla radice del repository esegui lo script di creazione del pacchetto:

```bash
./build_deb.sh
```

Lo script compila il driver in modalità `--release`, esegue lo `strip` dei simboli di debug e genera il file:
`libfprint-2-tod1-synaptics009a_0.1.0-1_amd64.deb`

Per installarlo:

```bash
sudo dpkg -i libfprint-2-tod1-synaptics009a_0.1.0-1_amd64.deb
```

### 3. Installazione manuale della sola libreria `.so` (senza `.deb`)

```bash
cargo build --release
sudo install -D -m 0644 target/release/libt480s_fingerprint_v2.so \
    /usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/libfprint-2-tod1-synaptics009a.so
sudo systemctl restart fprintd
```

---

## Utilizzo e Configurazione PAM

### Registrazione, Verifica ed Eliminazione Impronte da Terminale

```bash
# Registra l'indice destro (12 tocchi sul sensore)
fprintd-enroll -f right-index-finger

# Elenca le impronte registrate
fprintd-list "$USER"

# Verifica un'impronta registrata
fprintd-verify

# Elimina tutte le impronte dell'utente corrente (sia da fprintd che dalla flash DB2 del sensore)
fprintd-delete "$USER"
```

Puoi gestire le impronte anche tramite interfaccia grafica da **Impostazioni di GNOME → Utenti → Accesso con impronta** oppure tramite **Fingwit**.

### Abilitazione dell'Impronta per `sudo`, Login e Blocco Schermo

Esegui:

```bash
sudo pam-auth-update
```

Assicurati che la voce **`[*] Fingerprint authentication`** sia selezionata con la barra spaziatrice e premi **Invio**.

---

## Diagnostica e Logging (`journalctl`)

Il driver integra un sistema di logging strutturato che scrive direttamente nel journal di `fprintd`:

```bash
journalctl -u fprintd -f
```

Per abilitare i log dettagliati a livello `DEBUG` (tempi di trasferimento USB Bulk/Interrupt, stati del sensore `0x51` e handshake TLS), aggiungi la variabile d'ambiente `SYNAPTICS_009A_LOG=debug` al servizio `fprintd`:

```bash
sudo systemctl edit fprintd.service
```

Aggiungi:

```ini
[Service]
Environment="SYNAPTICS_009A_LOG=debug"
```

Poi riavvia il demone:

```bash
sudo systemctl restart fprintd
```

Livelli supportati per `SYNAPTICS_009A_LOG`: `error`, `warn`, `info` (predefinito), `debug`, `off`.

---

## Struttura del Progetto

| File | Descrizione |
| :--- | :--- |
| [`Cargo.toml`](Cargo.toml) | Manifesto del crate Rust (`cdylib` + `rlib`) |
| [`build.rs`](build.rs) | Script di build per il linking con `libfprint-2-tod.so.1` e `libglib-2.0.so.0` |
| [`build_deb.sh`](build_deb.sh) | Script automatizzato per compilare e impacchettare il `.deb` |
| [`calib_06cb_009a.bin`](calib_06cb_009a.bin) | Tabella di calibrazione capacitiva 2D (`13.440` byte) per il sensore `0x0199` |
| [`src/lib.rs`](src/lib.rs) | Entrypoint della libreria ed esportazioni pubbliche |
| [`src/tod.rs`](src/tod.rs) | Plugin GObject `libfprint-2-tod1` (`FpDeviceClass` vtable, pre-warming, suspend/resume) |
| [`src/moc.rs`](src/moc.rs) | Acquisizione frame 2D (`0x02`), motore QMatcher (`0x5e..0x62`), enroll (`0x68..0x6b`) e DB2 (`0x45..0x4b`) |
| [`src/protocol.rs`](src/protocol.rs) | Sessione sensore, sequenza di init Metallica e definizioni `WireOpcode` |
| [`src/tls.rs`](src/tls.rs) | Stack TLS 1.2 custom Synaptics (`ECDH_ECDSA_AES256_CBC_SHA256`) e parser Partizione 1 (`0x40`) |
| [`src/usb.rs`](src/usb.rs) | Trasporto USB `rusb` (`libusb`) con cancellazione cooperativa su Interrupt `0x83` |
| [`src/error.rs`](src/error.rs) | Codici di stato hardware (`SensorStatus`) e mappatura errori di scansione |
| [`src/log.rs`](src/log.rs) | Logger leggero thread-safe configurabile via `SYNAPTICS_009A_LOG` |

---

## Licenza

Distribuito sotto doppia licenza **MIT** oppure **LGPL-2.1-or-later**.
