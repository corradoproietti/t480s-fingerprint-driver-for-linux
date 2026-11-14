//! Cargo build script for linking against `libfprint-2`, `libfprint-2-tod1` (on Debian/Ubuntu),
//! or `libfprint-2.so.2` directly (on Fedora/RHEL), along with `GLib`/`GObject`.

use std::path::Path;

/// Emit Cargo linker flags (`cargo:rustc-link-*`) and target `cfg` flags depending on
/// whether the host distribution provides Debian/Ubuntu's `libfprint-2-tod.so.1` or
/// Fedora's standalone `/usr/lib64/libfprint-2.so.2`.
fn main() {
    println!("cargo:rustc-check-cfg=cfg(fedora_libfprint)");

    let debian_tod = Path::new("/usr/lib/x86_64-linux-gnu/libfprint-2-tod.so.1");
    let fedora_libfprint = Path::new("/usr/lib64/libfprint-2.so.2");

    if debian_tod.exists() && std::env::var_os("CARGO_FEATURE_FEDORA").is_none() {
        println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu");
        println!("cargo:rustc-link-arg=-Wl,/usr/lib/x86_64-linux-gnu/libfprint-2.so.2");
        println!("cargo:rustc-link-arg=-Wl,/usr/lib/x86_64-linux-gnu/libfprint-2-tod.so.1");
        println!("cargo:rustc-link-lib=dylib=gobject-2.0");
        println!("cargo:rustc-link-lib=dylib=glib-2.0");
    } else if fedora_libfprint.exists() {
        println!("cargo:rustc-cfg=fedora_libfprint");
        println!("cargo:rustc-link-search=native=/usr/lib64");
        println!("cargo:rustc-link-arg=-Wl,/usr/lib64/libfprint-2.so.2");
        println!("cargo:rustc-link-lib=dylib=gobject-2.0");
        println!("cargo:rustc-link-lib=dylib=glib-2.0");
        println!("cargo:rustc-link-lib=dylib=dl");
    } else {
        println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu");
        println!("cargo:rustc-link-arg=-Wl,/usr/lib/x86_64-linux-gnu/libfprint-2.so.2");
        println!("cargo:rustc-link-arg=-Wl,/usr/lib/x86_64-linux-gnu/libfprint-2-tod.so.1");
        println!("cargo:rustc-link-lib=dylib=gobject-2.0");
        println!("cargo:rustc-link-lib=dylib=glib-2.0");
    }
}
