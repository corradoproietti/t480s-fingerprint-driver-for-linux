//! Cargo build script for linking against `libfprint-2`, `libfprint-2-tod1`, and `GLib`/`GObject`.
//!
//! When `libfprint-2-tod1-synaptics009a.so` is loaded via `dlopen()` by `/usr/libexec/fprintd`,
//! it resolves the `FpDevice` / `FpiDevice` symbols from `/usr/lib/x86_64-linux-gnu/libfprint-2.so.2`
//! and `/usr/lib/x86_64-linux-gnu/libfprint-2-tod.so.1`, as well as GObject/GLib primitives from
//! `libgobject-2.0` and `libglib-2.0`.

fn main() {
    println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu");
    println!("cargo:rustc-link-arg=-Wl,/usr/lib/x86_64-linux-gnu/libfprint-2.so.2");
    println!("cargo:rustc-link-arg=-Wl,/usr/lib/x86_64-linux-gnu/libfprint-2-tod.so.1");
    println!("cargo:rustc-link-lib=dylib=gobject-2.0");
    println!("cargo:rustc-link-lib=dylib=glib-2.0");
}
