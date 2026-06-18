// Thin wrapper so `cargo run --bin uniffi-bindgen -- generate ...` uses a
// generator built against the exact `uniffi` version this crate links.
fn main() {
    uniffi::uniffi_bindgen_main()
}
