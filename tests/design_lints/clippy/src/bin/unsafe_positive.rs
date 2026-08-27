#![deny(unsafe_code)]

#[expect(
    unsafe_code,
    reason = "DL-001 fixture: low-level unsafe is isolated to a documented platform adapter"
)]
fn documented_unsafe_island() -> u8 {
    let value = 1u8;
    // SAFETY: the reference points to a live initialized value for the call.
    unsafe { std::ptr::read_volatile(&value) }
}

fn main() {
    let _ = documented_unsafe_island();
}
