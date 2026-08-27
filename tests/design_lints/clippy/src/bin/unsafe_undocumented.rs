#![deny(unsafe_code)]

#[expect(
    unsafe_code,
    reason = "DL-001 fixture: unsafe code expectation isolates the lint under test"
)]
fn undocumented_unsafe_island() -> u8 {
    let value = 1u8;
    unsafe { std::ptr::read_volatile(&value) }
}

fn main() {
    let _ = undocumented_unsafe_island();
}
