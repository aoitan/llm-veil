#![deny(unsafe_code)]

fn unsafe_outside_island() -> u8 {
    let value = 1u8;
    unsafe { std::ptr::read_volatile(&value) }
}

fn main() {
    let _ = unsafe_outside_island();
}
