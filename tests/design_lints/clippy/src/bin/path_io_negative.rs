use std::fs;

fn main() {
    let _ = std::path::Path::new("fixture").canonicalize();
    let _ = fs::read("fixture");
    let _ = fs::OpenOptions::new().read(true).open("fixture");
}
