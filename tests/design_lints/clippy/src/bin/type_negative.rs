use std::process::Command;

fn accepts_process_type(_: Option<Command>) {}

fn main() {
    accepts_process_type(None);
}
