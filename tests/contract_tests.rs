use std::process::Command;

#[test]
fn safety_gate_contract_verification_passes() {
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let script = format!("{repo_root}/scripts/verify_contract.py");

    let output = Command::new("python3")
        .arg(&script)
        .current_dir(repo_root)
        .output()
        .expect("failed to run scripts/verify_contract.py with python3");

    assert!(
        output.status.success(),
        "safety gate contract verification failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
