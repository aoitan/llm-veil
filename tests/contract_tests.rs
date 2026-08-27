#![deny(unfulfilled_lint_expectations)]

use std::sync::Mutex;

static CONTRACT_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
#[expect(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "WB-15-012: integration harness launches the strict contract verifier"
)]
fn safety_gate_contract_verification_passes() {
    use std::process::Command;

    let _guard = CONTRACT_TEST_LOCK
        .lock()
        .expect("contract test lock poisoned");
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let script = format!("{repo_root}/scripts/verify_contract.py");

    let output = Command::new("python3")
        .arg(&script)
        .arg("--strict-coverage")
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

#[test]
#[expect(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "WB-15-013: integration harness launches the metadata verifier"
)]
fn safety_gate_meta_verification_rejects_corrupted_snapshot() {
    use std::process::Command;

    let _guard = CONTRACT_TEST_LOCK
        .lock()
        .expect("contract test lock poisoned");
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let script = format!("{repo_root}/scripts/verify_meta.py");

    let output = Command::new("python3")
        .arg(&script)
        .current_dir(repo_root)
        .output()
        .expect("failed to run scripts/verify_meta.py with python3");

    assert!(
        output.status.success(),
        "safety gate contract meta verification failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
