#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

static CLI_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn cli_lock() -> &'static Mutex<()> {
    CLI_TEST_LOCK.get_or_init(|| Mutex::new(()))
}

fn temp_data_home(prefix: &str) -> PathBuf {
    let path = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temporary directory")
        .join(format!("{prefix}-{}", Uuid::new_v4()));
    fs::create_dir(&path).expect("create isolated data home");
    path
}

#[cfg(target_os = "macos")]
fn storage_root(_data_home: &PathBuf, home: &PathBuf) -> PathBuf {
    home.join("Library")
        .join("Application Support")
        .join("llm-veil")
        .join("store")
        .join("v1")
}

#[cfg(not(target_os = "macos"))]
fn storage_root(data_home: &PathBuf, _home: &PathBuf) -> PathBuf {
    data_home.join("llm-veil").join("store").join("v1")
}

fn veil(data_home: &PathBuf, home: &PathBuf) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_veil"));
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("XDG_DATA_HOME", data_home)
        .env("HOME", home)
        .env_remove("LLM_VEIL_TTL_SECONDS")
        .env_remove("LLM_VEIL_TOMBSTONE_TTL_SECONDS");
    command
}

fn run_id_from(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr)
        .lines()
        .find_map(|line| line.strip_prefix("run_id: ").map(str::to_owned))
        .expect("run id in command receipt")
}

#[test]
fn default_storage_retrieval_delete_and_no_store_are_observable() {
    let _guard = cli_lock().lock().expect("CLI test lock poisoned");
    let data_home = temp_data_home("llm-veil-cli");
    let home = temp_data_home("llm-veil-cli-home");

    let output_text = (1..=40)
        .map(|line| format!("line-{line:02} password=known-secret\n"))
        .collect::<String>();
    let run = veil(&data_home, &home)
        .args(["--max-chars", "80", "run", "printf", output_text.as_str()])
        .output()
        .expect("run veil");
    assert!(run.status.success(), "run failed: {:?}", run);
    let initial_stdout = String::from_utf8_lossy(&run.stdout);
    assert!(initial_stdout.contains("TRUNCATED"));
    assert!(!initial_stdout.contains("known-secret"));

    let run_id = run_id_from(&run.stderr);
    let record_dir = storage_root(&data_home, &home)
        .join("records")
        .join(&run_id);
    assert!(record_dir.join("manifest.json").is_file());
    for entry in fs::read_dir(&record_dir).expect("read stored record") {
        let bytes = fs::read(entry.expect("record entry").path()).expect("read stored file");
        assert!(!String::from_utf8_lossy(&bytes).contains("known-secret"));
    }

    let retrieve = veil(&data_home, &home)
        .args([
            "--max-chars",
            "1000",
            "retrieve",
            &run_id,
            "--stream",
            "stdout",
            "--start-line",
            "20",
            "--lines",
            "2",
        ])
        .output()
        .expect("retrieve veil");
    assert!(retrieve.status.success(), "retrieve failed: {:?}", retrieve);
    let retrieved_stdout = String::from_utf8_lossy(&retrieve.stdout);
    assert!(retrieved_stdout.contains("line-21"));
    assert!(retrieved_stdout.contains("[REDACTED_SECRET]"));
    assert!(!retrieved_stdout.contains("known-secret"));

    let delete = veil(&data_home, &home)
        .args(["store", "delete", &run_id])
        .output()
        .expect("delete veil");
    assert!(delete.status.success(), "delete failed: {:?}", delete);
    assert!(String::from_utf8_lossy(&delete.stdout).contains("status: deleted"));

    let after_delete = veil(&data_home, &home)
        .args([
            "retrieve",
            &run_id,
            "--stream",
            "stdout",
            "--start-line",
            "0",
            "--lines",
            "1",
        ])
        .output()
        .expect("retrieve deleted veil");
    assert!(!after_delete.status.success());
    assert!(String::from_utf8_lossy(&after_delete.stderr).contains("status: deleted"));

    let no_store_home = temp_data_home("llm-veil-cli-no-store");
    let no_store_home_config = temp_data_home("llm-veil-cli-no-store-home");
    let no_store = veil(&no_store_home, &no_store_home_config)
        .args([
            "--max-chars",
            "80",
            "run",
            "--no-store",
            "printf",
            "password=known-secret\nuseful output\n",
        ])
        .output()
        .expect("run no-store veil");
    assert!(no_store.status.success(), "no-store failed: {:?}", no_store);
    assert!(String::from_utf8_lossy(&no_store.stderr).contains("storage_reason: no_store"));
    assert!(!storage_root(&no_store_home, &no_store_home_config).exists());

    fs::remove_dir_all(data_home).expect("remove CLI test data");
    fs::remove_dir_all(home).expect("remove CLI test home");
    fs::remove_dir_all(no_store_home).expect("remove no-store data");
    fs::remove_dir_all(no_store_home_config).expect("remove no-store home");
}
