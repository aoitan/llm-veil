#![cfg(unix)]
#![deny(unfulfilled_lint_expectations)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

static CLI_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn cli_lock() -> &'static Mutex<()> {
    CLI_TEST_LOCK.get_or_init(|| Mutex::new(()))
}

#[expect(
    clippy::disallowed_methods,
    reason = "WB-15-014: CLI test fixture resolves its temporary parent directory"
)]
fn temp_data_home(prefix: &str) -> PathBuf {
    let path = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temporary directory")
        .join(format!("{prefix}-{}", Uuid::new_v4()));
    fs::create_dir(&path).expect("create isolated data home");
    path
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    #[expect(
        clippy::disallowed_methods,
        reason = "WB-15-015: CLI test fixture resolves its temporary parent directory"
    )]
    fn new(prefix: &str) -> Self {
        let path = std::env::temp_dir()
            .canonicalize()
            .expect("canonicalize temporary directory")
            // Keep nested Unix-socket fixtures below Darwin's SUN_LEN limit.
            .join(format!(
                "p{}-{}",
                prefix.chars().take(4).collect::<String>(),
                &Uuid::new_v4().to_string()[..8]
            ));
        fs::create_dir(&path).expect("create temporary fixture directory");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(target_os = "macos")]
fn storage_root(_data_home: &Path, home: &Path) -> PathBuf {
    home.join("Library")
        .join("Application Support")
        .join("llm-veil")
        .join("store")
        .join("v1")
}

#[cfg(not(target_os = "macos"))]
fn storage_root(data_home: &Path, _home: &Path) -> PathBuf {
    data_home.join("llm-veil").join("store").join("v1")
}

#[expect(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "WB-15-016: CLI integration harness launches the built binary"
)]
fn veil(data_home: &Path, home: &Path) -> std::process::Command {
    use std::process::Command;

    let mut command = Command::new(env!("CARGO_BIN_EXE_veil"));
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("XDG_DATA_HOME", data_home)
        .env("HOME", home)
        .env_remove("LLM_VEIL_TTL_SECONDS")
        .env_remove("LLM_VEIL_TOMBSTONE_TTL_SECONDS");
    command
}

fn run_veil_in_workspace(
    data_home: &Path,
    home: &Path,
    workspace: &Path,
    args: &[String],
) -> Output {
    let mut command = veil(data_home, home);
    command.env("LLM_VEIL_WORKSPACE_ROOT", workspace).args(args);
    command.output().expect("run veil path decision fixture")
}

fn output_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn run_id_from(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr)
        .lines()
        .find_map(|line| line.strip_prefix("run_id: ").map(str::to_owned))
        .expect("run id in command receipt")
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "WB-15-017: CLI integration test inspects sanitized persisted files"
)]
fn default_storage_retrieval_delete_and_no_store_are_observable() {
    let _guard = cli_lock().lock().expect("CLI test lock poisoned");
    let data_home = temp_data_home("llm-veil-cli");
    let home = temp_data_home("llm-veil-cli-home");

    let mut output_text = String::new();
    for line in 1..=40 {
        use std::fmt::Write as _;
        writeln!(output_text, "line-{line:02} password=known-secret")
            .expect("append CLI output fixture");
    }
    let run = veil(&data_home, &home)
        .args(["--max-chars", "80", "run", "printf", output_text.as_str()])
        .output()
        .expect("run veil");
    assert!(run.status.success(), "run failed: {run:?}");
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
    assert!(retrieve.status.success(), "retrieve failed: {retrieve:?}");
    let retrieved_stdout = String::from_utf8_lossy(&retrieve.stdout);
    assert!(retrieved_stdout.contains("line-21"));
    assert!(retrieved_stdout.contains("[REDACTED_SECRET]"));
    assert!(!retrieved_stdout.contains("known-secret"));

    let delete = veil(&data_home, &home)
        .args(["store", "delete", &run_id])
        .output()
        .expect("delete veil");
    assert!(delete.status.success(), "delete failed: {delete:?}");
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
    assert!(no_store.status.success(), "no-store failed: {no_store:?}");
    assert!(String::from_utf8_lossy(&no_store.stderr).contains("storage_reason: no_store"));
    assert!(!storage_root(&no_store_home, &no_store_home_config).exists());

    fs::remove_dir_all(data_home).expect("remove CLI test data");
    fs::remove_dir_all(home).expect("remove CLI test home");
    fs::remove_dir_all(no_store_home).expect("remove no-store data");
    fs::remove_dir_all(no_store_home_config).expect("remove no-store home");
}

#[test]
fn wb04_observes_current_path_ux_and_traversal_limit_baseline() {
    let _guard = cli_lock().lock().expect("CLI test lock poisoned");
    let workspace = TempDir::new("llm-veil-wb04-workspace");
    let outside = TempDir::new("llm-veil-wb04-outside");
    let home = TempDir::new("llm-veil-wb04-home");
    let data_home = TempDir::new("llm-veil-wb04-data");

    let inside_file = workspace.path().join("inside.txt");
    fs::write(&inside_file, "inside-marker\n").expect("write inside fixture");

    let outside_file = outside.path().join("outside.txt");
    fs::write(&outside_file, "outside-marker\n").expect("write outside fixture");

    let outside_dir = outside.path().join("outside-dir");
    fs::create_dir(&outside_dir).expect("create outside directory fixture");
    fs::write(outside_dir.join("linked.txt"), "linked-outside-marker\n")
        .expect("write linked outside fixture");

    let direct_file_link = workspace.path().join("direct-file-link.txt");
    symlink(&outside_file, &direct_file_link).expect("create direct file symlink");

    let root_dir_link = workspace.path().join("root-dir-link");
    symlink(&outside_dir, &root_dir_link).expect("create root directory symlink");

    let tree = workspace.path().join("tree");
    fs::create_dir(&tree).expect("create traversal tree");
    let intermediate_dir_link = tree.join("intermediate-dir-link");
    symlink(&outside_dir, &intermediate_dir_link).expect("create intermediate symlink");

    let error_tree = workspace.path().join("error-tree");
    fs::create_dir(&error_tree).expect("create error traversal tree");
    let child_socket_path = error_tree.join("child-socket");
    let _child_socket_listener =
        UnixListener::bind(&child_socket_path).expect("create child socket fixture");
    let unreadable_dir = error_tree.join("z-unreadable");
    fs::create_dir(&unreadable_dir).expect("create unreadable directory");
    fs::write(unreadable_dir.join("file.txt"), "unreadable-marker\n")
        .expect("write unreadable child fixture");
    fs::set_permissions(&unreadable_dir, fs::Permissions::from_mode(0o000))
        .expect("make child unreadable");

    let depth_root = workspace.path().join("depth");
    fs::create_dir(&depth_root).expect("create depth root");
    let mut deep_dir = depth_root.clone();
    for level in 0..16 {
        deep_dir = deep_dir.join(format!("level-{level:02}"));
        fs::create_dir(&deep_dir).expect("create nested depth fixture");
    }
    let deep_file = deep_dir.join("deep.txt");
    fs::write(&deep_file, "depth-marker\n").expect("write deep fixture");

    let entries_root = workspace.path().join("entries");
    fs::create_dir(&entries_root).expect("create entry-count root");
    for entry in 0..205 {
        let path = entries_root.join(format!("entry-{entry:03}.txt"));
        let mut file = fs::File::create(path).expect("create entry fixture");
        writeln!(file, "entry-marker-{entry:03}").expect("write entry fixture");
    }

    let long_line = workspace.path().join("long-line.txt");
    fs::write(
        &long_line,
        format!("long-marker-{}\n", "x".repeat(64 * 1024)),
    )
    .expect("write long-line fixture");

    let socket_path = workspace.path().join("unix-socket");
    let _socket_listener = UnixListener::bind(&socket_path).expect("create Unix socket fixture");

    let cat_inside = run_veil_in_workspace(
        data_home.path(),
        home.path(),
        workspace.path(),
        &[
            "cat".to_string(),
            "--no-store".to_string(),
            inside_file.display().to_string(),
        ],
    );
    assert_eq!(cat_inside.status.code(), Some(0));
    assert!(output_text(&cat_inside.stdout).contains("inside-marker"));
    assert!(output_text(&cat_inside.stderr).contains("exit_code: 0"));

    let cat_outside = run_veil_in_workspace(
        data_home.path(),
        home.path(),
        workspace.path(),
        &[
            "cat".to_string(),
            "--no-store".to_string(),
            outside_file.display().to_string(),
        ],
    );
    let cat_outside_stdout = output_text(&cat_outside.stdout);
    assert_eq!(cat_outside.status.code(), Some(1));
    assert!(cat_outside_stdout.contains("blocked: true"));
    assert!(cat_outside_stdout.contains("path_rule: workspace_boundary"));
    assert!(!cat_outside_stdout.contains("outside-marker"));
    assert!(output_text(&cat_outside.stderr).contains("Access outside workspace was denied"));

    let cat_symlink = run_veil_in_workspace(
        data_home.path(),
        home.path(),
        workspace.path(),
        &[
            "cat".to_string(),
            "--no-store".to_string(),
            direct_file_link.display().to_string(),
        ],
    );
    let cat_symlink_stdout = output_text(&cat_symlink.stdout);
    assert_eq!(cat_symlink.status.code(), Some(1));
    assert!(cat_symlink_stdout.contains("path_rule: workspace_boundary"));
    assert!(!cat_symlink_stdout.contains("outside-marker"));

    let cat_traversal_path = workspace
        .path()
        .join("..")
        .join(outside.path().file_name().expect("outside directory name"))
        .join("outside.txt");
    let cat_traversal = run_veil_in_workspace(
        data_home.path(),
        home.path(),
        workspace.path(),
        &[
            "cat".to_string(),
            "--no-store".to_string(),
            cat_traversal_path.display().to_string(),
        ],
    );
    assert_eq!(cat_traversal.status.code(), Some(1));
    assert!(output_text(&cat_traversal.stdout).contains("path_rule: workspace_boundary"));

    let grep_inside = run_veil_in_workspace(
        data_home.path(),
        home.path(),
        workspace.path(),
        &[
            "grep".to_string(),
            "--no-store".to_string(),
            "inside-marker".to_string(),
            inside_file.display().to_string(),
        ],
    );
    assert_eq!(grep_inside.status.code(), Some(0));
    assert!(output_text(&grep_inside.stdout).contains("inside-marker"));

    let grep_no_match = run_veil_in_workspace(
        data_home.path(),
        home.path(),
        workspace.path(),
        &[
            "grep".to_string(),
            "--no-store".to_string(),
            "not-present".to_string(),
            inside_file.display().to_string(),
        ],
    );
    assert_eq!(grep_no_match.status.code(), Some(0));
    assert!(output_text(&grep_no_match.stderr).contains("exit_code: 0"));

    let grep_outside = run_veil_in_workspace(
        data_home.path(),
        home.path(),
        workspace.path(),
        &[
            "grep".to_string(),
            "--no-store".to_string(),
            "outside-marker".to_string(),
            outside_file.display().to_string(),
        ],
    );
    assert_eq!(grep_outside.status.code(), Some(1));
    assert!(output_text(&grep_outside.stdout).is_empty());
    assert!(output_text(&grep_outside.stderr).contains("outside the workspace"));

    let grep_direct_symlink = run_veil_in_workspace(
        data_home.path(),
        home.path(),
        workspace.path(),
        &[
            "grep".to_string(),
            "--no-store".to_string(),
            "outside-marker".to_string(),
            direct_file_link.display().to_string(),
        ],
    );
    assert_eq!(grep_direct_symlink.status.code(), Some(1));
    assert!(output_text(&grep_direct_symlink.stdout).is_empty());
    assert!(!output_text(&grep_direct_symlink.stdout).contains("outside-marker"));

    let grep_root_symlink = run_veil_in_workspace(
        data_home.path(),
        home.path(),
        workspace.path(),
        &[
            "grep".to_string(),
            "--no-store".to_string(),
            "linked-outside-marker".to_string(),
            root_dir_link.display().to_string(),
        ],
    );
    assert_eq!(grep_root_symlink.status.code(), Some(1));
    assert!(output_text(&grep_root_symlink.stdout).is_empty());
    assert!(!output_text(&grep_root_symlink.stderr).contains("linked-outside-marker"));

    let grep_intermediate_symlink = run_veil_in_workspace(
        data_home.path(),
        home.path(),
        workspace.path(),
        &[
            "grep".to_string(),
            "--no-store".to_string(),
            "linked-outside-marker".to_string(),
            tree.display().to_string(),
        ],
    );
    assert_eq!(grep_intermediate_symlink.status.code(), Some(2));
    assert!(!output_text(&grep_intermediate_symlink.stdout).contains("linked-outside-marker"));
    assert!(output_text(&grep_intermediate_symlink.stderr).contains("traversal_status: partial"));
    assert!(output_text(&grep_intermediate_symlink.stderr).contains("symlink_skipped"));

    let grep_unreadable = run_veil_in_workspace(
        data_home.path(),
        home.path(),
        workspace.path(),
        &[
            "grep".to_string(),
            "--no-store".to_string(),
            "marker".to_string(),
            error_tree.display().to_string(),
        ],
    );
    let grep_unreadable_stderr = output_text(&grep_unreadable.stderr);
    assert_eq!(grep_unreadable.status.code(), Some(2));
    assert!(grep_unreadable_stderr.contains("traversal_status: partial"));
    assert!(grep_unreadable_stderr.contains("unsupported_file_type"));
    assert!(grep_unreadable_stderr.contains("Error: grep traversal was incomplete"));
    fs::set_permissions(&unreadable_dir, fs::Permissions::from_mode(0o700))
        .expect("restore unreadable fixture permissions");

    let grep_socket = run_veil_in_workspace(
        data_home.path(),
        home.path(),
        workspace.path(),
        &[
            "grep".to_string(),
            "--no-store".to_string(),
            "socket".to_string(),
            socket_path.display().to_string(),
        ],
    );
    assert_eq!(grep_socket.status.code(), Some(1));
    assert!(output_text(&grep_socket.stdout).is_empty());
    assert!(output_text(&grep_socket.stderr).contains("Error:"));

    let grep_depth = run_veil_in_workspace(
        data_home.path(),
        home.path(),
        workspace.path(),
        &[
            "grep".to_string(),
            "--no-store".to_string(),
            "depth-marker".to_string(),
            depth_root.display().to_string(),
        ],
    );
    assert_eq!(grep_depth.status.code(), Some(0));
    assert!(output_text(&grep_depth.stdout).contains("depth-marker"));

    let grep_entries = run_veil_in_workspace(
        data_home.path(),
        home.path(),
        workspace.path(),
        &[
            "--max-chars".to_string(),
            "64".to_string(),
            "grep".to_string(),
            "--no-store".to_string(),
            "entry-marker".to_string(),
            entries_root.display().to_string(),
        ],
    );
    let grep_entries_stdout = output_text(&grep_entries.stdout);
    let grep_entries_stderr = output_text(&grep_entries.stderr);
    assert_eq!(grep_entries.status.code(), Some(0));
    assert!(grep_entries_stdout.contains("[TRUNCATED: omitted 5 lines ("));
    assert!(grep_entries_stdout.len() > 64);
    assert!(grep_entries_stderr.contains("truncated: true"));

    let grep_long_line = run_veil_in_workspace(
        data_home.path(),
        home.path(),
        workspace.path(),
        &[
            "--max-chars".to_string(),
            "64".to_string(),
            "grep".to_string(),
            "--no-store".to_string(),
            "long-marker".to_string(),
            long_line.display().to_string(),
        ],
    );
    let grep_long_line_stdout = output_text(&grep_long_line.stdout);
    assert_eq!(grep_long_line.status.code(), Some(0));
    assert!(grep_long_line_stdout.contains("long-marker"));
    assert!(grep_long_line_stdout.len() > 64);
    assert!(!grep_long_line_stdout.contains("[TRUNCATED:"));
}
