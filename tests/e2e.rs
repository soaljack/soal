//! End-to-end tests for the Soal CLI (Phase 0 + early Phase 1).
//!
//! These tests drive the compiled binary and verify core user workflows:
//! - Vault creation (encryption on by default)
//! - Adding files and directories
//! - Snapshots and history
//! - Restore fidelity
//! - Encryption at rest
//! - Deduplication
//! - Basic node/network commands (some skipped on Windows due to iroh networking in CI)

use assert_cmd::prelude::*;
use assert_fs::TempDir as AssertTempDir;
use predicates::prelude::*;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Helper: run the soal binary with a controlled home directory.
/// We set both HOME (Unix) and USERPROFILE (Windows) because `dirs::home_dir()`
/// behaves differently across platforms.
fn soal(home: &Path) -> Command {
    let mut cmd = Command::cargo_bin("soal").expect("binary not found");
    cmd.env("HOME", home);
    cmd.env("USERPROFILE", home);
    cmd
}

/// Helper: create a temp "home" directory for isolation.
fn temp_home() -> AssertTempDir {
    AssertTempDir::new().expect("failed to create temp dir")
}

/// Helper to get the vaults directory under a home.
fn vaults_dir(home: &Path) -> std::path::PathBuf {
    home.join(".soal").join("vaults")
}

/// Create some test data in a directory.
fn create_test_data(dir: &Path) {
    fs::create_dir_all(dir.join("subdir")).unwrap();
    fs::write(
        dir.join("file-a.txt"),
        "File A content for deduplication test\n",
    )
    .unwrap();
    fs::write(dir.join("file-b.txt"), "File B different content here\n").unwrap();
    fs::write(dir.join("subdir/nested.txt"), "Deeply nested content\n").unwrap();
}

#[test]
fn test_init() {
    let home = temp_home();
    soal(home.path())
        .arg("init")
        .assert()
        .success()
        .stdout(predicate::str::contains("Initialized Soal data dir"));

    let vaults = vaults_dir(home.path());
    assert!(vaults.exists());
}

#[test]
fn test_vault_create_default_encrypted() {
    let home = temp_home();
    soal(home.path()).arg("init").assert().success();

    soal(home.path())
        .args(["vault", "create", "photos"])
        .assert()
        .success()
        .stdout(predicate::str::contains("encryption=true"));

    let vault_dir = vaults_dir(home.path()).join("photos");
    assert!(vault_dir.join("vault.json").exists());
    assert!(vault_dir.join("chunks").exists());

    // Verify encryption is on in config
    let config: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(vault_dir.join("vault.json")).unwrap()).unwrap();
    assert_eq!(config["encryption_enabled"], true);
}

#[test]
fn test_vault_create_no_encrypt() {
    let home = temp_home();
    soal(home.path()).arg("init").assert().success();

    soal(home.path())
        .args(["vault", "create", "notes", "--no-encrypt"])
        .assert()
        .success()
        .stdout(predicate::str::contains("encryption=false"));

    let vault_dir = vaults_dir(home.path()).join("notes");
    let config: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(vault_dir.join("vault.json")).unwrap()).unwrap();
    assert_eq!(config["encryption_enabled"], false);
}

#[test]
fn test_vault_list() {
    let home = temp_home();
    soal(home.path()).arg("init").assert().success();

    soal(home.path())
        .args(["vault", "create", "photos"])
        .assert()
        .success();
    soal(home.path())
        .args(["vault", "create", "notes", "--no-encrypt"])
        .assert()
        .success();

    soal(home.path())
        .args(["vault", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("photos"))
        .stdout(predicate::str::contains("notes"));
}

#[test]
fn test_add_file_snapshot_and_restore_fidelity() {
    let home = temp_home();
    soal(home.path()).arg("init").assert().success();

    soal(home.path())
        .args(["vault", "create", "test"])
        .assert()
        .success();

    // Create source data
    let src = home.path().join("srcdata");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("hello.txt"), "Hello Soal Phase 0!\nLine two.\n").unwrap();

    // Add + snapshot
    soal(home.path())
        .args(["add", src.to_str().unwrap(), "--vault", "test"])
        .assert()
        .success();

    soal(home.path())
        .args(["snapshot", "Initial commit", "--vault", "test"])
        .assert()
        .success();

    // Restore
    let status_out = soal(home.path())
        .args(["status", "--vault", "test"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&status_out.stdout);
    let head = stdout
        .lines()
        .find(|l| l.contains("HEAD:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .expect("could not parse HEAD");

    let restore_dir = home.path().join("restored");
    soal(home.path())
        .args([
            "restore",
            head,
            "--vault",
            "test",
            "--to",
            restore_dir.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Verify fidelity
    let restored_file = restore_dir.join("srcdata/hello.txt");
    assert!(restored_file.exists());
    let content = fs::read_to_string(&restored_file).unwrap();
    assert_eq!(content, "Hello Soal Phase 0!\nLine two.\n");
}

#[test]
fn test_add_directory_recursive() {
    let home = temp_home();
    soal(home.path()).arg("init").assert().success();
    soal(home.path())
        .args(["vault", "create", "media"])
        .assert()
        .success();

    let src = home.path().join("media-src");
    create_test_data(&src);

    soal(home.path())
        .args(["add", src.to_str().unwrap(), "--vault", "media"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Added"));

    // Should have created nested structure under the base name
    let vault_dir = vaults_dir(home.path()).join("media");
    let head = get_head(&vault_dir);

    let restore_dir = home.path().join("restored-media");
    soal(home.path())
        .args([
            "restore",
            &head,
            "--vault",
            "media",
            "--to",
            restore_dir.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(restore_dir.join("media-src/subdir/nested.txt").exists());
    let nested = fs::read_to_string(restore_dir.join("media-src/subdir/nested.txt")).unwrap();
    assert!(nested.contains("Deeply nested"));
}

#[test]
fn test_multiple_snapshots_create_history() {
    let home = temp_home();
    soal(home.path()).arg("init").assert().success();
    soal(home.path())
        .args(["vault", "create", "hist"])
        .assert()
        .success();

    let src = home.path().join("data");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), "v1").unwrap();

    soal(home.path())
        .args(["add", src.to_str().unwrap(), "--vault", "hist"])
        .assert()
        .success();
    soal(home.path())
        .args(["snapshot", "v1", "--vault", "hist"])
        .assert()
        .success();

    fs::write(src.join("a.txt"), "v2").unwrap();
    soal(home.path())
        .args(["add", src.to_str().unwrap(), "--vault", "hist"])
        .assert()
        .success();
    soal(home.path())
        .args(["snapshot", "v2", "--vault", "hist"])
        .assert()
        .success();

    let commits_dir = vaults_dir(home.path()).join("hist/commits");
    let commit_count = fs::read_dir(&commits_dir)
        .unwrap()
        .filter(|e| e.as_ref().unwrap().path().extension() == Some(std::ffi::OsStr::new("json")))
        .count();

    assert!(
        commit_count >= 2,
        "expected at least 2 commits, got {commit_count}"
    );
}

#[test]
fn test_encryption_default_on_and_no_encrypt() {
    let home = temp_home();
    soal(home.path()).arg("init").assert().success();

    // Encrypted vault (default)
    soal(home.path())
        .args(["vault", "create", "secure"])
        .assert()
        .success();

    let src = home.path().join("secret");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("secret.txt"),
        "This is super secret Phase 0 data!!!",
    )
    .unwrap();

    soal(home.path())
        .args(["add", src.to_str().unwrap(), "--vault", "secure"])
        .assert()
        .success();

    let chunks_dir = vaults_dir(home.path()).join("secure/chunks");
    let has_plaintext = fs::read_dir(&chunks_dir).unwrap().any(|e| {
        let p = e.unwrap().path();
        if p.extension() == Some(std::ffi::OsStr::new("chunk")) {
            let content = fs::read_to_string(&p).unwrap_or_default();
            content.contains("super secret")
        } else {
            false
        }
    });
    assert!(
        !has_plaintext,
        "encrypted chunks should not contain plaintext"
    );

    // Unencrypted vault
    soal(home.path())
        .args(["vault", "create", "plain", "--no-encrypt"])
        .assert()
        .success();

    soal(home.path())
        .args(["add", src.to_str().unwrap(), "--vault", "plain"])
        .assert()
        .success();

    let plain_chunks = vaults_dir(home.path()).join("plain/chunks");
    let has_plain = fs::read_dir(&plain_chunks).unwrap().any(|e| {
        let p = e.unwrap().path();
        if p.extension() == Some(std::ffi::OsStr::new("chunk")) {
            fs::read_to_string(&p)
                .unwrap_or_default()
                .contains("super secret")
        } else {
            false
        }
    });
    assert!(
        has_plain,
        "unencrypted vault should store readable plaintext"
    );
}

#[test]
fn test_deduplication() {
    let home = temp_home();
    soal(home.path()).arg("init").assert().success();
    soal(home.path())
        .args(["vault", "create", "dedup"])
        .assert()
        .success();

    let src = home.path().join("dedup-src");
    fs::create_dir_all(&src).unwrap();
    let content = "This exact string will be duplicated across files.";
    fs::write(src.join("one.txt"), content).unwrap();
    fs::write(src.join("two.txt"), content).unwrap(); // identical content

    soal(home.path())
        .args(["add", src.to_str().unwrap(), "--vault", "dedup"])
        .assert()
        .success();

    let chunk_count = fs::read_dir(vaults_dir(home.path()).join("dedup/chunks"))
        .unwrap()
        .count();

    // With good CDC + dedup we should have very few chunks (ideally 1 for identical data)
    assert!(
        chunk_count <= 3,
        "expected strong deduplication, got {chunk_count} chunks"
    );
}

/// Helper to extract HEAD commit from status output.
fn get_head(vault_dir: &Path) -> String {
    let status = fs::read_to_string(vault_dir.join("HEAD")).unwrap_or_default();
    status.trim().to_string()
}

#[test]
fn test_status_and_vault_not_found() {
    let home = temp_home();
    soal(home.path()).arg("init").assert().success();

    // Non-existent vault should error reasonably
    soal(home.path())
        .args(["status", "--vault", "does-not-exist"])
        .assert()
        .failure();
}

#[test]
fn test_node_id() {
    let home = temp_home();
    soal(home.path())
        .args(["node", "id"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Node ID:"));
}

#[test]
fn test_node_add_peer() {
    let home = temp_home();
    soal(home.path())
        .args(["node", "add-peer", "fake-node-id-for-test"])
        .assert()
        .success();
}

#[test]
#[cfg(not(target_os = "windows"))] // real networking (iroh) can be flaky on Windows CI runners
fn test_node_announce() {
    let home = temp_home();
    soal(home.path())
        .args(["node", "announce", "photos", "head123"])
        .assert()
        .success();
}

#[test]
#[cfg(not(target_os = "windows"))] // real networking + short listener loop; keep responsive on all platforms
fn test_node_listen() {
    let home = temp_home();
    soal(home.path())
        .args(["node", "listen", "photos"])
        .assert()
        .success();
}

#[test]
fn test_snapshot_and_sync_smoke() {
    let home = temp_home();
    soal(home.path()).arg("init").assert().success();
    soal(home.path())
        .args(["vault", "create", "syncvault"])
        .assert()
        .success();

    let src = home.path().join("snap-src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("data.txt"), "snapshot sync test data").unwrap();

    soal(home.path())
        .args(["add", src.to_str().unwrap(), "--vault", "syncvault"])
        .assert()
        .success();

    soal(home.path())
        .args(["snapshot", "test snap", "--vault", "syncvault"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Snapshot"));

    // Sync should not crash (Phase 1 partial impl)
    soal(home.path())
        .args(["sync", "--vault", "syncvault"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Sync triggered"));
}
