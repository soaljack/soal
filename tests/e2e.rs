//! End-to-end tests for the Soal CLI (Phase 0 + Phase 1).
//!
//! These tests drive the compiled binary and verify core user workflows:
//! - Vault creation (encryption on by default; key separated from config)
//! - Adding files and directories (incremental merge into HEAD tree)
//! - Snapshots and history (DAG parents)
//! - Restore fidelity
//! - Encryption at rest
//! - Deduplication
//! - Persistent node identity + peers
//! - Basic network commands

use assert_cmd::prelude::*;
use assert_fs::TempDir as AssertTempDir;
use predicates::prelude::*;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Helper: run the soal binary with a controlled home directory.
fn soal(home: &Path) -> Command {
    let mut cmd = Command::cargo_bin("soal").expect("binary not found");
    cmd.env("HOME", home);
    cmd.env("USERPROFILE", home);
    cmd
}

fn temp_home() -> AssertTempDir {
    AssertTempDir::new().expect("failed to create temp dir")
}

fn vaults_dir(home: &Path) -> std::path::PathBuf {
    home.join(".soal").join("vaults")
}

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
    // Persistent node identity
    assert!(home.path().join(".soal/node.json").exists());
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
    assert!(vault_dir.join("vault.key").exists());

    let config: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(vault_dir.join("vault.json")).unwrap()).unwrap();
    assert_eq!(config["encryption_enabled"], true);
    // Key must not live in vault.json
    assert!(config.get("key_hex").is_none() || config["key_hex"].is_null());
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

    let src = home.path().join("srcdata");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("hello.txt"), "Hello Soal Phase 0!\nLine two.\n").unwrap();

    soal(home.path())
        .args(["add", src.to_str().unwrap(), "--vault", "test"])
        .assert()
        .success();

    soal(home.path())
        .args(["snapshot", "Initial commit", "--vault", "test"])
        .assert()
        .success();

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
fn test_incremental_add_merges_files() {
    // Design invariant: second add must not wipe the first file from the tree.
    let home = temp_home();
    soal(home.path()).arg("init").assert().success();
    soal(home.path())
        .args(["vault", "create", "merge"])
        .assert()
        .success();

    let a = home.path().join("a.txt");
    let b = home.path().join("b.txt");
    fs::write(&a, "content A").unwrap();
    fs::write(&b, "content B").unwrap();

    soal(home.path())
        .args(["add", a.to_str().unwrap(), "--vault", "merge"])
        .assert()
        .success();
    soal(home.path())
        .args(["add", b.to_str().unwrap(), "--vault", "merge"])
        .assert()
        .success();

    let head = get_head(&vaults_dir(home.path()).join("merge"));
    let restore_dir = home.path().join("merged-out");
    soal(home.path())
        .args([
            "restore",
            &head,
            "--vault",
            "merge",
            "--to",
            restore_dir.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read_to_string(restore_dir.join("a.txt")).unwrap(),
        "content A"
    );
    assert_eq!(
        fs::read_to_string(restore_dir.join("b.txt")).unwrap(),
        "content B"
    );
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
        .filter(|e| {
            let p = e.as_ref().unwrap().path();
            let ext = p.extension().and_then(|s| s.to_str());
            matches!(ext, Some("bin") | Some("json"))
        })
        .count();

    assert!(
        commit_count >= 2,
        "expected at least 2 commits, got {commit_count}"
    );

    // Verify parent chain via library (wire .bin dual-read)
    let vault = soal::vault::Vault::open(vaults_dir(home.path()), "hist").unwrap();
    let head = vault.head().unwrap().expect("HEAD present");
    let commit = vault.load_commit(head).unwrap();
    assert!(
        !commit.parents.is_empty(),
        "HEAD snapshot should parent to previous commit"
    );
    // tree CID is ContentHash (hex-displayable)
    assert_eq!(commit.tree.to_hex().len(), 64);
    // On-disk wire object must content-address
    let wire_path = commits_dir.join(format!("{}.bin", head.to_hex()));
    assert!(wire_path.exists(), "commit stored as .bin wire object");
    let wire = fs::read(&wire_path).unwrap();
    assert_eq!(soal::ContentHash::of(&wire), head);
}

#[test]
fn test_encryption_default_on_and_no_encrypt() {
    let home = temp_home();
    soal(home.path()).arg("init").assert().success();

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
    fs::write(src.join("two.txt"), content).unwrap();

    soal(home.path())
        .args(["add", src.to_str().unwrap(), "--vault", "dedup"])
        .assert()
        .success();

    let chunk_count = fs::read_dir(vaults_dir(home.path()).join("dedup/chunks"))
        .unwrap()
        .count();

    assert!(
        chunk_count <= 3,
        "expected strong deduplication, got {chunk_count} chunks"
    );
}

fn get_head(vault_dir: &Path) -> String {
    let status = fs::read_to_string(vault_dir.join("HEAD")).unwrap_or_default();
    status.trim().to_string()
}

#[test]
fn test_status_and_vault_not_found() {
    let home = temp_home();
    soal(home.path()).arg("init").assert().success();

    soal(home.path())
        .args(["status", "--vault", "does-not-exist"])
        .assert()
        .failure();
}

#[test]
fn test_node_id_stable() {
    let home = temp_home();
    let out1 = soal(home.path()).args(["node", "id"]).output().unwrap();
    assert!(out1.status.success());
    let stdout1 = String::from_utf8_lossy(&out1.stdout);
    let id1 = stdout1
        .lines()
        .find(|l| l.contains("Node ID:"))
        .map(|l| l.trim().to_string())
        .expect("node id line");
    assert!(
        stdout1.contains("Ticket:"),
        "node id should print EndpointTicket for dialing"
    );

    let out2 = soal(home.path()).args(["node", "id"]).output().unwrap();
    let id2 = String::from_utf8_lossy(&out2.stdout)
        .lines()
        .find(|l| l.contains("Node ID:"))
        .map(|l| l.trim().to_string())
        .expect("node id line");

    assert_eq!(
        id1, id2,
        "node identity must be stable across CLI invocations"
    );
}

#[test]
fn test_node_add_peer_validates_and_persists() {
    let home = temp_home();
    // Generate a real node id
    let out = soal(home.path()).args(["node", "id"]).output().unwrap();
    let id_line = String::from_utf8_lossy(&out.stdout);
    let node_id = id_line
        .lines()
        .find(|l| l.contains("Node ID:"))
        .and_then(|l| l.split_whitespace().nth(2))
        .expect("parse node id")
        .to_string();

    // Using own id as peer is fine for persistence test
    soal(home.path())
        .args(["node", "add-peer", &node_id])
        .assert()
        .success()
        .stdout(predicate::str::contains("Added peer"));

    soal(home.path())
        .args(["node", "peers"])
        .assert()
        .success()
        .stdout(predicate::str::contains(&node_id));

    // Invalid peer rejected
    soal(home.path())
        .args(["node", "add-peer", "not-a-valid-endpoint-id"])
        .assert()
        .failure();
}

#[test]
#[cfg(not(target_os = "windows"))]
fn test_node_announce() {
    let home = temp_home();
    soal(home.path()).arg("init").assert().success();
    soal(home.path())
        .args(["vault", "create", "photos", "--no-encrypt"])
        .assert()
        .success();

    let src = home.path().join("ann-src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), "announce me").unwrap();
    let add = soal(home.path())
        .args(["add", src.to_str().unwrap(), "--vault", "photos"])
        .output()
        .unwrap();
    assert!(add.status.success());
    let stdout = String::from_utf8_lossy(&add.stdout);
    // "Added '...' -> commit <hex>"
    let commit = stdout
        .split_whitespace()
        .find(|t| t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()))
        .expect("commit hash in add output")
        .to_string();

    soal(home.path())
        .args(["node", "announce", "photos", &commit])
        .assert()
        .success()
        .stdout(predicate::str::contains("Broadcast signed head"));
}

#[test]
#[cfg(not(target_os = "windows"))]
fn test_node_listen() {
    let home = temp_home();
    soal(home.path()).arg("init").assert().success();
    soal(home.path())
        .args(["vault", "create", "photos", "--no-encrypt"])
        .assert()
        .success();
    soal(home.path())
        .args(["node", "listen", "photos"])
        .assert()
        .success();
}

#[test]
fn test_large_file_roundtrip() {
    let home = temp_home();
    soal(home.path()).arg("init").assert().success();
    soal(home.path())
        .args(["vault", "create", "big", "--no-encrypt"])
        .assert()
        .success();

    // ~3 MiB of patterned data to force multi-chunk CDC
    let big = home.path().join("big.bin");
    let mut data = Vec::with_capacity(3 * 1024 * 1024);
    for i in 0..(3 * 1024 * 1024) {
        data.push((i % 251) as u8);
    }
    fs::write(&big, &data).unwrap();

    let out = soal(home.path())
        .args(["add", big.to_str().unwrap(), "--vault", "big"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let commit = stdout
        .split_whitespace()
        .find(|t| t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()))
        .expect("commit")
        .to_string();

    let dest = home.path().join("restored-big");
    soal(home.path())
        .args([
            "restore",
            &commit,
            "--vault",
            "big",
            "--to",
            dest.to_str().unwrap(),
        ])
        .assert()
        .success();
    let restored = fs::read(dest.join("big.bin")).unwrap();
    assert_eq!(restored, data, "large file restore must be bit-exact");
}

#[test]
fn test_log_and_gc() {
    let home = temp_home();
    soal(home.path()).arg("init").assert().success();
    soal(home.path())
        .args(["vault", "create", "lg", "--no-encrypt"])
        .assert()
        .success();
    let f = home.path().join("one.txt");
    fs::write(&f, "log history content").unwrap();
    soal(home.path())
        .args(["add", f.to_str().unwrap(), "--vault", "lg"])
        .assert()
        .success();
    soal(home.path())
        .args(["snapshot", "label", "--vault", "lg"])
        .assert()
        .success();
    soal(home.path())
        .args(["log", "--vault", "lg", "-n", "5"])
        .assert()
        .success()
        .stdout(predicate::str::contains("label").or(predicate::str::contains("Add")));
    soal(home.path())
        .args(["gc", "--vault", "lg"])
        .assert()
        .success()
        .stdout(predicate::str::contains("dry-run"));
    soal(home.path())
        .args(["status", "--vault", "lg"])
        .assert()
        .success()
        .stdout(predicate::str::contains("vault_id="));
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

    soal(home.path())
        .args(["sync", "--vault", "syncvault"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Sync finished"));
}

#[test]
fn test_passphrase_protect_and_open() {
    let home = temp_home();
    soal(home.path()).arg("init").assert().success();
    soal(home.path())
        .args(["vault", "create", "secret"])
        .assert()
        .success();

    soal(home.path())
        .args([
            "vault",
            "protect",
            "secret",
            "--passphrase",
            "test-pass-123",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("passphrase-protected"));

    // Without passphrase, open fails
    soal(home.path())
        .args(["status", "--vault", "secret"])
        .assert()
        .failure();

    // With passphrase, works
    soal(home.path())
        .args([
            "--passphrase",
            "test-pass-123",
            "status",
            "--vault",
            "secret",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("secret"));

    let src = home.path().join("s.txt");
    fs::write(&src, "encrypted add").unwrap();
    soal(home.path())
        .args([
            "--passphrase",
            "test-pass-123",
            "add",
            src.to_str().unwrap(),
            "--vault",
            "secret",
        ])
        .assert()
        .success();
}

#[test]
fn test_invite_generate_and_join() {
    let home_a = temp_home();
    let home_b = temp_home();
    soal(home_a.path()).arg("init").assert().success();
    soal(home_b.path()).arg("init").assert().success();
    soal(home_a.path())
        .args(["vault", "create", "photos"])
        .assert()
        .success();

    let inv_path = home_a.path().join("invite.token");
    soal(home_a.path())
        .args([
            "invite",
            "generate",
            "--vault",
            "photos",
            "--out",
            inv_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert!(inv_path.exists());
    let token = fs::read_to_string(&inv_path).unwrap();
    assert!(token.len() > 32);

    soal(home_b.path())
        .args(["invite", "join", inv_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Joined vault"));

    // Same vault_id on both sides
    let va: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(vaults_dir(home_a.path()).join("photos/vault.json")).unwrap(),
    )
    .unwrap();
    let vb: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(vaults_dir(home_b.path()).join("photos/vault.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(va["vault_id"], vb["vault_id"]);
}

#[test]
fn test_merge_conflict_copies_cli() {
    let home = temp_home();
    soal(home.path()).arg("init").assert().success();
    // Use library path for divergent heads then CLI merge would need import;
    // exercise via soal binary: two sequential adds don't conflict. Library
    // covers merge; here validate heads listing + replicate CLI.
    soal(home.path())
        .args(["vault", "create", "m", "--replicas", "3"])
        .assert()
        .success();
    let f = home.path().join("n.txt");
    fs::write(&f, "note").unwrap();
    soal(home.path())
        .args(["add", f.to_str().unwrap(), "--vault", "m"])
        .assert()
        .success();

    soal(home.path())
        .args(["replicate", "--vault", "m"])
        .assert()
        .success()
        .stdout(predicate::str::contains("min_replicas: 3"));

    soal(home.path())
        .args(["vault", "policy", "m", "--replicas", "4"])
        .assert()
        .success()
        .stdout(predicate::str::contains("min_replicas=4"));

    soal(home.path())
        .args(["status", "--vault", "m"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Replication:"));
}

#[test]
fn test_retention_gc_and_node_probe() {
    let home = temp_home();
    soal(home.path()).arg("init").assert().success();
    soal(home.path())
        .args(["vault", "create", "keep", "--no-encrypt"])
        .assert()
        .success();
    soal(home.path())
        .args(["vault", "policy", "keep", "--retain", "2"])
        .assert()
        .success();

    let f = home.path().join("x.txt");
    for i in 0..4 {
        fs::write(&f, format!("v{i}")).unwrap();
        soal(home.path())
            .args(["add", f.to_str().unwrap(), "--vault", "keep"])
            .assert()
            .success();
        soal(home.path())
            .args(["snapshot", &format!("snap{i}"), "--vault", "keep"])
            .assert()
            .success();
    }

    // Registry should be pruned to 2 (retain)
    let snaps = vaults_dir(home.path()).join("keep/snapshots.json");
    assert!(snaps.exists(), "snapshots registry should exist");
    let log: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&snaps).unwrap()).unwrap();
    let n = log["entries"].as_array().map(|a| a.len()).unwrap_or(0);
    assert!(n <= 2, "retain=2 should keep at most 2 entries, got {n}");

    soal(home.path())
        .args(["gc", "--vault", "keep", "--apply"])
        .assert()
        .success()
        .stdout(predicate::str::contains("GC:"));

    // Probe with no peers is fine
    soal(home.path()).args(["node", "probe"]).assert().success();
}

#[test]
fn test_health_policy_schedule_diff_json() {
    let home = temp_home();
    soal(home.path()).arg("init").assert().success();
    soal(home.path())
        .args([
            "vault",
            "create",
            "daily",
            "--no-encrypt",
            "--replicas",
            "2",
        ])
        .assert()
        .success();

    let f = home.path().join("a.txt");
    fs::write(&f, "v1").unwrap();
    soal(home.path())
        .args(["add", f.to_str().unwrap(), "--vault", "daily"])
        .assert()
        .success();
    fs::write(&f, "v2").unwrap();
    soal(home.path())
        .args(["add", f.to_str().unwrap(), "--vault", "daily"])
        .assert()
        .success();

    soal(home.path())
        .args([
            "vault",
            "policy",
            "daily",
            "--snapshot-interval",
            "30",
            "--live",
            "true",
            "--label",
            "sanctuary",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("snapshot_interval=30"));

    soal(home.path())
        .args(["--json", "health", "--vault", "daily"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"vault\""))
        .stdout(predicate::str::contains("daily"));

    soal(home.path())
        .args(["schedule", "--vault", "daily", "--force"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Forced snapshot"));

    soal(home.path())
        .args(["diff", "--vault", "daily"])
        .assert()
        .success()
        .stdout(predicate::str::contains("diff"));
}

#[test]
fn test_watch_ingest_short() {
    let home = temp_home();
    soal(home.path()).arg("init").assert().success();
    soal(home.path())
        .args(["vault", "create", "live", "--no-encrypt"])
        .assert()
        .success();
    let root = home.path().join("live-dir");
    fs::create_dir_all(&root).unwrap();
    // Pre-create a file so short watch can pick up modify events after start
    fs::write(root.join("pre.txt"), "pre").unwrap();
    // Watch for 1 second (creates empty batch if no events; must not fail)
    soal(home.path())
        .args([
            "watch",
            root.to_str().unwrap(),
            "--vault",
            "live",
            "--for-secs",
            "1",
            "--debounce-ms",
            "100",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("[watch]"));
}
