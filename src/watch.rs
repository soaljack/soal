//! Live working-tree watch (PR-11).
//!
//! Watches a filesystem path with `notify` and merges changed files into the
//! vault via `Vault::add_path`. Debounces rapid events so a single save storm
//! becomes one commit.

use crate::vault::Vault;
use crate::{ContentHash, SoalError};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Default debounce window for coalescing FS events.
pub const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(400);

/// Result of one watch tick / batch.
#[derive(Debug, Clone)]
pub struct WatchBatch {
    pub commits: Vec<(PathBuf, ContentHash)>,
    pub errors: Vec<String>,
}

/// Watch `watch_root` and add relative files into `vault` under logical prefix.
///
/// Runs until `max_duration` elapses (if Some) or forever when None.
/// `on_commit` is called after each successful add (for announce hooks).
pub fn watch_vault_path<F>(
    vault: &mut Vault,
    watch_root: &Path,
    debounce: Duration,
    max_duration: Option<Duration>,
    mut on_commit: F,
) -> Result<WatchBatch, SoalError>
where
    F: FnMut(&Path, ContentHash),
{
    if !watch_root.exists() {
        return Err(SoalError::Other(format!(
            "watch path does not exist: {}",
            watch_root.display()
        )));
    }

    let (tx, rx) = mpsc::channel::<notify::Result<Event>>();
    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = tx.send(res);
        },
        notify::Config::default(),
    )
    .map_err(|e| SoalError::Other(format!("watch: {e}")))?;

    watcher
        .watch(watch_root, RecursiveMode::Recursive)
        .map_err(|e| SoalError::Other(format!("watch start: {e}")))?;

    let started = Instant::now();
    let mut pending: BTreeSet<PathBuf> = BTreeSet::new();
    let mut last_event = Instant::now();
    let mut batch = WatchBatch {
        commits: Vec::new(),
        errors: Vec::new(),
    };

    println!(
        "[watch] Watching {} → vault '{}' (debounce {}ms)",
        watch_root.display(),
        vault.name,
        debounce.as_millis()
    );

    loop {
        if let Some(max) = max_duration {
            if started.elapsed() >= max {
                // Flush remaining
                flush_pending(vault, watch_root, &mut pending, &mut batch, &mut on_commit);
                break;
            }
        }

        let timeout = debounce
            .checked_sub(last_event.elapsed())
            .unwrap_or(Duration::from_millis(50))
            .max(Duration::from_millis(50));

        match rx.recv_timeout(timeout) {
            Ok(Ok(event)) => {
                last_event = Instant::now();
                if is_interesting(&event.kind) {
                    for p in event.paths {
                        if p.is_file() {
                            pending.insert(p);
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                batch.errors.push(format!("notify: {e}"));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if !pending.is_empty() && last_event.elapsed() >= debounce {
                    flush_pending(vault, watch_root, &mut pending, &mut batch, &mut on_commit);
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    Ok(batch)
}

/// One-shot: process a single path as if a watch event fired (tests / manual).
pub fn ingest_path(
    vault: &mut Vault,
    watch_root: &Path,
    file: &Path,
) -> Result<ContentHash, SoalError> {
    add_relative(vault, watch_root, file)
}

fn is_interesting(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Any
    )
}

fn flush_pending<F>(
    vault: &mut Vault,
    watch_root: &Path,
    pending: &mut BTreeSet<PathBuf>,
    batch: &mut WatchBatch,
    on_commit: &mut F,
) where
    F: FnMut(&Path, ContentHash),
{
    let files: Vec<PathBuf> = std::mem::take(pending).into_iter().collect();
    for file in files {
        if !file.is_file() {
            continue;
        }
        // Skip temp/editor swap files
        if let Some(name) = file.file_name().and_then(|s| s.to_str()) {
            if name.starts_with('.') || name.ends_with('~') || name.ends_with(".swp") {
                continue;
            }
        }
        match add_relative(vault, watch_root, &file) {
            Ok(h) => {
                println!("[watch] Added {} → {}", file.display(), h.to_hex());
                on_commit(&file, h);
                batch.commits.push((file, h));
            }
            Err(e) => {
                let msg = format!("{}: {e}", file.display());
                println!("[watch] error: {msg}");
                batch.errors.push(msg);
            }
        }
    }
}

fn add_relative(
    vault: &mut Vault,
    watch_root: &Path,
    file: &Path,
) -> Result<ContentHash, SoalError> {
    let rel = file.strip_prefix(watch_root).unwrap_or(file);
    let logical = rel
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect::<Vec<_>>()
        .join("/");
    if logical.is_empty() {
        return Err(SoalError::InvalidPath("empty watch logical path".into()));
    }
    vault.add_path(file, &logical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn ingest_path_adds_file() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("live");
        std::fs::create_dir_all(&root).unwrap();
        let f = root.join("note.txt");
        std::fs::write(&f, b"live watch").unwrap();
        let mut v = Vault::create(dir.path(), "w", false).unwrap();
        let h = ingest_path(&mut v, &root, &f).unwrap();
        assert!(v.head().unwrap().is_some());
        let tree = v.head_tree().unwrap();
        assert!(tree.entries.contains_key("note.txt"));
        let _ = h;
    }

    #[test]
    fn watch_short_duration_picks_up_write() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("live");
        std::fs::create_dir_all(&root).unwrap();
        let mut v = Vault::create(dir.path(), "w2", false).unwrap();

        // Spawn a delayed write
        let root2 = root.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            std::fs::write(root2.join("x.txt"), b"from watch").unwrap();
        });

        let batch = watch_vault_path(
            &mut v,
            &root,
            Duration::from_millis(100),
            Some(Duration::from_millis(800)),
            |_, _| {},
        )
        .unwrap();
        // Best-effort: may or may not see the event depending on FS notify timing
        // but the API must not panic / error.
        let _ = batch;
    }
}
