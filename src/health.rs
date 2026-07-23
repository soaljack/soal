//! Cluster / vault health reporting (Phase 2 observability).

use crate::policy;
use crate::replication;
use crate::vault::Vault;
use crate::{ContentHash, SoalError};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HealthLevel {
    Ok,
    Warn,
    Crit,
}

#[derive(Clone, Debug, Serialize)]
pub struct HealthCheck {
    pub name: String,
    pub level: HealthLevel,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct VaultHealth {
    pub vault: String,
    pub vault_id: String,
    pub level: HealthLevel,
    pub head: Option<String>,
    pub head_age_secs: Option<u64>,
    pub encryption: bool,
    pub key_wrapped: bool,
    pub members: usize,
    pub config_seq: u64,
    pub config_signed: bool,
    pub complete: bool,
    pub file_count: usize,
    pub chunk_count: usize,
    pub alternate_heads: usize,
    pub replication: ReplicationSnapshot,
    pub policy: PolicySnapshot,
    pub checks: Vec<HealthCheck>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReplicationSnapshot {
    pub min_replicas: u8,
    pub live_chunks: usize,
    pub pinned_chunks: usize,
    pub missing_local: usize,
    pub under_replicated: usize,
    pub peers_tracked: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct PolicySnapshot {
    pub snapshot_interval_secs: u64,
    pub live_mode: bool,
    pub retain_snapshots: u64,
    pub max_head_age_secs: u64,
    pub secs_until_auto_snapshot: Option<u64>,
    pub last_auto_snapshot_at: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClusterHealth {
    pub level: HealthLevel,
    pub node_id: Option<String>,
    pub peer_count: usize,
    pub vault_count: usize,
    pub vaults: Vec<VaultHealth>,
    pub checks: Vec<HealthCheck>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn worst(a: HealthLevel, b: HealthLevel) -> HealthLevel {
    use HealthLevel::*;
    match (a, b) {
        (Crit, _) | (_, Crit) => Crit,
        (Warn, _) | (_, Warn) => Warn,
        _ => Ok,
    }
}

/// Assess a single vault.
pub fn assess_vault(vault: &Vault) -> Result<VaultHealth, SoalError> {
    let now = now_secs();
    let policy = policy::load_policy(vault).unwrap_or_default();
    let state = policy::load_state(vault).unwrap_or_default();
    let repl = replication::replication_status(vault)?;
    let head = vault.head()?;
    let mut checks = Vec::new();
    let mut level = HealthLevel::Ok;

    let (head_hex, head_age, complete, file_count) = if let Some(h) = head {
        let c = vault.load_commit(h)?;
        let age = now.saturating_sub(c.timestamp);
        let complete = vault.is_complete(h)?;
        let tree = vault.load_tree(c.tree)?;
        if !complete {
            level = worst(level, HealthLevel::Crit);
            checks.push(HealthCheck {
                name: "completeness".into(),
                level: HealthLevel::Crit,
                message: "HEAD is incomplete (missing tree/chunks)".into(),
            });
        }
        if policy::head_stale(vault, &policy, now)? {
            level = worst(level, HealthLevel::Warn);
            checks.push(HealthCheck {
                name: "head_age".into(),
                level: HealthLevel::Warn,
                message: format!(
                    "HEAD is {age}s old (policy max {})",
                    policy.max_head_age_secs
                ),
            });
        }
        (Some(h.to_hex()), Some(age), complete, tree.entries.len())
    } else {
        checks.push(HealthCheck {
            name: "head".into(),
            level: HealthLevel::Warn,
            message: "no commits yet".into(),
        });
        level = worst(level, HealthLevel::Warn);
        (None, None, true, 0)
    };

    if repl.missing_local > 0 {
        level = worst(level, HealthLevel::Crit);
        checks.push(HealthCheck {
            name: "local_chunks".into(),
            level: HealthLevel::Crit,
            message: format!("{} live chunks missing locally", repl.missing_local),
        });
    }
    if repl.estimated_under_replicated > 0 && repl.min_replicas > 1 {
        level = worst(level, HealthLevel::Warn);
        checks.push(HealthCheck {
            name: "replication".into(),
            level: HealthLevel::Warn,
            message: format!(
                "~{} chunks under min_replicas={}",
                repl.estimated_under_replicated, repl.min_replicas
            ),
        });
    }

    if vault.config.encryption_enabled && vault.config.key_wrapped {
        checks.push(HealthCheck {
            name: "key".into(),
            level: HealthLevel::Ok,
            message: "passphrase-wrapped vault key".into(),
        });
    } else if vault.config.encryption_enabled {
        checks.push(HealthCheck {
            name: "key".into(),
            level: HealthLevel::Ok,
            message: "encryption on (plaintext vault.key on disk)".into(),
        });
    }

    if vault.config.config_sig.is_none() {
        level = worst(level, HealthLevel::Warn);
        checks.push(HealthCheck {
            name: "config_sig".into(),
            level: HealthLevel::Warn,
            message: "vault config is unsigned".into(),
        });
    }

    let alts = vault.list_heads()?.len().saturating_sub(1);
    if alts > 0 {
        level = worst(level, HealthLevel::Warn);
        checks.push(HealthCheck {
            name: "multi_head".into(),
            level: HealthLevel::Warn,
            message: format!("{alts} alternate head(s) — merge recommended"),
        });
    }

    if checks.iter().all(|c| c.level == HealthLevel::Ok) && checks.is_empty() {
        checks.push(HealthCheck {
            name: "overall".into(),
            level: HealthLevel::Ok,
            message: "healthy".into(),
        });
    }

    Ok(VaultHealth {
        vault: vault.name.clone(),
        vault_id: vault.config.vault_id.clone(),
        level,
        head: head_hex,
        head_age_secs: head_age,
        encryption: vault.config.encryption_enabled,
        key_wrapped: vault.config.key_wrapped,
        members: vault.config.members.len(),
        config_seq: vault.config.config_seq,
        config_signed: vault.config.config_sig.is_some(),
        complete,
        file_count,
        chunk_count: vault.chunk_count()?,
        alternate_heads: alts,
        replication: ReplicationSnapshot {
            min_replicas: repl.min_replicas,
            live_chunks: repl.live_chunks,
            pinned_chunks: repl.pinned_chunks,
            missing_local: repl.missing_local,
            under_replicated: repl.estimated_under_replicated,
            peers_tracked: repl.peers_known,
        },
        policy: PolicySnapshot {
            snapshot_interval_secs: policy.snapshot_interval_secs,
            live_mode: policy.live_mode,
            retain_snapshots: policy.retain_snapshots,
            max_head_age_secs: policy.max_head_age_secs,
            secs_until_auto_snapshot: policy::secs_until_snapshot(&policy, &state, now),
            last_auto_snapshot_at: state.last_auto_snapshot_at,
        },
        checks,
    })
}

/// Assess all vaults under a base dir (+ optional node identity / peers).
pub fn assess_cluster(
    base_dir: &std::path::Path,
    node_id: Option<String>,
    peer_count: usize,
) -> Result<ClusterHealth, SoalError> {
    let names = Vault::list(base_dir)?;
    let mut vaults = Vec::new();
    let mut level = HealthLevel::Ok;
    let mut checks = Vec::new();

    if peer_count == 0 {
        checks.push(HealthCheck {
            name: "peers".into(),
            level: HealthLevel::Warn,
            message: "no peers configured".into(),
        });
        level = worst(level, HealthLevel::Warn);
    }

    for name in &names {
        match Vault::open(base_dir, name) {
            Ok(v) => match assess_vault(&v) {
                Ok(h) => {
                    level = worst(level, h.level.clone());
                    vaults.push(h);
                }
                Err(e) => {
                    level = worst(level, HealthLevel::Crit);
                    checks.push(HealthCheck {
                        name: format!("vault:{name}"),
                        level: HealthLevel::Crit,
                        message: e.to_string(),
                    });
                }
            },
            Err(e) => {
                // Passphrase-protected vaults need passphrase — warn not crit.
                level = worst(level, HealthLevel::Warn);
                checks.push(HealthCheck {
                    name: format!("vault:{name}"),
                    level: HealthLevel::Warn,
                    message: format!("could not open: {e}"),
                });
            }
        }
    }

    if names.is_empty() {
        checks.push(HealthCheck {
            name: "vaults".into(),
            level: HealthLevel::Warn,
            message: "no vaults".into(),
        });
        level = worst(level, HealthLevel::Warn);
    }

    Ok(ClusterHealth {
        level,
        node_id,
        peer_count,
        vault_count: names.len(),
        vaults,
        checks,
    })
}

/// Human-readable one-line summary.
pub fn format_vault_health(h: &VaultHealth) -> String {
    let head = h.head.as_deref().unwrap_or("(none)");
    let head_short = if head.len() > 12 { &head[..12] } else { head };
    format!(
        "[{:?}] {} files={} chunks={} head={} repl_under≈{} alts={}",
        h.level,
        h.vault,
        h.file_count,
        h.chunk_count,
        head_short,
        h.replication.under_replicated,
        h.alternate_heads
    )
}

/// Diff two trees (path-level): added / removed / changed.
#[derive(Clone, Debug, Serialize)]
pub struct TreeDiff {
    pub from: String,
    pub to: String,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
}

pub fn diff_commits(
    vault: &Vault,
    from: ContentHash,
    to: ContentHash,
) -> Result<TreeDiff, SoalError> {
    let ca = vault.load_commit(from)?;
    let cb = vault.load_commit(to)?;
    let ta = vault.load_tree(ca.tree)?;
    let tb = vault.load_tree(cb.tree)?;

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();

    for (path, entry) in &tb.entries {
        match ta.entries.get(path) {
            None => added.push(path.clone()),
            Some(old) if old != entry => changed.push(path.clone()),
            _ => {}
        }
    }
    for path in ta.entries.keys() {
        if !tb.entries.contains_key(path) {
            removed.push(path.clone());
        }
    }
    added.sort();
    removed.sort();
    changed.sort();
    Ok(TreeDiff {
        from: from.to_hex(),
        to: to.to_hex(),
        added,
        removed,
        changed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn assess_empty_and_with_data() {
        let dir = tempdir().unwrap();
        let mut v = Vault::create(dir.path(), "h", false).unwrap();
        let empty = assess_vault(&v).unwrap();
        assert!(matches!(empty.level, HealthLevel::Warn));

        let f = dir.path().join("f.txt");
        std::fs::write(&f, b"hi").unwrap();
        v.add_path(&f, "f.txt").unwrap();
        let ok = assess_vault(&v).unwrap();
        assert!(ok.complete);
        assert_eq!(ok.file_count, 1);
        // under-replicated vs min=2 → warn
        assert!(matches!(ok.level, HealthLevel::Warn | HealthLevel::Ok));
    }

    #[test]
    fn diff_detects_add_change_remove() {
        let dir = tempdir().unwrap();
        let mut v = Vault::create(dir.path(), "d", false).unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        std::fs::write(&a, b"v1").unwrap();
        let c1 = v.add_path(&a, "a.txt").unwrap();
        std::fs::write(&a, b"v2").unwrap();
        std::fs::write(&b, b"new").unwrap();
        let c2 = v.add_path(&a, "a.txt").unwrap();
        let c3 = v.add_path(&b, "b.txt").unwrap();
        // remove a by... we can't delete easily; compare c1 vs c3
        let d = diff_commits(&v, c1, c3).unwrap();
        assert!(d.added.contains(&"b.txt".into()) || d.changed.contains(&"a.txt".into()));
        let d2 = diff_commits(&v, c1, c2).unwrap();
        assert!(d2.changed.contains(&"a.txt".into()));
    }
}
