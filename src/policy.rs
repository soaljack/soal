//! Vault policy engine (Phase 2).
//!
//! Policies control replication targets, timed snapshots, retention, and live
//! mode. Stored beside vault config as `policy.json` so config signatures stay
//! stable while ops policy can evolve more freely.

use crate::vault::Vault;
use crate::SoalError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const POLICY_FILE: &str = "policy.json";
const STATE_FILE: &str = "policy_state.json";

/// Full vault policy (Phase 2).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultPolicy {
    /// Minimum distinct replicas for live content.
    #[serde(default = "default_min_replicas")]
    pub min_replicas: u8,
    /// Auto-snapshot interval in seconds (0 = disabled).
    #[serde(default)]
    pub snapshot_interval_secs: u64,
    /// Keep at most N explicit/auto snapshots when pruning (0 = unlimited).
    #[serde(default)]
    pub retain_snapshots: u64,
    /// Prefer continuous live working-tree watch when daemon runs.
    #[serde(default)]
    pub live_mode: bool,
    /// Prefer always-on / storage-heavy peers for placement (NodeID strings).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prefer_nodes: Vec<String>,
    /// Soft max age of HEAD before health warns (seconds; 0 = no warn).
    #[serde(default)]
    pub max_head_age_secs: u64,
    /// Human notes / tags for operators.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

fn default_min_replicas() -> u8 {
    2
}

impl Default for VaultPolicy {
    fn default() -> Self {
        Self {
            min_replicas: 2,
            snapshot_interval_secs: 0,
            retain_snapshots: 0,
            live_mode: false,
            prefer_nodes: Vec::new(),
            max_head_age_secs: 0,
            label: None,
        }
    }
}

impl VaultPolicy {
    pub fn validate(&self) -> Result<(), SoalError> {
        if self.min_replicas == 0 {
            return Err(SoalError::Other("min_replicas must be >= 1".into()));
        }
        if self.snapshot_interval_secs > 0 && self.snapshot_interval_secs < 5 {
            return Err(SoalError::Other(
                "snapshot_interval_secs must be 0 or >= 5".into(),
            ));
        }
        Ok(())
    }

    /// Merge non-None overrides into a copy.
    pub fn with_updates(
        mut self,
        min_replicas: Option<u8>,
        snapshot_interval_secs: Option<u64>,
        retain_snapshots: Option<u64>,
        live_mode: Option<bool>,
        max_head_age_secs: Option<u64>,
        label: Option<String>,
    ) -> Result<Self, SoalError> {
        if let Some(r) = min_replicas {
            self.min_replicas = r.max(1);
        }
        if let Some(s) = snapshot_interval_secs {
            self.snapshot_interval_secs = s;
        }
        if let Some(n) = retain_snapshots {
            self.retain_snapshots = n;
        }
        if let Some(l) = live_mode {
            self.live_mode = l;
        }
        if let Some(a) = max_head_age_secs {
            self.max_head_age_secs = a;
        }
        if let Some(lab) = label {
            self.label = if lab.is_empty() { None } else { Some(lab) };
        }
        self.validate()?;
        Ok(self)
    }
}

/// Runtime state for scheduled actions (last snapshot time, etc.).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PolicyState {
    pub last_auto_snapshot_at: u64,
    pub last_auto_snapshot_head: Option<String>,
    pub auto_snapshot_count: u64,
    pub updated_at: u64,
}

fn policy_path(vault: &Vault) -> PathBuf {
    vault.root.join(POLICY_FILE)
}

fn state_path(vault: &Vault) -> PathBuf {
    vault.root.join(STATE_FILE)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Load policy; if missing, seed from vault config min_replicas.
pub fn load_policy(vault: &Vault) -> Result<VaultPolicy, SoalError> {
    let path = policy_path(vault);
    if path.exists() {
        let s = fs::read_to_string(path)?;
        let p: VaultPolicy = serde_json::from_str(&s)?;
        p.validate()?;
        return Ok(p);
    }
    // Seed from vault config for seamless upgrade.
    let p = VaultPolicy {
        min_replicas: vault.config.min_replicas.max(1),
        ..VaultPolicy::default()
    };
    save_policy(vault, &p)?;
    Ok(p)
}

pub fn save_policy(vault: &Vault, policy: &VaultPolicy) -> Result<(), SoalError> {
    policy.validate()?;
    let path = policy_path(vault);
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_string_pretty(policy)?)?;
    fs::rename(tmp, path)?;
    Ok(())
}

/// Apply policy and sync min_replicas into vault config (signed when possible).
pub fn apply_policy(vault: &mut Vault, policy: VaultPolicy) -> Result<VaultPolicy, SoalError> {
    policy.validate()?;
    save_policy(vault, &policy)?;
    if vault.config.min_replicas != policy.min_replicas {
        vault.set_min_replicas(policy.min_replicas)?;
    }
    Ok(policy)
}

pub fn load_state(vault: &Vault) -> Result<PolicyState, SoalError> {
    let path = state_path(vault);
    if !path.exists() {
        return Ok(PolicyState::default());
    }
    let s = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&s)?)
}

pub fn save_state(vault: &Vault, state: &PolicyState) -> Result<(), SoalError> {
    let path = state_path(vault);
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_string_pretty(state)?)?;
    fs::rename(tmp, path)?;
    Ok(())
}

/// Whether an auto-snapshot is due given policy + state.
pub fn snapshot_due(policy: &VaultPolicy, state: &PolicyState, now: u64) -> bool {
    if policy.snapshot_interval_secs == 0 {
        return false;
    }
    if state.last_auto_snapshot_at == 0 {
        return true;
    }
    now.saturating_sub(state.last_auto_snapshot_at) >= policy.snapshot_interval_secs
}

/// Run one auto-snapshot if due. Returns Some(commit) when a snapshot was taken.
pub fn maybe_auto_snapshot(
    vault: &mut Vault,
    policy: &VaultPolicy,
    message_prefix: &str,
) -> Result<Option<crate::ContentHash>, SoalError> {
    let mut state = load_state(vault)?;
    let now = now_secs();
    if !snapshot_due(policy, &state, now) {
        return Ok(None);
    }
    // Only snapshot if there is a HEAD (something to label).
    if vault.head()?.is_none() {
        return Ok(None);
    }
    let msg = format!("{message_prefix} auto @{}", chrono_like_stamp(now));
    let h = vault.snapshot(&msg)?;
    state.last_auto_snapshot_at = now;
    state.last_auto_snapshot_head = Some(h.to_hex());
    state.auto_snapshot_count = state.auto_snapshot_count.saturating_add(1);
    state.updated_at = now;
    save_state(vault, &state)?;
    Ok(Some(h))
}

fn chrono_like_stamp(secs: u64) -> String {
    // Keep deps light: unix seconds is fine for message uniqueness.
    secs.to_string()
}

/// Seconds until next auto-snapshot (None if disabled).
pub fn secs_until_snapshot(policy: &VaultPolicy, state: &PolicyState, now: u64) -> Option<u64> {
    if policy.snapshot_interval_secs == 0 {
        return None;
    }
    if state.last_auto_snapshot_at == 0 {
        return Some(0);
    }
    let elapsed = now.saturating_sub(state.last_auto_snapshot_at);
    if elapsed >= policy.snapshot_interval_secs {
        Some(0)
    } else {
        Some(policy.snapshot_interval_secs - elapsed)
    }
}

/// Whether HEAD is older than policy.max_head_age_secs.
pub fn head_stale(vault: &Vault, policy: &VaultPolicy, now: u64) -> Result<bool, SoalError> {
    if policy.max_head_age_secs == 0 {
        return Ok(false);
    }
    let Some(h) = vault.head()? else {
        return Ok(false);
    };
    let c = vault.load_commit(h)?;
    Ok(now.saturating_sub(c.timestamp) > policy.max_head_age_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn policy_roundtrip_and_seed() {
        let dir = tempdir().unwrap();
        let v = Vault::create(dir.path(), "p", false).unwrap();
        let p = load_policy(&v).unwrap();
        assert_eq!(p.min_replicas, 2);
        assert!(policy_path(&v).exists());

        let mut p2 = p.clone();
        p2.snapshot_interval_secs = 60;
        p2.live_mode = true;
        p2.label = Some("photos".into());
        save_policy(&v, &p2).unwrap();
        let loaded = load_policy(&v).unwrap();
        assert_eq!(loaded.snapshot_interval_secs, 60);
        assert!(loaded.live_mode);
    }

    #[test]
    fn auto_snapshot_respects_interval() {
        let dir = tempdir().unwrap();
        let mut v = Vault::create(dir.path(), "s", false).unwrap();
        let f = dir.path().join("a.txt");
        fs::write(&f, b"x").unwrap();
        v.add_path(&f, "a.txt").unwrap();

        let policy = VaultPolicy {
            snapshot_interval_secs: 3600,
            ..VaultPolicy::default()
        };
        save_policy(&v, &policy).unwrap();

        let h1 = maybe_auto_snapshot(&mut v, &policy, "test")
            .unwrap()
            .expect("first due");
        let h2 = maybe_auto_snapshot(&mut v, &policy, "test").unwrap();
        assert!(h2.is_none(), "second should not be due yet");
        assert!(v.load_commit(h1).unwrap().message.contains("auto"));
    }

    #[test]
    fn validate_rejects_zero_replicas() {
        let p = VaultPolicy {
            min_replicas: 0,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }
}
