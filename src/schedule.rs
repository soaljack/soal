//! Timed snapshot / policy daemon loop (Phase 2).

use crate::policy::{self, VaultPolicy};
use crate::replication;
use crate::vault::Vault;
use crate::{ContentHash, SoalError};
use serde::Serialize;
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Default)]
pub struct ScheduleTick {
    pub vault: String,
    pub snapshot: Option<String>,
    pub pins_added: usize,
    pub snapshots_pruned: usize,
    pub gc_removed: usize,
    pub skipped_reason: Option<String>,
}

/// Run one maintenance tick: auto-snapshot if due + pins + retention + light GC.
pub fn run_tick(vault: &mut Vault, policy: &VaultPolicy) -> Result<ScheduleTick, SoalError> {
    let mut tick = ScheduleTick {
        vault: vault.name.clone(),
        ..Default::default()
    };

    match policy::maybe_auto_snapshot(vault, policy, "scheduled")? {
        Some(h) => tick.snapshot = Some(h.to_hex()),
        None => {
            if policy.snapshot_interval_secs == 0 {
                tick.skipped_reason = Some("auto-snapshot disabled".into());
            } else {
                tick.skipped_reason = Some("interval not elapsed".into());
            }
        }
    }

    tick.pins_added = replication::ensure_local_pins(vault)?;
    tick.snapshots_pruned = policy::apply_retention(vault, policy)?;
    // Opportunistic GC of orphans after retention changes.
    if tick.snapshots_pruned > 0 || tick.snapshot.is_some() {
        tick.gc_removed = vault.gc_all().unwrap_or(0);
    }
    Ok(tick)
}

/// Run the scheduler for `duration`, ticking every `poll` seconds.
pub fn run_for(
    vault: &mut Vault,
    duration: Duration,
    poll: Duration,
) -> Result<Vec<ScheduleTick>, SoalError> {
    let policy = policy::load_policy(vault)?;
    let mut ticks = Vec::new();
    let deadline = std::time::Instant::now() + duration;
    // Always run at least one tick.
    ticks.push(run_tick(vault, &policy)?);
    while std::time::Instant::now() + poll < deadline {
        std::thread::sleep(poll);
        // Reload policy each tick so CLI updates apply.
        let policy = policy::load_policy(vault)?;
        ticks.push(run_tick(vault, &policy)?);
    }
    Ok(ticks)
}

/// Force an auto-snapshot now (ignores interval), updates policy state.
pub fn force_auto_snapshot(vault: &mut Vault, message: &str) -> Result<ContentHash, SoalError> {
    let policy = policy::load_policy(vault)?;
    let mut state = policy::load_state(vault)?;
    if vault.head()?.is_none() {
        return Err(SoalError::Other("no HEAD to snapshot".into()));
    }
    let h = vault.snapshot(message)?;
    let _ = policy::apply_retention(vault, &policy)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    state.last_auto_snapshot_at = now;
    state.last_auto_snapshot_head = Some(h.to_hex());
    state.auto_snapshot_count = state.auto_snapshot_count.saturating_add(1);
    state.updated_at = now;
    policy::save_state(vault, &state)?;
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::VaultPolicy;
    use tempfile::tempdir;

    #[test]
    fn tick_takes_snapshot_when_due() {
        let dir = tempdir().unwrap();
        let mut v = Vault::create(dir.path(), "sch", false).unwrap();
        let f = dir.path().join("x.txt");
        std::fs::write(&f, b"data").unwrap();
        v.add_path(&f, "x.txt").unwrap();
        let policy = VaultPolicy {
            snapshot_interval_secs: 10,
            ..VaultPolicy::default()
        };
        policy::save_policy(&v, &policy).unwrap();
        let tick = run_tick(&mut v, &policy).unwrap();
        assert!(tick.snapshot.is_some());
        let tick2 = run_tick(&mut v, &policy).unwrap();
        assert!(tick2.snapshot.is_none());
    }
}
