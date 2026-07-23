use clap::{Parser, Subcommand};
use soal::health;
use soal::invite::{self, InviteRole};
use soal::network::Network;
use soal::policy::{self, VaultPolicy};
use soal::replication;
use soal::schedule;
use soal::sync;
use soal::vault::{default_soal_dir, default_soal_home, Vault};
use soal::watch;
use soal::ContentHash;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "soal",
    version,
    about = "Soal — sovereign, content-addressed local file storage & sync"
)]
struct Cli {
    /// Passphrase for passphrase-wrapped vault keys
    #[arg(long, global = true, env = "SOAL_PASSPHRASE")]
    passphrase: Option<String>,

    /// Emit machine-readable JSON where supported
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize Soal local data directory
    Init {
        /// Optional custom data directory (vaults root)
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },

    /// Show status of a vault (or list vaults)
    Status {
        #[arg(short, long)]
        vault: Option<String>,
    },

    /// Health report for a vault or the whole cluster
    Health {
        #[arg(short, long)]
        vault: Option<String>,
    },

    /// Diff two commits (path-level added/removed/changed)
    Diff {
        /// From commit (default: HEAD parent)
        #[arg(long)]
        from: Option<String>,
        /// To commit (default: HEAD)
        #[arg(long)]
        to: Option<String>,
        #[arg(short, long)]
        vault: Option<String>,
    },

    /// Run policy scheduler (timed snapshots + pin refresh)
    Schedule {
        #[arg(short, long)]
        vault: Option<String>,
        /// How long to run (seconds); 0 = single tick
        #[arg(long, default_value_t = 0)]
        for_secs: u64,
        /// Poll interval between ticks (seconds)
        #[arg(long, default_value_t = 5)]
        every_secs: u64,
        /// Force a snapshot now regardless of interval
        #[arg(long)]
        force: bool,
    },

    /// Manage vaults
    Vault {
        #[command(subcommand)]
        action: VaultCmd,
    },

    /// Add a file or directory to a vault (merges into HEAD tree)
    Add {
        path: PathBuf,
        #[arg(short, long)]
        vault: Option<String>,
        #[arg(short, long)]
        message: Option<String>,
    },

    /// Create an explicit snapshot (labels current tree)
    Snapshot {
        message: String,
        #[arg(short, long)]
        vault: Option<String>,
        /// Also announce head and provide blobs to the network
        #[arg(long)]
        announce: bool,
    },

    /// Restore a commit into a directory
    Restore {
        commit: String,
        #[arg(short, long)]
        to: Option<PathBuf>,
        #[arg(short, long)]
        vault: Option<String>,
    },

    /// Show commit history (newest first)
    Log {
        #[arg(short, long)]
        vault: Option<String>,
        /// Max commits to show
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: usize,
    },

    /// Garbage-collect unreferenced chunks (reachable from HEAD DAG kept)
    Gc {
        #[arg(short, long)]
        vault: Option<String>,
        /// Actually delete (default is dry-run)
        #[arg(long)]
        apply: bool,
    },

    /// Sync a vault from known peers (fetch remote commit graph + chunks)
    Sync {
        #[arg(short, long)]
        vault: Option<String>,
        /// Remote commit hash to pull (preferred). If omitted, listens briefly for gossip heads.
        #[arg(long)]
        head: Option<String>,
        /// Merge remote into local HEAD with conflict copies instead of fast-forward
        #[arg(long)]
        merge: bool,
        /// Label used in conflict copy filenames
        #[arg(long, default_value = "remote")]
        from: String,
    },

    /// Merge a remote head into local HEAD (conflict copies on divergence)
    Merge {
        /// Remote commit hash (must already be imported or reachable via --fetch)
        head: String,
        #[arg(short, long)]
        vault: Option<String>,
        #[arg(long, default_value = "remote")]
        from: String,
        /// Fetch missing objects from peers before merge
        #[arg(long)]
        fetch: bool,
    },

    /// Live-watch a directory and add changes into a vault
    Watch {
        path: PathBuf,
        #[arg(short, long)]
        vault: Option<String>,
        /// Debounce window in milliseconds
        #[arg(long, default_value_t = 400)]
        debounce_ms: u64,
        /// Optional max runtime in seconds (omit to run until Ctrl-C / forever in practice use max)
        #[arg(long)]
        for_secs: Option<u64>,
        /// Announce each commit after add
        #[arg(long)]
        announce: bool,
    },

    /// Replication status / self-heal provide
    Replicate {
        #[arg(short, long)]
        vault: Option<String>,
        /// Push HEAD blobs + signed announce to peers
        #[arg(long)]
        push: bool,
    },

    /// Generate or join vault invites
    Invite {
        #[command(subcommand)]
        action: InviteCmd,
    },

    /// Node identity and network
    Node {
        #[command(subcommand)]
        action: NodeCmd,
    },
}

#[derive(Subcommand)]
enum VaultCmd {
    /// Create a new vault
    Create {
        name: String,
        /// Disable encryption (default is enabled)
        #[arg(long)]
        no_encrypt: bool,
        /// Minimum replicas for replication policy
        #[arg(long, default_value_t = 2)]
        replicas: u8,
        /// Immediately wrap the vault key with a passphrase
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// List vaults
    List,
    /// Show or update vault policy (replicas, snapshot interval, live, retention)
    Policy {
        name: String,
        #[arg(long)]
        replicas: Option<u8>,
        /// Auto-snapshot interval seconds (0 disables)
        #[arg(long)]
        snapshot_interval: Option<u64>,
        /// Max snapshots to retain when pruning (0 = unlimited)
        #[arg(long)]
        retain: Option<u64>,
        /// Enable/disable live_mode policy flag
        #[arg(long)]
        live: Option<bool>,
        /// Warn when HEAD older than this many seconds (0 = off)
        #[arg(long)]
        max_head_age: Option<u64>,
        /// Operator label
        #[arg(long)]
        label: Option<String>,
    },
    /// Wrap vault key with passphrase
    Protect {
        name: String,
        #[arg(long)]
        passphrase: String,
    },
    /// Add a member NodeID
    AddMember { name: String, node_id: String },
    /// Remove a member NodeID
    RemoveMember { name: String, node_id: String },
}

#[derive(Subcommand)]
enum InviteCmd {
    /// Generate a signed invite token for a vault
    Generate {
        #[arg(short, long)]
        vault: String,
        #[arg(long, default_value = "write")]
        role: String,
        /// Time-to-live in seconds (default 7 days)
        #[arg(long)]
        ttl: Option<u64>,
        /// Write token to a file instead of stdout only
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Join a vault from an invite token (or @file / file path)
    Join {
        token_or_file: String,
        /// Local vault name (defaults to invite vault_name)
        #[arg(long)]
        name: Option<String>,
    },
}

#[derive(Subcommand)]
enum NodeCmd {
    /// Show this node's persistent identity
    Id,
    /// Add a peer by EndpointTicket (preferred) or bare EndpointId
    AddPeer { node_id: String },
    /// Remove a peer (ticket string or id as stored)
    RemovePeer { node_id: String },
    /// List known peers
    Peers,
    /// Announce a head for a vault (signed gossip + vault CAS provide)
    Announce { vault: String, head: String },
    /// Listen briefly for head announcements
    Listen { vault: String },
    /// Broadcast presence on the discovery topic (LAN gossip)
    Beacon {
        /// How long to stay online broadcasting (seconds)
        #[arg(long, default_value_t = 5)]
        secs: u64,
    },
    /// Listen for discovery beacons and optionally add peers
    Discover {
        #[arg(long, default_value_t = 5)]
        secs: u64,
        /// Automatically add discovered tickets as peers
        #[arg(long)]
        add: bool,
    },
}

fn open_vault(
    base_dir: &std::path::Path,
    name: &str,
    passphrase: Option<&str>,
) -> anyhow::Result<Vault> {
    Ok(Vault::open_with_passphrase(base_dir, name, passphrase)?)
}

fn print_json<T: serde::Serialize>(v: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let soal_home = default_soal_home();
    let base_dir = default_soal_dir();
    let pass = cli.passphrase.as_deref();
    let json = cli.json;

    match cli.command {
        Commands::Init { data_dir } => {
            let dir = data_dir.unwrap_or_else(|| base_dir.clone());
            std::fs::create_dir_all(&dir)?;
            std::fs::create_dir_all(&soal_home)?;
            let _ = Network::open(&soal_home).await;
            if json {
                print_json(&serde_json::json!({
                    "data_dir": dir,
                    "node_home": soal_home,
                }))?;
            } else {
                println!("Initialized Soal data dir at {}", dir.display());
                println!("Node home: {}", soal_home.display());
                println!("Use `soal vault create <name>` to get started.");
            }
        }

        Commands::Status { vault } => {
            if let Some(name) = vault {
                let v = open_vault(&base_dir, &name, pass)?;
                if json {
                    let h = health::assess_vault(&v)?;
                    print_json(&h)?;
                } else {
                    println!("{}", v.status()?);
                    if let Ok(st) = replication::replication_status(&v) {
                        println!(
                            "Replication: min={} live_chunks={} pinned={} under_replicated≈{} peers_tracked={}",
                            st.min_replicas,
                            st.live_chunks,
                            st.pinned_chunks,
                            st.estimated_under_replicated,
                            st.peers_known
                        );
                    }
                    if let Ok(p) = policy::load_policy(&v) {
                        println!(
                            "Policy: snapshot_interval={}s live={} retain={} max_head_age={}s",
                            p.snapshot_interval_secs,
                            p.live_mode,
                            p.retain_snapshots,
                            p.max_head_age_secs
                        );
                    }
                    let heads = v.list_heads()?;
                    if heads.len() > 1 {
                        println!("Heads ({}):", heads.len());
                        for h in heads {
                            println!("  {}", h.to_hex());
                        }
                    }
                }
            } else {
                let vaults = Vault::list(&base_dir)?;
                if json {
                    print_json(&vaults)?;
                } else if vaults.is_empty() {
                    println!("No vaults found. Run `soal vault create myvault`");
                } else {
                    println!("Vaults:");
                    for v in vaults {
                        println!("  - {v}");
                    }
                }
            }
        }

        Commands::Health { vault } => {
            if let Some(name) = vault {
                let v = open_vault(&base_dir, &name, pass)?;
                let h = health::assess_vault(&v)?;
                if json {
                    print_json(&h)?;
                } else {
                    println!("{}", health::format_vault_health(&h));
                    for c in &h.checks {
                        println!("  - {:?}: {} — {}", c.level, c.name, c.message);
                    }
                }
            } else {
                let (node_id, peers) = match Network::open(&soal_home).await {
                    Ok(n) => (Some(n.node_id()), n.peers().len()),
                    Err(_) => (None, 0),
                };
                let cluster = health::assess_cluster(&base_dir, node_id, peers)?;
                if json {
                    print_json(&cluster)?;
                } else {
                    println!(
                        "Cluster [{:?}] vaults={} peers={} node={}",
                        cluster.level,
                        cluster.vault_count,
                        cluster.peer_count,
                        cluster.node_id.as_deref().unwrap_or("?")
                    );
                    for c in &cluster.checks {
                        println!("  - {:?}: {} — {}", c.level, c.name, c.message);
                    }
                    for v in &cluster.vaults {
                        println!("  {}", health::format_vault_health(v));
                    }
                }
            }
        }

        Commands::Diff { from, to, vault } => {
            let vault_name = vault.unwrap_or_else(|| "default".to_string());
            let v = open_vault(&base_dir, &vault_name, pass)?;
            let to_h = match to {
                Some(s) => ContentHash::from_hex(&s)?,
                None => v
                    .head()?
                    .ok_or_else(|| anyhow::anyhow!("no HEAD; pass --to"))?,
            };
            let from_h = match from {
                Some(s) => ContentHash::from_hex(&s)?,
                None => {
                    let c = v.load_commit(to_h)?;
                    c.parents.first().copied().ok_or_else(|| {
                        anyhow::anyhow!("HEAD has no parent; pass --from <commit>")
                    })?
                }
            };
            let d = health::diff_commits(&v, from_h, to_h)?;
            if json {
                print_json(&d)?;
            } else {
                println!("diff {} → {}", &d.from[..12], &d.to[..12]);
                for p in &d.added {
                    println!("  + {p}");
                }
                for p in &d.removed {
                    println!("  - {p}");
                }
                for p in &d.changed {
                    println!("  ~ {p}");
                }
                if d.added.is_empty() && d.removed.is_empty() && d.changed.is_empty() {
                    println!("  (no path differences)");
                }
            }
        }

        Commands::Schedule {
            vault,
            for_secs,
            every_secs,
            force,
        } => {
            let vault_name = vault.unwrap_or_else(|| "default".to_string());
            let mut v = open_vault(&base_dir, &vault_name, pass)?;
            if force {
                let h = schedule::force_auto_snapshot(&mut v, "forced schedule snapshot")?;
                if json {
                    print_json(&serde_json::json!({"snapshot": h.to_hex()}))?;
                } else {
                    println!("Forced snapshot: {h}");
                }
            } else if for_secs == 0 {
                let policy = policy::load_policy(&v)?;
                let tick = schedule::run_tick(&mut v, &policy)?;
                if json {
                    print_json(&tick)?;
                } else {
                    match &tick.snapshot {
                        Some(s) => println!("Auto-snapshot: {s}"),
                        None => println!(
                            "No snapshot ({})",
                            tick.skipped_reason.as_deref().unwrap_or("n/a")
                        ),
                    }
                    println!("Pins refreshed (+{})", tick.pins_added);
                }
            } else {
                let ticks = schedule::run_for(
                    &mut v,
                    Duration::from_secs(for_secs),
                    Duration::from_secs(every_secs.max(1)),
                )?;
                if json {
                    print_json(&ticks)?;
                } else {
                    for t in &ticks {
                        if let Some(s) = &t.snapshot {
                            println!("[{}] snapshot {s}", t.vault);
                        }
                    }
                    println!("Schedule finished ({} ticks)", ticks.len());
                }
            }
        }

        Commands::Vault { action } => match action {
            VaultCmd::Create {
                name,
                no_encrypt,
                replicas,
                passphrase: create_pass,
            } => {
                let encrypt = !no_encrypt;
                let mut v = Vault::create_with_policy(&base_dir, &name, encrypt, replicas)?;
                let pol = VaultPolicy {
                    min_replicas: replicas.max(1),
                    ..VaultPolicy::default()
                };
                policy::save_policy(&v, &pol)?;
                if let Some(p) = create_pass.as_deref().or(pass) {
                    if encrypt {
                        v.enable_passphrase(p)?;
                        println!("Vault key wrapped with passphrase.");
                    }
                }
                if json {
                    print_json(&serde_json::json!({
                        "name": name,
                        "encryption": encrypt,
                        "min_replicas": replicas,
                        "vault_id": v.config.vault_id,
                        "path": v.root,
                    }))?;
                } else {
                    println!(
                        "Created vault '{name}' (encryption={encrypt}, min_replicas={replicas})"
                    );
                    println!("vault_id={}", v.config.vault_id);
                    if let Some(sig) = &v.config.config_sig {
                        println!("config_sig={}", &sig[..16.min(sig.len())]);
                    }
                    println!("Data: {}", v.root.display());
                }
            }
            VaultCmd::List => {
                let vaults = Vault::list(&base_dir)?;
                if json {
                    print_json(&vaults)?;
                } else if vaults.is_empty() {
                    println!("No vaults yet.");
                } else {
                    for name in vaults {
                        println!("{name}");
                    }
                }
            }
            VaultCmd::Policy {
                name,
                replicas,
                snapshot_interval,
                retain,
                live,
                max_head_age,
                label,
            } => {
                let mut v = open_vault(&base_dir, &name, pass)?;
                let current = policy::load_policy(&v)?;
                let any = replicas.is_some()
                    || snapshot_interval.is_some()
                    || retain.is_some()
                    || live.is_some()
                    || max_head_age.is_some()
                    || label.is_some();
                if any {
                    let updated = current.with_updates(
                        replicas,
                        snapshot_interval,
                        retain,
                        live,
                        max_head_age,
                        label,
                    )?;
                    let applied = policy::apply_policy(&mut v, updated)?;
                    if json {
                        print_json(&applied)?;
                    } else {
                        println!(
                            "Policy updated on '{name}': min_replicas={} snapshot_interval={}s live={} retain={} max_head_age={}s",
                            applied.min_replicas,
                            applied.snapshot_interval_secs,
                            applied.live_mode,
                            applied.retain_snapshots,
                            applied.max_head_age_secs
                        );
                    }
                } else if json {
                    print_json(&current)?;
                } else {
                    println!("Policy for vault '{name}':");
                    println!("  min_replicas: {}", current.min_replicas);
                    println!(
                        "  snapshot_interval_secs: {}",
                        current.snapshot_interval_secs
                    );
                    println!("  retain_snapshots: {}", current.retain_snapshots);
                    println!("  live_mode: {}", current.live_mode);
                    println!("  max_head_age_secs: {}", current.max_head_age_secs);
                    println!("  prefer_nodes: {:?}", current.prefer_nodes);
                    println!("  label: {:?}", current.label);
                    println!("  config_seq: {}", v.config.config_seq);
                }
            }
            VaultCmd::Protect {
                name,
                passphrase: p,
            } => {
                let mut v = open_vault(&base_dir, &name, pass)?;
                v.enable_passphrase(&p)?;
                println!("Vault '{name}' key is now passphrase-protected.");
            }
            VaultCmd::AddMember { name, node_id } => {
                let mut v = open_vault(&base_dir, &name, pass)?;
                v.add_member(&node_id)?;
                println!(
                    "Added member {node_id} (members={})",
                    v.config.members.len()
                );
            }
            VaultCmd::RemoveMember { name, node_id } => {
                let mut v = open_vault(&base_dir, &name, pass)?;
                if v.remove_member(&node_id)? {
                    println!("Removed member {node_id}");
                } else {
                    println!("Member not found: {node_id}");
                }
            }
        },

        Commands::Add {
            path,
            vault,
            message,
        } => {
            let vault_name = vault.unwrap_or_else(|| "default".to_string());
            let mut v = match open_vault(&base_dir, &vault_name, pass) {
                Ok(v) => v,
                Err(_) => {
                    println!("Vault '{vault_name}' not found, creating...");
                    Vault::create(&base_dir, &vault_name, true)?
                }
            };

            let logical = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("item")
                .to_string();

            let commit = v.add_path(&path, &logical)?;
            println!("Added '{}' -> commit {}", path.display(), commit);
            let _ = replication::ensure_local_pins(&v);

            if let Some(msg) = message {
                let c = v.snapshot(&msg)?;
                println!("Snapshot created: {c}");
            }
        }

        Commands::Snapshot {
            message,
            vault,
            announce,
        } => {
            let vault_name = vault.unwrap_or_else(|| "default".to_string());
            let mut v = open_vault(&base_dir, &vault_name, pass)?;
            let commit = v.snapshot(&message)?;
            println!("Snapshot '{message}' created: {commit}");

            if announce {
                if let Ok(net) = Network::open(&soal_home).await {
                    let _ = net.announce_head_signed(&v, commit).await;
                }
            }
        }

        Commands::Restore { commit, to, vault } => {
            let vault_name = vault.unwrap_or_else(|| "default".to_string());
            let v = open_vault(&base_dir, &vault_name, pass)?;
            let h = ContentHash::from_hex(&commit)
                .map_err(|_| anyhow::anyhow!("commit must be 64 hex chars"))?;
            let target = to.unwrap_or_else(|| PathBuf::from("restored"));
            v.restore(h, &target)?;
            println!("Restored commit {commit} into {}", target.display());
        }

        Commands::Log { vault, limit } => {
            let vault_name = vault.unwrap_or_else(|| "default".to_string());
            let v = open_vault(&base_dir, &vault_name, pass)?;
            let hist = v.history(None, limit)?;
            if hist.is_empty() {
                println!("No commits yet.");
            } else {
                for (h, c) in hist {
                    let sig = if c.is_signed() { "signed" } else { "unsigned" };
                    println!(
                        "{} {} {} ({sig})\n    {}",
                        h.to_hex(),
                        c.timestamp,
                        c.author,
                        c.message
                    );
                }
            }
        }

        Commands::Gc { vault, apply } => {
            let vault_name = vault.unwrap_or_else(|| "default".to_string());
            let v = open_vault(&base_dir, &vault_name, pass)?;
            let live = v.live_chunk_hashes()?.len();
            let total = v.chunk_count()?;
            let unreachable = total.saturating_sub(live);
            if apply {
                let n = v.gc_unreachable_chunks()?;
                println!("GC: removed {n} unreferenced chunks ({live} live remain)");
            } else {
                println!(
                    "GC dry-run: {unreachable} unreferenced / {total} total chunks ({live} live)"
                );
                println!("Re-run with --apply to delete unreferenced chunks.");
            }
        }

        Commands::Merge {
            head,
            vault,
            from,
            fetch,
        } => {
            let vault_name = vault.unwrap_or_else(|| "default".to_string());
            let mut v = open_vault(&base_dir, &vault_name, pass)?;
            let h = ContentHash::from_hex(&head)?;
            if fetch {
                let net = Network::open(&soal_home).await?;
                let peers = net.peers();
                if !peers.is_empty() {
                    let _ = sync::fetch_dag(&v, &net, &peers, h, false).await?;
                }
            }
            let (merge_h, conflicts) = v.merge_head(h, &from)?;
            println!(
                "Merged {} → {} ({} conflict{})",
                head,
                merge_h.to_hex(),
                conflicts,
                if conflicts == 1 { "" } else { "s" }
            );
        }

        Commands::Watch {
            path,
            vault,
            debounce_ms,
            for_secs,
            announce,
        } => {
            let vault_name = vault.unwrap_or_else(|| "default".to_string());
            let mut v = open_vault(&base_dir, &vault_name, pass)?;
            let max = for_secs.map(Duration::from_secs);
            let mut last_commit: Option<ContentHash> = None;
            let batch = watch::watch_vault_path(
                &mut v,
                &path,
                Duration::from_millis(debounce_ms),
                max.or(Some(Duration::from_secs(3600 * 24))),
                |_, commit| {
                    last_commit = Some(commit);
                },
            )?;
            if announce {
                if let Some(commit) = last_commit.or_else(|| batch.commits.last().map(|c| c.1)) {
                    if let Ok(net) = Network::open(&soal_home).await {
                        let _ = net.announce_head_signed(&v, commit).await;
                    }
                }
            }
            println!(
                "[watch] Done: {} commits, {} errors",
                batch.commits.len(),
                batch.errors.len()
            );
        }

        Commands::Replicate { vault, push } => {
            let vault_name = vault.unwrap_or_else(|| "default".to_string());
            let v = open_vault(&base_dir, &vault_name, pass)?;
            let st = replication::replication_status(&v)?;
            println!(
                "Replication status for '{vault_name}':\n  min_replicas: {}\n  live_chunks: {}\n  pinned: {}\n  missing_local: {}\n  under_replicated≈: {}\n  peers_tracked: {}",
                st.min_replicas,
                st.live_chunks,
                st.pinned_chunks,
                st.missing_local,
                st.estimated_under_replicated,
                st.peers_known
            );
            if push {
                let net = Network::open(&soal_home).await?;
                let n = replication::replicate_head(&v, &net).await?;
                println!("Pushed {n} blobs + head announce");
            } else {
                let _ = replication::ensure_local_pins(&v)?;
                println!("Pins refreshed. Use --push to provide HEAD to the network.");
            }
        }

        Commands::Invite { action } => match action {
            InviteCmd::Generate {
                vault,
                role,
                ttl,
                out,
            } => {
                let v = open_vault(&base_dir, &vault, pass)?;
                let net = Network::open(&soal_home).await?;
                let sk = net.secret_key().clone();
                let role = InviteRole::parse(&role)?;
                let inv = invite::generate_invite(&v, &sk, role, ttl)?;
                let token = inv.to_token()?;
                if let Some(path) = out {
                    std::fs::write(&path, &token)?;
                    println!("Invite written to {}", path.display());
                } else {
                    println!("{token}");
                }
                println!(
                    "# vault={} role={:?} expires={} issuer={}",
                    inv.vault_name, inv.role, inv.expires_at, inv.issuer
                );
            }
            InviteCmd::Join {
                token_or_file,
                name,
            } => {
                let token = if let Some(path) = token_or_file.strip_prefix('@') {
                    std::fs::read_to_string(path)?
                } else if std::path::Path::new(&token_or_file).is_file() {
                    std::fs::read_to_string(&token_or_file)?
                } else {
                    token_or_file
                };
                let v = invite::join_invite(&base_dir, &soal_home, token.trim(), name.as_deref())?;
                println!(
                    "Joined vault '{}' (vault_id={}, encrypt={})",
                    v.name, v.config.vault_id, v.config.encryption_enabled
                );
            }
        },

        Commands::Node { action } => match action {
            NodeCmd::Id => {
                let net = Network::open(&soal_home).await?;
                println!("Node ID: {}", net.node_id());
                println!("Ticket: {}", net.ticket());
            }
            NodeCmd::AddPeer { node_id } => {
                let mut net = Network::open(&soal_home).await?;
                net.add_peer(node_id.clone())?;
                println!("Added peer: {node_id}");
            }
            NodeCmd::RemovePeer { node_id } => {
                let mut net = Network::open(&soal_home).await?;
                if net.remove_peer(&node_id)? {
                    println!("Removed peer: {node_id}");
                } else {
                    println!("Peer not found: {node_id}");
                }
            }
            NodeCmd::Peers => {
                let net = Network::open(&soal_home).await?;
                let peers = net.peers();
                if peers.is_empty() {
                    println!("No peers configured.");
                } else {
                    for p in peers {
                        println!("{p}");
                    }
                }
            }
            NodeCmd::Announce { vault, head } => {
                let v = open_vault(&base_dir, &vault, pass)?;
                let h = ContentHash::from_hex(&head)
                    .map_err(|_| anyhow::anyhow!("head must be 64 hex chars"))?;
                let net = Network::open(&soal_home).await?;
                let _ = net.announce_head_signed(&v, h).await?;
            }
            NodeCmd::Listen { vault } => {
                let net = Network::open(&soal_home).await?;
                let anns = if let Ok(v) = open_vault(&base_dir, &vault, pass) {
                    net.listen_for_heads_vault(&v).await?
                } else {
                    net.listen_for_heads(&vault).await?
                };
                if anns.is_empty() {
                    println!("(no announcements received in listen window)");
                }
            }
            NodeCmd::Beacon { secs } => {
                let net = Network::open(&soal_home).await?;
                net.discovery_beacon(Duration::from_secs(secs)).await?;
            }
            NodeCmd::Discover { secs, add } => {
                let mut net = Network::open(&soal_home).await?;
                let found = net.discovery_listen(Duration::from_secs(secs)).await?;
                if found.is_empty() {
                    println!("(no peers discovered)");
                } else {
                    for t in found {
                        println!("discovered: {t}");
                        if add {
                            if let Err(e) = net.add_peer(t.clone()) {
                                println!("  (could not add: {e})");
                            } else {
                                println!("  added as peer");
                            }
                        }
                    }
                }
            }
        },

        Commands::Sync {
            vault,
            head,
            merge,
            from,
        } => {
            let vault_name = vault.unwrap_or_else(|| "default".to_string());
            let mut v = match open_vault(&base_dir, &vault_name, pass) {
                Ok(v) => v,
                Err(_) => {
                    println!("Vault not found for sync");
                    return Ok(());
                }
            };

            let net = Arc::new(Network::open(&soal_home).await?);
            let peers = net.peers();
            if peers.is_empty() {
                println!("No peers configured. Use `soal node add-peer <id>` or `soal node discover --add`.");
                let _ = net.sync_vault(&vault_name).await;
                println!("Sync finished for {vault_name}");
                return Ok(());
            }

            let mut targets: Vec<ContentHash> = Vec::new();
            if let Some(h) = head {
                targets.push(ContentHash::from_hex(&h)?);
            } else {
                match net.listen_for_heads_vault(&v).await {
                    Ok(anns) => {
                        for ann in anns {
                            if !targets.contains(&ann.head) {
                                targets.push(ann.head);
                            }
                            let _ = replication::note_peer_has(&v, &ann.node_id_hex(), &[ann.head]);
                        }
                    }
                    Err(e) => println!("[sync] listen for heads: {e}"),
                }
                if targets.is_empty() {
                    println!(
                        "[sync] No --head and no remote announcements; pass --head <commit> to pull"
                    );
                }
            }

            for commit_hash in targets {
                match sync::fetch_dag(&v, &net, &peers, commit_hash, !merge).await {
                    Ok(res) => {
                        println!(
                            "[sync] Ingested {} (commits={}, trees={}, chunks={})",
                            res.target.to_hex(),
                            res.commits_imported,
                            res.trees_imported,
                            res.chunks_imported
                        );
                        if merge {
                            match v.merge_head(commit_hash, &from) {
                                Ok((mh, c)) => println!(
                                    "[sync] Merged → {} ({} conflict{})",
                                    mh.to_hex(),
                                    c,
                                    if c == 1 { "" } else { "s" }
                                ),
                                Err(e) => println!("[sync] merge failed: {e}"),
                            }
                        }
                        let _ = replication::ensure_local_pins(&v);
                    }
                    Err(e) => {
                        println!(
                            "[sync] Could not fully ingest {}: {e}",
                            commit_hash.to_hex()
                        );
                    }
                }
            }

            let _ = net.sync_vault(&vault_name).await;
            println!("Sync finished for {vault_name}");
        }
    }

    Ok(())
}
