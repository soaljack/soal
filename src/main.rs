use clap::{Parser, Subcommand};
use soal::invite::{self, InviteRole};
use soal::network::Network;
use soal::replication;
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
    /// Set vault policy (min replicas)
    Policy {
        name: String,
        #[arg(long)]
        replicas: Option<u8>,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let soal_home = default_soal_home();
    let base_dir = default_soal_dir();
    let pass = cli.passphrase.as_deref();

    match cli.command {
        Commands::Init { data_dir } => {
            let dir = data_dir.unwrap_or_else(|| base_dir.clone());
            std::fs::create_dir_all(&dir)?;
            std::fs::create_dir_all(&soal_home)?;
            let _ = Network::open(&soal_home).await;
            println!("Initialized Soal data dir at {}", dir.display());
            println!("Node home: {}", soal_home.display());
            println!("Use `soal vault create <name>` to get started.");
        }

        Commands::Status { vault } => {
            if let Some(name) = vault {
                let v = open_vault(&base_dir, &name, pass)?;
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
                let heads = v.list_heads()?;
                if heads.len() > 1 {
                    println!("Heads ({}):", heads.len());
                    for h in heads {
                        println!("  {}", h.to_hex());
                    }
                }
            } else {
                let vaults = Vault::list(&base_dir)?;
                if vaults.is_empty() {
                    println!("No vaults found. Run `soal vault create myvault`");
                } else {
                    println!("Vaults:");
                    for v in vaults {
                        println!("  - {v}");
                    }
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
                if let Some(p) = create_pass.as_deref().or(pass) {
                    if encrypt {
                        v.enable_passphrase(p)?;
                        println!("Vault key wrapped with passphrase.");
                    }
                }
                println!("Created vault '{name}' (encryption={encrypt}, min_replicas={replicas})");
                println!("vault_id={}", v.config.vault_id);
                if let Some(sig) = &v.config.config_sig {
                    println!("config_sig={}", &sig[..16.min(sig.len())]);
                }
                println!("Data: {}", v.root.display());
            }
            VaultCmd::List => {
                let vaults = Vault::list(&base_dir)?;
                if vaults.is_empty() {
                    println!("No vaults yet.");
                } else {
                    for name in vaults {
                        println!("{name}");
                    }
                }
            }
            VaultCmd::Policy { name, replicas } => {
                let mut v = open_vault(&base_dir, &name, pass)?;
                if let Some(r) = replicas {
                    v.set_min_replicas(r)?;
                    println!(
                        "Set min_replicas={r} on vault '{name}' (config_seq={})",
                        v.config.config_seq
                    );
                } else {
                    println!(
                        "Vault '{name}' min_replicas={} config_seq={}",
                        v.config.min_replicas, v.config.config_seq
                    );
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
