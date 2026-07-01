use clap::{Parser, Subcommand};
use soal::network::Network;
use soal::vault::{default_soal_dir, Vault};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "soal",
    version,
    about = "Soal - Sovereign local file storage (Phase 0 + Phase 1 networking)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize Soal local data directory
    Init {
        /// Optional custom data directory
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

    /// Add a file or directory to a vault and create/update snapshot
    Add {
        path: PathBuf,
        #[arg(short, long)]
        vault: Option<String>,
        #[arg(short, long)]
        message: Option<String>,
    },

    /// Create an explicit snapshot
    Snapshot {
        message: String,
        #[arg(short, long)]
        vault: Option<String>,
    },

    /// Restore a commit into a directory
    Restore {
        commit: String,
        #[arg(short, long)]
        to: Option<PathBuf>,
        #[arg(short, long)]
        vault: Option<String>,
    },

    /// Sync a vault (Phase 1)
    Sync {
        #[arg(short, long)]
        vault: Option<String>,
    },

    /// Node identity and basic network (Phase 1 start)
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
    },
    /// List vaults
    List,
}

#[derive(Subcommand)]
enum NodeCmd {
    /// Show this node's identity
    Id,
    /// Add a peer by NodeId string (for Phase 1 sync)
    AddPeer { node_id: String },
    /// Announce a head for a vault (real gossip)
    Announce { vault: String, head: String },
    /// Listen for head announcements (receives + auto-triggers sync logic)
    Listen { vault: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let base_dir = default_soal_dir();

    match cli.command {
        Commands::Init { data_dir } => {
            let dir = data_dir.unwrap_or_else(|| base_dir.clone());
            std::fs::create_dir_all(&dir)?;
            println!("Initialized Soal data dir at {}", dir.display());
            println!("Use `soal vault create <name>` to get started.");
        }

        Commands::Status { vault } => {
            if let Some(name) = vault {
                let v = Vault::open(&base_dir, &name)?;
                println!("{}", v.status()?);
            } else {
                let vaults = Vault::list(&base_dir)?;
                if vaults.is_empty() {
                    println!("No vaults found. Run `soal vault create myvault`");
                } else {
                    println!("Vaults:");
                    for v in vaults {
                        println!("  - {}", v);
                    }
                }
            }
        }

        Commands::Vault { action } => match action {
            VaultCmd::Create { name, no_encrypt } => {
                let encrypt = !no_encrypt;
                let v = Vault::create(&base_dir, &name, encrypt)?;
                println!("Created vault '{}' (encryption={})", name, encrypt);
                println!("Data: {}", v.root.display());
            }
            VaultCmd::List => {
                let vaults = Vault::list(&base_dir)?;
                if vaults.is_empty() {
                    println!("No vaults yet.");
                } else {
                    for name in vaults {
                        println!("{}", name);
                    }
                }
            }
        },

        Commands::Add {
            path,
            vault,
            message,
        } => {
            let vault_name = vault.unwrap_or_else(|| "default".to_string());
            let mut v = match Vault::open(&base_dir, &vault_name) {
                Ok(v) => v,
                Err(_) => {
                    println!("Vault '{}' not found, creating...", vault_name);
                    Vault::create(&base_dir, &vault_name, true)?
                }
            };

            let logical = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("item")
                .to_string();

            let commit = v.add_path(&path, &logical)?;
            println!(
                "Added '{}' -> commit {}",
                path.display(),
                hex::encode(commit)
            );

            if let Some(msg) = message {
                let c = v.snapshot(&msg)?;
                println!("Snapshot created: {}", hex::encode(c));
            }
        }

        Commands::Snapshot { message, vault } => {
            let vault_name = vault.unwrap_or_else(|| "default".to_string());
            let mut v = Vault::open(&base_dir, &vault_name)?;
            let commit = v.snapshot(&message)?;
            println!("Snapshot '{}' created: {}", message, hex::encode(commit));

            // Phase 1: announce via gossip + provide data for transfer
            if let Ok(net) = Network::new().await {
                // Provide commit manifest (receiver can discover tree + chunks from it)
                if let Ok(bytes) = v.export_commit_bytes(commit) {
                    let _ = net.provide(commit, &bytes).await;
                }
                // Provide the tree too (high value for real transfer of full snapshot)
                let commits_dir = base_dir.join(&vault_name).join("commits");
                if let Ok(cjson) = std::fs::read_to_string(
                    commits_dir.join(format!("{}.json", hex::encode(commit))),
                ) {
                    if let Ok(cval) = serde_json::from_str::<serde_json::Value>(&cjson) {
                        if let Some(th) = cval.get("tree").and_then(|x| x.as_str()) {
                            if let Ok(thb) = hex::decode(th) {
                                if thb.len() == 32 {
                                    let mut th_arr = [0u8; 32];
                                    th_arr.copy_from_slice(&thb);
                                    if let Ok(tree_bytes) = v.export_tree_bytes(th_arr) {
                                        let _ = net.provide(th_arr, &tree_bytes).await;
                                    }
                                }
                            }
                        }
                    }
                }
                let _ = net.announce_head(&vault_name, &hex::encode(commit)).await;
            }
        }

        Commands::Restore { commit, to, vault } => {
            let vault_name = vault.unwrap_or_else(|| "default".to_string());
            let v = Vault::open(&base_dir, &vault_name)?;

            let commit_bytes =
                hex::decode(&commit).map_err(|_| anyhow::anyhow!("bad commit hash"))?;
            if commit_bytes.len() != 32 {
                return Err(anyhow::anyhow!("commit must be 64 hex chars"));
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&commit_bytes);

            let target = to.unwrap_or_else(|| PathBuf::from("restored"));
            v.restore(h, &target)?;
            println!("Restored commit {} into {}", commit, target.display());
        }

        Commands::Node { action } => match action {
            NodeCmd::Id => {
                if let Ok(net) = Network::new().await {
                    println!("Node ID: {}", net.node_id());
                }
            }
            NodeCmd::AddPeer { node_id } => {
                // For Phase 1, accept as string (NodeId fmt)
                if let Ok(mut net) = Network::new().await {
                    net.add_peer(node_id.clone());
                    println!("Added peer: {}", node_id);
                }
            }
            NodeCmd::Announce { vault, head } => {
                if let Ok(net) = Network::new().await {
                    let _ = net.announce_head(&vault, &head).await;
                }
            }
            NodeCmd::Listen { vault } => {
                if let Ok(net) = Network::new().await {
                    let _ = net.listen_for_heads(&vault).await;
                }
            }
        },

        Commands::Sync { vault } => {
            let vault_name = vault.unwrap_or_else(|| "default".to_string());
            let v = match Vault::open(&base_dir, &vault_name) {
                Ok(v) => v,
                Err(_) => {
                    println!("Vault not found for sync");
                    return Ok(());
                }
            };

            if let Ok(net) = Network::new().await {
                // If we have peers, try to pull our current HEAD (or its commit manifest) via real blobs transfer
                if let Some(head) = v.head().ok().flatten() {
                    for peer in net.peers() {
                        if let Ok(bytes) = net.get_chunk_from_peer(&peer, head).await {
                            // Import the received commit bytes (raw)
                            let _ = v.import_commit_bytes(head, &bytes);
                            println!(
                                "[sync] Fetched and imported commit {} from {}",
                                hex::encode(head),
                                peer
                            );
                            // Try to also fetch+import the tree referenced by this commit (real transfer)
                            if let Ok(cval) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                                if let Some(t) = cval.get("tree").and_then(|x| x.as_str()) {
                                    if let Ok(th) = hex::decode(t) {
                                        if th.len() == 32 {
                                            let mut th_arr = [0u8; 32];
                                            th_arr.copy_from_slice(&th);
                                            if let Ok(tbytes) =
                                                net.get_chunk_from_peer(&peer, th_arr).await
                                            {
                                                let _ = v.import_tree_bytes(th_arr, &tbytes);
                                                println!(
                                                    "[sync]   also imported tree for the commit"
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
                let _ = net.sync_vault(&vault_name).await;
            }
            println!("Sync triggered for {}", vault_name);
        }
    }

    Ok(())
}
