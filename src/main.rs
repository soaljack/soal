use clap::{Parser, Subcommand};
use soal::vault::{Vault, default_soal_dir};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "soal", version, about = "Soal - Sovereign local file storage (Phase 0)")]
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

fn main() -> anyhow::Result<()> {
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

        Commands::Add { path, vault, message } => {
            let vault_name = vault.unwrap_or_else(|| "default".to_string());
            let mut v = match Vault::open(&base_dir, &vault_name) {
                Ok(v) => v,
                Err(_) => {
                    println!("Vault '{}' not found, creating...", vault_name);
                    Vault::create(&base_dir, &vault_name, true)?
                }
            };

            let logical = path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("item")
                .to_string();

            let commit = v.add_path(&path, &logical)?;
            println!("Added '{}' -> commit {}", path.display(), hex::encode(commit));

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
        }

        Commands::Restore { commit, to, vault } => {
            let vault_name = vault.unwrap_or_else(|| "default".to_string());
            let v = Vault::open(&base_dir, &vault_name)?;

            let commit_bytes = hex::decode(&commit).map_err(|_| anyhow::anyhow!("bad commit hash"))?;
            if commit_bytes.len() != 32 {
                return Err(anyhow::anyhow!("commit must be 64 hex chars"));
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&commit_bytes);

            let target = to.unwrap_or_else(|| PathBuf::from("restored"));
            v.restore(h, &target)?;
            println!("Restored commit {} into {}", commit, target.display());
        }
    }

    Ok(())
}
