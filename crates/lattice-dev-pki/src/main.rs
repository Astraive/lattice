use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "lattice-dev-pki",
    about = "Generate local test-only Lattice X.509 credentials"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Ca {
        #[command(subcommand)]
        command: CaCommand,
    },
    Issue {
        #[arg(long)]
        ca_cert: PathBuf,
        #[arg(long)]
        ca_key: PathBuf,
        #[arg(long)]
        csr: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        device_name: String,
    },
}

#[derive(Subcommand)]
enum CaCommand {
    Create {
        #[arg(long)]
        output_dir: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Ca {
            command: CaCommand::Create { output_dir },
        } => {
            lattice_dev_pki::create_ca(&output_dir)?;
            println!("Test-only CA created in {}", output_dir.display());
        }
        Command::Issue {
            ca_cert,
            ca_key,
            csr,
            output_dir,
            device_name,
        } => {
            lattice_dev_pki::issue_to_directory(
                ca_cert,
                ca_key,
                csr,
                output_dir.clone(),
                &device_name,
            )?;
            println!("Test-only credential issued in {}", output_dir.display());
        }
    }
    Ok(())
}
