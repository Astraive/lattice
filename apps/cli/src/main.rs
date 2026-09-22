use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "lattice",
    version,
    about = "Local-first community communication"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show the implementation stage and active product boundary.
    About,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::About => {
            println!("Lattice protocol lab");
            println!("Identity, messaging, and network commands are not available yet.");
        }
    }
}
