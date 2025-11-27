mod client;
mod protocol;
mod server;
mod tls;
use crate::protocol::utils::NATType;
use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand, Debug)]
enum Mode {
    Server {
        #[arg(long, default_value_t = 4433)]
        port: u16,
    },
    Client {
        #[arg(long, default_value = "127.0.0.1:1080")]
        local: String,
        #[arg(long, default_value = "127.0.0.1:4433")]
        remote: String,
        #[arg(long, default_value_t = NATType::FullCone)]
        nat: NATType,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.mode {
        Mode::Server { port } => server::run(port).await,
        Mode::Client { local, remote, nat } => client::run(&local, &remote, nat).await,
    }
}
