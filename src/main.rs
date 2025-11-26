mod client;
mod protocol;
mod server;
mod tls;
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
        #[arg(long, default_value = "0.0.0.0:4433")]
        listen: String,
    },
    Client {
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: String,
        #[arg(long, default_value = "127.0.0.1:4433")]
        server: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.mode {
        Mode::Server { listen } => server::run(&listen).await,
        Mode::Client { listen, server } => client::run(&listen, &server).await,
    }
}
