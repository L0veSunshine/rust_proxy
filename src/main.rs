mod client;
mod log;
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
        #[arg(long, default_value_t = 4433)]
        port: u16,
    },
    Client {
        #[arg(long, default_value = "127.0.0.1:1080")]
        local: String,
        #[arg(long, default_value = "127.0.0.1:4433")]
        remote: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let log_name = match cli.mode {
        Mode::Server { .. } => "server",
        Mode::Client { .. } => "client",
    };
    let appender = log::SizeRotatingAppender::new(".", log_name, 5 * 1024 * 1024);
    let (non_blocking, _guard) = tracing_appender::non_blocking(appender);
    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(false)
        .init();

    match cli.mode {
        Mode::Server { port } => server::run(port).await,
        Mode::Client { local, remote } => client::run(&local, &remote).await,
    }
}
