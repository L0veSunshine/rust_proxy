mod client;
mod config;
mod log;
mod protocol;
mod secret;
mod server;

use crate::config::get_shared_keys;
use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use std::sync::Arc;

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
        #[arg(long, default_value = "keys.txt")]
        keys_file: String,
    },
    Client {
        #[arg(long)]
        key: String,
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
        Mode::Server { port, keys_file } => {
            let keys = match get_shared_keys(&keys_file) {
                Ok(k) => k,
                Err(e) => {
                    bail!("Read keys error: {}", e)
                }
            };
            let arc_keys = Arc::new(keys);
            server::run(port, arc_keys).await
        }
        Mode::Client { local, remote, key } => client::run(&local, &remote, &key).await,
    }
}
