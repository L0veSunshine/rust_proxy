mod api;
mod client;
mod config;
mod log;
mod protocol;
mod secret;
mod server;

use crate::api::client::start_stat_api;
use crate::api::server::{ServerStatistic, start_server_stat_api};
use crate::config::{build_key_map, get_shared_keys};
use anyhow::{Result, bail};
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
        #[arg(long, default_value = "keys")]
        keys_file: String,
        #[arg(long, default_value_t = 1081)]
        api_port: u16,
    },
    Client {
        #[arg(long)]
        key: String,
        #[arg(long, default_value = "127.0.0.1:1080")]
        local: String,
        #[arg(long, default_value = "127.0.0.1:4433")]
        remote: String,
        #[arg(long, default_value_t = 1081)]
        api_port: u16,
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
        Mode::Server { port, keys_file, api_port} => {
            let keys = match get_shared_keys(&keys_file) {
                Ok(k) => k,
                Err(e) => {
                    bail!("Read keys error: {}", e)
                }
            };
            let arc_keys = build_key_map(&keys);
            let stat_map = ServerStatistic::new();
            let stat_map_clone = stat_map.clone();
            tokio::spawn(async move {
                start_server_stat_api(api_port, stat_map).await;
            });
            server::run(port, arc_keys, stat_map_clone).await
        }
        Mode::Client {
            local,
            remote,
            key,
            api_port,
        } => {
            tokio::spawn(async move {
                start_stat_api(api_port).await;
            });

            client::run(&local, &remote, &key).await
        }
    }
}
