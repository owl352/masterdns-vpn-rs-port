//! Port of `cmd/server/main.go`: CLI entry point for the UDP server.

use std::path::Path;
use std::sync::Arc;

fn print_usage() {
    eprintln!(
        "Usage: masterdnsvpn-server [-config <path>] [-json <path>] [-json_base64 <string>] [-log <path>] [-genkey] [-version]\n\
         \n\
         A positional argument is treated as the config file path (same as -config)."
    );
}

struct Args {
    config_path: Option<String>,
    json_path: Option<String>,
    json_base64: Option<String>,
    log_path: Option<String>,
    genkey: bool,
}

fn parse_args() -> Result<Args, ()> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut args = Args { config_path: None, json_path: None, json_base64: None, log_path: None, genkey: false };

    let mut i = 0;
    while i < raw.len() {
        // Go's `flag` package treats `-x` and `--x` identically; normalize so
        // this parser accepts both (matters for compatibility with tools that
        // invoke the server binary the way they'd invoke the Go one, e.g.
        // scripts/bench/bench.go's `--config`).
        let normalized = if let Some(rest) = raw[i].strip_prefix("--") { format!("-{rest}") } else { raw[i].clone() };
        match normalized.as_str() {
            "-config" | "-c" => {
                i += 1;
                args.config_path = raw.get(i).cloned();
            }
            "-json" | "-j" => {
                i += 1;
                args.json_path = raw.get(i).cloned();
            }
            "-json_base64" => {
                i += 1;
                args.json_base64 = raw.get(i).cloned();
            }
            "-log" | "-l" => {
                i += 1;
                args.log_path = raw.get(i).cloned();
            }
            "-genkey" => args.genkey = true,
            "-version" | "-v" => {
                println!("masterdnsvpn-server (Rust rewrite) {}", env!("CARGO_PKG_VERSION"));
                return Err(());
            }
            "-help" | "-h" => {
                print_usage();
                return Err(());
            }
            other if !other.starts_with('-') && args.config_path.is_none() => {
                args.config_path = Some(other.to_string());
            }
            unknown => {
                eprintln!("unrecognized argument: {unknown}");
                print_usage();
                return Err(());
            }
        }
        i += 1;
    }

    Ok(args)
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(()) => std::process::exit(0),
    };

    let cfg = if let Some(b64) = &args.json_base64 {
        config::load_server_json_base64(b64)
    } else if let Some(path) = &args.json_path {
        config::load_server_json(Path::new(path))
    } else {
        let path = args.config_path.clone().unwrap_or_else(|| "server_config.toml".to_string());
        config::load_server_toml(Path::new(&path))
    };

    let cfg = match cfg {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load config: {e}");
            std::process::exit(1);
        }
    };

    let log = Arc::new(logger::Logger::with_file("MasterDnsVPN-Server", &cfg.log_level, args.log_path.as_deref()));

    let key_info = match security::ensure_server_encryption_key(cfg.data_encryption_method, &cfg.encryption_key_path()) {
        Ok(info) => info,
        Err(e) => {
            eprintln!("failed to ensure encryption key: {e}");
            std::process::exit(1);
        }
    };

    if args.genkey {
        println!("Encryption key ({}): {}", key_info.method_name, key_info.key);
        return;
    }

    log.infof(&format!(
        "Encryption key ready | Method: {} | Path: {} | Generated: {}",
        key_info.method_name,
        key_info.path.display(),
        key_info.generated
    ));

    let codec = match security::Codec::new(cfg.data_encryption_method, &key_info.key) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("failed to build encryption codec: {e}");
            std::process::exit(1);
        }
    };

    let server = udpserver::Server::new(cfg, log.clone(), codec);

    let shutdown = tokio_util::sync::CancellationToken::new();
    spawn_signal_handlers(shutdown.clone());

    if let Err(e) = udpserver::run(server, shutdown).await {
        log.errorf(&format!("server exited with error: {e}"));
        std::process::exit(1);
    }
}

fn spawn_signal_handlers(shutdown: tokio_util::sync::CancellationToken) {
    let ctrl_c_shutdown = shutdown.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        ctrl_c_shutdown.cancel();
    });

    #[cfg(unix)]
    {
        tokio::spawn(async move {
            let Ok(mut sigterm) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) else { return };
            sigterm.recv().await;
            shutdown.cancel();
        });
    }
}
