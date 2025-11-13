use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use clap::Parser;
use notify::{Event, RecursiveMode, Watcher};
use serde::Deserialize;
use std::{path::PathBuf, sync::Arc};
use tokio::{net::TcpListener, sync::RwLock};
use tracing::{info, warn};
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

mod defmt_tcp;
mod parse_elf;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value_t = 65455)]
    port: u16,

    /// Directory containing ELF files
    #[arg(long)]
    elf_dir: PathBuf,
}

#[derive(Deserialize, Debug, Default)]
struct Config {
    /// Loki endpoint URL (e.g., http://localhost:3100)
    loki_url: Option<String>,
    loki_user: Option<String>,
    loki_password: Option<String>,
}

impl Config {
    fn parse() -> Self {
        std::fs::read_to_string("cfg.toml")
            .ok()
            .and_then(|content| toml::from_str(&content).ok())
            .unwrap_or_default()
    }
}

fn get_loki_auth(config: &Config) -> String {
    let loki_user = config.loki_user.as_ref().unwrap().to_owned();
    let loki_password = config.loki_password.as_ref().unwrap().to_owned();

    let basic_auth = format!("{loki_user}:{loki_password}");
    BASE64_STANDARD.encode(basic_auth.as_bytes())
}

type TableEntry = (String, PathBuf, Vec<u8>); // build-id, path, elf bytes
type SharedTables = Arc<RwLock<Vec<TableEntry>>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config = Config::parse();

    // Create a filter for the frames target only
    /* let frame_filter = tracing_subscriber::filter::Targets::new()
        .with_target("frames", tracing::Level::ERROR); // TODO log this to file!

    let frame_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_filter(frame_filter);
    */

    // Create the main filter and layer based on RUST_LOG env variable, default to INFO
    // e.g. use RUST_LOG=warn,frames=info to see only frame related logs

    let main_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
        .from_env()?;

    let main_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stdout)
        .with_filter(main_filter);

    let registry = tracing_subscriber::registry().with(main_layer);
    // Add Loki layer if URL is provided
    if let Some(loki_url) = &config.loki_url {
        let (loki_layer, task) = tracing_loki::builder()
            .label("service", "remote-defmt-srv_try1")?
            .http_header("Authorization", format!("Basic {}", get_loki_auth(&config)))?
            .build_url(loki_url.parse()?)?;

        tokio::spawn(task);
        registry.with(loki_layer).init();
    } else {
        registry.init();
    }

    // parse files in elf_dir
    let tables = Arc::new(RwLock::new(parse_elf::parse_elf_dir(&args.elf_dir).await));
    if tables.read().await.is_empty() {
        warn!("No defmt tables found in {:?}", args.elf_dir);
        return Ok(());
    }

    // Set up file watcher
    let tables_clone = Arc::clone(&tables);
    let elf_dir = args.elf_dir.clone();

    let (tx, mut rx) = tokio::sync::mpsc::channel(100);

    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        if let Ok(event) = res {
            let _ = tx.blocking_send(event);
        }
    })?;

    watcher.watch(&args.elf_dir, RecursiveMode::NonRecursive)?;

    // Spawn a task to handle file system events
    tokio::spawn(async move {
        let mut debounce_timer: Option<tokio::time::Instant> = None;
        let debounce_duration = std::time::Duration::from_secs(1);

        loop {
            tokio::select! {
                // Wait for events from the file watcher
                Some(event) = rx.recv() => {
                    use notify::EventKind;
                    match event.kind {
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
                            // info!("File system event: {:?}, scheduling table reload", event);
                            // Reset the debounce timer
                            debounce_timer = Some(tokio::time::Instant::now() + debounce_duration);
                        }
                        _ => {}
                    }
                }
                // Wait for debounce timer to expire
                _ = async {
                    if let Some(deadline) = debounce_timer {
                        tokio::time::sleep_until(deadline).await
                    } else {
                        // Sleep indefinitely if no timer is set
                        std::future::pending::<()>().await
                    }
                }, if debounce_timer.is_some() => {
                    // Timer expired, process the update
                    info!("ELF directory changed, reloading tables...");
                    let new_tables = parse_elf::parse_elf_dir(&elf_dir).await;
                    *tables_clone.write().await = new_tables;
                    info!("Tables reloaded");
                    debounce_timer = None;
                }
            }
        }
    });

    let addr = format!("0.0.0.0:{}", args.port);
    let listener = TcpListener::bind(&addr).await?;
    info!("TCP server listening on {}", addr);

    // Create a semaphore to limit concurrent connections to 10
    let connection_semaphore = Arc::new(tokio::sync::Semaphore::new(10));

    let local = tokio::task::LocalSet::new();
    let result = local
        .run_until(async {
            loop {
                let (socket, peer_addr) = listener.accept().await?;

                // Try to acquire a permit for this connection
                let permit = connection_semaphore.clone().acquire_owned().await.unwrap();

                info!("New connection from {}", peer_addr);
                let tables_clone = Arc::clone(&tables);
                tokio::task::spawn_local(async move {
                    defmt_tcp::handle_connection(socket, peer_addr, tables_clone).await;
                    // Permit is automatically released when dropped
                    drop(permit);
                });
            }
        })
        .await;

    // Keep watcher alive
    drop(watcher);
    result
}
