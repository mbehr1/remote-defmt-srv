use clap::Parser;
use defmt_decoder::{DecodeError, Table};
use notify::{Event, RecursiveMode, Watcher};
use socket2::TcpKeepalive;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::{fs, io::AsyncReadExt};
use tracing::{info, warn};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

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

type TableEntry = (String, PathBuf, Vec<u8>); // build-id, path, elf bytes
type SharedTables = Arc<RwLock<Vec<TableEntry>>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    tracing_subscriber::registry()
        .with(main_layer)
        // .with(frame_layer)
        .init();

    let args = Args::parse();

    // parse files in elf_dir
    let tables = Arc::new(RwLock::new(parse_elf_dir(&args.elf_dir).await));
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
                    let new_tables = parse_elf_dir(&elf_dir).await;
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
                    handle_connection(socket, peer_addr, tables_clone).await;
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

async fn parse_elf_dir(elf_dir: &PathBuf) -> Vec<(String, PathBuf, Vec<u8>)> {
    let mut tables = Vec::new();
    // iterate over all .elf files in elf_dir and parse them
    if let Ok(mut entries) = tokio::fs::read_dir(elf_dir).await {
        // tokio::pin!(entries); ???
        while let Some(entry) = entries.next_entry().await.unwrap_or(None) {
            let path = entry.path().canonicalize().unwrap();
            if path.is_dir() {
                //warn!("Skipping directory {:?}", path);
                continue;
            }
            // info!("Parsing ELF file: {:?}", path);
            // TODO parse ELF file and store relevant data
            let bytes = fs::read(&path).await;
            if let Ok(bytes) = bytes {
                // Extract build ID
                let build_id = if let Some(build_id) = extract_build_id(&bytes) {
                    let build_id = hex::encode(&build_id);
                    info!("Build ID: {}", build_id);
                    build_id
                } else {
                    info!("No build ID found in {:?}. Skipping.", path);
                    continue;
                };
                let table = Table::parse(&bytes);
                match table {
                    Ok(Some(table)) => {
                        info!(
                            "Parsed defmt table from {:?}: {} entries",
                            path,
                            table.indices().count()
                        );
                        // store table somewhere
                        // as the Table is not clone, we keep the bytes and later recreate the Table
                        tables.push((build_id, path, bytes));
                    }
                    Ok(None) => {
                        info!("No defmt table found in {:?}", path);
                    }
                    Err(e) => {
                        warn!("Failed to parse defmt table from {:?}: {}", path, e);
                    }
                }
            } else {
                warn!(
                    "Failed to read ELF file {:?}: {}",
                    path,
                    bytes.err().unwrap()
                );
            }
        }
    }
    tables
}

fn extract_build_id(bytes: &[u8]) -> Option<Vec<u8>> {
    use object::{Object, ObjectSection};

    let file = object::File::parse(bytes).ok()?;

    // Look for .note.gnu.build-id section
    for section in file.sections() {
        if section.name().ok()? == ".note.gnu.build-id" {
            let data = section.data().ok()?;

            // Parse the note section
            // Note format: namesz (4 bytes), descsz (4 bytes), type (4 bytes), name, desc
            if data.len() < 12 {
                return None;
            }

            let namesz = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]) as usize;
            let descsz = u32::from_ne_bytes([data[4], data[5], data[6], data[7]]) as usize;

            // Calculate aligned offset
            let name_offset = 12;
            let desc_offset = name_offset + ((namesz + 3) & !3); // Align to 4 bytes

            if data.len() >= desc_offset + descsz {
                return Some(data[desc_offset..desc_offset + descsz].to_vec());
            }
        }
    }

    None
}

#[derive(Debug)]
enum ConnectionError {
    UnsupportedProtocol(u8),
    UnknownBuildId(String),
    Io(std::io::Error),
}

impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionError::UnsupportedProtocol(version) => {
                write!(f, "Unsupported protocol version: {}", version)
            }
            ConnectionError::UnknownBuildId(build_id) => {
                write!(f, "Unknown build ID: {}", build_id)
            }
            ConnectionError::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for ConnectionError {}

impl From<std::io::Error> for ConnectionError {
    fn from(err: std::io::Error) -> Self {
        ConnectionError::Io(err)
    }
}

async fn handle_connection(
    mut socket: tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
    tables: SharedTables,
) {
    info!("Handling connection from {}", peer_addr);

    match handle_connection_impl(&mut socket, peer_addr, tables).await {
        Ok(()) => {}
        Err(ConnectionError::UnsupportedProtocol(_)) => {
            warn!(
                "Closing connection from {} due to unsupported protocol",
                peer_addr
            );
            tokio::time::sleep(std::time::Duration::from_secs(2)).await
        }
        Err(ConnectionError::UnknownBuildId(_)) => {
            warn!(
                "Closing connection from {} due to unknown build ID",
                peer_addr
            );
            tokio::time::sleep(std::time::Duration::from_secs(2)).await
        }
        Err(e) => {
            info!("Connection error from {}: {}", peer_addr, e);
        }
    }
}

async fn handle_connection_impl(
    socket: &mut tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
    tables: SharedTables,
) -> Result<(), ConnectionError> {
    // we expect the following data:
    // protocol version (u8)

    // read protocol version:
    let mut buf = [0u8; 1];
    socket.read_exact(&mut buf).await?;
    let protocol_version = buf[0];
    info!("Protocol version: {}", protocol_version);
    match protocol_version {
        1 => handle_protocol_v1(socket, peer_addr, tables).await,
        version => Err(ConnectionError::UnsupportedProtocol(version)),
    }
}

#[derive(Debug)]
struct ProtocolV1Header {
    build_id: String, // [u8; 32], // hex string with 32 bytes
}

async fn handle_protocol_v1(
    socket: &mut tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
    tables: SharedTables,
) -> Result<(), ConnectionError> {
    info!("Handling protocol v1 for {}", peer_addr);

    // Set TCP keepalive using socket2
    let sock_ref = socket2::SockRef::from(&socket);
    let keepalive = TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(3))
        .with_interval(std::time::Duration::from_secs(1));

    if let Err(e) = sock_ref.set_tcp_keepalive(&keepalive) {
        info!("Failed to set keepalive: {}", e);
    }

    // Implement protocol v1 handling here
    // read the ProtolV1Header:

    let mut build_id_buf = [0u8; 32];
    socket.read_exact(&mut build_id_buf).await?;
    let header = ProtocolV1Header {
        build_id: String::from_utf8_lossy(&build_id_buf).to_string(),
    };
    info!("Read ProtocolV1Header: {:?}", header);

    // Acquire read lock and keep it for the duration of the connection
    // This is necessary because stream_decoder borrows from Table
    let tables_guard = tables.read().await;
    let table = tables_guard
        .iter()
        .find(|(id, _, _)| id == &header.build_id);
    let table = match table {
        Some(t) => {
            // recreate Table from bytes
            let table = Table::parse(&t.2);
            match table {
                Ok(Some(table)) => (t.0.clone(), t.1.clone(), table),
                _ => {
                    // todo mark as internal error
                    return Err(ConnectionError::UnknownBuildId(header.build_id));
                }
            }
        }
        None => {
            return Err(ConnectionError::UnknownBuildId(header.build_id));
        }
    };
    drop(tables_guard);

    let mut stream_decoder = table.2.new_stream_decoder();

    // read from socket in 256 byte chunks until EOF and decode defmt frames
    let mut chunk = [0u8; 256];
    loop {
        let n = match socket.read(&mut chunk).await {
            Ok(0) => break, // EOF
            Ok(n) => n,
            Err(e) => return Err(ConnectionError::Io(e)),
        };
        // info!("Read {} bytes", n);
        stream_decoder.received(&chunk[..n]);
        loop {
            match stream_decoder.decode() {
                Ok(frame) => {
                    tracing::info!(target: "frames", "{}", frame.display(false));
                }
                Err(DecodeError::UnexpectedEof) => break,
                Err(e) => {
                    info!(
                        "Failed to decode defmt frame: {}, data: {:?}",
                        e,
                        &chunk[..n]
                    );
                    // continue decoding
                }
            };
        }
    }

    Ok(())
}
