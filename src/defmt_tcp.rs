use crate::SharedTables;
use defmt_decoder::{DecodeError, Table};
use defmt_parser::Level;
use socket2::TcpKeepalive;
use std::net::SocketAddr;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tracing::{debug, error, info, trace, warn};

#[derive(Debug)]
pub enum ConnectionError {
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

pub async fn handle_connection(mut socket: TcpStream, peer_addr: SocketAddr, tables: SharedTables) {
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
    socket: &mut TcpStream,
    peer_addr: SocketAddr,
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
    socket: &mut TcpStream,
    peer_addr: SocketAddr,
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
    let encoder_can_recover = table.2.encoding().can_recover();

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
            // todo log frame timestamp? display_timestamp returns an option...
            match stream_decoder.decode() {
                Ok(frame) => match frame.level() {
                    Some(Level::Trace) => {
                        trace!(target: "frames", "{}", frame.display_message())
                    }
                    Some(Level::Debug) => {
                        debug!(target: "frames", "{}", frame.display_message())
                    }
                    Some(Level::Info) => {
                        info!(target: "frames", "{}", frame.display_message())
                    }
                    Some(Level::Warn) => {
                        warn!(target: "frames", "{}", frame.display_message())
                    }
                    Some(Level::Error) => {
                        error!(target: "frames", "{}", frame.display_message())
                    }
                    None => info!(target: "frames", "{}", frame.display_message()),
                },
                Err(DecodeError::UnexpectedEof) => break,
                Err(e) => {
                    info!(
                        "Failed to decode defmt frame: {}, data: {:?}",
                        e,
                        &chunk[..n]
                    );
                    if !encoder_can_recover {
                        break;
                    }
                }
            };
        }
    }
    Ok(())
}
