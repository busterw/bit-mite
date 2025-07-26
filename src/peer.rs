use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Represents the handshake message.
#[derive(Debug)]
pub struct Handshake {
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
}

impl Handshake {
    pub fn new(info_hash: [u8; 20], peer_id: [u8; 20]) -> Self {
        Self { info_hash, peer_id }
    }

    /// Serializes the Handshake struct into the 68-byte message format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(68);
        // 1. Protocol string length
        bytes.push(19);
        // 2. Protocol string
        bytes.extend_from_slice(b"BitTorrent protocol");
        // 3. Reserved bytes
        bytes.extend_from_slice(&[0; 8]);
        // 4. Info hash
        bytes.extend_from_slice(&self.info_hash);
        // 5. Peer ID
        bytes.extend_from_slice(&self.peer_id);
        bytes
    }
}

/// Attempts to perform a handshake with a given peer.
///
/// On success, it returns the TcpStream, which can be used for further communication.
pub fn perform_handshake(
    peer: &super::torrent::Peer,
    info_hash: &[u8; 20],
    our_peer_id: &[u8; 20],
) -> Result<TcpStream, Box<dyn std::error::Error>> {
    println!("Attempting handshake with peer: {}", peer.socket_address());

    // 1. Establish a TCP connection. Set a timeout to avoid hanging indefinitely.
    let socket_addr = peer.socket_address();
    //conversion shenanigans - easier to just cast and then pass a ref
    let generic_socket_addr = std::net::SocketAddr::from(socket_addr);
    let mut stream = TcpStream::connect_timeout(&generic_socket_addr, Duration::from_secs(3))?;
    println!("TCP connection established with {}", peer.socket_address());

    // 2. Construct and send our handshake message.
    let handshake_message = Handshake::new(*info_hash, *our_peer_id);
    stream.write_all(&handshake_message.to_bytes())?;
    println!("Sent handshake to {}", peer.socket_address());

    // 3. Read the peer's handshake response (must be 68 bytes).
    let mut response_buf = [0u8; 68];
    stream.read_exact(&mut response_buf)?;
    println!("Received handshake response from {}", peer.socket_address());

    // 4. Validate the response.
    // The most important part is checking if the info_hash matches.
    let their_info_hash = &response_buf[28..48];
    if their_info_hash != info_hash {
        return Err(format!(
            "Handshake failed: Info hash mismatch with peer {}",
            peer.socket_address()
        )
        .into());
    }

    // Optional: You could also parse their full handshake and get their peer_id.
    // let their_peer_id = &response_buf[48..68];
    // println!("Peer {} has peer_id: {}", peer.socket_address(), String::from_utf8_lossy(their_peer_id));

    println!("Handshake successful with peer {}!", peer.socket_address());
    // The stream is now ready for the next phase of communication.
    Ok(stream)
}
