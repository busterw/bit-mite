use super::messages::Message;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug)]
pub struct Handshake {
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
}

impl Handshake {
    pub fn new(info_hash: [u8; 20], peer_id: [u8; 20]) -> Self {
        Self { info_hash, peer_id }
    }

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
    let their_info_hash = &response_buf[28..48];
    if their_info_hash != info_hash {
        return Err(format!(
            "Handshake failed: Info hash mismatch with peer {}",
            peer.socket_address()
        )
        .into());
    }

    println!("Handshake successful with peer {}!", peer.socket_address());
    Ok(stream)
}

pub fn run_peer_session(
    mut stream: TcpStream,
    state: &mut super::torrent::DownloadState,
    file_handles: &mut HashMap<PathBuf, File>,
    mapper: &super::torrent::FileMapper,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut peer_choked = true;
    let mut peer_bitfield: Option<Vec<u8>> = None;

    const BLOCK_SIZE: u32 = 16384;

    while !state.pieces_to_download.is_empty() {
        match Message::parse(&mut stream) {
            Ok(message) => {
                match message {
                    Message::Unchoke => peer_choked = false,
                    Message::Bitfield(bf) => peer_bitfield = Some(bf),
                    Message::Piece {
                        index,
                        begin,
                        block,
                    } => {
                        if index as usize == state.current_piece_index {
                            let block_start = begin as usize;
                            let block_end = block_start + block.len();
                            state.current_piece_data[block_start..block_end]
                                .copy_from_slice(&block);
                            state.blocks_received += 1;

                            // We need to know the torrent's piece_length to calculate when a piece is complete.
                            // We can get this from the state's internal reference to the Info struct.
                            let piece_length = state.get_info().piece_length as u32;
                            let num_blocks_in_piece = (piece_length + BLOCK_SIZE - 1) / BLOCK_SIZE;

                            if state.blocks_received == num_blocks_in_piece as usize {
                                // The call to verify now passes the file_handles and mapper.
                                if state.verify_and_save_current_piece(file_handles, mapper)? {
                                    state.prepare_for_next_piece();
                                } else {
                                    state.current_piece_data.fill(0);
                                    state.blocks_received = 0;
                                }
                            }
                        }
                    }
                    _ => {} // Ignore other messages for now
                }
            }
            Err(e) => return Err(format!("Error reading message from peer: {}", e).into()),
        }

        if !peer_choked {
            if let Some(bf) = &peer_bitfield {
                let byte_index = state.current_piece_index / 8;
                let bit_index = state.current_piece_index % 8;
                if let Some(&byte) = bf.get(byte_index) {
                    if (byte >> (7 - bit_index)) & 1 != 0 {
                        let piece_length = state.get_info().piece_length as u32;
                        let next_block_offset = (state.blocks_received as u32) * BLOCK_SIZE;

                        if next_block_offset < piece_length {
                            let remaining_bytes = piece_length - next_block_offset;
                            let block_length = if remaining_bytes < BLOCK_SIZE {
                                remaining_bytes
                            } else {
                                BLOCK_SIZE
                            };

                            let request_msg = Message::Request {
                                index: state.current_piece_index as u32,
                                begin: next_block_offset,
                                length: block_length,
                            };
                            stream.write_all(&request_msg.serialize())?;
                        }
                    }
                }
            }
        }
    }

    println!("\nDOWNLOAD SESSION COMPLETE (with this peer).");
    Ok(())
}
