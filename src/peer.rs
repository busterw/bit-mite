use crate::bencode::BencodeValue;
use crate::metadata::MetadataDownloader;
use crate::torrent::{BlockInfo, PieceManager, Torrent, BLOCK_SIZE};use crate::tracker;
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{Buf, BytesMut};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::Duration;
use std::fs::File;

#[derive(Debug, PartialEq, Eq)]
pub struct Handshake {
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
    pub supports_extended: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    KeepAlive,
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have(u32),
    Bitfield(Vec<u8>),
    Request { index: u32, begin: u32, length: u32 },
    Piece { index: u32, begin: u32, block: Vec<u8> },
    Cancel { index: u32, begin: u32, length: u32 },
    Extended(ExtendedMessage),
}

#[derive(Clone)]
pub enum GlobalState {
    MetadataPending,
    MetadataInProgress,
    ContentDownload(Arc<Torrent>, Arc<Mutex<PieceManager>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtendedMessage {
    Handshake {
        m: BTreeMap<Vec<u8>, i64>,
        metadata_size: Option<i64>,
    },
    MetadataRequest {
        piece: i64,
    },
    MetadataPiece {
        piece: i64,
        total_size: i64,
        data: Vec<u8>,
    },
    MetadataReject {
        piece: i64,
    },
}

#[derive(Error, Debug)]
pub enum PeerError {
    #[error("TCP connection failed: {0}")]
    Connection(#[from] std::io::Error),
    #[error("Handshake failed: peer sent invalid data")]
    InvalidHandshake,
    #[error("Peer is for a different torrent (info_hash mismatch)")]
    InfoHashMismatch,
    #[error("Peer connection timed out")]
    Timeout,
}
struct PeerState {
    am_choking: bool,
    am_interested: bool,
    peer_choking: bool,
    peer_interested: bool,
    bitfield: Option<Vec<u8>>,
    pending_blocks: Vec<BlockInfo>, 
}
pub struct PeerConnection {
    stream: TcpStream,
    buffer: BytesMut,
}

impl Handshake {
    const PROTOCOL_STRING: &'static [u8] = b"BitTorrent protocol";

    pub fn new(info_hash: [u8; 20], peer_id: [u8; 20]) -> Self {
        Self {
            info_hash,
            peer_id,
            supports_extended: false,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(68);
        bytes.push(19);
        bytes.extend_from_slice(Self::PROTOCOL_STRING);
        let mut reserved = [0u8; 8];
        reserved[5] |= 0x10;
        bytes.extend_from_slice(&reserved);
        bytes.extend_from_slice(&self.info_hash);
        bytes.extend_from_slice(&self.peer_id);
        bytes
    }

    pub async fn read_from(stream: &mut TcpStream) -> Result<Self, std::io::Error> {
        let mut buffer = [0u8; 68];
        stream.read_exact(&mut buffer).await?;
        if buffer[0] != 19 || &buffer[1..20] != Self::PROTOCOL_STRING {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid BitTorrent protocol handshake",
            ));
        }
        let reserved = &buffer[20..28];
        let supports_extended = (reserved[5] & 0x10) != 0;
        let info_hash = buffer[28..48].try_into().unwrap();
        let peer_id = buffer[48..68].try_into().unwrap();
        Ok(Handshake {
            info_hash,
            peer_id,
            supports_extended,
        })
    }
}

struct PeerHandshakeResult {
    ut_metadata_id: Option<u8>,
    metadata_size: Option<usize>,
}

impl PeerConnection {
    pub fn new(stream: TcpStream) -> Self {
        Self { stream, buffer: BytesMut::with_capacity(4 * 1024) }
    }

    pub async fn read_message(&mut self) -> Result<Option<Message>, std::io::Error> {
        loop {
            if let Some(message) = self.parse_message()? {
                return Ok(Some(message));
            }
            if self.stream.read_buf(&mut self.buffer).await? == 0 {
                return if self.buffer.is_empty() { Ok(None) } else { Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "connection reset by peer")) };
            }
        }
    }

    fn parse_message(&mut self) -> Result<Option<Message>, std::io::Error> {
        if self.buffer.len() < 4 { return Ok(None); }
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&self.buffer[..4]);
        let length = u32::from_be_bytes(len_bytes);
        if length == 0 { self.buffer.advance(4); return Ok(Some(Message::KeepAlive)); }
        if self.buffer.len() < 4 + (length as usize) { return Ok(None); }
        self.buffer.advance(4);
        let payload = &self.buffer[..(length as usize)];
        let message_id = payload[0];
        let mut payload_reader = &payload[1..];
        let message = match message_id {
            0 => Message::Choke,
            1 => Message::Unchoke,
            2 => Message::Interested,
            3 => Message::NotInterested,
            4 => Message::Have(ReadBytesExt::read_u32::<BigEndian>(&mut payload_reader)?),
            5 => Message::Bitfield(payload_reader.to_vec()),
            6 => {
                let index = ReadBytesExt::read_u32::<BigEndian>(&mut payload_reader)?;
                let begin = ReadBytesExt::read_u32::<BigEndian>(&mut payload_reader)?;
                let length = ReadBytesExt::read_u32::<BigEndian>(&mut payload_reader)?;
                Message::Request { index, begin, length }
            },
            7 => {
                let index = ReadBytesExt::read_u32::<BigEndian>(&mut payload_reader)?;
                let begin = ReadBytesExt::read_u32::<BigEndian>(&mut payload_reader)?;
                let block = payload_reader.to_vec();
                Message::Piece { index, begin, block }
            },
            20 => {
                let extended_id = payload_reader[0];
                let bencode_payload = &payload_reader[1..];
                if extended_id == 0 {
                    let (val, _) = crate::bencode::decode(bencode_payload).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("bencode error: {:?}", e)))?;
                    let dict = val.as_dict().ok_or(std::io::ErrorKind::InvalidData)?;
                    let m = dict.get(&b"m"[..]).and_then(|v| v.as_dict()).map(|m_dict| m_dict.iter().filter_map(|(k, v)| v.as_integer().map(|id| (k.clone(), id))).collect()).unwrap_or_default();
                    let metadata_size = dict.get(&b"metadata_size"[..]).and_then(|v| v.as_integer());
                    Message::Extended(ExtendedMessage::Handshake { m, metadata_size })
                } else if let Ok((bencoded_part, remaining_data)) = crate::bencode::decode(bencode_payload) {
                    let dict = bencoded_part.as_dict().ok_or(std::io::ErrorKind::InvalidData)?;
                    let msg_type = dict.get(&b"msg_type"[..]).and_then(|v| v.as_integer()).ok_or(std::io::ErrorKind::InvalidData)?;
                    let piece = dict.get(&b"piece"[..]).and_then(|v| v.as_integer()).ok_or(std::io::ErrorKind::InvalidData)?;
                    match msg_type {
                        1 => {
                            let total_size = dict.get(&b"total_size"[..]).and_then(|v| v.as_integer()).unwrap_or(0);
                            Message::Extended(ExtendedMessage::MetadataPiece { piece, total_size, data: remaining_data.to_vec() })
                        }
                        2 => Message::Extended(ExtendedMessage::MetadataReject { piece }),
                        _ => return Ok(None),
                    }
                } else { return Ok(None); }
            }
            _ => return Ok(None),
        };
        self.buffer.advance(length as usize);
        Ok(Some(message))
    }

    pub async fn send_message(&mut self, message: Message, ut_metadata_id: Option<u8>) -> Result<(), std::io::Error> {
        let mut full_message = Vec::new();
        match message {
            Message::Interested => {
                full_message.extend_from_slice(&1u32.to_be_bytes());
                full_message.push(2);
            }
            Message::Extended(ExtendedMessage::Handshake { .. }) => {
                let mut m_dict = BTreeMap::new();
                m_dict.insert(b"ut_metadata".to_vec(), BencodeValue::Integer(1));
                let mut handshake_dict = BTreeMap::new();
                handshake_dict.insert(b"m".to_vec(), BencodeValue::Dictionary(m_dict));
                let payload = BencodeValue::Dictionary(handshake_dict).to_bytes();
                let mut message_body = Vec::new();
                message_body.push(20);
                message_body.push(0);
                message_body.extend_from_slice(&payload);
                full_message.extend_from_slice(&(message_body.len() as u32).to_be_bytes());
                full_message.extend_from_slice(&message_body);
            }
            Message::Request { index, begin, length } => {
                let mut message_body = Vec::new();
                message_body.push(6);
                message_body.extend_from_slice(&index.to_be_bytes());
                message_body.extend_from_slice(&begin.to_be_bytes());
                message_body.extend_from_slice(&length.to_be_bytes());
                full_message.extend_from_slice(&(message_body.len() as u32).to_be_bytes());
                full_message.extend_from_slice(&message_body);
            }
            Message::Extended(ExtendedMessage::MetadataRequest { piece }) => {
                let ut_metadata_id = ut_metadata_id.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "Missing ut_metadata_id for request"))?;
                let mut dict = BTreeMap::new();
                dict.insert(b"msg_type".to_vec(), BencodeValue::Integer(0));
                dict.insert(b"piece".to_vec(), BencodeValue::Integer(piece));
                let payload = BencodeValue::Dictionary(dict).to_bytes();
                let mut message_body = Vec::new();
                message_body.push(20);
                message_body.push(ut_metadata_id);
                message_body.extend_from_slice(&payload);
                full_message.extend_from_slice(&(message_body.len() as u32).to_be_bytes());
                full_message.extend_from_slice(&message_body);
            }
            _ => { return Ok(()); }
        }
        self.stream.write_all(&full_message).await
    }

    /// Helper to perform both standard and extended handshakes.
    async fn perform_handshakes(&mut self) -> Result<PeerHandshakeResult, Box<dyn std::error::Error>> {
        let handshake_msg = Message::Extended(ExtendedMessage::Handshake { m: Default::default(), metadata_size: None });
        self.send_message(handshake_msg, None).await?;
        
        let response = self.read_message().await?.ok_or("Peer closed connection")?;
        
        if let Message::Extended(ExtendedMessage::Handshake { m, metadata_size }) = response {
            let ut_metadata_id = m.get(&b"ut_metadata"[..]).map(|&id| id as u8);
            Ok(PeerHandshakeResult { ut_metadata_id, metadata_size: metadata_size.map(|s| s as usize) })
        } else {
            Err("Expected extended handshake as first message".into())
        }
    }
    
    /// Helper that runs the metadata download process with this peer.
    async fn download_metadata_from_peer(
        &mut self,
        info_hash: [u8; 20],
        ut_metadata_id: u8,
        metadata_size: usize,
    ) -> Result<BencodeValue, Box<dyn std::error::Error>> {
        let mut downloader = MetadataDownloader::new(info_hash, metadata_size);
        let mut requested_pieces = vec![false; downloader.num_pieces()];
        
        loop {
            // Find and request the next needed piece
            if let Some(idx) = requested_pieces.iter().position(|&r| !r) {
                 let msg = Message::Extended(ExtendedMessage::MetadataRequest { piece: idx as i64 });
                 self.send_message(msg, Some(ut_metadata_id)).await?;
                 requested_pieces[idx] = true;
            } else if downloader.is_complete() {
                 // All pieces have been requested and received.
                 return downloader.assemble_and_verify().ok_or("Metadata hash mismatch".into());
            }
            
            // Wait for a response from the peer
            let response_msg = self.read_message().await?.ok_or("Peer closed connection")?;
            if let Message::Extended(ExtendedMessage::MetadataPiece { piece, data, .. }) = response_msg {
                 downloader.add_piece(piece as usize, data);
            }
            // A real client would also handle Reject messages here.
        }
    }
}

impl GlobalState {
    pub fn is_content_complete(&self) -> bool {
        if let GlobalState::ContentDownload(_, manager_mutex) = self {
            let manager = manager_mutex.blocking_lock();
            manager.is_complete()
        } else {
            false
        }
    }
}

pub async fn connect(
    peer: tracker::Peer,
    info_hash: [u8; 20],
    our_peer_id: [u8; 20],
) -> Result<PeerConnection, PeerError> {
    let peer_addr = SocketAddr::from((peer.ip, peer.port));
    let connect_future = TcpStream::connect(peer_addr);
    let mut stream = tokio::time::timeout(Duration::from_secs(5), connect_future)
        .await
        .map_err(|_| PeerError::Timeout)??;
    let our_handshake = Handshake::new(info_hash, our_peer_id);
    stream.write_all(&our_handshake.to_bytes()).await?;
    let peer_handshake = Handshake::read_from(&mut stream).await?;
    if peer_handshake.info_hash != our_handshake.info_hash {
        return Err(PeerError::InfoHashMismatch);
    }
    if !peer_handshake.supports_extended {
        return Err(PeerError::InvalidHandshake);
    }
    Ok(PeerConnection::new(stream))
}

pub async fn download_metadata(
    mut connection: PeerConnection,
    info_hash: [u8; 20],
    shared_torrent: Arc<Mutex<Option<Arc<Torrent>>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let our_ext_handshake = Message::Extended(ExtendedMessage::Handshake {
        m: BTreeMap::new(),
        metadata_size: None,
    });
    connection.send_message(our_ext_handshake, None).await?;    let ext_handshake_msg = connection.read_message().await?.ok_or("Peer closed connection")?;
    
    let (ut_metadata_id, metadata_size) = if let Message::Extended(ExtendedMessage::Handshake { m, metadata_size }) = ext_handshake_msg {
        (m.get(&b"ut_metadata"[..]).copied(), metadata_size)
    } else {
        return Err("Expected extended handshake".into());
    };
    let (ut_metadata_id, metadata_size) = match (ut_metadata_id, metadata_size) {
        (Some(id), Some(size)) => (id as u8, size as usize),
        _ => return Err("Peer does not support ut_metadata".into()),
    };
    
    let mut downloader = MetadataDownloader::new(info_hash, metadata_size);
    let mut requested_pieces = vec![false; downloader.num_pieces()];
    connection.send_message(Message::Interested, None).await?;
    let mut peer_choking = true;

    loop {
        if !peer_choking {
            if let Some(piece_index) = requested_pieces.iter().position(|&r| !r) {
                let msg = Message::Extended(ExtendedMessage::MetadataRequest { piece: piece_index as i64 });
                connection.send_message(msg, Some(ut_metadata_id)).await?;
                requested_pieces[piece_index] = true;
            } else if downloader.is_complete() {
                break;
            }
        }
        let maybe_msg = tokio::time::timeout(Duration::from_secs(10), connection.read_message()).await;
        if let Ok(Ok(Some(message))) = maybe_msg {
            match message {
                Message::Unchoke => { peer_choking = false; },
                Message::Choke => { peer_choking = true; },
                Message::Extended(ExtendedMessage::MetadataPiece { piece, data, .. }) => {
                    downloader.add_piece(piece as usize, data);
                },
                _ => {}
            }
        } else {
            return Err("Peer connection timed out or closed.".into());
        }
    }
    
    if let Some(info_dict) = downloader.assemble_and_verify() {
        let new_torrent = Arc::new(Torrent::new(&info_dict, info_hash)?);
        *shared_torrent.lock().await = Some(new_torrent);
    }
    Ok(())
}

pub async fn download_content(
    mut connection: PeerConnection,
    torrent: Arc<Torrent>,
    piece_manager: Arc<Mutex<PieceManager>>,
    file_handles: Arc<Mutex<Vec<File>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Logic from previous step for Phase 3
    let bitfield_msg = connection.read_message().await?.ok_or("Peer closed connection")?;
    let peer_bitfield = if let Message::Bitfield(b) = bitfield_msg { b } else { return Err("Expected Bitfield".into()) };
    connection.send_message(Message::Interested, None).await?;
    let mut am_choked = true;

    loop {
        if !am_choked {
            let mut manager = piece_manager.lock().await;
            if let Some(block_to_request) = manager.get_block_to_request(&torrent, &peer_bitfield) {
                                let begin = block_to_request.block_index as u32 * BLOCK_SIZE;
                let request_msg = Message::Request {
                    index: block_to_request.piece_index as u32,
                    begin,
                    length: block_to_request.length,
                };
                drop(manager); // Unlock the mutex before the .await call
                connection.send_message(request_msg, None).await?;
            } else {
                break;
            }
        }
        match tokio::time::timeout(Duration::from_secs(30), connection.read_message()).await {
            Ok(Ok(Some(message))) => match message {
                Message::Unchoke => { println!("  > [Content] Got Unchoke from peer."); am_choked = false; },
                Message::Choke => { am_choked = true; },
                Message::Piece { index, begin, block } => {
                    println!("  > [RAW RECV] Piece #{} Block @{} len={}. Data starts with: {:?}", 
                             index, begin, block.len(), &block.get(..8).unwrap_or_default());

                    let block_index = (begin / BLOCK_SIZE) as usize;
                    let block_info = BlockInfo { piece_index: index as usize, block_index, length: block.len() as u32 };
                    
                    let mut manager = piece_manager.lock().await;
                    if manager.add_block(&block_info, block) {
                        println!("  > Piece #{} is complete!", index);
                        let piece = &manager.pieces[index as usize];
                        let piece_data = piece.assemble(); // Assemble the data once
                        
                        if piece.verify(&piece_data) {
                             println!("  > ✅ Piece #{} is VALID.", index);
                             manager.pieces[index as usize].state = crate::torrent::PieceState::Have;
                             
                             // --- THIS IS THE NEW LOGIC ---
                             // Lock the file handles and write the piece data to disk.
                             let mut handles = file_handles.lock().await;
                             if let Err(e) = manager.write_piece_to_disk(index as usize, &piece_data, &torrent, &mut handles) {
                                 eprintln!("  > ❌ FAILED to write piece #{} to disk: {}", index, e);
                                 // We failed to write, so we need to re-download this piece.
                                 manager.pieces[index as usize].state = crate::torrent::PieceState::Needed;
                             } else {
                                 println!("  > 💾 Piece #{} successfully written to disk.", index);
                             }
                             // --- END NEW LOGIC ---

                        } else {
                            println!("  > ❌ PIECE #{} IS INVALID. HASH MISMATCH.", index);
                             manager.pieces[index as usize].state = crate::torrent::PieceState::Needed;
                             // also reset the blocks so we can re-request them
                             for block in manager.pieces[index as usize].blocks.iter_mut() { *block = None; }
                             manager.pieces[index as usize].downloaded_blocks = 0;
                        }
                    }
                }
                _ => {}
            },
            _ => return Err("Peer connection timed out or closed.".into()),
        }
    }
    Ok(())
}

pub async fn run_session(
    mut connection: PeerConnection,
    info_hash: [u8; 20],
    shared_state: Arc<Mutex<GlobalState>>,
) -> Result<(), Box<dyn std::error::Error>> {

    // --- Phase 1: Handshakes and State Initialization ---
    let peer_handshake_result = connection.perform_handshakes().await?;
    let ut_metadata_id = peer_handshake_result.ut_metadata_id;
    let metadata_size = peer_handshake_result.metadata_size;
    
    // --- Initialize the state for this specific peer connection ---
    let mut local_peer_state = PeerState {
        am_choking: true,
        am_interested: false,
        peer_choking: true,
        peer_interested: false,
        bitfield: None,
        pending_blocks: Vec::new(),
    };

    // Check if another task has already completed metadata download.
    let mut am_metadata_downloader = false;
    { 
        let mut state = shared_state.lock().await;
        if let GlobalState::MetadataPending = *state {
            if let (Some(_), Some(_)) = (ut_metadata_id, metadata_size) {
                *state = GlobalState::MetadataInProgress;
                am_metadata_downloader = true;
            }
        }
    } 
    if am_metadata_downloader {
        let metadata = connection.download_metadata_from_peer(info_hash, ut_metadata_id.unwrap(), metadata_size.unwrap()).await?;
        let torrent = Arc::new(Torrent::new(&metadata, info_hash)?);
        let manager = Arc::new(Mutex::new(PieceManager::new(&torrent)));
        *shared_state.lock().await = GlobalState::ContentDownload(torrent, manager);
        println!("  > ✅ This peer completed metadata download.");
    }
    
    // Set a long timeout for the overall session.
    let session_timeout = Duration::from_secs(180); 
    let start_time = std::time::Instant::now();

    // --- The Main Event Loop ---
    while start_time.elapsed() < session_timeout {
        
        // --- Lock and determine current global state ---
        let global_state = shared_state.lock().await.clone();

        if let GlobalState::ContentDownload(torrent, manager_mutex) = &global_state {
            // We have the metadata, we are now in the content download phase.

            // 1. Express interest if we haven't already.
            if !local_peer_state.am_interested {
                connection.send_message(Message::Interested, None).await?;
                local_peer_state.am_interested = true;
            }

            // 2. Fill the pipeline with new block requests.
            if !local_peer_state.peer_choking {
                if let Some(bitfield) = &local_peer_state.bitfield {
                    let block_req_to_send = { // Create a new scope
                        let mut manager = manager_mutex.lock().await;
                        if manager.is_complete() { break; }
                        manager.get_block_to_request(&torrent, bitfield)
                    }; // The manager lock is dropped here as `manager` goes out of scope
    
                    // Now we are free to await on I/O without holding the lock.
                    if let Some(block_req) = block_req_to_send {
                        let begin = block_req.block_index as u32 * BLOCK_SIZE;
                        let msg = Message::Request { index: block_req.piece_index as u32, begin, length: block_req.length };
                        connection.send_message(msg, None).await?;
                    }
                }
            }

            // Check if our work here is done (all pending blocks are received, and no more to request)
            if local_peer_state.pending_blocks.is_empty() {
                 let manager = manager_mutex.lock().await;
                 if manager.is_complete() {
                     println!("  > Download is complete. Closing session with this peer.");
                     break;
                 }
            }
        
        } else {
            // Metadata is still pending or in progress by another peer. Wait patiently.
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue; // Skip to the next iteration to re-check the global state.
        }


        // --- React to incoming messages ---
        // We use a shorter timeout for receiving messages to keep the loop spinning.
        let maybe_msg = tokio::time::timeout(Duration::from_secs(10), connection.read_message()).await;
        if let Ok(Ok(Some(msg))) = maybe_msg {
            match msg {
                Message::Choke => local_peer_state.peer_choking = true,
                Message::Unchoke => local_peer_state.peer_choking = false,
                Message::Bitfield(b) => local_peer_state.bitfield = Some(b),
                Message::Have(piece_index) => {
                    if let Some(bitfield) = local_peer_state.bitfield.as_mut() {
                        let byte_index = piece_index as usize / 8;
                        if byte_index < bitfield.len() {
                            bitfield[byte_index] |= 1 << (7 - (piece_index % 8));
                        }
                    }
                }
                Message::Piece { index, begin, block } => {
                    let block_index = (begin / BLOCK_SIZE) as usize;

                    // Remove the completed request from our pending queue
                    if let Some(pos) = local_peer_state.pending_blocks.iter().position(|b| b.piece_index == index as usize && b.block_index == block_index) {
                        local_peer_state.pending_blocks.remove(pos);
                    }

                    if let GlobalState::ContentDownload(_, manager_mutex) = &*shared_state.lock().await {
                        let mut manager = manager_mutex.lock().await;
                        let block_info = BlockInfo { piece_index: index as usize, block_index, length: block.len() as u32 };
                        if manager.add_block(&block_info, block) {
                            let piece_data = manager.pieces[index as usize].assemble();
                            if manager.pieces[index as usize].verify(&piece_data) {
                                manager.pieces[index as usize].state = crate::torrent::PieceState::Have;
                                println!("  > ✅ Piece #{} is VALID. ({}/{})", index, manager.count_have_pieces(), manager.pieces.len());
                            } else {
                                manager.reset_piece(index as usize);
                            }
                        }
                    }
                }
                _ => {} 
            }
        } else if let Ok(Ok(None)) = maybe_msg {
             // Peer closed the connection cleanly
            break;
        }
        // If it's a timeout error, we just loop again, which is fine.
    }
    
    Ok(())
}
