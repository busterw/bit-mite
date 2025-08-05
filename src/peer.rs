// src/peer.rs

use crate::bencode::BencodeValue;
use crate::metadata::MetadataDownloader;
use crate::torrent::{BLOCK_SIZE, BlockInfo, PieceManager, PieceRarity, Torrent};
use crate::tracker;
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
    Request {
        index: u32,
        begin: u32,
        length: u32,
    },
    Piece {
        index: u32,
        begin: u32,
        block: Vec<u8>,
    },
    Cancel {
        index: u32,
        begin: u32,
        length: u32,
    },
    Extended(ExtendedMessage),
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
    #[error("Handshake failed")]
    InvalidHandshake,
    #[error("Info_hash mismatch")]
    InfoHashMismatch,
    #[error("Timed out")]
    Timeout,
}
pub struct PeerConnection {
    stream: TcpStream,
    buffer: BytesMut,
}
struct PeerHandshakeResult {
    ut_metadata_id: Option<u8>,
    metadata_size: Option<usize>,
}

#[derive(Clone)]
pub enum GlobalState {
    MetadataPending,
    MetadataInProgress,
    ContentDownload(
        Arc<Torrent>,
        Arc<Mutex<PieceManager>>,
        Arc<Mutex<PieceRarity>>,
    ),
}

struct PeerState {
    am_interested: bool,
    peer_choking: bool,
    bitfield: Option<Vec<u8>>,
    pending_blocks: Vec<BlockInfo>,
}

pub async fn connect(
    peer: tracker::Peer,
    info_hash: [u8; 20],
    our_peer_id: [u8; 20],
) -> Result<PeerConnection, PeerError> {
    let peer_addr = SocketAddr::from((peer.ip, peer.port));
    let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(peer_addr))
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

pub async fn run_session(
    mut connection: PeerConnection,
    info_hash: [u8; 20],
    shared_state: Arc<Mutex<GlobalState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let peer_handshake_result = connection.perform_extended_handshake().await?;
    let mut local_peer_state = PeerState {
        am_interested: false,
        peer_choking: true,
        bitfield: None,
        pending_blocks: Vec::new(),
    };
    let mut am_metadata_downloader = false;
    {
        let mut state = shared_state.lock().await;
        if let GlobalState::MetadataPending = *state {
            if let (Some(_), Some(_)) = (
                peer_handshake_result.ut_metadata_id,
                peer_handshake_result.metadata_size,
            ) {
                *state = GlobalState::MetadataInProgress;
                am_metadata_downloader = true;
            }
        }
    }
    if am_metadata_downloader {
        let (ut_id, meta_size) = (
            peer_handshake_result.ut_metadata_id.unwrap(),
            peer_handshake_result.metadata_size.unwrap(),
        );
        match connection
            .download_metadata_from_peer(info_hash, ut_id, meta_size)
            .await
        {
            Ok(metadata) => {
                let torrent = Arc::new(Torrent::new(&metadata, info_hash)?);
                let manager = Arc::new(Mutex::new(PieceManager::new(&torrent)));
                let rarity = Arc::new(Mutex::new(PieceRarity::new(torrent.piece_hashes.len())));
                *shared_state.lock().await = GlobalState::ContentDownload(torrent, manager, rarity);
                println!("  > ✅ Peer completed metadata download.");
            }
            Err(e) => {
                *shared_state.lock().await = GlobalState::MetadataPending;
                return Err(e);
            }
        }
    }

    let session_timeout = Duration::from_secs(180);
    let start_time = std::time::Instant::now();

    while start_time.elapsed() < session_timeout {
        let global_state = shared_state.lock().await.clone();
        if let GlobalState::ContentDownload(torrent, manager_mutex, rarity_mutex) = &global_state {
            if !local_peer_state.am_interested {
                connection.send_message(Message::Interested, None).await?;
                local_peer_state.am_interested = true;
            }
            if !local_peer_state.peer_choking {
                const MAX_PIPELINED_REQUESTS: usize = 5;
                if let Some(bitfield) = &local_peer_state.bitfield {
                    let mut manager = manager_mutex.lock().await;
                    while manager.get_pending_request_count() < MAX_PIPELINED_REQUESTS {
                        if manager.is_complete() {
                            break;
                        }
                        let rarity = rarity_mutex.lock().await;
                        if let Some(block_req) =
                            manager.get_block_to_request(torrent, bitfield, &rarity)
                        {
                            manager.add_pending_request(&block_req);
                            local_peer_state.pending_blocks.push(block_req);
                            let begin = block_req.block_index as u32 * BLOCK_SIZE;
                            let msg = Message::Request {
                                index: block_req.piece_index as u32,
                                begin,
                                length: block_req.length,
                            };
                            drop(rarity);
                            drop(manager);
                            connection.send_message(msg, None).await?;
                            manager = manager_mutex.lock().await;
                        } else {
                            break;
                        }
                    }
                }
            }
        } else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }

        let maybe_msg =
            tokio::time::timeout(Duration::from_secs(20), connection.read_message()).await;
        if let Ok(Ok(Some(msg))) = maybe_msg {
            match msg {
                Message::Choke => {
                    local_peer_state.peer_choking = true;
                    if let GlobalState::ContentDownload(_, manager_mutex, _) =
                        &*shared_state.lock().await
                    {
                        let mut manager = manager_mutex.lock().await;
                        manager.reset_pending_requests(&local_peer_state.pending_blocks);
                    }
                    local_peer_state.pending_blocks.clear();
                }
                Message::Unchoke => {
                    local_peer_state.peer_choking = false;
                }
                Message::Bitfield(b) => {
                    local_peer_state.bitfield = Some(b.clone());
                    if let GlobalState::ContentDownload(_, _, rarity_mutex) =
                        &*shared_state.lock().await
                    {
                        let mut rarity = rarity_mutex.lock().await;
                        for i in 0..rarity.counts.len() {
                            if i / 8 < b.len() && (b[i / 8] >> (7 - (i % 8))) & 1 != 0 {
                                rarity.counts[i] += 1;
                            }
                        }
                    }
                }
                Message::Have(piece_index) => {
                    if let Some(bitfield) = local_peer_state.bitfield.as_mut() {
                        let byte_index = piece_index as usize / 8;
                        if byte_index < bitfield.len() {
                            bitfield[byte_index] |= 1 << (7 - (piece_index % 8));
                        }
                    }
                    if let GlobalState::ContentDownload(_, _, rarity_mutex) =
                        &*shared_state.lock().await
                    {
                        let mut rarity = rarity_mutex.lock().await;
                        if (piece_index as usize) < rarity.counts.len() {
                            rarity.counts[piece_index as usize] += 1;
                        }
                    }
                }
                Message::Piece {
                    index,
                    begin,
                    block,
                } => {
                    let block_index = (begin / BLOCK_SIZE) as usize;
                    let block_key = BlockInfo {
                        piece_index: index as usize,
                        block_index,
                        length: 0,
                    };
                    if let Some(pos) = local_peer_state.pending_blocks.iter().position(|b| {
                        b.piece_index == block_key.piece_index
                            && b.block_index == block_key.block_index
                    }) {
                        local_peer_state.pending_blocks.remove(pos);
                    }
                    if let GlobalState::ContentDownload(_, manager_mutex, _) =
                        &*shared_state.lock().await
                    {
                        let mut manager = manager_mutex.lock().await;
                        let block_info = BlockInfo {
                            piece_index: index as usize,
                            block_index,
                            length: block.len() as u32,
                        };
                        manager.remove_pending_request(&block_info);
                        if manager.add_block(&block_info, block) {
                            let piece_data = manager.pieces[index as usize].assemble();
                            if manager.pieces[index as usize].verify(&piece_data) {
                                manager.pieces[index as usize].state =
                                    crate::torrent::PieceState::Have;
                                println!(
                                    "  > ✅ Piece #{} is VALID. ({}/{})",
                                    index,
                                    manager.count_have_pieces(),
                                    manager.pieces.len()
                                );
                            } else {
                                manager.reset_piece(index as usize);
                            }
                        }
                    }
                }
                _ => {}
            }
        } else {
            if let GlobalState::ContentDownload(_, manager_mutex, _) = &*shared_state.lock().await {
                let mut manager = manager_mutex.lock().await;
                manager.reset_pending_requests(&local_peer_state.pending_blocks);
            }
            break;
        }
    }
    Ok(())
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
        let mut b = Vec::with_capacity(68);
        b.push(19);
        b.extend_from_slice(Self::PROTOCOL_STRING);
        let mut r = [0u8; 8];
        r[5] |= 0x10;
        b.extend_from_slice(&r);
        b.extend_from_slice(&self.info_hash);
        b.extend_from_slice(&self.peer_id);
        b
    }
    pub async fn read_from(stream: &mut TcpStream) -> Result<Self, std::io::Error> {
        let mut b = [0u8; 68];
        stream.read_exact(&mut b).await?;
        if b[0] != 19 || &b[1..20] != Self::PROTOCOL_STRING {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid handshake",
            ));
        }
        Ok(Self {
            info_hash: b[28..48].try_into().unwrap(),
            peer_id: b[48..68].try_into().unwrap(),
            supports_extended: (b[20..28][5] & 0x10) != 0,
        })
    }
}

impl PeerConnection {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            buffer: BytesMut::with_capacity(18 * 1024),
        }
    }

    pub async fn read_message(&mut self) -> Result<Option<Message>, std::io::Error> {
        loop {
            if let Some(message) = self.parse_message()? {
                return Ok(Some(message));
            }
            if self.stream.read_buf(&mut self.buffer).await? == 0 {
                return if self.buffer.is_empty() {
                    Ok(None)
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "connection reset",
                    ))
                };
            }
        }
    }

    fn parse_message(&mut self) -> Result<Option<Message>, std::io::Error> {
        if self.buffer.len() < 4 {
            return Ok(None);
        }
        let length = u32::from_be_bytes(self.buffer[..4].try_into().unwrap());
        if length == 0 {
            self.buffer.advance(4);
            return Ok(Some(Message::KeepAlive));
        }
        if self.buffer.len() < 4 + (length as usize) {
            return Ok(None);
        }
        self.buffer.advance(4);
        let payload = &self.buffer[..(length as usize)];
        let message_id = payload[0];
        let mut reader = &payload[1..];
        let message = match message_id {
            0 => Message::Choke,
            1 => Message::Unchoke,
            2 => Message::Interested,
            3 => Message::NotInterested,
            4 => Message::Have(ReadBytesExt::read_u32::<BigEndian>(&mut reader)?),
            5 => Message::Bitfield(reader.to_vec()),
            6 => Message::Request {
                index: ReadBytesExt::read_u32::<BigEndian>(&mut reader)?,
                begin: ReadBytesExt::read_u32::<BigEndian>(&mut reader)?,
                length: ReadBytesExt::read_u32::<BigEndian>(&mut reader)?,
            },
            7 => Message::Piece {
                index: ReadBytesExt::read_u32::<BigEndian>(&mut reader)?,
                begin: ReadBytesExt::read_u32::<BigEndian>(&mut reader)?,
                block: reader.to_vec(),
            },
            20 => {
                let extended_id = reader[0];
                let bencode_payload = &reader[1..];
                if extended_id == 0 {
                    let (val, _) = crate::bencode::decode(bencode_payload).map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, "bencode error")
                    })?;
                    let dict = val.as_dict().ok_or(std::io::ErrorKind::InvalidData)?;
                    let m = dict
                        .get(&b"m"[..])
                        .and_then(|v| v.as_dict())
                        .map(|m_dict| {
                            m_dict
                                .iter()
                                .filter_map(|(k, v)| v.as_integer().map(|id| (k.clone(), id)))
                                .collect()
                        })
                        .unwrap_or_default();
                    let metadata_size =
                        dict.get(&b"metadata_size"[..]).and_then(|v| v.as_integer());
                    Message::Extended(ExtendedMessage::Handshake { m, metadata_size })
                } else if let Ok((b_part, rem_data)) = crate::bencode::decode(bencode_payload) {
                    let dict = b_part.as_dict().ok_or(std::io::ErrorKind::InvalidData)?;
                    let msg_type = dict
                        .get(&b"msg_type"[..])
                        .and_then(|v| v.as_integer())
                        .ok_or(std::io::ErrorKind::InvalidData)?;
                    let piece = dict
                        .get(&b"piece"[..])
                        .and_then(|v| v.as_integer())
                        .ok_or(std::io::ErrorKind::InvalidData)?;
                    match msg_type {
                        1 => Message::Extended(ExtendedMessage::MetadataPiece {
                            piece,
                            total_size: dict
                                .get(&b"total_size"[..])
                                .and_then(|v| v.as_integer())
                                .unwrap_or(0),
                            data: rem_data.to_vec(),
                        }),
                        2 => Message::Extended(ExtendedMessage::MetadataReject { piece }),
                        _ => return Ok(None),
                    }
                } else {
                    return Ok(None);
                }
            }
            _ => return Ok(None),
        };
        self.buffer.advance(length as usize);
        Ok(Some(message))
    }

    pub async fn send_message(
        &mut self,
        message: Message,
        ut_metadata_id: Option<u8>,
    ) -> Result<(), std::io::Error> {
        let mut full_message = Vec::new();
        match message {
            Message::Interested => {
                full_message.extend_from_slice(&1u32.to_be_bytes());
                full_message.push(2);
            }
            Message::Extended(ExtendedMessage::Handshake { .. }) => {
                let mut m_dict = BTreeMap::new();
                m_dict.insert(b"ut_metadata".to_vec(), BencodeValue::Integer(1));
                let mut h_dict = BTreeMap::new();
                h_dict.insert(b"m".to_vec(), BencodeValue::Dictionary(m_dict));
                let payload = BencodeValue::Dictionary(h_dict).to_bytes();
                let mut body = Vec::new();
                body.push(20);
                body.push(0);
                body.extend_from_slice(&payload);
                full_message.extend_from_slice(&(body.len() as u32).to_be_bytes());
                full_message.extend_from_slice(&body);
            }
            Message::Request {
                index,
                begin,
                length,
            } => {
                let mut body = Vec::new();
                body.push(6);
                body.extend_from_slice(&index.to_be_bytes());
                body.extend_from_slice(&begin.to_be_bytes());
                body.extend_from_slice(&length.to_be_bytes());
                full_message.extend_from_slice(&(body.len() as u32).to_be_bytes());
                full_message.extend_from_slice(&body);
            }
            Message::Extended(ExtendedMessage::MetadataRequest { piece }) => {
                let ut_id = ut_metadata_id.ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::Other, "Missing ut_metadata_id")
                })?;
                let mut dict = BTreeMap::new();
                dict.insert(b"msg_type".to_vec(), BencodeValue::Integer(0));
                dict.insert(b"piece".to_vec(), BencodeValue::Integer(piece));
                let payload = BencodeValue::Dictionary(dict).to_bytes();
                let mut body = Vec::new();
                body.push(20);
                body.push(ut_id);
                body.extend_from_slice(&payload);
                full_message.extend_from_slice(&(body.len() as u32).to_be_bytes());
                full_message.extend_from_slice(&body);
            }
            _ => {
                return Ok(());
            }
        }
        self.stream.write_all(&full_message).await
    }

    async fn perform_extended_handshake(
        &mut self,
    ) -> Result<PeerHandshakeResult, Box<dyn std::error::Error + Send + Sync>> {
        let handshake_msg = Message::Extended(ExtendedMessage::Handshake {
            m: Default::default(),
            metadata_size: None,
        });
        self.send_message(handshake_msg, None).await?;
        let response = self.read_message().await?.ok_or("Peer closed connection")?;
        if let Message::Extended(ExtendedMessage::Handshake { m, metadata_size }) = response {
            let ut_metadata_id = m.get(&b"ut_metadata"[..]).map(|&id| id as u8);
            Ok(PeerHandshakeResult {
                ut_metadata_id,
                metadata_size: metadata_size.map(|s| s as usize),
            })
        } else {
            Err("Expected extended handshake".into())
        }
    }

    async fn download_metadata_from_peer(
        &mut self,
        info_hash: [u8; 20],
        ut_metadata_id: u8,
        metadata_size: usize,
    ) -> Result<BencodeValue, Box<dyn std::error::Error + Send + Sync>> {
        let mut downloader = MetadataDownloader::new(info_hash, metadata_size);
        let mut requested_pieces = vec![false; downloader.num_pieces()];
        loop {
            if let Some(idx) = requested_pieces.iter().position(|&r| !r) {
                let msg = Message::Extended(ExtendedMessage::MetadataRequest { piece: idx as i64 });
                self.send_message(msg, Some(ut_metadata_id)).await?;
                requested_pieces[idx] = true;
            } else if downloader.is_complete() {
                return downloader
                    .assemble_and_verify()
                    .ok_or("Metadata hash mismatch".into());
            }
            let msg = self.read_message().await?.ok_or("Peer closed")?;
            if let Message::Extended(ExtendedMessage::MetadataPiece { piece, data, .. }) = msg {
                downloader.add_piece(piece as usize, data);
            }
        }
    }
}
