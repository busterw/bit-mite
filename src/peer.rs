use crate::bencode::BencodeValue;
use crate::metadata::MetadataDownloader;
use crate::torrent::Torrent;
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
    #[error("Handshake failed: peer sent invalid data")]
    InvalidHandshake,
    #[error("Peer is for a different torrent (info_hash mismatch)")]
    InfoHashMismatch,
    #[error("Peer connection timed out")]
    Timeout,
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

impl PeerConnection {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            buffer: BytesMut::with_capacity(4 * 1024),
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
                        "connection reset by peer",
                    ))
                };
            }
        }
    }

    fn parse_message(&mut self) -> Result<Option<Message>, std::io::Error> {
        if self.buffer.len() < 4 {
            return Ok(None);
        }
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&self.buffer[..4]);
        let length = u32::from_be_bytes(len_bytes);
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
        let mut payload_reader = &payload[1..];
        let message = match message_id {
            0 => Message::Choke,
            1 => Message::Unchoke,
            2 => Message::Interested,
            3 => Message::NotInterested,
            4 => Message::Have(ReadBytesExt::read_u32::<BigEndian>(&mut payload_reader)?),
            5 => Message::Bitfield(payload_reader.to_vec()),
            6 => Message::Request {
                index: 0,
                begin: 0,
                length: 0,
            },
            7 => Message::Piece {
                index: 0,
                begin: 0,
                block: vec![],
            },
            20 => {
                let extended_id = payload_reader[0];
                let bencode_payload = &payload_reader[1..];
                if extended_id == 0 {
                    let (val, _) = crate::bencode::decode(bencode_payload).map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("bencode error: {:?}", e),
                        )
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
                } else {
                    if let Ok((bencoded_part, remaining_data)) =
                        crate::bencode::decode(bencode_payload)
                    {
                        let dict = bencoded_part
                            .as_dict()
                            .ok_or(std::io::ErrorKind::InvalidData)?;
                        let msg_type = dict
                            .get(&b"msg_type"[..])
                            .and_then(|v| v.as_integer())
                            .ok_or(std::io::ErrorKind::InvalidData)?;
                        let piece = dict
                            .get(&b"piece"[..])
                            .and_then(|v| v.as_integer())
                            .ok_or(std::io::ErrorKind::InvalidData)?;
                        match msg_type {
                            1 => {
                                let total_size = dict
                                    .get(&b"total_size"[..])
                                    .and_then(|v| v.as_integer())
                                    .unwrap_or(0);
                                Message::Extended(ExtendedMessage::MetadataPiece {
                                    piece,
                                    total_size,
                                    data: remaining_data.to_vec(),
                                })
                            }
                            2 => Message::Extended(ExtendedMessage::MetadataReject { piece }),
                            _ => return Ok(None),
                        }
                    } else {
                        return Ok(None);
                    }
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
                // This builds: d1:md11:ut_metadatai1eee
                let mut m_dict = BTreeMap::new();
                m_dict.insert(b"ut_metadata".to_vec(), BencodeValue::Integer(1));

                let mut handshake_dict = BTreeMap::new();
                handshake_dict.insert(b"m".to_vec(), BencodeValue::Dictionary(m_dict));

                let payload = BencodeValue::Dictionary(handshake_dict).to_bytes();

                let mut message_body = Vec::new();
                message_body.push(20);
                message_body.push(0); // Extended Handshake ID is always 0
                message_body.extend_from_slice(&payload);

                full_message.extend_from_slice(&(message_body.len() as u32).to_be_bytes());
                full_message.extend_from_slice(&message_body);
            }
            Message::Extended(ExtendedMessage::MetadataRequest { piece }) => {
                let ut_metadata_id = ut_metadata_id.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Missing ut_metadata_id for request",
                    )
                })?;

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
            _ => {
                return Ok(());
            }
        }

        self.stream.write_all(&full_message).await
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

pub async fn run_session(
    mut connection: PeerConnection,
    info_hash: [u8; 20],
    shared_torrent: Arc<Mutex<Option<Arc<Torrent>>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let our_ext_handshake = Message::Extended(ExtendedMessage::Handshake {
        m: BTreeMap::new(),
        metadata_size: None,
    });
    connection.send_message(our_ext_handshake, None).await?;

    // --- Phase 1: Handshake ---
    let ext_handshake_msg = connection
        .read_message()
        .await?
        .ok_or("Peer closed connection")?;

    let (ut_metadata_id, metadata_size) =
        if let Message::Extended(ExtendedMessage::Handshake { m, metadata_size }) =
            ext_handshake_msg
        {
            (m.get(&b"ut_metadata"[..]).copied(), metadata_size)
        } else {
            return Err("Expected extended handshake as first message from peer".into());
        };

    let (ut_metadata_id, metadata_size) = match (ut_metadata_id, metadata_size) {
        (Some(id), Some(size)) => (id as u8, size as usize),
        _ => return Err("Peer does not support ut_metadata extension".into()),
    };
    println!(
        "  > Peer supports metadata exchange! (ut_metadata ID: {}, Size: {} bytes)",
        ut_metadata_id, metadata_size
    );

    // --- Phase 2: Politely Request Metadata ---
    let mut downloader = MetadataDownloader::new(info_hash, metadata_size);
    let mut requested_pieces = vec![false; downloader.num_pieces()];

    let mut peer_choking = true;

    // Send an Interested message
    connection.send_message(Message::Interested, None).await?;
    let am_interested = true;

    loop {
        // only request pieces if we are interested AND we're not choked
        if am_interested && !peer_choking {
            if let Some(piece_index) = requested_pieces.iter().position(|&r| !r) {
                let msg = Message::Extended(ExtendedMessage::MetadataRequest {
                    piece: piece_index as i64,
                });
                connection.send_message(msg, Some(ut_metadata_id)).await?;
                requested_pieces[piece_index] = true;
            } else if downloader.is_complete() {
                break;
            }
        }

        let maybe_msg =
            tokio::time::timeout(Duration::from_secs(30), connection.read_message()).await;
        if let Ok(Ok(Some(message))) = maybe_msg {
            match message {
                Message::Unchoke => {
                    println!("  > Got Unchoke! Peer is ready.");
                    peer_choking = false;
                }
                Message::Choke => {
                    println!("  > Got Choke. Peer is not ready.");
                    peer_choking = true;
                }
                Message::Extended(ExtendedMessage::MetadataPiece { piece, data, .. }) => {
                    println!("  > Got metadata piece #{}", piece);
                    downloader.add_piece(piece as usize, data);
                }
                _ => {}
            }
        } else {
            return Err("Peer connection timed out or closed.".into());
        }
    }

    // --- Phase 2.5: Verification ---
    println!("  > Metadata download complete. Verifying...");
    if let Some(info_dict) = downloader.assemble_and_verify() {
        println!("  > Metadata verified successfully!");
        let new_torrent = Arc::new(Torrent::new(&info_dict)?);
        *shared_torrent.lock().await = Some(new_torrent);
    } else {
        return Err("Metadata verification failed".into());
    }

    println!("  > Proceeding to file download phase.");
    Ok(())
}
