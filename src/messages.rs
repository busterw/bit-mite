use std::io::{Read, Write};
use std::net::TcpStream;

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    KeepAlive,
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have(u32), // piece index
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
}

impl Message {
    pub fn parse(stream: &mut TcpStream) -> Result<Self, Box<dyn std::error::Error>> {
        // read length prefix (first 4 bytes)
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let length = u32::from_be_bytes(len_buf);

        // KeepAlive message
        if length == 0 {
            return Ok(Message::KeepAlive);
        }

        // read message id (1 byte)
        let mut id_buf = [0u8; 1];
        stream.read_exact(&mut id_buf)?;
        let id = id_buf[0];

        // read payload
        let payload_len = (length - 1) as usize;
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            stream.read_exact(&mut payload)?;
        }

        match id {
            0 => Ok(Message::Choke),
            1 => Ok(Message::Unchoke),
            2 => Ok(Message::Interested),
            3 => Ok(Message::NotInterested),
            4 => Ok(Message::Have(u32::from_be_bytes(payload[..].try_into()?))),
            5 => Ok(Message::Bitfield(payload)),
            6 => Ok(Message::Request {
                index: u32::from_be_bytes(payload[0..4].try_into()?),
                begin: u32::from_be_bytes(payload[4..8].try_into()?),
                length: u32::from_be_bytes(payload[8..12].try_into()?),
            }),
            7 => Ok(Message::Piece {
                index: u32::from_be_bytes(payload[0..4].try_into()?),
                begin: u32::from_be_bytes(payload[4..8].try_into()?),
                block: payload[8..].to_vec(),
            }),
            8 => Ok(Message::Cancel {
                index: u32::from_be_bytes(payload[0..4].try_into()?),
                begin: u32::from_be_bytes(payload[4..8].try_into()?),
                length: u32::from_be_bytes(payload[8..12].try_into()?),
            }),
            _ => Err(format!("Unknown message ID: {}", id).into()),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Message::KeepAlive => u32::to_be_bytes(0).to_vec(),
            
            // --- CORRECTED SIMPLE MESSAGES ---
            Message::Choke => {
                let mut bytes = Vec::with_capacity(5);
                bytes.extend_from_slice(&u32::to_be_bytes(1)); // Length prefix
                bytes.push(0); // Message ID
                bytes
            }
            Message::Unchoke => {
                let mut bytes = Vec::with_capacity(5);
                bytes.extend_from_slice(&u32::to_be_bytes(1));
                bytes.push(1);
                bytes
            }
            Message::Interested => {
                let mut bytes = Vec::with_capacity(5);
                bytes.extend_from_slice(&u32::to_be_bytes(1));
                bytes.push(2);
                bytes
            }
            Message::NotInterested => {
                let mut bytes = Vec::with_capacity(5);
                bytes.extend_from_slice(&u32::to_be_bytes(1));
                bytes.push(3);
                bytes
            }
            // --- END CORRECTION ---

            Message::Have(index) => {
                let mut bytes = Vec::with_capacity(9);
                bytes.extend_from_slice(&u32::to_be_bytes(5)); // Length prefix (1 for ID + 4 for index)
                bytes.push(4); // Message ID
                bytes.extend_from_slice(&index.to_be_bytes());
                bytes
            }
            Message::Request { index, begin, length } => {
                let mut bytes = Vec::with_capacity(17);
                bytes.extend_from_slice(&u32::to_be_bytes(13)); // Length prefix (1 for ID + 12 for payload)
                bytes.push(6); // Message ID
                bytes.extend_from_slice(&index.to_be_bytes());
                bytes.extend_from_slice(&begin.to_be_bytes());
                bytes.extend_from_slice(&length.to_be_bytes());
                bytes
            }
            // Other message types can be serialized here as needed...
            _ => vec![], // Placeholder for simplicity
        }
    }
}
