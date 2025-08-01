// src/torrent.rs

use crate::bencode::BencodeValue;
use sha1::{Digest, Sha1};
use std::path::PathBuf;

// Standard block size is 2^14 bytes, or 16KiB.
pub const BLOCK_SIZE: u32 = 16384;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PieceState {
    Needed,
    InProgress,
    Have,
}

#[derive(Debug, Clone)]
pub struct Piece {
    pub state: PieceState,
    pub blocks: Vec<Option<Vec<u8>>>,
    pub downloaded_blocks: usize,
    pub expected_hash: [u8; 20],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockInfo {
    pub piece_index: usize,
    pub block_index: usize,
    pub length: u32,
}

impl Piece {
    /// Creates a new Piece in the "Needed" state.
    fn new(expected_hash: [u8; 20], size: u32) -> Self {
        let num_blocks = (size as f64 / BLOCK_SIZE as f64).ceil() as usize;
        Self {
            state: PieceState::Needed,
            blocks: vec![None; num_blocks],
            downloaded_blocks: 0,
            expected_hash,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.downloaded_blocks == self.blocks.len()
    }

    pub fn assemble(&self) -> Vec<u8> {
        assert!(self.is_complete(), "Cannot assemble an incomplete piece");
        self.blocks
            .iter()
            .filter_map(|b| b.as_ref())
            .flat_map(|data| data.iter().cloned())
            .collect()
    }

    pub fn verify(&self, data: &[u8]) -> bool {
        let mut hasher = Sha1::new();
        hasher.update(data);
        let hash_result: [u8; 20] = hasher.finalize().into();
        hash_result == self.expected_hash
    }
}


#[derive(Debug, Clone)]
pub struct Torrent {
    pub name: String,
    pub piece_length: u32,
    pub piece_hashes: Vec<[u8; 20]>,
    pub total_length: u64,
    pub info_hash: [u8; 20],
}

impl Torrent {
    pub fn new(info_dict: &BencodeValue, info_hash: [u8; 20]) -> Result<Self, &'static str> { // <-- UPDATED SIGNATURE
        let info_map = info_dict.as_dict().ok_or("Invalid info dictionary format")?;
        let piece_length = info_map.get(&b"piece length"[..]).and_then(|v| v.as_integer()).ok_or("Info dictionary missing 'piece length'")? as u32;
        let name = info_map.get(&b"name"[..]).and_then(|v| v.as_string()).ok_or("Info dictionary missing 'name'")?.to_string();
        let pieces_raw = info_map.get(&b"pieces"[..]).and_then(|v| v.as_bytes()).ok_or("Info dictionary missing 'pieces'")?;
        if pieces_raw.len() % 20 != 0 { return Err("Invalid 'pieces' length, must be a multiple of 20"); }
        let piece_hashes = pieces_raw.chunks_exact(20).map(|chunk| chunk.try_into().unwrap()).collect();
        let total_length: u64;
        if let Some(length_val) = info_map.get(&b"length"[..]) {
            total_length = length_val.as_integer().ok_or("Invalid 'length' in single-file torrent")? as u64;
        } else if let Some(files_val) = info_map.get(&b"files"[..]) {
            let files_list = files_val.as_list().ok_or("'files' key is not a list")?;
            let mut calculated_length = 0;
            for file_entry in files_list {
                let file_dict = file_entry.as_dict().ok_or("File entry in 'files' is not a dictionary")?;
                let file_length = file_dict.get(&b"length"[..]).and_then(|v| v.as_integer()).ok_or("File entry in 'files' is missing a 'length'")?;
                calculated_length += file_length as u64;
            }
            total_length = calculated_length;
        } else {
            return Err("Torrent info must contain either a 'length' or a 'files' key");
        }

        Ok(Self { info_hash, name, piece_length, piece_hashes, total_length }) // <-- STORE THE `info_hash`
    }
}


#[derive(Debug)]
pub struct PieceManager {
    pub pieces: Vec<Piece>,
}

impl PieceManager {
    pub fn new(torrent: &Torrent) -> Self {
        let pieces = torrent.piece_hashes.iter().enumerate().map(|(i, &hash)| {
            let is_last_piece = i == torrent.piece_hashes.len() - 1;
            let piece_size = if is_last_piece {
                let remainder = torrent.total_length % torrent.piece_length as u64;
                if remainder == 0 { torrent.piece_length } else { remainder as u32 }
            } else {
                torrent.piece_length
            };
            Piece::new(hash, piece_size)
        }).collect();

        Self { pieces }
    }

    pub fn add_block(&mut self, info: &BlockInfo, data: Vec<u8>) -> bool {
        let piece = &mut self.pieces[info.piece_index];
        
        if piece.blocks[info.block_index].is_none() {
            piece.blocks[info.block_index] = Some(data);
            piece.downloaded_blocks += 1;
        }

        piece.is_complete()
    }

    pub fn get_block_to_request(&mut self, peer_bitfield: &[u8]) -> Option<BlockInfo> {
        let total_pieces = self.pieces.len();

        for (piece_index, piece) in self.pieces.iter_mut().enumerate() {
            let peer_has_piece = {
                let byte_index = piece_index / 8;
                let bit_index = 7 - (piece_index % 8);
                byte_index < peer_bitfield.len() && (peer_bitfield[byte_index] >> bit_index) & 1 != 0
            };

            if piece.state == PieceState::Needed && peer_has_piece {
                if let Some(block_index) = piece.blocks.iter().position(|b| b.is_none()) {
                    piece.state = PieceState::InProgress;
                    
                    let is_last_piece = piece_index == total_pieces - 1;
                    let last_block_index = piece.blocks.len() - 1;
                    
                    let block_length = if is_last_piece && block_index == last_block_index {
                        let piece_size = piece.blocks.len() as u32 * BLOCK_SIZE;
                        let remainder = piece_size % BLOCK_SIZE;
                        if remainder == 0 { BLOCK_SIZE } else { remainder }
                    } else {
                        BLOCK_SIZE
                    };

                    return Some(BlockInfo {
                        piece_index,
                        block_index,
                        length: block_length,
                    });
                }
            }
        }
        
        None
    }
}