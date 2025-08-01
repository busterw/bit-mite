// src/torrent.rs

use crate::bencode::BencodeValue;
use sha1::{Digest, Sha1};
use std::fs::{self, File};
use std::path::PathBuf;
use std::io::{Seek, SeekFrom, Write}; 
use std::sync::Arc; 

// Standard block size is 2^14 bytes, or 16KiB.
pub const BLOCK_SIZE: u32 = 16384;

#[derive(Debug, Clone)]
pub struct Torrent {
    pub info_hash: [u8; 20], // <-- Field is correctly present
    pub name: String,
    pub piece_length: u32,
    pub piece_hashes: Vec<[u8; 20]>,
    pub total_length: u64,
    pub files: Vec<FileInfo>,
}

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

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: PathBuf,
    pub length: u64,
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
        
        let mut full_piece_data = Vec::with_capacity(self.blocks.len() * BLOCK_SIZE as usize);
        for block_option in &self.blocks {
            let block_data = block_option.as_ref().unwrap();
            full_piece_data.extend_from_slice(block_data);
        }
        full_piece_data
    }

    pub fn verify(&self, data: &[u8]) -> bool {
        let mut hasher = Sha1::new();
        hasher.update(data);
        let hash_result: [u8; 20] = hasher.finalize().into();
        hash_result == self.expected_hash
    }
}

impl Torrent {
    /// Creates a new `Torrent` from a bencoded `info` dictionary and its pre-computed info_hash.
    pub fn new(info_dict: &BencodeValue, info_hash: [u8; 20]) -> Result<Self, &'static str> { // <-- Signature is now correct
        let info_map = info_dict.as_dict().ok_or("Invalid info dictionary format")?;

        let piece_length = info_map.get(&b"piece length"[..]).and_then(|v| v.as_integer()).ok_or("Info dictionary missing 'piece length'")? as u32;
        let name = info_map.get(&b"name"[..]).and_then(|v| v.as_string()).ok_or("Info dictionary missing 'name'")?.to_string();
        let pieces_raw = info_map.get(&b"pieces"[..]).and_then(|v| v.as_bytes()).ok_or("Info dictionary missing 'pieces'")?;
        if pieces_raw.len() % 20 != 0 { return Err("Invalid 'pieces' length"); }
        let piece_hashes = pieces_raw.chunks_exact(20).map(|chunk| chunk.try_into().unwrap()).collect();

        let mut files = Vec::new();
        let mut total_length: u64 = 0;

        if let Some(length_val) = info_map.get(&b"length"[..]) {
            // Single-file torrent
            let length = length_val.as_integer().ok_or("Invalid 'length' in single-file torrent")? as u64;
            files.push(FileInfo { path: PathBuf::from(&name), length });
            total_length = length;
        } else if let Some(files_val) = info_map.get(&b"files"[..]) {
            // Multi-file torrent
            let files_list = files_val.as_list().ok_or("'files' key is not a list")?;
            for file_entry in files_list {
                let file_dict = file_entry.as_dict().ok_or("File entry is not a dictionary")?;
                let file_length = file_dict.get(&b"length"[..]).and_then(|v| v.as_integer()).ok_or("File entry missing 'length'")? as u64;
                let path_list = file_dict.get(&b"path"[..]).and_then(|v| v.as_list()).ok_or("File entry missing 'path'")?;
                let path_components = path_list.iter().map(|v| v.as_string().ok_or("Invalid path component")).collect::<Result<Vec<_>, _>>()?;
                files.push(FileInfo { path: path_components.iter().collect(), length: file_length });
                total_length += file_length;
            }
        } else {
            return Err("Torrent info must contain either 'length' or 'files' key");
        }

        Ok(Self { info_hash, name, piece_length, piece_hashes, total_length, files }) // <-- info_hash correctly included
    }
}


#[derive(Debug)]
pub struct PieceManager {
    pub pieces: Vec<Piece>,
}

impl PieceManager {
    /// Creates a new PieceManager from the torrent's metadata.
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

    /// Finds a needed block that a peer has and returns its info.
    /// This function implements a sequential download strategy.
    pub fn get_block_to_request(&mut self, torrent: &Torrent, peer_bitfield: &[u8]) -> Option<BlockInfo> {
        // Iterate through each piece to see if we need it and the peer has it.
        for (piece_index, piece) in self.pieces.iter_mut().enumerate() {
            let peer_has_piece = {
                let byte_index = piece_index / 8;
                let bit_index = 7 - (piece_index % 8);
                byte_index < peer_bitfield.len() && (peer_bitfield[byte_index] >> bit_index) & 1 != 0
            };

            // --- THIS IS THE CORRECTED LOGIC ---
            // We can request blocks for a piece if it's "Needed" (we haven't started it yet)
            // OR if it's "InProgress" (we've started it, but haven't finished).
            if (piece.state == PieceState::Needed || piece.state == PieceState::InProgress) && peer_has_piece {
                
                // If we're starting a new piece, mark it as InProgress.
                if piece.state == PieceState::Needed {
                    piece.state = PieceState::InProgress;
                }

                // Now, find the first block within this piece that we don't have.
                if let Some(block_index) = piece.blocks.iter().position(|b| b.is_none()) {
                    
                    let is_last_piece = piece_index == torrent.piece_hashes.len() - 1;
                    let piece_size = if is_last_piece {
                        let remainder = torrent.total_length % torrent.piece_length as u64;
                        if remainder == 0 { torrent.piece_length } else { remainder as u32 }
                    } else {
                        torrent.piece_length
                    };
                    
                    let is_last_block = block_index == piece.blocks.len() - 1;
                    let block_length = if is_last_block {
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

    pub fn add_block(&mut self, info: &BlockInfo, data: Vec<u8>) -> bool {
        let piece = &mut self.pieces[info.piece_index];
        if piece.blocks[info.block_index].is_none() {
            println!("  > [STORAGE] Storing Piece #{} Block #{}", info.piece_index, info.block_index);
            piece.blocks[info.block_index] = Some(data);
            piece.downloaded_blocks += 1;
        }
        piece.is_complete()
    }
    pub fn write_piece_to_disk(
        &self,
        piece_index: usize,
        piece_data: &[u8],
        torrent: &Torrent,
        file_handles: &mut [File],
    ) -> std::io::Result<()> {
        let is_all_nulls = piece_data.iter().all(|&byte| byte == 0);
        if is_all_nulls {
            eprintln!("  > WARNING: Attempting to write a piece (#{}) that is all null bytes. Data length: {}", piece_index, piece_data.len());
        }
        println!("  > [WRITE] Writing Piece #{} to disk. Total len={}. Data starts with: {:?}",
        piece_index, piece_data.len(), &piece_data.get(..8).unwrap_or_default());
        let piece_length = torrent.piece_length as u64;
        let piece_start_offset_in_torrent = piece_index as u64 * piece_length;

        let mut file_start_offset_in_torrent: u64 = 0;

        for (file_index, file_info) in torrent.files.iter().enumerate() {
            let file_end_offset_in_torrent = file_start_offset_in_torrent + file_info.length;
            
            // Check if this file overlaps with the piece's data range
            if file_end_offset_in_torrent > piece_start_offset_in_torrent && file_start_offset_in_torrent < piece_start_offset_in_torrent + piece_data.len() as u64 {
                let overlap_start = piece_start_offset_in_torrent.max(file_start_offset_in_torrent);
                let overlap_end = (piece_start_offset_in_torrent + piece_data.len() as u64).min(file_end_offset_in_torrent);

                let offset_in_file = overlap_start - file_start_offset_in_torrent;
                let start_in_piece_data = (overlap_start - piece_start_offset_in_torrent) as usize;
                let end_in_piece_data = (overlap_end - piece_start_offset_in_torrent) as usize;
                
                let data_to_write = &piece_data[start_in_piece_data..end_in_piece_data];
                
                let mut file = &mut file_handles[file_index];
                file.seek(SeekFrom::Start(offset_in_file))?;
                file.write_all(data_to_write)?;
            }

            file_start_offset_in_torrent += file_info.length;
        }
        
        Ok(())
    }
    pub fn is_complete(&self) -> bool {
        self.pieces.iter().all(|p| p.state == PieceState::Have)
    }

    pub fn write_to_disk(&self, torrent: &Torrent) -> std::io::Result<()> {
        let download_dir = PathBuf::from("./downloads").join(&torrent.name);
        println!("   Writing to directory: {}", download_dir.display());

        let mut current_offset_in_torrent: u64 = 0;
        for file_info in &torrent.files {
            let file_path = download_dir.join(&file_info.path);
            if let Some(parent) = file_path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }
            let mut file = File::create(&file_path)?;

            let mut bytes_written_to_file: u64 = 0;
            while bytes_written_to_file < file_info.length {
                let piece_index = (current_offset_in_torrent / torrent.piece_length as u64) as usize;
                let offset_in_piece = current_offset_in_torrent % torrent.piece_length as u64;

                let piece = &self.pieces[piece_index];
                if piece.state != PieceState::Have {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Trying to write an incomplete piece: {}", piece_index)));
                }
                let piece_data = piece.assemble();

                let bytes_to_write_from_piece = (file_info.length - bytes_written_to_file).min(torrent.piece_length as u64 - offset_in_piece);
                
                let data_slice = &piece_data[offset_in_piece as usize .. (offset_in_piece + bytes_to_write_from_piece) as usize];
                file.write_all(data_slice)?;
                
                bytes_written_to_file += bytes_to_write_from_piece;
                current_offset_in_torrent += bytes_to_write_from_piece;
            }
        }
        Ok(())
    }

    pub fn count_have_pieces(&self) -> usize {
        self.pieces.iter().filter(|p| p.state == PieceState::Have).count()
    }

    
    pub fn reset_piece(&mut self, piece_index: usize) {
        let piece = &mut self.pieces[piece_index];
        piece.state = PieceState::Needed;
        piece.downloaded_blocks = 0;
        for block in piece.blocks.iter_mut() {
            *block = None;
        }
    }
}