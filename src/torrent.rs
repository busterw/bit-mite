use crate::bencode::BencodeValue;
use sha1::{Digest, Sha1};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
pub const BLOCK_SIZE: u32 = 16384;
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
#[derive(Debug, Clone)]
pub struct Torrent {
    pub info_hash: [u8; 20],
    pub name: String,
    pub piece_length: u32,
    pub piece_hashes: Vec<[u8; 20]>,
    pub total_length: u64,
    pub files: Vec<FileInfo>,
}
#[derive(Debug, Clone)]
pub struct PieceRarity {
    pub counts: Vec<u32>,
}
#[derive(Debug)]
pub struct PieceManager {
    pub pieces: Vec<Piece>,
    pub pending_requests: Vec<BlockInfo>,
}

impl Piece {
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
        assert!(self.is_complete());
        let mut data = Vec::with_capacity(self.blocks.len() * BLOCK_SIZE as usize);
        for b in &self.blocks {
            data.extend_from_slice(b.as_ref().unwrap());
        }
        data
    }
    pub fn verify(&self, data: &[u8]) -> bool {
        let mut hasher = Sha1::new();
        hasher.update(data);
        let hash: [u8; 20] = hasher.finalize().into();
        hash == self.expected_hash
    }
}

impl Torrent {
    pub fn new(info_dict: &BencodeValue, info_hash: [u8; 20]) -> Result<Self, &'static str> {
        let info_map = info_dict
            .as_dict()
            .ok_or("Invalid info dictionary format")?;
        let piece_length = info_map
            .get(&b"piece length"[..])
            .and_then(|v| v.as_integer())
            .ok_or("Missing 'piece length'")? as u32;
        let name = info_map
            .get(&b"name"[..])
            .and_then(|v| v.as_string())
            .ok_or("Missing 'name'")?
            .to_string();
        let pieces_raw = info_map
            .get(&b"pieces"[..])
            .and_then(|v| v.as_bytes())
            .ok_or("Missing 'pieces'")?;
        if pieces_raw.len() % 20 != 0 {
            return Err("Invalid 'pieces' length");
        }
        let piece_hashes = pieces_raw
            .chunks_exact(20)
            .map(|c| c.try_into().unwrap())
            .collect();

        let mut files = Vec::new();
        let total_length: u64;

        if let Some(len_val) = info_map.get(&b"length"[..]) {
            // This is a SINGLE-FILE torrent.
            let length = len_val
                .as_integer()
                .ok_or("Invalid 'length' in single-file torrent")? as u64;
            files.push(FileInfo {
                path: name.clone().into(),
                length,
            });
            total_length = length;
        } else if let Some(files_val) = info_map.get(&b"files"[..]) {
            // This is a MULTI-FILE torrent.
            let files_list = files_val.as_list().ok_or("'files' key is not a list")?;
            let mut calculated_length: u64 = 0;

            // --- THIS IS THE CORRECTED LOGIC ---
            for file_entry in files_list {
                let file_dict = file_entry
                    .as_dict()
                    .ok_or("File entry in 'files' is not a dictionary")?;

                let len = file_dict
                    .get(&b"length"[..])
                    .and_then(|v| v.as_integer())
                    .ok_or("File entry missing 'length'")? as u64;

                let path_list = file_dict
                    .get(&b"path"[..])
                    .and_then(|v| v.as_list())
                    .ok_or("File entry missing 'path'")?;

                let mut path_components = Vec::new();
                for component in path_list {
                    let path_str = component
                        .as_string()
                        .ok_or("Invalid path component in 'files' list")?;
                    path_components.push(path_str);
                }

                files.push(FileInfo {
                    path: path_components.iter().collect(),
                    length: len,
                });
                calculated_length += len;
            }
            total_length = calculated_length;
            // --- END CORRECTION ---
        } else {
            return Err("Missing 'length' or 'files'");
        };

        Ok(Self {
            info_hash,
            name,
            piece_length,
            piece_hashes,
            total_length,
            files,
        })
    }
}

impl PieceRarity {
    pub fn new(num_pieces: usize) -> Self {
        Self {
            counts: vec![0; num_pieces],
        }
    }
}

// src/torrent.rs

impl PieceManager {
    pub fn new(torrent: &Torrent) -> Self {
        let pieces = torrent
            .piece_hashes
            .iter()
            .enumerate()
            .map(|(i, &hash)| {
                let piece_size = if i == torrent.piece_hashes.len() - 1 {
                    let rem = torrent.total_length % torrent.piece_length as u64;
                    if rem == 0 {
                        torrent.piece_length
                    } else {
                        rem as u32
                    }
                } else {
                    torrent.piece_length
                };
                Piece::new(hash, piece_size)
            })
            .collect();
        Self {
            pieces,
            pending_requests: Vec::new(),
        }
    }

    pub fn count_have_pieces(&self) -> usize {
        self.pieces
            .iter()
            .filter(|p| p.state == PieceState::Have)
            .count()
    }

    pub fn is_complete(&self) -> bool {
        self.count_have_pieces() == self.pieces.len()
    }

    /// Resets a piece if its hash verification fails.
    pub fn reset_piece(&mut self, piece_index: usize) {
        let piece = &mut self.pieces[piece_index];
        piece.state = PieceState::Needed;
        piece.downloaded_blocks = 0;
        for block in piece.blocks.iter_mut() {
            *block = None;
        }
        // Also remove any pending requests for this failed piece so we can try them again.
        self.pending_requests
            .retain(|req| req.piece_index != piece_index);
    }

    pub fn get_pending_request_count(&self) -> usize {
        self.pending_requests.len()
    }

    pub fn add_pending_request(&mut self, block_info: &BlockInfo) {
        self.pending_requests.push(*block_info);
    }

    pub fn remove_pending_request(&mut self, block_info: &BlockInfo) {
        if let Some(pos) = self.pending_requests.iter().position(|b| {
            b.piece_index == block_info.piece_index && b.block_index == block_info.block_index
        }) {
            self.pending_requests.remove(pos);
        }
    }

    // --- THIS IS THE MISSING METHOD ---
    /// Puts a list of pending requests back into the "needed" state when a peer disconnects.
    pub fn reset_pending_requests(&mut self, pending_blocks: &[BlockInfo]) {
        for block_info in pending_blocks {
            self.remove_pending_request(block_info);
        }
    }
    // --- END OF MISSING METHOD ---

    pub fn get_block_to_request(
        &self,
        torrent: &Torrent,
        peer_bitfield: &[u8],
        rarity: &PieceRarity,
    ) -> Option<BlockInfo> {
        let mut candidates = self
            .pieces
            .iter()
            .enumerate()
            .filter(|(i, p)| {
                p.state != PieceState::Have
                    && peer_bitfield
                        .get(*i / 8)
                        .map_or(false, |&byte| (byte >> (7 - (*i % 8))) & 1 != 0)
            })
            .collect::<Vec<_>>();

        candidates.sort_by_key(|(i, _)| rarity.counts[*i]);

        for (piece_index, _) in candidates {
            let piece = &self.pieces[piece_index];
            if let Some(block_index) = piece.blocks.iter().position(|b| b.is_none()) {
                let block_info = BlockInfo {
                    piece_index,
                    block_index,
                    length: 0,
                };
                if !self.pending_requests.contains(&block_info) {
                    let piece_size = if piece_index == torrent.piece_hashes.len() - 1 {
                        let rem = torrent.total_length % torrent.piece_length as u64;
                        if rem == 0 {
                            torrent.piece_length
                        } else {
                            rem as u32
                        }
                    } else {
                        torrent.piece_length
                    };
                    let is_last_block = block_index == piece.blocks.len() - 1;
                    let block_length = if is_last_block {
                        let rem = piece_size % BLOCK_SIZE;
                        if rem == 0 { BLOCK_SIZE } else { rem }
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
        if info.block_index < piece.blocks.len() && piece.blocks[info.block_index].is_none() {
            piece.blocks[info.block_index] = Some(data);
            piece.downloaded_blocks += 1;
        }
        piece.is_complete()
    }
    pub fn write_to_disk(&self, torrent: &Torrent) -> std::io::Result<()> {
        use std::fs;
        use std::io::{Seek, SeekFrom, Write};
        use std::path::PathBuf;

        let download_dir = PathBuf::from("./downloads").join(&torrent.name);
        println!("   Writing to directory: {}", download_dir.display());

        let mut file_offset: u64 = 0;
        for file_info in &torrent.files {
            let file_path = download_dir.join(&file_info.path);
            if let Some(parent) = file_path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }
            let mut file = fs::File::create(&file_path)?;

            let mut bytes_written_to_file: u64 = 0;
            while bytes_written_to_file < file_info.length {
                let piece_index = (file_offset / torrent.piece_length as u64) as usize;
                let offset_in_piece = file_offset % torrent.piece_length as u64;

                // Ensure we have this piece before trying to write it
                if self.pieces[piece_index].state != PieceState::Have {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Attempted to write an incomplete or missing piece: #{}",
                            piece_index
                        ),
                    ));
                }

                let piece_data = self.pieces[piece_index].assemble();

                let bytes_to_write_from_piece = (file_info.length - bytes_written_to_file)
                    .min(torrent.piece_length as u64 - offset_in_piece);

                let data_slice = &piece_data[offset_in_piece as usize
                    ..(offset_in_piece + bytes_to_write_from_piece) as usize];

                file.write_all(data_slice)?;

                bytes_written_to_file += bytes_to_write_from_piece;
                file_offset += bytes_to_write_from_piece;
            }
        }
        Ok(())
    }
}
