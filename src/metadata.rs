
use crate::bencode::BencodeValue;
use sha1::{Digest, Sha1};

pub const METADATA_BLOCK_SIZE: usize = 16384; // 16 KiB

#[derive(Debug)]
pub struct MetadataDownloader {
    info_hash: [u8; 20],
    size: usize,
    pieces: Vec<Option<Vec<u8>>>,
}

impl MetadataDownloader {
    pub fn new(info_hash: [u8; 20], size: usize) -> Self {
        let num_pieces = size.div_ceil(METADATA_BLOCK_SIZE);
        Self {
            info_hash,
            size,
            pieces: vec![None; num_pieces],
        }
    }

    pub fn add_piece(&mut self, piece_index: usize, data: Vec<u8>) {
        if piece_index < self.pieces.len() {
            self.pieces[piece_index] = Some(data);
        }
    }

    pub fn num_pieces(&self) -> usize {
        self.pieces.len()
    }

    pub fn is_complete(&self) -> bool {
        self.pieces.iter().all(Option::is_some)
    }

    pub fn assemble_and_verify(&self) -> Option<BencodeValue> {
        if !self.is_complete() {
            return None;
        }

        let mut full_data: Vec<u8> = self
            .pieces
            .iter()
            .filter_map(|p| p.as_ref())
            .flat_map(|data| data.iter().cloned())
            .collect();

        full_data.truncate(self.size);

        let mut hasher = Sha1::new();
        hasher.update(&full_data);
        let hash_result: [u8; 20] = hasher.finalize().into();

        if hash_result == self.info_hash {
            crate::bencode::decode(&full_data).ok().map(|(val, _)| val)
        } else {
            eprintln!("Metadata hash mismatch!");
            None
        }
    }
}
