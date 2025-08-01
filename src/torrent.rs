use crate::bencode::BencodeValue;

#[derive(Debug, Clone)]
pub struct Torrent {
    pub name: String,
    pub piece_length: u32,
    pub piece_hashes: Vec<[u8; 20]>,
    pub total_length: u64,
}

impl Torrent {
    pub fn new(info_dict: &BencodeValue) -> Result<Self, &'static str> {
        let info_map = info_dict
            .as_dict()
            .ok_or("Invalid info dictionary format")?;

        let piece_length = info_map
            .get(&b"piece length"[..])
            .and_then(|v| v.as_integer())
            .ok_or("Info dictionary missing 'piece length'")? as u32;

        let name = info_map
            .get(&b"name"[..])
            .and_then(|v| v.as_string())
            .ok_or("Info dictionary missing 'name'")?
            .to_string();

        let pieces_raw = info_map
            .get(&b"pieces"[..])
            .and_then(|v| v.as_bytes())
            .ok_or("Info dictionary missing 'pieces'")?;

        if pieces_raw.len() % 20 != 0 {
            return Err("Invalid 'pieces' length, must be a multiple of 20");
        }
        let piece_hashes = pieces_raw
            .chunks_exact(20)
            .map(|chunk| chunk.try_into().unwrap())
            .collect();

        let total_length: u64;

        if let Some(length_val) = info_map.get(&b"length"[..]) {
            // This is a SINGLE-FILE torrent.
            total_length = length_val
                .as_integer()
                .ok_or("Invalid 'length' in single-file torrent")?
                as u64;
        } else if let Some(files_val) = info_map.get(&b"files"[..]) {
            // This is a MULTI-FILE torrent.
            let files_list = files_val.as_list().ok_or("'files' key is not a list")?;

            let mut calculated_length = 0;
            for file_entry in files_list {
                let file_dict = file_entry
                    .as_dict()
                    .ok_or("File entry in 'files' is not a dictionary")?;
                let file_length = file_dict
                    .get(&b"length"[..])
                    .and_then(|v| v.as_integer())
                    .ok_or("File entry in 'files' is missing a 'length'")?;
                calculated_length += file_length as u64;
            }
            total_length = calculated_length;
        } else {
            return Err("Torrent info must contain either a 'length' or a 'files' key");
        }

        Ok(Self {
            name,
            piece_length,
            piece_hashes,
            total_length,
        })
    }
}
