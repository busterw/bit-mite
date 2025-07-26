use super::bencode::{BencodeValue, BencodeError};

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub enum TorrentParseError {
    Bencode(BencodeError),
    Io(std::io::Error),
    InvalidRoot,
    InvalidInfo,
    MissingKey(String),
    InvalidType(String),
}

impl From<BencodeError> for TorrentParseError {
    fn from(e: BencodeError) -> Self {
        TorrentParseError::Bencode(e)
    }
}

impl From<std::io::Error> for TorrentParseError {
    fn from(e: std::io::Error) -> Self {
        TorrentParseError::Io(e)
    }
}


#[derive(Debug, Clone)]
pub struct Torrent {
    pub announce: String,
    pub info_hash: [u8; 20],
    pub info: Info,
}

#[derive(Debug, Clone)]
pub struct Info {
    pub name: String,
    pub piece_length: i64,
    pub pieces: Vec<Vec<u8>>,
}

impl Torrent {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, TorrentParseError> {
        let bytes = fs::read(path)?;
        
        let (value, info_slice) = decode_and_extract_info(&bytes)?;

        if let BencodeValue::Dictionary(mut root_dict) = value {
            let announce = get_string(&mut root_dict, b"announce")?;
            
            let info = if let BencodeValue::Dictionary(mut info_dict) = super::bencode::decode(&info_slice)?.0 {
                let name = get_string(&mut info_dict, b"name")?;
                let piece_length = get_integer(&mut info_dict, b"piece length")?;
                let pieces_bytes = get_bytes(&mut info_dict, b"pieces")?;

                if pieces_bytes.len() % 20 != 0 {
                    return Err(TorrentParseError::InvalidType("pieces length not divisible by 20".to_string()));
                }
                let pieces = pieces_bytes.chunks(20).map(|chunk| chunk.to_vec()).collect();

                Info { name, piece_length, pieces }
            } else {
                return Err(TorrentParseError::InvalidInfo);
            };

            let info_hash = sha1_smol::Sha1::from(info_slice).digest().bytes();

            Ok(Torrent { announce, info_hash, info })
        } else {
            Err(TorrentParseError::InvalidRoot)
        }
    }
}


fn get_string(dict: &mut BTreeMap<Vec<u8>, BencodeValue>, key: &[u8]) -> Result<String, TorrentParseError> {
    let bytes = get_bytes(dict, key)?;
    String::from_utf8(bytes).map_err(|_| TorrentParseError::InvalidType(String::from_utf8_lossy(key).to_string()))
}

fn get_integer(dict: &mut BTreeMap<Vec<u8>, BencodeValue>, key: &[u8]) -> Result<i64, TorrentParseError> {
    match dict.remove(key) {
        Some(BencodeValue::Integer(i)) => Ok(i),
        Some(_) => Err(TorrentParseError::InvalidType(String::from_utf8_lossy(key).to_string())),
        None => Err(TorrentParseError::MissingKey(String::from_utf8_lossy(key).to_string())),
    }
}

fn get_bytes(dict: &mut BTreeMap<Vec<u8>, BencodeValue>, key: &[u8]) -> Result<Vec<u8>, TorrentParseError> {
    match dict.remove(key) {
        Some(BencodeValue::Bytes(b)) => Ok(b),
        Some(_) => Err(TorrentParseError::InvalidType(String::from_utf8_lossy(key).to_string())),
        None => Err(TorrentParseError::MissingKey(String::from_utf8_lossy(key).to_string())),
    }
}

fn decode_and_extract_info(encoded_value: &[u8]) -> Result<(BencodeValue, &[u8]), TorrentParseError> {
    if encoded_value.is_empty() || encoded_value[0] != b'd' {
        return Err(TorrentParseError::InvalidRoot);
    }
    
    // This is a slightly lazy way to do this, but it works for many files, we want to walk the bencode structure at some point
    let info_key = b"4:info";
    let mut info_slice_start = 0;

    for i in 1..encoded_value.len().saturating_sub(info_key.len()) {
        if &encoded_value[i..i+info_key.len()] == info_key {
            info_slice_start = i + info_key.len();
            break;
        }
    }

    if info_slice_start == 0 {
        return Err(TorrentParseError::MissingKey("info".to_string()));
    }

    let (value, _) = super::bencode::decode(encoded_value)?;
    
    let (_, info_remainder) = super::bencode::decode(&encoded_value[info_slice_start..])?;
    let info_slice_end = encoded_value.len() - info_remainder.len();
    
    Ok((value, &encoded_value[info_slice_start..info_slice_end]))
}
