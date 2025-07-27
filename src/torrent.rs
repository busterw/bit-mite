use percent_encoding::{NON_ALPHANUMERIC, percent_encode};

use super::bencode::{BencodeError, BencodeValue};

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;
use std::path::PathBuf;

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
    pub name: String, // name of file (single) or directory (multi)
    pub piece_length: i64,
    pub pieces: Vec<Vec<u8>>,
    pub mode: InfoMode,
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub ip: Ipv4Addr,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct AnnounceResponse {
    pub peers: Vec<Peer>,
    pub interval: i64, // The number of seconds the client should wait before re-announcing.
}

#[derive(Debug)]
pub struct DownloadState<'a> {
    pub info: &'a Info,
    pub pieces_to_download: Vec<usize>,
    pub current_piece_index: usize,
    pub current_piece_data: Vec<u8>,
    pub blocks_received: usize,
}

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: std::path::PathBuf, // Using PathBuf for proper path handling
    pub length: i64,
}

#[derive(Debug, Clone)]
pub enum InfoMode {
    SingleFile { length: i64 },
    MultiFile { files: Vec<FileInfo> },
}

#[derive(Debug)]
pub struct FileMapper {
    file_offsets: Vec<(u64, FileInfo)>,
}

#[derive(Debug, PartialEq)]
pub struct MagnetLink {
    pub name: Option<String>,
    pub info_hash: [u8; 20],
    pub trackers: Vec<String>,
}

impl Peer {
    pub fn new(ip: Ipv4Addr, port: u16) -> Self {
        Self { ip, port }
    }

    pub fn socket_address(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.ip, self.port)
    }
}

impl Torrent {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, TorrentParseError> {
        let bytes = fs::read(path)?;

        let (value, info_slice) = decode_and_extract_info(&bytes)?;

        if let BencodeValue::Dictionary(mut root_dict) = value {
            let announce = get_string(&mut root_dict, b"announce")?;

            let info = if let BencodeValue::Dictionary(mut info_dict) =
                super::bencode::decode(&info_slice)?.0
            {
                let name = get_string(&mut info_dict, b"name")?;
                let piece_length = get_integer(&mut info_dict, b"piece length")?;
                let pieces_bytes = get_bytes(&mut info_dict, b"pieces")?;
                let pieces = pieces_bytes.chunks(20).map(|c| c.to_vec()).collect();

                let mode = if let Some(BencodeValue::List(files_list)) =
                    info_dict.remove(&b"files".to_vec())
                {
                    let mut files = Vec::new();
                    for file_val in files_list {
                        if let BencodeValue::Dictionary(mut file_dict) = file_val {
                            let length = get_integer(&mut file_dict, b"length")?;
                            // The path is a list of byte-strings
                            let path_list = match file_dict.remove(&b"path".to_vec()) {
                                Some(BencodeValue::List(p)) => p,
                                _ => {
                                    return Err(TorrentParseError::InvalidType(
                                        "file path".to_string(),
                                    ));
                                }
                            };
                            let mut path = std::path::PathBuf::new();
                            for part_val in path_list {
                                if let BencodeValue::Bytes(part_bytes) = part_val {
                                    path.push(String::from_utf8(part_bytes).unwrap());
                                }
                            }
                            files.push(FileInfo { path, length });
                        }
                    }
                    InfoMode::MultiFile { files }
                } else {
                    // SINGLE-FILE MODE
                    let length = get_integer(&mut info_dict, b"length")?;
                    InfoMode::SingleFile { length }
                };

                Info {
                    name,
                    piece_length,
                    pieces,
                    mode,
                }
            } else {
                return Err(TorrentParseError::InvalidInfo);
            };

            let info_hash = sha1_smol::Sha1::from(info_slice).digest().bytes();

            Ok(Torrent {
                announce,
                info_hash,
                info,
            })
        } else {
            Err(TorrentParseError::InvalidRoot)
        }
    }

    pub fn discover_peers(
        &self,
        our_peer_id: &[u8; 20],
    ) -> Result<AnnounceResponse, Box<dyn std::error::Error>> {
        // Pass the peer_id down to the URL builder
        let tracker_url = self.build_tracker_url(our_peer_id)?;
        println!("Announcing to tracker: {}", tracker_url);

        let client = reqwest::blocking::Client::new();
        let response = client.get(tracker_url).send()?;

        if !response.status().is_success() {
            return Err(
                format!("Tracker request failed with status: {}", response.status()).into(),
            );
        }

        let response_bytes = response.bytes()?;

        match super::bencode::decode(&response_bytes) {
            Ok((bencode_response, _)) => {
                if let BencodeValue::Dictionary(mut dict) = bencode_response {
                    if let Some(BencodeValue::Bytes(reason)) = dict.get(&b"failure reason".to_vec())
                    {
                        let reason_str = String::from_utf8_lossy(reason);
                        return Err(format!("Tracker returned failure: {}", reason_str).into());
                    }

                    let interval = match dict.get(&b"interval".to_vec()) {
                        Some(BencodeValue::Integer(i)) => *i,
                        _ => 1800, // Default to 30 minutes if not present
                    };

                    let peers = if let Some(BencodeValue::Bytes(peers_bytes)) =
                        dict.remove(&b"peers".to_vec())
                    {
                        Self::parse_compact_peers(&peers_bytes)?
                    } else {
                        Vec::new()
                    };

                    Ok(AnnounceResponse { peers, interval })
                } else {
                    Err("Tracker response was not a valid dictionary.".into())
                }
            }
            Err(e) => {
                let raw_response = String::from_utf8_lossy(&response_bytes);
                eprintln!(
                    "Failed to parse tracker response. Raw response:\n---\n{}\n---",
                    raw_response
                );
                Err(format!("Failed to parse tracker response: {:?}", e).into())
            }
        }
    }

    fn build_tracker_url(
        &self,
        our_peer_id: &[u8; 20],
    ) -> Result<String, Box<dyn std::error::Error>> {
        let base_url = &self.announce;
        let port: u16 = 6881;
        let uploaded: i64 = 0;
        let downloaded: i64 = 0;
        let left = self.info.piece_length * self.info.pieces.len() as i64;

        let encoded_info_hash = percent_encode(&self.info_hash, NON_ALPHANUMERIC).to_string();
        let encoded_peer_id = percent_encode(our_peer_id, NON_ALPHANUMERIC).to_string();

        let tracker_url = format!(
            "{}?info_hash={}&peer_id={}&port={}&uploaded={}&downloaded={}&left={}&compact=1&event=started",
            base_url, encoded_info_hash, encoded_peer_id, port, uploaded, downloaded, left
        );

        Ok(tracker_url)
    }

    /// Private helper to parse the compact 6-byte peer format.
    fn parse_compact_peers(bytes: &[u8]) -> Result<Vec<Peer>, Box<dyn std::error::Error>> {
        if bytes.len() % 6 != 0 {
            return Err("Compact peer list has invalid length.".into());
        }

        let peers = bytes
            .chunks_exact(6)
            .map(|chunk| {
                // First 4 bytes are IP
                let ip = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
                // Next 2 bytes are the port
                let port = u16::from_be_bytes([chunk[4], chunk[5]]);
                Peer::new(ip, port)
            })
            .collect();

        Ok(peers)
    }
}

impl<'a> DownloadState<'a> {
    pub fn new(info: &'a Info) -> Self {
        let pieces_to_download: Vec<usize> = (0..info.pieces.len()).collect();
        Self {
            info,
            current_piece_index: *pieces_to_download.first().unwrap_or(&0),
            pieces_to_download,
            current_piece_data: vec![0; info.piece_length as usize],
            blocks_received: 0,
        }
    }

    pub fn get_info(&self) -> &'a Info {
        self.info
    }

    /// Verifies the SHA-1 hash of the currently assembled piece.
    pub fn verify_and_save_current_piece(
        &mut self,
        file_handles: &mut HashMap<PathBuf, File>,
        mapper: &FileMapper,
    ) -> Result<bool, std::io::Error> {
        let piece_slice = &self.current_piece_data[..];
        let expected_hash = &self.info.pieces[self.current_piece_index];
        let actual_hash = sha1_smol::Sha1::from(piece_slice).digest().bytes();

        if actual_hash != expected_hash.as_slice() {
            eprintln!(
                "ERROR: Piece #{} failed hash check.",
                self.current_piece_index
            );
            return Ok(false);
        }

        println!(
            "SUCCESS: Piece #{} passed hash check.",
            self.current_piece_index
        );
        let piece_offset = self.current_piece_index as u64 * self.info.piece_length as u64;

        match &self.info.mode {
            InfoMode::SingleFile { .. } => {
                let file_path = PathBuf::from(&self.info.name);
                let file = file_handles.get_mut(&file_path).unwrap();
                file.seek(SeekFrom::Start(piece_offset))?;
                file.write_all(piece_slice)?;
            }
            InfoMode::MultiFile { .. } => {
                let mut bytes_written = 0;
                for (file_start_offset, file_info) in &mapper.file_offsets {
                    // Check if this piece overlaps with this file at all
                    let file_end_offset = file_start_offset + file_info.length as u64;
                    if piece_offset >= file_end_offset
                        || piece_offset + piece_slice.len() as u64 <= *file_start_offset
                    {
                        continue; // No overlap
                    }

                    let write_start = std::cmp::max(piece_offset, *file_start_offset);
                    let write_end =
                        std::cmp::min(piece_offset + piece_slice.len() as u64, file_end_offset);
                    let data_start = (write_start - piece_offset) as usize;
                    let data_end = (write_end - piece_offset) as usize;
                    let data_to_write = &piece_slice[data_start..data_end];

                    let file_offset = write_start - file_start_offset;
                    let file = file_handles.get_mut(&file_info.path).unwrap();
                    file.seek(SeekFrom::Start(file_offset))?;
                    file.write_all(data_to_write)?;

                    bytes_written += data_to_write.len();
                }
                println!(
                    "Piece #{} written to disk ({} bytes across files).",
                    self.current_piece_index, bytes_written
                );
            }
        }
        Ok(true)
    }

    pub fn prepare_for_next_piece(&mut self) {
        self.pieces_to_download
            .retain(|&p| p != self.current_piece_index);

        self.current_piece_data = vec![0; self.info.piece_length as usize];
        self.blocks_received = 0;

        if let Some(&next_piece) = self.pieces_to_download.first() {
            self.current_piece_index = next_piece;
        }
    }
}

impl FileMapper {
    pub fn new(info: &Info) -> Self {
        let mut file_offsets = Vec::new();
        let mut current_offset = 0;

        if let InfoMode::MultiFile { files } = &info.mode {
            for file_info in files {
                file_offsets.push((current_offset, file_info.clone()));
                current_offset += file_info.length as u64;
            }
        }
        Self { file_offsets }
    }
}

impl MagnetLink {
    /// Parses a magnet URI string into a MagnetLink struct.
    pub fn from_uri(uri: &str) -> Result<Self, &'static str> {
        let url = match url::Url::parse(uri) {
            Ok(u) => u,
            Err(_) => return Err("Failed to parse magnet URI"),
        };

        if url.scheme() != "magnet" {
            return Err("URI is not a magnet link");
        }

        let mut info_hash = [0u8; 20];
        let mut name = None;
        let mut trackers = Vec::new();

        let xt_param = url.query_pairs().find(|(key, _)| key == "xt");

        if let Some((_, xt_val)) = xt_param {
            if let Some(hash_str) = xt_val.strip_prefix("urn:btih:") {
                if hash_str.len() == 40 {
                    if hex::decode_to_slice(hash_str, &mut info_hash).is_err() {
                        return Err("Info hash contains invalid hex characters");
                    }
                } else {
                    return Err("Info hash is not 40 characters long");
                }
            } else {
                return Err("Invalid or missing URN in xt parameter");
            }
        } else {
            return Err("Missing info_hash (xt) in magnet link");
        }

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "dn" => name = Some(value.to_string()),   // Display Name
                "tr" => trackers.push(value.to_string()), // Tracker
                _ => {}                                   // Ignore other params for now
            }
        }

        Ok(Self {
            name,
            info_hash,
            trackers,
        })
    }
}

fn get_string(
    dict: &mut BTreeMap<Vec<u8>, BencodeValue>,
    key: &[u8],
) -> Result<String, TorrentParseError> {
    let bytes = get_bytes(dict, key)?;
    String::from_utf8(bytes)
        .map_err(|_| TorrentParseError::InvalidType(String::from_utf8_lossy(key).to_string()))
}

fn get_integer(
    dict: &mut BTreeMap<Vec<u8>, BencodeValue>,
    key: &[u8],
) -> Result<i64, TorrentParseError> {
    match dict.remove(key) {
        Some(BencodeValue::Integer(i)) => Ok(i),
        Some(_) => Err(TorrentParseError::InvalidType(
            String::from_utf8_lossy(key).to_string(),
        )),
        None => Err(TorrentParseError::MissingKey(
            String::from_utf8_lossy(key).to_string(),
        )),
    }
}

fn get_bytes(
    dict: &mut BTreeMap<Vec<u8>, BencodeValue>,
    key: &[u8],
) -> Result<Vec<u8>, TorrentParseError> {
    match dict.remove(key) {
        Some(BencodeValue::Bytes(b)) => Ok(b),
        Some(_) => Err(TorrentParseError::InvalidType(
            String::from_utf8_lossy(key).to_string(),
        )),
        None => Err(TorrentParseError::MissingKey(
            String::from_utf8_lossy(key).to_string(),
        )),
    }
}

fn decode_and_extract_info(
    encoded_value: &[u8],
) -> Result<(BencodeValue, &[u8]), TorrentParseError> {
    if encoded_value.is_empty() || encoded_value[0] != b'd' {
        return Err(TorrentParseError::InvalidRoot);
    }

    // This is a slightly lazy way to do this, but it works for most files, we want to walk the bencode structure at some point
    let info_key = b"4:info";
    let mut info_slice_start = 0;

    for i in 1..encoded_value.len().saturating_sub(info_key.len()) {
        if &encoded_value[i..i + info_key.len()] == info_key {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::path::Path;

    #[test]
    fn test_parse_sample_torrent_file() {
        // Arrange: Define what we expect to find in the file.

        let expected_announce = "udp://tracker.openbittorrent.com:80";
        let expected_info_name = "sample.txt";
        let expected_piece_length = 65536;
        let expected_num_pieces = 1;
        // converte hash from hex to bytes for comparison
        let expected_hash_hex = "d0d14c926e6e99761a2fdcff27b403d96376eff6";
        let expected_hash_bytes: [u8; 20] = hex::decode(expected_hash_hex)
            .expect("Failed to decode hex string")
            .try_into()
            .expect("Info hash was not 20 bytes");

        // Act: Parse the file

        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let file_path = Path::new(manifest_dir)
            .join("tests")
            .join("data")
            .join("sample.torrent");

        let torrent = Torrent::from_file(&file_path)
            .expect(&format!("Failed to parse torrent file at {:?}", file_path));

        // Assert: Check if the parsed data matches

        assert_eq!(torrent.announce, expected_announce);
        assert_eq!(torrent.info.name, expected_info_name);
        assert_eq!(torrent.info.piece_length, expected_piece_length);
        assert_eq!(torrent.info.pieces.len(), expected_num_pieces);
        assert_eq!(torrent.info_hash, expected_hash_bytes);
    }
    #[test]
    fn test_parse_full_magnet_link() {
        let uri = "magnet:?xt=urn:btih:d0d14c926e6e99761a2fdcff27b403d96376eff6&dn=sample.txt&tr=udp://tracker.openbittorrent.com:80";
        let magnet = MagnetLink::from_uri(uri).unwrap();

        let expected_hash: [u8; 20] = hex::decode("d0d14c926e6e99761a2fdcff27b403d96376eff6")
            .unwrap()
            .try_into()
            .unwrap();

        assert_eq!(magnet.info_hash, expected_hash);
        assert_eq!(magnet.name, Some("sample.txt".to_string()));
        assert_eq!(
            magnet.trackers,
            vec!["udp://tracker.openbittorrent.com:80".to_string()]
        );
    }

    // Test a link with multiple trackers.
    #[test]
    fn test_parse_multiple_trackers() {
        let uri = "magnet:?xt=urn:btih:d0d14c926e6e99761a2fdcff27b403d96376eff6&tr=udp://tracker.one:80&tr=udp://tracker.two:80";
        let magnet = MagnetLink::from_uri(uri).unwrap();

        assert_eq!(magnet.trackers.len(), 2);
        assert_eq!(magnet.trackers[0], "udp://tracker.one:80");
        assert_eq!(magnet.trackers[1], "udp://tracker.two:80");
    }

    // Test a minimal magnet link with only the required info_hash.
    #[test]
    fn test_parse_minimal_magnet_link() {
        let uri = "magnet:?xt=urn:btih:d0d14c926e6e99761a2fdcff27b403d96376eff6";
        let magnet = MagnetLink::from_uri(uri).unwrap();

        let expected_hash: [u8; 20] = hex::decode("d0d14c926e6e99761a2fdcff27b403d96376eff6")
            .unwrap()
            .try_into()
            .unwrap();

        assert_eq!(magnet.info_hash, expected_hash);
        assert!(magnet.name.is_none());
        assert!(magnet.trackers.is_empty());
    }

    // Test failure cases.
    #[test]
    fn test_parse_invalid_links() {
        // Not a magnet link
        assert!(MagnetLink::from_uri("http://example.com").is_err());
        // Missing xt parameter
        assert!(MagnetLink::from_uri("magnet:?dn=sample.txt").is_err());
        // Malformed hash (too short)
        assert!(MagnetLink::from_uri("magnet:?xt=urn:btih:12345").is_err());
        // Malformed hash (not hex)
        assert!(
            MagnetLink::from_uri("magnet:?xt=urn:btih:gggggggggggggggggggggggggggggggggggggggg")
                .is_err()
        );
    }
}
