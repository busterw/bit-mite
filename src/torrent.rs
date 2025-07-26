use percent_encoding::{AsciiSet, CONTROLS, percent_encode};

use super::bencode::{BencodeError, BencodeValue};

use rand::Rng;
use std::collections::BTreeMap;
use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4};
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

                if pieces_bytes.len() % 20 != 0 {
                    return Err(TorrentParseError::InvalidType(
                        "pieces length not divisible by 20".to_string(),
                    ));
                }
                let pieces = pieces_bytes
                    .chunks(20)
                    .map(|chunk| chunk.to_vec())
                    .collect();

                Info {
                    name,
                    piece_length,
                    pieces,
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

    pub fn discover_peers(&self) -> Result<AnnounceResponse, Box<dyn std::error::Error>> {
        let tracker_url = self.build_tracker_url()?;
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
                        // If the key exists, parse the compact peer list.
                        Self::parse_compact_peers(&peers_bytes)?
                    } else {
                        // If the key is missing, successfully return an empty list.
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

    // CORRECTED build_tracker_url function
    fn build_tracker_url(&self) -> Result<String, Box<dyn std::error::Error>> {
        let base_url = &self.announce;

        // most trackers only like being connected via a 'real'
        // torrent client, so we have to fake being one:
        // generate a peer_id that impersonates Transmission 2.94
        // The format is: -<Client Code><Version>-<Random Chars>
        // -TR2940-<12 random bytes>
        let mut peer_id = [0u8; 20];
        peer_id[..8].copy_from_slice(b"-TR2940-");
        // Generate 12 random bytes for the end
        let mut rng = rand::thread_rng();
        peer_id[8..].copy_from_slice(&rng.r#gen::<[u8; 12]>());

        let port: u16 = 6881;
        let uploaded: i64 = 0;
        let downloaded: i64 = 0;
        let left = self.info.piece_length * self.info.pieces.len() as i64;

        const URL_ENCODE_SET: &AsciiSet = &CONTROLS
            .add(b' ')
            .add(b'"')
            .add(b'#')
            .add(b'<')
            .add(b'>')
            .add(b'?')
            .add(b'`')
            .add(b'{')
            .add(b'}');

        let encoded_info_hash = percent_encode(&self.info_hash, URL_ENCODE_SET).to_string();
        let encoded_peer_id = percent_encode(&peer_id, URL_ENCODE_SET).to_string();

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

        // chunks_exact provides a non-overlapping iterator over slices of 6 bytes
        let peers = bytes
            .chunks_exact(6)
            .map(|chunk| {
                // First 4 bytes are the IP address.
                let ip = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
                // Next 2 bytes are the port in big-endian format.
                let port = u16::from_be_bytes([chunk[4], chunk[5]]);
                Peer::new(ip, port)
            })
            .collect();

        Ok(peers)
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
}
