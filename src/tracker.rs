use crate::bencode::BencodeValue;
use crate::magnet::Magnet;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rand::{Rng, RngCore};
use reqwest::blocking::Client;
use std::io::{Cursor, Write};
use std::net::Ipv4Addr;
use std::net::UdpSocket;
use std::time::Duration;
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone)]
pub struct Peer {
    pub ip: Ipv4Addr,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct TrackerResponse {
    /// in seconds
    pub interval: i64,
    pub peers: Vec<Peer>,
}

#[derive(Error, Debug)]
pub enum TrackerError {
    #[error("HTTP request failed: {0}")]
    HttpRequest(#[from] reqwest::Error),
    #[error("Tracker returned a failure reason: {0}")]
    Failure(String),
    #[error("Could not decode bencoded response")]
    Bencode,
    #[error("Invalid peer data in tracker response")]
    InvalidPeerData,
    #[error("UDP Socket error: {0}")]
    UdpSocket(#[from] std::io::Error),
    #[error("Failed to parse UDP tracker URL")]
    UdpUrlParse,
    #[error("UDP tracker response timed out")]
    UdpTimeout,
    #[error("Received unexpected action from UDP tracker. Expected {expected}, got {got}")]
    UdpInvalidAction { expected: u32, got: u32 },
    #[error("UDP tracker response transaction_id did not match request")]
    UdpTransactionIdMismatch,
    #[error("UDP tracker response was too short. Expected at least {expected} bytes, got {got}")]
    UdpResponseTooShort { expected: usize, got: usize },
}

pub fn announce_udp(
    tracker_url_str: &str,
    info_hash: [u8; 20],
) -> Result<TrackerResponse, TrackerError> {
    let tracker_url = Url::parse(tracker_url_str).map_err(|_| TrackerError::UdpUrlParse)?;
    let tracker_addr = tracker_url
        .socket_addrs(|| Some(6969))? // Default UDP port if not in URL
        .into_iter()
        .next()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Could not resolve tracker address",
            )
        })?;

    let socket = UdpSocket::bind("0.0.0.0:0")?; // Bind to any available local port
    socket.connect(tracker_addr)?;

    let timeout = Duration::from_secs(8);
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;

    let conn_trans_id = rand::thread_rng().r#gen::<u32>();
    let mut conn_req_buf = Vec::with_capacity(16);
    conn_req_buf.write_u64::<BigEndian>(0x41727101980)?; // Magic connection_id constant
    conn_req_buf.write_u32::<BigEndian>(0)?; // Action: connect
    conn_req_buf.write_u32::<BigEndian>(conn_trans_id)?;

    socket.send(&conn_req_buf)?;

    let mut conn_resp_buf = [0u8; 16];
    socket
        .recv(&mut conn_resp_buf)
        .map_err(|_| TrackerError::UdpTimeout)?;

    let mut reader = Cursor::new(conn_resp_buf);
    let resp_action = reader.read_u32::<BigEndian>()?;
    let resp_trans_id = reader.read_u32::<BigEndian>()?;
    let connection_id = reader.read_u64::<BigEndian>()?;

    if resp_action != 0 {
        return Err(TrackerError::UdpInvalidAction {
            expected: 0,
            got: resp_action,
        });
    }
    if resp_trans_id != conn_trans_id {
        return Err(TrackerError::UdpTransactionIdMismatch);
    }

    let peer_id = {
        let mut id = [0u8; 20];
        id[0..8].copy_from_slice(b"-RS0001-");
        rand::thread_rng().fill_bytes(&mut id[8..]);
        id
    };
    let ann_trans_id = rand::thread_rng().r#gen::<u32>();

    let mut ann_req_buf = Vec::with_capacity(98);
    ann_req_buf.write_u64::<BigEndian>(connection_id)?; // From connect response
    ann_req_buf.write_u32::<BigEndian>(1)?; // Action: announce
    ann_req_buf.write_u32::<BigEndian>(ann_trans_id)?;
    ann_req_buf.write_all(&info_hash)?;
    ann_req_buf.write_all(&peer_id)?;
    ann_req_buf.write_u64::<BigEndian>(0)?; // downloaded
    ann_req_buf.write_u64::<BigEndian>(0)?; // left (we don't know yet)
    ann_req_buf.write_u64::<BigEndian>(0)?; // uploaded
    ann_req_buf.write_u32::<BigEndian>(2)?; // Event: started
    ann_req_buf.write_u32::<BigEndian>(0)?; // ip address (0 = tracker derives)
    ann_req_buf.write_u32::<BigEndian>(rand::thread_rng().r#gen::<u32>())?; // key
    ann_req_buf.write_i32::<BigEndian>(-1)?; // num_want (-1 = default)
    ann_req_buf.write_u16::<BigEndian>(6881)?; // port
    socket.send(&ann_req_buf)?;

    let mut ann_resp_buf = vec![0u8; 8192]; // Use a large buffer
    let bytes_read = socket
        .recv(&mut ann_resp_buf)
        .map_err(|_| TrackerError::UdpTimeout)?;
    ann_resp_buf.truncate(bytes_read); // Shrink to actual data size

    if ann_resp_buf.len() < 20 {
        return Err(TrackerError::UdpResponseTooShort {
            expected: 20,
            got: ann_resp_buf.len(),
        });
    }

    let mut reader = Cursor::new(&ann_resp_buf);
    let resp_action = reader.read_u32::<BigEndian>()?;
    let resp_trans_id = reader.read_u32::<BigEndian>()?;

    // Check for an error response from the tracker first
    if resp_action == 3 {
        let mut error_text = String::new();
        std::io::Read::read_to_string(&mut reader, &mut error_text)?;
        return Err(TrackerError::Failure(error_text));
    }

    if resp_action != 1 {
        return Err(TrackerError::UdpInvalidAction {
            expected: 1,
            got: resp_action,
        });
    }
    if resp_trans_id != ann_trans_id {
        return Err(TrackerError::UdpTransactionIdMismatch);
    }

    let interval = reader.read_u32::<BigEndian>()? as i64;
    reader.read_u32::<BigEndian>()?; // leechers
    reader.read_u32::<BigEndian>()?; // seeders

    let peers_bytes = &ann_resp_buf[20..];
    let peers = parse_peers(peers_bytes)?;

    Ok(TrackerResponse { interval, peers })
}

fn parse_peers(bytes: &[u8]) -> Result<Vec<Peer>, TrackerError> {
    if bytes.len() % 6 != 0 {
        return Err(TrackerError::InvalidPeerData);
    }
    // Chunks of 6 bytes: 4 for IP, 2 for port
    Ok(bytes
        .chunks_exact(6)
        .map(|chunk| {
            let ip_bytes: [u8; 4] = chunk[0..4].try_into().unwrap();
            let port_bytes: [u8; 2] = chunk[4..6].try_into().unwrap();
            Peer {
                ip: Ipv4Addr::from(ip_bytes),
                port: u16::from_be_bytes(port_bytes),
            }
        })
        .collect())
}

pub fn announce(tracker_url: &str, info_hash: [u8; 20]) -> Result<TrackerResponse, TrackerError> {
    let peer_id = {
        let mut id = [0u8; 20];
        // <Client Abbreviation><Version>-<Randomness>
        id[0..8].copy_from_slice(b"-RS0001-");
        rand::thread_rng().fill_bytes(&mut id[8..]);
        id
    };

    let mut request_url = reqwest::Url::parse_with_params(
        tracker_url,
        &[
            ("port", "6881"), // The port our client will listen on
            ("uploaded", "0"),
            ("downloaded", "0"),
            ("left", "0"),
            ("compact", "1"),
            ("event", "started"),
        ],
    )
    .unwrap();

    let mut url_serializer = request_url.query_pairs_mut();
    url_serializer.append_pair("info_hash", &String::from_utf8_lossy(&info_hash));
    url_serializer.append_pair("peer_id", &String::from_utf8_lossy(&peer_id));

    let final_url = url_serializer.finish().to_string();

    println!("Announcing to tracker: {}", final_url);
    let client = Client::new();
    let response_bytes = client.get(final_url).send()?.bytes()?;

    let (bencode_response, _) =
        crate::bencode::decode(&response_bytes).map_err(|_| TrackerError::Bencode)?;

    let response_dict = match bencode_response {
        BencodeValue::Dictionary(d) => d,
        _ => return Err(TrackerError::Bencode),
    };

    if let Some(BencodeValue::Bytes(reason_bytes)) = response_dict.get(&b"failure reason"[..]) {
        let reason = String::from_utf8_lossy(reason_bytes).to_string();
        return Err(TrackerError::Failure(reason));
    }

    let interval = match response_dict.get(&b"interval"[..]) {
        Some(BencodeValue::Integer(i)) => *i,
        _ => return Err(TrackerError::Bencode),
    };

    let peers = match response_dict.get(&b"peers"[..]) {
        Some(BencodeValue::Bytes(p)) => parse_peers(p)?,
        _ => return Err(TrackerError::Bencode),
    };

    Ok(TrackerResponse { interval, peers })
}

pub async fn find_peers(magnet: &Magnet) -> Result<(Vec<Peer>, Duration), Box<dyn std::error::Error>> {
        for tracker_url in &magnet.trackers {
        let response_result = if tracker_url.starts_with("http") {
            // TODO: Replace with non-blocking
            tokio::task::block_in_place(move || announce(tracker_url, magnet.info_hash))
        } else if tracker_url.starts_with("udp") {
            announce_udp(tracker_url, magnet.info_hash)
        } else {
            eprintln!("  > Skipping unsupported tracker protocol: {}", tracker_url);
            continue;
        };
        
        match response_result {
            Ok(response) => {
                let interval = Duration::from_secs(response.interval as u64);
                return Ok((response.peers, interval));
           }
            Err(e) => {
                eprintln!("    > Announce to {} failed: {}", tracker_url, e);
            }
        }
    }

    Err("Could not get a peer list from any tracker.".into())
}
