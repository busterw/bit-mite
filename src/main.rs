pub mod bencode;
pub mod magnet;
pub mod metadata;
pub mod peer;
pub mod torrent;
pub mod tracker;

use crate::magnet::Magnet;
use crate::torrent::Torrent;
use futures::future::join_all;
use rand::RngCore;
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    let magnet_link = "magnet:?xt=urn:btih:A46191E0C823E42FF8EAED2E6ACB9127383CC190&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2F9.rarbg.to%3A2920%2Fannounce&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337&tr=udp%3A%2F%2Ftracker.internetwarriors.net%3A1337%2Fannounce&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.pirateparty.gr%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.cyberia.is%3A6969%2Fannounce";

    println!("Starting BitTorrent client...");

    let shared_torrent: Arc<Mutex<Option<Arc<Torrent>>>> = Arc::new(Mutex::new(None));

    let magnet = match Magnet::from_uri(magnet_link) {
        Ok(m) => {
            println!(
                "Parsed magnet link for info_hash: {}",
                hex::encode(m.info_hash)
            );
            m
        }
        Err(e) => {
            eprintln!("Error: Could not parse magnet link. {}", e);
            return;
        }
    };

    let our_peer_id = {
        let mut id = [0u8; 20];
        // "RS" for Rust, "0001" for version (some clients probably won't like this, so we might have to fake being a different client at some point)
        id[0..8].copy_from_slice(b"-RS0001-");
        rand::thread_rng().fill_bytes(&mut id[8..]);
        id
    };

    println!("\nContacting trackers to find peers...");
    let mut peer_list: Option<Vec<tracker::Peer>> = None;
    for tracker_url in &magnet.trackers {
        println!("  - Announcing to {}", tracker_url);
        let response = if tracker_url.starts_with("http") {
            tracker::announce(tracker_url, magnet.info_hash)
        } else if tracker_url.starts_with("udp") {
            tracker::announce_udp(tracker_url, magnet.info_hash)
        } else {
            eprintln!("    > Skipping unsupported tracker protocol.");
            continue;
        };

        match response {
            Ok(res) => {
                println!("    > Success! Got {} peers from tracker.", res.peers.len());
                peer_list = Some(res.peers);
                break; // We have a peer list, no need to contact more trackers.
            }
            Err(e) => {
                eprintln!("    > Failed to announce: {}", e);
            }
        }
    }

    let Some(peers) = peer_list else {
        println!("\nCould not retrieve a peer list from any trackers. Exiting.");
        return;
    };

    println!("\nStarting peer sessions...");

    let mut tasks = vec![];
    for p in peers {
        let shared_torrent_clone = shared_torrent.clone();

        let task = tokio::spawn(async move {
            let peer_ip = p.ip;
            let peer_port = p.port;

            match peer::connect(p, magnet.info_hash, our_peer_id).await {
                Ok(connection) => {
                    println!(
                        "  > [Peer {}:{}] ✅ Handshake complete.",
                        peer_ip, peer_port
                    );

                    if let Err(e) =
                        peer::run_session(connection, magnet.info_hash, shared_torrent_clone).await
                    {
                        eprintln!("    [Peer {}:{}] Session Error: {}", peer_ip, peer_port, e);
                    }
                }
                Err(e) => {
                    eprintln!(
                        "  > [Peer {}:{}] ❌ Failed to connect: {}",
                        peer_ip, peer_port, e
                    );
                }
            }
        });
        tasks.push(task);
    }

    join_all(tasks).await;

    if let Some(torrent) = &*shared_torrent.lock().await {
        println!("\n✅ Success! Metadata downloaded and verified.");
        println!("   Torrent Name: {}", torrent.name);
    } else {
        println!(
            "\n❌ Failure. Could not download torrent metadata from any of the connected peers."
        );
    }
}
//let torrent_file = "/home/buster/Downloads/scifiarchivum_archive.torrent"
//"magnet:?xt=urn:btih:A46191E0C823E42FF8EAED2E6ACB9127383CC190&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2F9.rarbg.to%3A2920%2Fannounce&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337&tr=udp%3A%2F%2Ftracker.internetwarriors.net%3A1337%2Fannounce&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.pirateparty.gr%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.cyberia.is%3A6969%2Fannounce"    ;
