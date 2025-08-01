
pub mod bencode;
pub mod magnet;
pub mod metadata;
pub mod peer;
pub mod torrent;
pub mod tracker;

use crate::magnet::Magnet;
use crate::torrent::{PieceManager, Torrent};
use futures::future::join_all;
use rand::{Rng, RngCore};
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    let magnet_link = "magnet:?xt=urn:btih:A46191E0C823E42FF8EAED2E6ACB9127383CC190&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2F9.rarbg.to%3A2920%2Fannounce&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337&tr=udp%3A%2F%2Ftracker.internetwarriors.net%3A1337%2Fannounce&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.pirateparty.gr%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.cyberia.is%3A6969%2Fannounce";
    println!("Starting BitTorrent client for magnet link...");

    let magnet = match Magnet::from_uri(magnet_link) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error: Could not parse magnet link. {}", e);
            return;
        }
    };
    
    let our_peer_id = {
        let mut id = [0u8; 20];
        id[0..8].copy_from_slice(b"-RS0001-");
        rand::thread_rng().fill_bytes(&mut id[8..]);
        id
    };

    println!("\nContacting trackers to find peers...");
    let peers = match tracker::find_peers(&magnet).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: Could not find peers from trackers. {}", e);
            return;
        }
    };
    println!("  > Found {} potential peers.", peers.len());

    println!("\nStage 1: Acquiring Torrent Metadata...");
    let shared_torrent_metadata: Arc<Mutex<Option<Arc<Torrent>>>> = Arc::new(Mutex::new(None));
    
    let mut metadata_tasks = vec![];
    for p in &peers {
        let shared_torrent_clone = shared_torrent_metadata.clone();
        let peer = p.clone();
        
        metadata_tasks.push(tokio::spawn(async move {
            if let Ok(connection) = peer::connect(peer, magnet.info_hash, our_peer_id).await {
                let _ = peer::download_metadata(connection, magnet.info_hash, shared_torrent_clone).await;
            }
        }));
    }
    join_all(metadata_tasks).await;

    let torrent = {
        let lock = shared_torrent_metadata.lock().await;
        if lock.is_none() {
            println!("\n❌ Failure. Could not download torrent metadata from any peer. Exiting.");
            return;
        }
        lock.clone().unwrap()
    };
    println!("\n✅ Success! Metadata downloaded for '{}'.", torrent.name);

    println!("\nStage 2: Downloading File Content...");
    let piece_manager = Arc::new(Mutex::new(PieceManager::new(&torrent)));
    
    let mut content_tasks = vec![];
    for p in peers {
        let torrent_clone = torrent.clone();
        let manager_clone = piece_manager.clone();

        content_tasks.push(tokio::spawn(async move {
            if let Ok(connection) = peer::connect(p, torrent_clone.info_hash, our_peer_id).await {
                let _ = peer::download_content(connection, torrent_clone, manager_clone).await;
            }
        }));
    }
    join_all(content_tasks).await;

    println!("\n✅ File download phase complete!");
}

//let torrent_file = "/home/buster/Downloads/scifiarchivum_archive.torrent"
//"magnet:?xt=urn:btih:A46191E0C823E42FF8EAED2E6ACB9127383CC190&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2F9.rarbg.to%3A2920%2Fannounce&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337&tr=udp%3A%2F%2Ftracker.internetwarriors.net%3A1337%2Fannounce&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.pirateparty.gr%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.cyberia.is%3A6969%2Fannounce"    ;
