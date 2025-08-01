
// src/main.rs

// src/main.rs

pub mod bencode;
pub mod magnet;
pub mod metadata;
pub mod peer;
pub mod torrent;
pub mod tracker;

use crate::magnet::Magnet;
use crate::peer::GlobalState;
use crate::torrent::PieceManager;
use futures::future::join_all;
use rand::{Rng, RngCore};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let magnet_link = "magnet:?xt=urn:btih:A46191E0C823E42FF8EAED2E6ACB9127383CC190&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2F9.rarbg.to%3A2920%2Fannounce&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337&tr=udp%3A%2F%2Ftracker.internetwarriors.net%3A1337%2Fannounce&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.pirateparty.gr%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.cyberia.is%3A6969%2Fannounce";
    println!("Starting BitTorrent client...");

    let magnet = Magnet::from_uri(magnet_link)?;
    let our_peer_id = { let mut id = [0u8; 20]; id[0..8].copy_from_slice(b"-RS0001-"); rand::thread_rng().fill_bytes(&mut id[8..]); id };

    println!("\nContacting trackers to find peers...");
    let peers = tracker::find_peers(&magnet).await?;
    println!("  > Found {} potential peers.", peers.len());

    let shared_state: Arc<Mutex<GlobalState>> = Arc::new(Mutex::new(GlobalState::MetadataPending));
    
    let mut tasks = vec![];
    println!("\nSpawning sessions for all peers...");
    for p in peers {
        let state_clone = shared_state.clone();
        
        tasks.push(tokio::spawn(async move {
            if let Ok(connection) = peer::connect(p, magnet.info_hash, our_peer_id).await {
                if let Err(e) = peer::run_session(connection, magnet.info_hash, state_clone).await {
                     // eprintln!("  > Session ended with error: {}", e);
                }
            }
        }));
    }
    join_all(tasks).await;

    println!("\nAll peer sessions concluded.");
    
    // --- Final Step: Check State and Write to Disk ---
    let final_state = shared_state.lock().await;
    if let GlobalState::ContentDownload(torrent, manager_mutex) = &*final_state {
        let manager = manager_mutex.lock().await;
        let downloaded_pieces = manager.pieces.iter().filter(|p| p.state == crate::torrent::PieceState::Have).count();
        let total_pieces = manager.pieces.len();
        
        if downloaded_pieces == total_pieces && total_pieces > 0 {
            println!("\n✅ Download complete! All {} pieces verified.", total_pieces);
            match manager.write_to_disk(&torrent) {
                Ok(_) => println!("   Files written successfully to './downloads/{}'", torrent.name),
                Err(e) => eprintln!("   Error writing files to disk: {}", e),
            }
        } else {
            println!("\n❌ Download incomplete. Got {} out of {} pieces.", downloaded_pieces, total_pieces);
        }
    } else {
        println!("\n❌ Failure. Could not download torrent metadata.");
    }

    Ok(())
}
//let torrent_file = "/home/buster/Downloads/scifiarchivum_archive.torrent"
//"magnet:?xt=urn:btih:A46191E0C823E42FF8EAED2E6ACB9127383CC190&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2F9.rarbg.to%3A2920%2Fannounce&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337&tr=udp%3A%2F%2Ftracker.internetwarriors.net%3A1337%2Fannounce&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.pirateparty.gr%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.cyberia.is%3A6969%2Fannounce"    ;
