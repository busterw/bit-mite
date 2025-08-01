// src/main.rs

pub mod bencode;
pub mod magnet;
pub mod metadata;
pub mod peer;
pub mod torrent;
pub mod tracker;

use crate::magnet::Magnet;
use crate::peer::GlobalState;
use crate::torrent::{PieceManager, Torrent};
use futures::future::join_all;
use rand::{Rng, RngCore};
use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {    
    let start_time = Instant::now();
    let magnet_link = "magnet:?xt=urn:btih:A46191E0C823E42FF8EAED2E6ACB9127383CC190&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2F9.rarbg.to%3A2920%2Fannounce&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337&tr=udp%3A%2F%2Ftracker.internetwarriors.net%3A1337%2Fannounce&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.pirateparty.gr%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.cyberia.is%3A6969%2Fannounce";
    println!("Starting BitTorrent client...");

    let magnet = Magnet::from_uri(magnet_link)?;
    let our_peer_id = { let mut id = [0u8; 20]; id[0..8].copy_from_slice(b"-RS0001-"); rand::thread_rng().fill_bytes(&mut id[8..]); id };

    let shared_state: Arc<Mutex<GlobalState>> = Arc::new(Mutex::new(GlobalState::MetadataPending));
    let peer_queue: Arc<Mutex<VecDeque<tracker::Peer>>> = Arc::new(Mutex::new(VecDeque::new()));
    
    let mut last_announce_time = Instant::now();
    let mut tracker_interval = Duration::from_secs(60 * 15); 
    
    const TARGET_CONNECTIONS: usize = 50;
    let mut active_tasks: Vec<JoinHandle<()>> = Vec::new();

    println!("\nStarting Connection Manager...");
    loop {
        let (is_complete, active_count) = {
            active_tasks.retain(|task| !task.is_finished());
            let state = shared_state.lock().await;
            let complete = if let GlobalState::ContentDownload(_, manager_mutex, _) = &*state {
                manager_mutex.lock().await.is_complete()
            } else { false };
            (complete, active_tasks.len())
        };

        if is_complete { break; }

        let mut queue = peer_queue.lock().await;
        if queue.is_empty() || last_announce_time.elapsed() >= tracker_interval {
            println!("\nRe-announcing to tracker...");
            match tracker::find_peers(&magnet).await {
                Ok((new_peers, interval)) => {
                    queue.extend(new_peers);
                    last_announce_time = Instant::now();
                    tracker_interval = interval;
                },
                Err(e) => eprintln!("  > Failed to re-announce: {}", e),
            }
        }
        
        if active_count < TARGET_CONNECTIONS {
            let needed = TARGET_CONNECTIONS - active_count;
            for _ in 0..needed {
                if let Some(peer) = queue.pop_front() {
                    let state_clone = shared_state.clone();
                    active_tasks.push(tokio::spawn(async move {
                        if let Ok(connection) = peer::connect(peer, magnet.info_hash, our_peer_id).await {
                           let _ = peer::run_session(connection, magnet.info_hash, state_clone).await;
                        }
                    }));
                } else { break; }
            }
        }
        drop(queue);

        if peer_queue.lock().await.is_empty() && active_tasks.is_empty() {
             println!("\nNo active peers and queue is empty. Awaiting re-announce.");
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    
    join_all(active_tasks).await;

    println!("\nAll peer sessions concluded.");
    let final_state = shared_state.lock().await;
    if let GlobalState::ContentDownload(torrent, manager_mutex, _) = &*final_state {
        let manager = manager_mutex.lock().await;
        if manager.is_complete() {
            println!("\n✅ Download complete!");
            manager.write_to_disk(&torrent)?;
        } else {
             println!("\n❌ Download incomplete.");
        }
    } else {
        println!("\n❌ Failure. Could not download torrent metadata.");
    }

    let elapsed = start_time.elapsed();
    println!("\nTotal execution time: {:.2?}", elapsed);
    Ok(())
}
//let torrent_file = "/home/buster/Downloads/scifiarchivum_archive.torrent"
//"magnet:?xt=urn:btih:A46191E0C823E42FF8EAED2E6ACB9127383CC190&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2F9.rarbg.to%3A2920%2Fannounce&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337&tr=udp%3A%2F%2Ftracker.internetwarriors.net%3A1337%2Fannounce&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.pirateparty.gr%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.cyberia.is%3A6969%2Fannounce"    ;

// debug mode, with 1 second wait: 501.64s
// release mode, with 1 seconds wait: 500.78 seconds
// release mode, with rarity changes: 340.97 seconds
