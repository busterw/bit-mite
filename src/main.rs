
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
use futures::future::join_all;
use rand::RngCore;
use tokio::task::JoinHandle;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

// src/main.rs

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Instant::now();
    let magnet_link = "magnet:?xt=urn:btih:A46191E0C823E42FF8EAED2E6ACB9127383CC190&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2F9.rarbg.to%3A2920%2Fannounce&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337&tr=udp%3A%2F%2Ftracker.internetwarriors.net%3A1337%2Fannounce&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.pirateparty.gr%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.cyberia.is%3A6969%2Fannounce";
    println!("Starting BitTorrent client...");

    let magnet = Magnet::from_uri(magnet_link)?;
    let our_peer_id = { let mut id = [0u8; 20]; id[0..8].copy_from_slice(b"-RS0001-"); rand::thread_rng().fill_bytes(&mut id[8..]); id };

    // --- State for the Connection & Re-announce Manager ---
    let shared_state: Arc<Mutex<GlobalState>> = Arc::new(Mutex::new(GlobalState::MetadataPending));
    let peer_queue: Arc<Mutex<VecDeque<tracker::Peer>>> = Arc::new(Mutex::new(VecDeque::new()));
    
    // --- New State for Re-announcing ---
    let mut last_announce_time = Instant::now();
    // Start with a reasonable default, the tracker will give us a better one.
    let mut tracker_interval = Duration::from_secs(60 * 15); 
    
    const TARGET_CONNECTIONS: usize = 50;
    let mut active_tasks: Vec<JoinHandle<()>> = Vec::new();

    // --- The Connection Manager Loop ---
    println!("\nStarting Connection Manager. Target connections: {}", TARGET_CONNECTIONS);
    loop {
        // --- THIS IS THE CORRECTED BLOCK ---
        let (is_complete, active_count) = {
            // First, remove any tasks that have finished. This is essential.
            active_tasks.retain(|task| !task.is_finished());

            // Now, perform the check for completion.
            let state = shared_state.lock().await;
            let complete = match &*state {
                GlobalState::ContentDownload(_, manager_mutex) => {
                    let manager = manager_mutex.lock().await;
                    manager.is_complete()
                }
                _ => false,
            };
            
            // Return both the completion status AND the accurate count of active tasks.
            (complete, active_tasks.len())
        };
        // --- END CORRECTION ---

        if is_complete {
            println!("\nDownload is complete. Shutting down connection manager.");
            break;
        }

        // --- Part 2: Re-announce to tracker if needed ---
        let mut queue = peer_queue.lock().await;
        let should_announce = queue.is_empty() || last_announce_time.elapsed() >= tracker_interval;
        if should_announce {
            println!("\nQueue is empty or interval expired. Re-announcing to tracker...");
            // In a real client, you would also pass stats like downloaded/uploaded amounts.
            match tracker::find_peers(&magnet).await {
                Ok((new_peers, interval)) => {
                    println!("  > Found {} new peers. Next announce in {:?}.", new_peers.len(), interval);
                    queue.extend(new_peers);
                    last_announce_time = Instant::now();
                    tracker_interval = interval;
                },
                Err(e) => eprintln!("  > Failed to re-announce: {}", e),
            }
        }
        
        // --- Part 3: Spawn new peer sessions ---
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
                } else {
                    break; // No more peers in the queue for now
                }
            }
        }
        drop(queue); // Release the lock

        if peer_queue.lock().await.is_empty() && active_tasks.is_empty() && !is_complete {
            println!("\nAll peers attempted and all sessions concluded, but download is not complete. Retrying tracker announce...");
        }

        tokio::time::sleep(Duration::from_secs(1)).await; // Main loop heartbeat
    }

    // Wait for any remaining tasks to gracefully finish.
    join_all(active_tasks).await;

    // --- Final Step: Write to Disk (logic is unchanged) ---
    println!("\nAll peer sessions concluded.");
    let final_state = shared_state.lock().await;
    if let GlobalState::ContentDownload(torrent, manager_mutex) = &*final_state {
        let manager = manager_mutex.lock().await;
        if manager.is_complete() {
            println!("\n✅ Download complete! All {} pieces verified.", manager.pieces.len());
            manager.write_to_disk(&torrent)?;
            println!("   Files written successfully to './downloads/{}'", torrent.name);
        } else {
             println!("\n❌ Download incomplete. Got {} out of {} pieces.", manager.count_have_pieces(), manager.pieces.len());
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
// release mode, with 1 seconds wait: