use rand::Rng;
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::PathBuf;

pub mod bencode;
pub mod messages;
pub mod peer;
pub mod torrent;

fn prepare_filesystem(info: &torrent::Info) -> Result<HashMap<PathBuf, File>, std::io::Error> {
    let mut file_handles = HashMap::new();

    match &info.mode {
        torrent::InfoMode::SingleFile { length } => {
            let file = File::create(&info.name)?;
            file.set_len(*length as u64)?; // Pre-allocate the file size
            file_handles.insert(PathBuf::from(&info.name), file);
        }
        torrent::InfoMode::MultiFile { files } => {
            // Create the root directory
            let root_dir = PathBuf::from(&info.name);
            fs::create_dir_all(&root_dir)?;

            for file_info in files {
                // Create any parent directories for the file
                let full_path = root_dir.join(&file_info.path);
                if let Some(parent) = full_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                // Create and pre-allocate the file
                let file = File::create(&full_path)?;
                file.set_len(file_info.length as u64)?;
                file_handles.insert(file_info.path.clone(), file);
            }
        }
    }
    Ok(file_handles)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let torrent_file = "/home/buster/Downloads/scifiarchivum_archive.torrent";
    let t = torrent::Torrent::from_file(torrent_file).unwrap();
    println!("Successfully parsed torrent: {}", t.info.name);

    println!("Preparing filesystem...");
    let mut file_handles = prepare_filesystem(&t.info)?;
    let mapper = torrent::FileMapper::new(&t.info);
    println!("Filesystem prepared.");

    let mut our_peer_id = [0u8; 20];
    our_peer_id[..8].copy_from_slice(b"-TR2940-");
    let mut rng = rand::thread_rng();
    our_peer_id[8..].copy_from_slice(&rng.r#gen::<[u8; 12]>());

    let response = t.discover_peers(&our_peer_id)?;
    println!(
        "Tracker announce successful! Interval: {}",
        response.interval
    );

    if response.peers.is_empty() {
        println!("No peers found.");
    } else {
        println!(
            "Discovered {} peers. Attempting to connect...",
            response.peers.len()
        );

        let mut download_state = torrent::DownloadState::new(&t.info);

        for peer in response.peers {
            if download_state.pieces_to_download.is_empty() {
                break;
            }

            match peer::perform_handshake(&peer, &t.info_hash, &our_peer_id) {
                Ok(stream) => {
                    println!("HANDSHAKE SUCCEEDED with {}", peer.socket_address());

                    if let Err(e) = peer::run_peer_session(
                        stream,
                        &mut download_state,
                        &mut file_handles,
                        &mapper,
                    ) {
                        eprintln!("Session failed with {}: {}", peer.socket_address(), e);
                    }
                }
                Err(e) => {
                    eprintln!("Handshake failed with {}: {}", peer.socket_address(), e);
                }
            }
        }

        if download_state.pieces_to_download.is_empty() {
            println!("\n--------------------------------");
            println!("  All pieces downloaded and verified successfully! ");
            println!("  Output directory: {}", t.info.name);
            println!("--------------------------------");
        } else {
            println!(
                "\nCould not complete download. Still need {} pieces.",
                download_state.pieces_to_download.len()
            );
        }
    }

    Ok(())
}

//let torrent_file = "/home/buster/Downloads/scifiarchivum_archive.torrent"
