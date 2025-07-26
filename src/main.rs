use rand::Rng;

mod bencode;
mod peer;
mod torrent;

fn main() {
    let torrent_file = "/home/buster/Downloads/scifiarchivum_archive.torrent";
    match torrent::Torrent::from_file(torrent_file) {
        Ok(t) => {
            println!("Successfully parsed torrent: {}", t.info.name);

            let mut our_peer_id = [0u8; 20];
            our_peer_id[..8].copy_from_slice(b"-TR2940-");
            let mut rng = rand::thread_rng();
            our_peer_id[8..].copy_from_slice(&rng.r#gen::<[u8; 12]>());

            match t.discover_peers(&our_peer_id) {
                Ok(response) => {
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

                        // iterate through the peers until we find one to handshake with
                        let mut connected_stream: Option<std::net::TcpStream> = None;

                        for peer in response.peers {
                            match peer::perform_handshake(&peer, &t.info_hash, &our_peer_id) {
                                Ok(stream) => {
                                    // Success! We found a working peer.
                                    println!("Handshake Succeeded with {}", peer.socket_address());
                                    connected_stream = Some(stream);
                                    // We've got our connection, so we can stop trying other peers.
                                    break;
                                }
                                Err(e) => {
                                    eprintln!(
                                        "Handshake failed with {}: {}",
                                        peer.socket_address(),
                                        e
                                    );
                                }
                            }
                        }
                        if connected_stream.is_none() {
                            println!(
                                "Could not establish a connection with any of the discovered peers."
                            );
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to discover peers: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to parse torrent file: {:?}", e);
        }
    }
}

//let torrent_file = "/home/buster/Downloads/scifiarchivum_archive.torrent";
