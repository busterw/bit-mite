mod bencode;
mod torrent;

fn main() {
    let torrent_file = "/home/buster/Downloads/scifiarchivum_archive.torrent";
    match torrent::Torrent::from_file(torrent_file) {
        Ok(t) => {
            println!("Successfully parsed torrent: {}", t.info.name);
            
            // The return type is now AnnounceResponse
            match t.discover_peers() {
                Ok(response) => {
                    println!("Tracker announce successful!");
                    println!("Interval: {} seconds", response.interval);
                    
                    if response.peers.is_empty() {
                        println!("No peers found.");
                    } else {
                        println!("Discovered {} peers:", response.peers.len());
                        for peer in response.peers {
                            println!("- {}:{}", peer.ip, peer.port);
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




    //let torrent_file = "/home/buster/Downloads/ml-005-e8b1f9c5bf555fe58bc73addb83457dd6da69630.torrent";
