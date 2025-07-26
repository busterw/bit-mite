mod bencode;
mod torrent;

fn main() {
    let torrent_file = "/home/buster/Downloads/sample.torrent";
    match torrent::Torrent::from_file(torrent_file) {
        Ok(t) => {
            println!("Successfully parsed torrent!");
            println!("Tracker URL: {}", t.announce);
            println!("Info Name: {}", t.info.name);
            println!("Piece Length: {}", t.info.piece_length);
            println!("Number of pieces: {}", t.info.pieces.len());
            println!("Info Hash: {}", hex::encode(t.info_hash)); // use hex crate to print
        }
        Err(e) => {
            eprintln!("Failed to parse torrent file: {:?}", e);
        }
    }
}