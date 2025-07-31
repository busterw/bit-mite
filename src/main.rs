mod magnet;

use magnet::Magnet;

fn main() {
    // Replace this with your actual magnet link for testing
    let magnet_link = "magnet:?xt=urn:btih:A46191E0C823E42FF8EAED2E6ACB9127383CC190&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2F9.rarbg.to%3A2920%2Fannounce&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337&tr=udp%3A%2F%2Ftracker.internetwarriors.net%3A1337%2Fannounce&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.pirateparty.gr%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.cyberia.is%3A6969%2Fannounce";

    match Magnet::from_uri(magnet_link) {
        Ok(magnet) => {
            println!("Successfully parsed magnet link!");
            println!("  Display Name: {}", magnet.display_name.unwrap_or_else(|| "N/A".to_string()));
            println!("  Info Hash: {}", hex::encode(magnet.info_hash));
            println!("  Trackers:");
            if magnet.trackers.is_empty() {
                println!("    No trackers found in the magnet link.");
            } else {
                for tracker in magnet.trackers {
                    println!("    - {}", tracker);
                }
            }
        }
        Err(e) => {
            eprintln!("Error parsing magnet link: {}", e);
        }
    }
}
//let torrent_file = "/home/buster/Downloads/scifiarchivum_archive.torrent"
//"magnet:?xt=urn:btih:A46191E0C823E42FF8EAED2E6ACB9127383CC190&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2F9.rarbg.to%3A2920%2Fannounce&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337&tr=udp%3A%2F%2Ftracker.internetwarriors.net%3A1337%2Fannounce&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.pirateparty.gr%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.cyberia.is%3A6969%2Fannounce"    ;
