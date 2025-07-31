use std::collections::HashMap;

/// Represents the data parsed from a magnet link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Magnet {
    /// The 20-byte SHA-1 hash of the bencoded info dictionary.
    pub info_hash: [u8; 20],
    /// The display name of the torrent.
    pub display_name: Option<String>,
    /// A list of tracker URLs.
    pub trackers: Vec<String>,
}

impl Magnet {
    /// Parses a magnet link URI string into a `Magnet` struct.
    pub fn from_uri(uri: &str) -> Result<Self, &'static str> {
        if !uri.starts_with("magnet:?") {
            return Err("Invalid magnet URI: Must start with 'magnet:?'");
        }

        let params_str = &uri[8..];
        let params: HashMap<&str, Vec<&str>> = params_str
            .split('&')
            .filter_map(|p| {
                let mut parts = p.splitn(2, '=');
                let key = parts.next()?;
                let value = parts.next()?;
                Some((key, value))
            })
            .fold(HashMap::new(), |mut acc, (k, v)| {
                acc.entry(k).or_default().push(v);
                acc
            });

        let xt = params
            .get("xt")
            .and_then(|v| v.first())
            .ok_or("Magnet URI is missing the 'xt' (info hash) parameter")?;

        if !xt.starts_with("urn:btih:") {
            return Err("Invalid 'xt' parameter format: Must start with 'urn:btih:'");
        }

        let info_hash_hex = &xt[9..];
        let info_hash_bytes =
            hex::decode(info_hash_hex).map_err(|_| "Invalid hex-encoded info hash")?;

        if info_hash_bytes.len() != 20 {
            return Err("Info hash must be 20 bytes long");
        }
        let mut info_hash = [0u8; 20];
        info_hash.copy_from_slice(&info_hash_bytes);

        let display_name = params.get("dn").and_then(|v| v.first()).and_then(|s| {
            // Manually replace '+' with ' ' to handle form-style encoding.
            let s_with_spaces = s.replace('+', " ");
            // `decode` returns a `Result<Cow<str>, _>`.
            // We map the `Cow` to an owned `String` *inside* the closure
            // to ensure the value's lifetime is not tied to `s_with_spaces`.
            urlencoding::decode(&s_with_spaces)
                .ok()
                .map(|cow| cow.into_owned())
        });

        let trackers = params.get("tr").map_or(Vec::new(), |v| {
            v.iter()
                .filter_map(|s| urlencoding::decode(s).ok())
                .map(|cow| cow.into_owned())
                .collect()
        });

        Ok(Self {
            info_hash,
            display_name,
            trackers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_full_magnet_link() {
        let uri = "magnet:?xt=urn:btih:e8f320feb8215d29994b29b472e043b2f8469e77&dn=ubuntu-24.04-desktop-amd64.iso&tr=https%3A%2F%2Ftorrent.ubuntu.com%2Fannounce";
        let magnet = Magnet::from_uri(uri).unwrap();

        assert_eq!(
            hex::encode(magnet.info_hash),
            "e8f320feb8215d29994b29b472e043b2f8469e77"
        );
        assert_eq!(
            magnet.display_name,
            Some("ubuntu-24.04-desktop-amd64.iso".to_string())
        );
        assert_eq!(magnet.trackers.len(), 1);
        assert_eq!(
            magnet.trackers[0],
            "https://torrent.ubuntu.com/announce".to_string()
        );
    }

    #[test]
    fn test_parse_magnet_with_multiple_trackers() {
        let uri = "magnet:?xt=urn:btih:e8f320feb8215d29994b29b472e043b2f8469e77&dn=test&tr=udp%3A%2F%2Ftracker1.com%3A6969&tr=http%3A%2F%2Ftracker2.org%2Fannounce";
        let magnet = Magnet::from_uri(uri).unwrap();

        assert_eq!(magnet.trackers.len(), 2);
        assert!(
            magnet
                .trackers
                .contains(&"udp://tracker1.com:6969".to_string())
        );
        assert!(
            magnet
                .trackers
                .contains(&"http://tracker2.org/announce".to_string())
        );
    }

    #[test]
    fn test_parse_magnet_no_display_name() {
        let uri = "magnet:?xt=urn:btih:e8f320feb8215d29994b29b472e043b2f8469e77&tr=udp%3A%2F%2Ftracker.openbittorrent.com%3A80";
        let magnet = Magnet::from_uri(uri).unwrap();
        assert_eq!(magnet.display_name, None);
    }

    #[test]
    fn test_parse_magnet_no_trackers() {
        let uri = "magnet:?xt=urn:btih:e8f320feb8215d29994b29b472e043b2f8469e77&dn=some-file.zip";
        let magnet = Magnet::from_uri(uri).unwrap();
        assert!(magnet.trackers.is_empty());
    }

    #[test]
    fn test_parse_magnet_with_url_encoded_display_name() {
        let uri = "magnet:?xt=urn:btih:13a40134f0c768c2d589e003ce73e23c0c978051&dn=A+Great+Movie+%282024%29";
        let magnet = Magnet::from_uri(uri).unwrap();
        assert_eq!(
            magnet.display_name,
            Some("A Great Movie (2024)".to_string())
        );
    }

    #[test]
    fn test_invalid_uri_scheme() {
        let uri = "http:?xt=urn:btih:e8f320feb8215d29994b29b472e043b2f8469e77";
        let result = Magnet::from_uri(uri);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid magnet URI: Must start with 'magnet:?'"
        );
    }

    #[test]
    fn test_missing_info_hash() {
        let uri = "magnet:?dn=ubuntu-24.04-desktop-amd64.iso";
        let result = Magnet::from_uri(uri);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Magnet URI is missing the 'xt' (info hash) parameter"
        );
    }

    #[test]
    fn test_invalid_info_hash_urn() {
        let uri = "magnet:?xt=urn:btih-invalid:e8f320feb8215d29994b29b472e043b2f8469e77";
        let result = Magnet::from_uri(uri);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid 'xt' parameter format: Must start with 'urn:btih:'"
        );
    }

    #[test]
    fn test_invalid_info_hash_hex() {
        let uri = "magnet:?xt=urn:btih:thisisnothex";
        let result = Magnet::from_uri(uri);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid hex-encoded info hash");
    }

    #[test]
    fn test_info_hash_wrong_length() {
        let uri = "magnet:?xt=urn:btih:deadbeef";
        let result = Magnet::from_uri(uri);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Info hash must be 20 bytes long");
    }
}
