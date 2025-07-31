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
        let params: HashMap<&str, Vec<&str>> = params_str.split('&').filter_map(|p| {
            let mut parts = p.splitn(2, '=');
            let key = parts.next()?;
            let value = parts.next()?;
            Some((key, value))
        }).fold(HashMap::new(), |mut acc, (k, v)| {
            acc.entry(k).or_default().push(v);
            acc
        });

        let xt = params.get("xt")
            .and_then(|v| v.first())
            .ok_or("Magnet URI is missing the 'xt' (info hash) parameter")?;

        if !xt.starts_with("urn:btih:") {
            return Err("Invalid 'xt' parameter format: Must start with 'urn:btih:'");
        }

        let info_hash_hex = &xt[9..];
        let info_hash_bytes = hex::decode(info_hash_hex).map_err(|_| "Invalid hex-encoded info hash")?;

        if info_hash_bytes.len() != 20 {
            return Err("Info hash must be 20 bytes long");
        }
        let mut info_hash = [0u8; 20];
        info_hash.copy_from_slice(&info_hash_bytes);

        let display_name = params.get("dn")
            .and_then(|v| v.first())
            .and_then(|s| urlencoding::decode(s).ok())
            .map(|cow| cow.into_owned());

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