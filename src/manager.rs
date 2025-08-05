// src/manager.rs

use crate::torrent::BlockInfo;
use tokio::sync::oneshot;

/// A message sent FROM a peer session TO the central manager task.
#[derive(Debug)]
pub enum ToManager {
    /// Request to find a block for this peer to download.
    RequestBlock {
        peer_bitfield: Vec<u8>,
        response_tx: oneshot::Sender<Option<BlockInfo>>,
    },
    /// Sent when a peer has successfully received a block.
    BlockComplete { info: BlockInfo, data: Vec<u8> },
    /// Sent when a peer sends a `Have` message, to update the global rarity.
    UpdateRarity(usize),
    /// Sent when a peer provides its initial bitfield.
    UpdateRarityFromBitfield(Vec<u8>),
}

/// A message sent FROM the central manager task TO a specific peer session.
#[derive(Debug)]
pub enum FromManager {
    // This enum is not used in our current model, but is kept for future extensions.
}
