use crate::core::types::{PublicKey as NodeId, VrfValue, VrfProof};
use std::collections::HashMap;

/// The fixed size of the BFT Committee.
/// It must be an odd number to guarantee a 2/3 majority.
/// A small number (like 9 or 15) is ideal for fast BFT communication.
const BFT_COMMITTEE_SIZE: usize = 21;

// --- Helper Structs for VRF Competition ---

/// Represents a node's entry in the VRF competition for a given block height.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VrfEntry {
    pub node_id: NodeId,
    pub vrf_value: VrfValue,
    pub vrf_proof: VrfProof,
}

// ----------------------------------------------------
// Core Selection Function
// ----------------------------------------------------

/// Selects the Proposer and the Rotating BFT Committee based on the VRF results.
///
/// The node with the absolute smallest VRF value wins the Proposer role.
/// The next K nodes with the smallest VRF values form the BFT Committee.
///
/// # Arguments
/// * `vrf_results` - A map of all active nodes' VrfEntries for the current epoch.
///
/// # Returns
/// A tuple containing: (Proposer's VrfEntry, BFT Committee VrfEntries)
pub fn select_proposer_and_committee(vrf_results: HashMap<NodeId, VrfEntry>) -> Option<(VrfEntry, Vec<VrfEntry>)> {
    // 1. Convert HashMap values into a vector for sorting
    let mut sorted_entries: Vec<VrfEntry> = vrf_results.into_values().collect();

    // 2. Sort the entries based on VrfValue (lexicographical comparison)
    sorted_entries.sort_by(|a, b| a.vrf_value.0.cmp(&b.vrf_value.0));

    // Ensure we have enough nodes for both the Proposer and the Committee
    if sorted_entries.len() < BFT_COMMITTEE_SIZE {
        return None;
    }

    // 3. Select the Proposer
     let proposer_entry = sorted_entries[0].clone();

    // 4. Select the BFT Committee
    let committee: Vec<VrfEntry> = sorted_entries
        .into_iter()
        .take(BFT_COMMITTEE_SIZE)
        .collect();

    Some((proposer_entry, committee))
}

