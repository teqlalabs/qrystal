// src/consensus/proof_of_randomness.rs

use crate::core::types::{Hash, VrfValue};
use crate::consensus::vrf;
use ed25519_dalek::{
    SigningKey as EdSecretKey,
    VerifyingKey as EdPublicKey,
};

/// The Eligibility Threshold (T) is a numeric value.
/// A node can only propose a block if its VRF value (V) is less than the threshold (T).
///
/// V < T * Hmax / S
/// Where:
///   - V: VRF Value (the node's random number)
///   - Hmax: The maximum possible value for the VRF Value (2^256 for our 32-byte hash)
///   - S: The node's total Stake. For simplicity, we use 1 (minimum participation).
///   - T: Eligibility Target threshold (e.g., 0.001)

// The base Eligibility Threshold (Target)
const ELIGIBILITY_TARGET: f64 = 0.0001; // 0.01% base chance to be elected

// The maximum value for a 32-byte VRF Value (2^256)
// NOTE: This is a SIMPLIFICATION. We use f64::MAX for comparison.
const HASH_MAX_F64: f64 = f64::MAX; 


/// Main function to determine if a node is eligible to propose the block.
/// This function is called after VRF generation.
pub fn is_eligible_proposer(
    vrf_value: &VrfValue,
    stake: u64,
) -> bool {
    
    // 1. Convert the VRF Value (32 bytes) to a float for comparison.
    // NOTE: In a real blockchain, this comparison would use 256-bit
    // integers (U256) to avoid precision loss. For learning, we treat
    // the first 8 bytes (u64) as the value.
    
    // Get the first 8 bytes (u64) of the VRF Value
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&vrf_value.0[0..8]);
    let vrf_value_u64 = u64::from_le_bytes(bytes);
    
    let vrf_value_f64 = vrf_value_u64 as f64;
    
    // 2. Define the Required Target Threshold
    // Formula: Threshold = Target * Stake
    // Simplification: Multiply the base target by the stake to increase chance
    let adjusted_target = ELIGIBILITY_TARGET * (stake as f64);
    
    // 3. The node is eligible if its VRF Value is less than the Threshold.
    // Probability = VRF_Value / HASH_MAX
    // Condition: Probability < Adjusted_Target
    
    if vrf_value_f64 == 0.0 {
        // If VRF value is zero, it's eligible (minimum chance)
        return true;
    }
    
    let probability = vrf_value_f64 / HASH_MAX_F64;
    
    probability < adjusted_target
}


/// Combines VRF generation and eligibility checking.
/// Returns the VrfValue and VrfProof (Hash) if eligible.
pub fn check_eligibility(
    secret_key: &EdSecretKey,
    _public_key: &EdPublicKey,
    stake: u64,
    previous_hash: Hash,
) -> Option<(VrfValue, [u8; 96])> {
    
    // 1. Generate the VRF (Value and Proof) using the previous block hash (seed)
    let (vrf_value, vrf_proof) = vrf::generate_vrf(
        secret_key, 
        previous_hash
    );

    // 2. Check if the node is eligible to propose
    if is_eligible_proposer(&vrf_value, stake) {
        // If eligible, return the value and proof (hash) for inclusion in the block
        // The compiler now expects [u8; 96], and vrf_proof.0 is [u8; 96]
        Some((vrf_value, vrf_proof.0))
    } else {
        None
    }
}