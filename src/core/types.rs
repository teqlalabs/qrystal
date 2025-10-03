// src/core/types.rs
use blake3::Hash as Blake3Hash;
use serde::{Serialize, Deserialize};

// 👇 TAMANHOS FIXOS para Dilithium5
pub const DILITHIUM5_PUBLIC_KEY_SIZE: usize = 2592;
pub const DILITHIUM5_SECRET_KEY_SIZE: usize = 4864; 
pub const DILITHIUM5_SIGNATURE_SIZE: usize = 4595; // SignedMessage size

// --- HASH ---
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Hash(pub [u8; 32]);

impl From<Blake3Hash> for Hash {
    fn from(hash: Blake3Hash) -> Self {
        Hash(*hash.as_bytes()) 
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Hash {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// --- CHAVES E ASSINATURAS PQC ---
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct PublicKey(
    #[serde(with = "serde_bytes")]
    pub [u8; DILITHIUM5_PUBLIC_KEY_SIZE]
);

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Signature(
    #[serde(with = "serde_bytes")]
    pub [u8; DILITHIUM5_SIGNATURE_SIZE]
);

// --- VRF TYPES ---
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct VrfValue(
    #[serde(with = "serde_bytes")]
    pub [u8; 32]
); 

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct VrfProof(
    #[serde(with = "serde_bytes")]
    pub [u8; 96]
); 

pub type NodeId = PublicKey;