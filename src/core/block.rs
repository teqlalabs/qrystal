// src/core/block.rs
use serde::{Serialize, Deserialize};
use crate::core::transaction::Transaction;
use crate::core::types::{Hash, VrfValue, VrfProof, PublicKey, Signature, DILITHIUM5_SIGNATURE_SIZE};
use blake3::Hash as Blake3Hash;

// 👇 IMPORTAR TRAITS NECESSÁRIOS
use pqcrypto_traits::sign::{SignedMessage, PublicKey as PqcPublicKey};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub parent_hash: Hash, 
    pub block_height: u64,
    pub timestamp: u64,
    pub vrf_value: VrfValue,
    pub vrf_proof: VrfProof,
    pub proposer_key: PublicKey, 
    pub merkle_root: Hash,
    pub block_signature: Signature,
    pub finality_votes: Vec<Signature>, 
}

impl BlockHeader {
    pub fn calculate_hash(&self) -> Hash {
        let mut header_clone = self.clone();
        header_clone.finality_votes = Vec::new();
        
        let bytes = bincode::serialize(&header_clone).expect("Failed to serialize header");
        let blake3_hash = blake3::hash(&bytes);
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(blake3_hash.as_bytes());
        Hash(hash_array)
    }

    pub fn calculate_hash_for_voting(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(self.parent_hash.as_bytes());
        data.extend_from_slice(self.merkle_root.as_bytes());
        data.extend_from_slice(&self.block_height.to_le_bytes()); 
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&self.vrf_value.0);
        data.extend_from_slice(&self.vrf_proof.0);
        let blake3_hash = blake3::hash(&data);
        blake3_hash.into()
    }

    pub fn sign_with_dilithium(&mut self, secret_key: &pqcrypto_dilithium::dilithium5::SecretKey) -> Result<(), String> {
        let message = self.calculate_hash_for_voting();
        let signed_message = pqcrypto_dilithium::dilithium5::sign(&message.as_bytes(), secret_key);
        
        // 👇 CORREÇÃO: Usar trait SignedMessage
        let signature_bytes = signed_message.as_bytes();
        if signature_bytes.len() != DILITHIUM5_SIGNATURE_SIZE {
            return Err(format!("Tamanho de assinatura inválido: {}", signature_bytes.len()));
        }
        
        let mut signature_array = [0u8; DILITHIUM5_SIGNATURE_SIZE];
        signature_array.copy_from_slice(signature_bytes);
        self.block_signature = Signature(signature_array);
        
        Ok(())
    }

    pub fn verify_dilithium_signature(&self) -> Result<(), String> {
        let _message = self.calculate_hash_for_voting(); // 👈 Adicionar underscore
        
        let signed_msg = pqcrypto_dilithium::dilithium5::SignedMessage::from_bytes(&self.block_signature.0)
            .map_err(|_| "Assinatura PQC inválida".to_string())?;
            
        let public_key = pqcrypto_dilithium::dilithium5::PublicKey::from_bytes(&self.proposer_key.0)
            .map_err(|_| "Chave pública PQC inválida".to_string())?;

        pqcrypto_dilithium::dilithium5::open(&signed_msg, &public_key)
            .map_err(|e| format!("Verificação PQC falhou: {}", e))?;

        Ok(())
        }
    }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn new_genesis_block(_initial_stakes: Vec<(PublicKey, u64)>) -> Self {
        let zero_hash = Hash(Blake3Hash::from_bytes([0u8; 32]).into());
        let zero_signature = Signature([0u8; DILITHIUM5_SIGNATURE_SIZE]);
        let zero_vrf_value = VrfValue([0u8; 32]);
        let zero_vrf_proof = VrfProof([0u8; 96]);
        let zero_public_key = PublicKey([0u8; 2592]);
        
        let header = BlockHeader {
            parent_hash: zero_hash,
            block_height: 0,
            timestamp: 0,
            vrf_value: zero_vrf_value,
            vrf_proof: zero_vrf_proof,
            proposer_key: zero_public_key, 
            finality_votes: Vec::new(),
            merkle_root: zero_hash,
            block_signature: zero_signature,
        };
        
        Block {
            header,
            transactions: Vec::new(),
        }
    }

    pub fn new_signed_block(
        parent_hash: Hash,
        block_height: u64,
        timestamp: u64,
        vrf_value: VrfValue,
        vrf_proof: VrfProof,
        proposer_key: PublicKey,
        merkle_root: Hash,
        transactions: Vec<Transaction>,
        secret_key: &pqcrypto_dilithium::dilithium5::SecretKey,
    ) -> Result<Self, String> {
        let mut header = BlockHeader {
            parent_hash,
            block_height,
            timestamp,
            vrf_value,
            vrf_proof,
            proposer_key,
            merkle_root,
            finality_votes: Vec::new(),
            block_signature: Signature([0u8; DILITHIUM5_SIGNATURE_SIZE]),
        };

        header.sign_with_dilithium(secret_key)?;
        Ok(Block { header, transactions })
    }
    
    pub fn calculate_hash(&self) -> Hash {
        self.header.calculate_hash()
    }
    
    #[allow(dead_code)]
    pub fn get_hash(&self) -> Hash {
        self.calculate_hash()
    }

    pub fn verify_all_pqc_signatures(&self) -> Result<(), String> {
        self.header.verify_dilithium_signature()?;

        for tx in &self.transactions {
            tx.verify_signature_pqc()?;
        }

        println!("🔐 Todas as assinaturas PQC verificadas com sucesso");
        Ok(())
    }
}