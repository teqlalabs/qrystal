// src/consensus/block_creator.rs
use crate::core::block::{Block, BlockHeader};
use crate::core::transaction::Transaction;
use crate::core::types::{Hash, VrfProof, PublicKey, Signature, DILITHIUM5_SIGNATURE_SIZE}; 
use blake3::Hash as Blake3Hash;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct BlockCreator {
    secret_key: ed25519_dalek::SigningKey,
    dilithium_secret_key: pqcrypto_dilithium::dilithium5::SecretKey,
    dilithium_public_key: pqcrypto_dilithium::dilithium5::PublicKey,
    pub public_key: PublicKey, 
    stake: u64,
}

impl BlockCreator {
    pub fn new(secret_key: ed25519_dalek::SigningKey, public_key: PublicKey, stake: u64) -> Self {
        use pqcrypto_dilithium::dilithium5::keypair as dilithium_keypair;
        let (dilithium_pk, dilithium_sk) = dilithium_keypair();
        
        BlockCreator {
            secret_key,
            dilithium_secret_key: dilithium_sk,
            dilithium_public_key: dilithium_pk,
            public_key,
            stake,
        }
    }

    pub fn new_pqc(
        secret_key: ed25519_dalek::SigningKey, 
        public_key: PublicKey, 
        stake: u64,
        dilithium_secret_key: pqcrypto_dilithium::dilithium5::SecretKey,
        dilithium_public_key: pqcrypto_dilithium::dilithium5::PublicKey,
    ) -> Self {
        BlockCreator {
            secret_key,
            dilithium_secret_key,
            dilithium_public_key,
            public_key,
            stake,
        }
    }

    pub fn try_create_block(
        &self, 
        previous_block_hash: Hash, 
        transactions: Vec<Transaction>,
        height: u64
    ) -> Option<Block> {
        
        println!("🔐 Criando bloco PQC #{} (VRF temporariamente desabilitado)", height);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let zero_hash = Hash(Blake3Hash::from_bytes([0u8; 32]).into());
        let zero_signature = Signature([0u8; DILITHIUM5_SIGNATURE_SIZE]);
        let zero_vrf_value = crate::core::types::VrfValue([0u8; 32]);
        let zero_vrf_proof = VrfProof([0u8; 96]);
        
        let mut header = BlockHeader {
            parent_hash: previous_block_hash,
            block_height: height,
            proposer_key: self.public_key, 
            merkle_root: zero_hash,
            timestamp,
            block_signature: zero_signature, 
            finality_votes: Vec::new(), 
            vrf_value: zero_vrf_value,
            vrf_proof: zero_vrf_proof, 
        };

        // ✅ CORREÇÃO: Assinar com Dilithium diretamente (sem método sign_with_dilithium)
        use pqcrypto_dilithium::dilithium5::sign as dilithium_sign;
        use pqcrypto_traits::sign::SignedMessage as PqcSignedMessageTrait;
        
        let message = header.calculate_hash();
        let pqc_signature = dilithium_sign(&message.as_bytes(), &self.dilithium_secret_key);
        let sig_bytes = pqc_signature.as_bytes();
        
        // Converter para array fixo de 4595 bytes
        let mut final_sig = [0u8; 4595];
        let copy_len = std::cmp::min(final_sig.len(), sig_bytes.len());
        final_sig[..copy_len].copy_from_slice(&sig_bytes[..copy_len]);
        
        header.block_signature = Signature(final_sig);

        let block = Block {
            header,
            transactions,
        };
        
        println!("✅ Bloco #{} assinado com PQC (Dilithium5) - {} bytes", height, copy_len);
        Some(block)
    }

    pub fn get_secret_key(&self) -> &ed25519_dalek::SigningKey {
        &self.secret_key
    }

    pub fn get_dilithium_secret_key(&self) -> &pqcrypto_dilithium::dilithium5::SecretKey {
        &self.dilithium_secret_key
    }

    pub fn create_signed_transaction(
        &self,
        to: PublicKey,
        amount: u64,
        nonce: u64,
    ) -> Result<Transaction, String> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        Transaction::create_signed_transaction(
            self.public_key,
            to,
            amount,
            nonce,
            timestamp,
            &self.dilithium_secret_key,
        )
    }
    pub fn get_dilithium_public_key(&self) -> &pqcrypto_dilithium::dilithium5::PublicKey {
        &self.dilithium_public_key
    }
}