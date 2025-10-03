// src/core/transaction.rs
use serde::{Serialize, Deserialize};
use crate::core::types::{PublicKey, Signature, Hash, DILITHIUM5_SIGNATURE_SIZE};
use blake3;

// ✅ CORREÇÃO: Importar os traits necessários
use pqcrypto_traits::sign::{SignedMessage, PublicKey as PqcPublicKey};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Transaction {
    pub from: PublicKey,
    pub to: PublicKey,
    pub amount: u64,
    pub nonce: u64,
    pub timestamp: u64,
    pub signature: Signature, 
}

impl Transaction {
    #[allow(dead_code)] 
    pub fn calculate_hash(&self) -> Hash {
        let bytes = bincode::serialize(&self).expect("Falha ao serializar transação para hash");
        blake3::hash(&bytes).into()
    }
    
    pub fn calculate_hash_for_signing(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&self.from.0);
        data.extend_from_slice(&self.to.0);
        data.extend_from_slice(&self.nonce.to_le_bytes()); 
        data.extend_from_slice(&self.timestamp.to_le_bytes()); 
        data.extend_from_slice(&self.amount.to_le_bytes());
        let blake3_hash = blake3::hash(&data);
        Hash(blake3_hash.into())
    }

    pub fn sign_with_dilithium(&mut self, secret_key: &pqcrypto_dilithium::dilithium5::SecretKey) -> Result<(), String> {
        let message = self.calculate_hash_for_signing();
        let signed_message = pqcrypto_dilithium::dilithium5::sign(&message.as_bytes(), secret_key);
        
        // ✅ CORREÇÃO: Usar o trait SignedMessage
        let signature_bytes = signed_message.as_bytes();
        if signature_bytes.len() != DILITHIUM5_SIGNATURE_SIZE {
            return Err(format!("Tamanho de assinatura inválido: {}", signature_bytes.len()));
        }
        
        let mut signature_array = [0u8; DILITHIUM5_SIGNATURE_SIZE];
        signature_array.copy_from_slice(signature_bytes);
        self.signature = Signature(signature_array);
        
        Ok(())
    }

    pub fn verify_signature_pqc(&self) -> Result<(), String> {
        let _message = self.calculate_hash_for_signing();
        
        // ✅ CORREÇÃO: Usar o trait SignedMessage
        let signed_msg = pqcrypto_dilithium::dilithium5::SignedMessage::from_bytes(&self.signature.0)
            .map_err(|_| "Assinatura PQC inválida".to_string())?;

        // ✅ CORREÇÃO: Usar o trait PublicKey
        let public_key = pqcrypto_dilithium::dilithium5::PublicKey::from_bytes(&self.from.0)
            .map_err(|_| "Chave pública PQC inválida".to_string())?;

        // ✅ CORREÇÃO: open() precisa da chave pública
        let _verified_message = pqcrypto_dilithium::dilithium5::open(&signed_msg, &public_key)
            .map_err(|e| format!("Verificação PQC falhou: {}", e))?;

        Ok(())
    }

    #[allow(dead_code)]
    pub fn verify_signature(&self) -> Result<(), &'static str> {
        self.verify_signature_pqc()
            .map_err(|_| "Assinatura inválida. A transação foi forjada ou alterada.")
    }

    pub fn create_signed_transaction(
        from: PublicKey,
        to: PublicKey,
        amount: u64,
        nonce: u64,
        timestamp: u64,
        secret_key: &pqcrypto_dilithium::dilithium5::SecretKey,
    ) -> Result<Self, String> {
        let mut transaction = Transaction {
            from,
            to,
            amount,
            nonce,
            timestamp,
            signature: Signature([0u8; DILITHIUM5_SIGNATURE_SIZE]),
        };

        transaction.sign_with_dilithium(secret_key)?;
        Ok(transaction)
    }

    pub fn verify_signature_pqc_with_key(&self, public_key: &pqcrypto_dilithium::dilithium5::PublicKey) -> Result<(), String> {
        let _message = self.calculate_hash_for_signing(); // 👈 Adicione underscore
    
        let signed_msg = pqcrypto_dilithium::dilithium5::SignedMessage::from_bytes(&self.signature.0)
            .map_err(|_| "Assinatura PQC inválida".to_string())?;

        let _verified_message = pqcrypto_dilithium::dilithium5::open(&signed_msg, public_key)
            .map_err(|e| format!("Verificação PQC falhou: {}", e))?;

         Ok(())
    }
}