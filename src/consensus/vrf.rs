// src/consensus/vrf.rs
use ed25519_dalek::{
    Signer, Verifier,
    SigningKey,
    VerifyingKey,
    Signature,
};
use rand::RngCore;
use rand::rngs::OsRng;
use core::convert::TryFrom;

use crate::core::types::{Hash, VrfProof, VrfValue, PublicKey};
use blake3::Hasher;

// A semente (seed) de entrada deve ser o hash do bloco anterior
pub type VrfSeed = Hash; 

/// Gera uma nova chave pública/privada (keypair) para um nó.
pub fn generate_keypair() -> (VerifyingKey, SigningKey) {
    let mut secret_key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_key_bytes);

    // ✅ CORREÇÃO: Usar SigningKey::from_bytes diretamente
    let signing_key = SigningKey::from_bytes(&secret_key_bytes);
    let public_key = signing_key.verifying_key();
    
    (public_key, signing_key)
}

/// Executa o Verifiable Random Function (VRF).
pub fn generate_vrf(secret_key: &SigningKey, seed: Hash) -> (VrfValue, VrfProof) {
    let signature = secret_key.sign(seed.as_ref());

    // 1. Prova (Proof) é a Assinatura (Signature)
    let proof_slice = signature.to_bytes();
    let mut proof_array = [0u8; 96];
    proof_array[0..64].copy_from_slice(&proof_slice);
    
    // 2. Valor (Value) é o Hash da Prova
    let value_hash = blake3::hash(&proof_array);
    let mut value_array = [0u8; 32];
    value_array.copy_from_slice(value_hash.as_bytes());

    (VrfValue(value_array), VrfProof(proof_array))
}

/// Verifica se a Prova VRF é válida para a Chave Pública e a Semente (Seed).
pub fn verify_vrf(public_key: &VerifyingKey, seed: Hash, value: &VrfValue, proof: &VrfProof) -> bool {
    // 1. Recalcula o Hash do Valor a partir da Prova (Proof)
    let value_hash = blake3::hash(&proof.0); 
    let mut calculated_value_array = [0u8; 32];
    calculated_value_array.copy_from_slice(value_hash.as_bytes());

    // 2. Verifica se o valor recalculado bate com o valor fornecido
    if value.0 != calculated_value_array { 
        return false;
    }
    
    // 3. Verifica a assinatura/prova criptograficamente
    let signature_result = Signature::try_from(&proof.0[0..64]);
    
    if let Ok(signature) = signature_result {
        public_key.verify(seed.as_ref(), &signature).is_ok()
    } else {
        false
    }
}

/// Deriva um par de chaves Ed25519 a partir de uma chave pública Dilithium
pub fn derive_ed25519_from_dilithium(dilithium_pubkey: &PublicKey) -> Option<(VerifyingKey, SigningKey)> {
    // Usar o hash Blake3 do pubkey Dilithium como seed determinística
    let mut hasher = Hasher::new();
    hasher.update(dilithium_pubkey.as_ref());
    let derived_seed = hasher.finalize();
    
    // Gerar chave Ed25519 determinística a partir do seed
    let mut secret_key_bytes = [0u8; 32];
    secret_key_bytes.copy_from_slice(&derived_seed.as_bytes()[..32]);
    
    // ✅ CORREÇÃO: Usar SigningKey::from_bytes diretamente
    let signing_key = SigningKey::from_bytes(&secret_key_bytes);
    let public_key = signing_key.verifying_key();
    
    Some((public_key, signing_key))
}