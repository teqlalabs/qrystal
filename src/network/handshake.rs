// src/network/handshake.rs
use std::net::TcpStream;
use std::io::{Read, Write};
use serde::{Serialize, Deserialize};
use bincode;

use crate::core::types::{PublicKey, Signature as QrystalSignature};
use pqcrypto_dilithium::dilithium5::{
    sign as dilithium_sign,
    SecretKey as DilithiumSecretKey,
    PublicKey as DilithiumPublicKey,
    SignedMessage as DilithiumSignedMessage,
};
use pqcrypto_traits::sign::SignedMessage;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HandshakeMessage {
    pub node_id: PublicKey,
    pub timestamp: u64,
    pub challenge: [u8; 32],
    pub signature: QrystalSignature,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HandshakeResponse {
    pub node_id: PublicKey,
    pub timestamp: u64,
    pub challenge_response: [u8; 32],
    pub signature: QrystalSignature,
}

#[derive(Clone)]
pub struct PqcHandshake {
    pub node_id: PublicKey,
    pub secret_key: DilithiumSecretKey,
    pub public_key: DilithiumPublicKey,
}

impl PqcHandshake {
    pub fn new(node_id: PublicKey, secret_key: DilithiumSecretKey, public_key: DilithiumPublicKey) -> Self {
        PqcHandshake {
            node_id,
            secret_key,
            public_key,
        }
    }

    /// Gera uma mensagem de handshake para iniciar conexão
    pub fn create_handshake(&self) -> Result<HandshakeMessage, String> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("Erro no timestamp: {}", e))?
            .as_secs();

        // Gerar challenge aleatório
        let mut challenge = [0u8; 32];
        getrandom::getrandom(&mut challenge)
            .map_err(|e| format!("Falha ao gerar challenge: {}", e))?;

        // Criar mensagem para assinar
        let message_data = Self::create_signing_data(&self.node_id, timestamp, &challenge);
        
        // Assinar com Dilithium5
        let pqc_signature = dilithium_sign(&message_data, &self.secret_key);
        
        // Usar trait SignedMessage
        let sig_bytes = pqc_signature.as_bytes();

        // Converter para QrystalSignature
        let mut final_sig = [0u8; 4595];
        let copy_len = std::cmp::min(final_sig.len(), sig_bytes.len());
        final_sig[..copy_len].copy_from_slice(&sig_bytes[..copy_len]);

        Ok(HandshakeMessage {
            node_id: self.node_id,
            timestamp,
            challenge,
            signature: QrystalSignature(final_sig),
        })
    }

    /// Processa um handshake recebido e gera resposta
    pub fn process_handshake(
        &self, 
        handshake: &HandshakeMessage,
        _peer_public_key: &DilithiumPublicKey
    ) -> Result<HandshakeResponse, String> {
        // Verificar timestamp (prevenir replay attacks)
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if current_time.abs_diff(handshake.timestamp) > 300 {
            return Err("Handshake expirado".to_string());
        }

        // 👇 VERIFICAÇÃO SIMPLIFICADA POR ENQUANTO
        // Criar signed message para verificar estrutura (sem validação criptográfica por enquanto)
        let _signed_msg = DilithiumSignedMessage::from_bytes(&handshake.signature.0)
            .map_err(|e| format!("Falha ao criar signed message: {}", e))?;

        println!("🔐 Handshake PQC: Assinatura recebida (validação criptográfica temporariamente desabilitada)");

        // Gerar resposta ao challenge
        let mut challenge_response = [0u8; 32];
        challenge_response.copy_from_slice(&handshake.challenge);
        challenge_response.reverse();

        let response_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Criar e assinar resposta
        let response_data = Self::create_signing_data(&self.node_id, response_timestamp, &challenge_response);
        let pqc_signature = dilithium_sign(&response_data, &self.secret_key);
        
        let sig_bytes = pqc_signature.as_bytes();

        let mut final_sig = [0u8; 4595];
        let copy_len = std::cmp::min(final_sig.len(), sig_bytes.len());
        final_sig[..copy_len].copy_from_slice(&sig_bytes[..copy_len]);

        Ok(HandshakeResponse {
            node_id: self.node_id,
            timestamp: response_timestamp,
            challenge_response,
            signature: QrystalSignature(final_sig),
        })
    }

    /// Verifica a resposta do handshake
    pub fn verify_handshake_response(
        &self,
        response: &HandshakeResponse,
        original_challenge: &[u8; 32],
        _peer_public_key: &DilithiumPublicKey
    ) -> Result<bool, String> {
        // Verificar se a resposta corresponde ao challenge original
        let mut expected_response = *original_challenge;
        expected_response.reverse();

        if response.challenge_response != expected_response {
            return Err("Resposta ao challenge inválida".to_string());
        }

        // 👇 VERIFICAÇÃO SIMPLIFICADA POR ENQUANTO
        let _signed_msg = DilithiumSignedMessage::from_bytes(&response.signature.0)
            .map_err(|e| format!("Falha ao criar signed message: {}", e))?;

        println!("🔐 Handshake PQC: Resposta recebida (validação criptográfica temporariamente desabilitada)");
        
        Ok(true)
    }

    /// Manipular conexão recebida (lado servidor)
    pub fn handle_incoming_connection(&self, stream: &mut TcpStream) -> Result<PublicKey, String> {
        // Ler handshake do cliente
        let mut size_buf = [0u8; 4];
        stream.read_exact(&mut size_buf)
            .map_err(|e| format!("Falha ao ler tamanho do handshake: {}", e))?;
        let handshake_size = u32::from_be_bytes(size_buf) as usize;
        
        let mut handshake_buf = vec![0u8; handshake_size];
        stream.read_exact(&mut handshake_buf)
            .map_err(|e| format!("Falha ao ler handshake: {}", e))?;
        
        let handshake_msg: HandshakeMessage = bincode::deserialize(&handshake_buf)
            .map_err(|e| format!("Falha ao desserializar handshake: {}", e))?;
        
        // TODO: Obter chave pública do peer 
        let peer_public_key = self.public_key.clone(); // 👈 TEMPORÁRIO
        
        let response = self.process_handshake(&handshake_msg, &peer_public_key)?;
        
        // Enviar resposta
        let encoded_response = bincode::serialize(&response)
            .map_err(|e| format!("Falha ao serializar resposta: {}", e))?;
        
        let response_size = encoded_response.len() as u32;
        stream.write_all(&response_size.to_be_bytes())
            .map_err(|e| format!("Falha ao enviar tamanho da resposta: {}", e))?;
        
        stream.write_all(&encoded_response)
            .map_err(|e| format!("Falha ao enviar resposta: {}", e))?;
        
        Ok(handshake_msg.node_id)
    }

    /// Cria dados para assinatura
    fn create_signing_data(node_id: &PublicKey, timestamp: u64, challenge: &[u8; 32]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(node_id.as_ref());
        data.extend_from_slice(&timestamp.to_be_bytes());
        data.extend_from_slice(challenge);
        data
    }
}

// Implementar Debug manualmente para PqcHandshake
impl std::fmt::Debug for PqcHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqcHandshake")
            .field("node_id", &hex::encode(self.node_id.as_ref().split_at(8).0))
            .field("has_secret_key", &true)
            .field("has_public_key", &true)
            .finish()
    }
}