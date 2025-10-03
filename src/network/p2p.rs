use std::collections::{HashMap};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::io::{Read, Write};

//use serde::{Serialize, Deserialize};
//use bincode;

//use crate::core::block::Block;
//use crate::core::transaction::Transaction;
//use crate::core::types::{PublicKey, Hash, Signature as QrystalSignature};
use crate::core::types::PublicKey;
use crate::network::handshake::{PqcHandshake, HandshakeResponse};

// Adicionar getrandom ao Cargo.toml
//use getrandom::getrandom;

#[derive(Debug, Clone)]
pub struct Peer {
    pub node_id: PublicKey,
    pub address: SocketAddr,
    pub last_seen: u64,
    pub peer_score: f64,
    pub authenticated: bool, // 👈 NOVO: Se passou pelo handshake PQC
}

#[derive(Debug)]
pub struct P2PNetwork {
    pub peers: Arc<Mutex<HashMap<PublicKey, Peer>>>,
    pub bootstrap_nodes: Vec<SocketAddr>,
    pub listening_port: u16,
    pub node_id: PublicKey,
    pub handshake: PqcHandshake, // 👈 NOVO: Gerenciador de handshake PQC
}

impl P2PNetwork {
    pub fn new(
        node_id: PublicKey, 
        port: u16, 
        bootstrap_nodes: Vec<SocketAddr>,
        secret_key: pqcrypto_dilithium::dilithium5::SecretKey,
        public_key: pqcrypto_dilithium::dilithium5::PublicKey
    ) -> Self {
        let handshake = PqcHandshake::new(node_id, secret_key, public_key);
        
        P2PNetwork {
            peers: Arc::new(Mutex::new(HashMap::new())),
            bootstrap_nodes,
            listening_port: port,
            node_id,
            handshake,
        }
    }
    
    // 👇 ADICIONAR ESTE MÉTODO start() PUBLICO
    pub fn start(&self) -> Result<(), String> {
        println!("🌐 Iniciando rede P2P na porta {}...", self.listening_port);
        
        self.start_server()?;
        self.connect_to_bootstrap_nodes()?;
        
        println!("✅ Rede P2P inicializada com sucesso");
        Ok(())
    }
    
    fn start_server(&self) -> Result<(), String> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.listening_port))
            .map_err(|e| format!("Falha ao bind na porta {}: {}", self.listening_port, e))?;
        
        let peers_clone = self.peers.clone();
        let handshake_clone = self.handshake.clone(); // 👈 Clonar handshake para a thread
        
        thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(mut stream) => {
                        let peer_addr = stream.peer_addr().unwrap();
                        println!("🔗 Nova conexão recebida: {}", peer_addr);
                        
                        // 👇 NOVO: Processar handshake PQC
                        match handshake_clone.handle_incoming_connection(&mut stream) {
                            Ok(peer_id) => {
                                println!("✅ Handshake PQC bem-sucedido com: {} ({})", 
                                         hex::encode(peer_id.as_ref().split_at(8).0), peer_addr);
                                
                                let mut peers = peers_clone.lock().unwrap();
                                peers.insert(peer_id, Peer {
                                    node_id: peer_id,
                                    address: peer_addr,
                                    last_seen: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH).unwrap()
                                        .as_secs(),
                                    peer_score: 100.0,
                                    authenticated: true,
                                });
                            }
                            Err(e) => {
                                println!("❌ Handshake PQC falhou com {}: {}", peer_addr, e);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ Erro na conexão: {}", e);
                    }
                }
            }
        });
        
        Ok(())
    }
    
    fn connect_to_bootstrap_nodes(&self) -> Result<(), String> {
        for bootstrap_addr in &self.bootstrap_nodes {
            match TcpStream::connect_timeout(bootstrap_addr, Duration::from_secs(5)) {
                Ok(mut stream) => {
                    println!("🔗 Conectado ao bootstrap node: {}", bootstrap_addr);
                    
                    // 👇 NOVO: Realizar handshake PQC
                    match self.perform_handshake(&mut stream) {
                        Ok(peer_id) => {
                            println!("✅ Handshake PQC bem-sucedido com bootstrap: {}", 
                                     hex::encode(peer_id.as_ref().split_at(8).0));
                            
                            let mut peers = self.peers.lock().unwrap();
                            peers.insert(peer_id, Peer {
                                node_id: peer_id,
                                address: *bootstrap_addr,
                                last_seen: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH).unwrap()
                                    .as_secs(),
                                peer_score: 100.0,
                                authenticated: true,
                            });
                        }
                        Err(e) => {
                            println!("❌ Handshake com bootstrap falhou: {}", e);
                        }
                    }
                }
                Err(e) => {
                    println!("⚠️  Não foi possível conectar ao bootstrap {}: {}", bootstrap_addr, e);
                }
            }
        }
        Ok(())
    }
    
    /// 👇 NOVO MÉTODO: Realizar handshake como cliente
    fn perform_handshake(&self, stream: &mut TcpStream) -> Result<PublicKey, String> {
        use bincode;
        //use crate::network::handshake::HandshakeMessage;
        
        // Enviar handshake
        let handshake_msg = self.handshake.create_handshake()?;
        let encoded = bincode::serialize(&handshake_msg)
            .map_err(|e| format!("Falha ao serializar handshake: {}", e))?;
        
        // Enviar tamanho primeiro
        let size = encoded.len() as u32;
        stream.write_all(&size.to_be_bytes())
            .map_err(|e| format!("Falha ao enviar tamanho do handshake: {}", e))?;
        
        // Enviar handshake
        stream.write_all(&encoded)
            .map_err(|e| format!("Falha ao enviar handshake: {}", e))?;
        
        // Aguardar resposta
        let mut size_buf = [0u8; 4];
        stream.read_exact(&mut size_buf)
            .map_err(|e| format!("Falha ao ler tamanho da resposta: {}", e))?;
        let response_size = u32::from_be_bytes(size_buf) as usize;
        
        let mut response_buf = vec![0u8; response_size];
        stream.read_exact(&mut response_buf)
            .map_err(|e| format!("Falha ao ler resposta: {}", e))?;
        
        let response: HandshakeResponse = bincode::deserialize(&response_buf)
            .map_err(|e| format!("Falha ao desserializar resposta: {}", e))?;
        
        // TODO: Verificar resposta (precisamos da chave pública do peer)
        Ok(response.node_id)
    }

    pub fn broadcast_block(&self, block: &crate::core::block::Block) {
        let peers = self.peers.lock().unwrap();
        println!("📤 Broadcast do bloco #{} para {} peers", block.header.block_height, peers.len());
        
        for (peer_id, peer) in peers.iter() {
            if peer.authenticated {
                println!("  → Enviando para peer autenticado: {} ({})", 
                         hex::encode(peer_id.as_ref().split_at(8).0), peer.address);
            }
        }
    }
    
    pub fn get_peer_count(&self) -> usize {
        self.peers.lock().unwrap().len()
    }
}