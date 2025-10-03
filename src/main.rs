// src/main.rs

// Importações de módulos e tipos
use std::collections::HashMap;
use qrystal::core::transaction::Transaction;
use qrystal::core::blockchain::Blockchain; 
use qrystal::core::types::{PublicKey as QrystalPublicKey, Signature as QrystalSignature};
use qrystal::network::P2PNetwork;
use std::thread;
use std::time::Duration;

// Importações dos módulos de consenso e utilitários
use qrystal::consensus::block_creator::BlockCreator; 
use qrystal::consensus::vrf::generate_keypair; 
use qrystal::db::DBManager; 

// Importações de crates externas
use blake3::Hasher as Blake3Hasher;
use hex; 
use rand::rngs::OsRng; 

// 👇 NOVAS IMPORTAÇÕES PQC CORRIGIDAS
use pqcrypto_dilithium::dilithium5::{
    keypair as dilithium_keypair, 
    sign as dilithium_sign,
    SecretKey as DilithiumSecretKey,
};
// ✅ CORREÇÃO FINAL: Importar todos os traits necessários
use pqcrypto_traits::sign::{
    PublicKey as PqcPublicKeyTrait, 
    SignedMessage as PqcSignedMessageTrait  // 👈 ADICIONAR ESTE
};

const TEST_VOTER_SEED: [u8; 32] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
];

const PERSISTENCE_PATH: &str = "qrystal_chain.dat";

fn main() {
    println!("--- QRYSTAL Proof of Randomness (PoRP) Node ---");
    println!("🔐 PQC SECURITY: Dilithium5 Active");

    // 👇 GERAR CHAVE PQC PARA TESTE (substitui ed25519)
    let (_test_voter_public_key, _test_voter_secret_key) = dilithium_keypair();

    // ----------------------------------------------------
    // 1. SETUP INICIAL: Geração de Chaves PQC e Stakes (14 Nós)
    // ----------------------------------------------------
    let mut full_node_data: Vec<(
        QrystalPublicKey, 
        ed25519_dalek::SigningKey, 
        u64, 
        DilithiumSecretKey, 
        pqcrypto_dilithium::dilithium5::PublicKey  // 👈 ADICIONAR
    )> = Vec::new();

    let min_stake: u64 = 1_000;
    let initial_stake: u64 = 10_000;

    // 1.1. O Nó Local - AGORA COM PQC
    let (_ed_public_key, secret_key) = generate_keypair();
    
    // 👇 CONVERSÃO PARA PQC: Gera par de chaves Dilithium
    let (dilithium_pk, dilithium_sk) = dilithium_keypair();
    
    // ✅ CORREÇÃO: Converter para array fixo [u8; 2592]
    let mut public_key_bytes = [0u8; 2592];
    let dilithium_bytes = dilithium_pk.as_bytes();
    public_key_bytes[..dilithium_bytes.len()].copy_from_slice(dilithium_bytes);
    let public_key = QrystalPublicKey(public_key_bytes);
    
    let node = BlockCreator::new_pqc(secret_key.clone(), public_key, initial_stake, dilithium_sk, dilithium_pk);
    full_node_data.push((public_key, secret_key, initial_stake, dilithium_sk, dilithium_pk));
    
    // 1.2. Os 13 Nós restantes - TODOS COM PQC
    for _i in 0..20 {
        let (_ed_public_key_i, secret_key_i) = generate_keypair();
        let (dilithium_pk_i, dilithium_sk_i) = dilithium_keypair();
        
        // ✅ CORREÇÃO: Converter para array fixo [u8; 2592]
        let mut public_key_bytes_i = [0u8; 2592];
        let dilithium_bytes_i = dilithium_pk_i.as_bytes();
        public_key_bytes_i[..dilithium_bytes_i.len()].copy_from_slice(dilithium_bytes_i);
        let public_key_i = QrystalPublicKey(public_key_bytes_i);
        
        let stake_i = 10_000;
        full_node_data.push((public_key_i, secret_key_i, stake_i, dilithium_sk_i, dilithium_pk_i)); 
    }

    // 1.3. Crie os BlockCreators (para o loop) - ATUALIZADO PARA PQC
    let all_creators: Vec<BlockCreator> = full_node_data
        .iter()
        .map(|(pub_key, sec_key, stake, dilithium_sk, dilithium_pk)| {

            BlockCreator::new_pqc(
                sec_key.clone(), 
                *pub_key, 
                *stake, 
                dilithium_sk.clone(),
                dilithium_pk.clone() // 👈 ADICIONAR este 5º argumento
        )
    })
        .collect();

    // 1.4. Crie o Mapa de Chaves Secretas PQC (14 chaves)
    let mut secret_key_map: HashMap<QrystalPublicKey, DilithiumSecretKey> = all_creators
        .iter()
        .map(|creator| (creator.public_key, creator.get_dilithium_secret_key().clone()))
        .collect();

    // 1.5. Crie a lista de stakes do Gênesis (14 stakes)
    let mut genesis_stakes: Vec<(QrystalPublicKey, u64)> = full_node_data
        .iter()
        .map(|(pub_key, _, stake, _, _)| (*pub_key, *stake))
        .collect();

    // ----------------------------------------------------
    // 2. CRIAÇÃO E INJEÇÃO DO NÓ TRANSACIONADOR (O 15º NÓ) - COM PQC
    // ----------------------------------------------------
    let _csprng = OsRng;
    
    // 👇 GERAR CHAVES PQC PARA O TRANSACIONADOR
    let (tx_dilithium_pk, tx_dilithium_sk) = dilithium_keypair();
    
    // ✅ CORREÇÃO: Converter para array fixo [u8; 2592]
    let mut tx_pk_bytes = [0u8; 2592];
    let tx_dilithium_bytes = tx_dilithium_pk.as_bytes();
    tx_pk_bytes[..tx_dilithium_bytes.len()].copy_from_slice(tx_dilithium_bytes);
    let tx_signer_public_key = QrystalPublicKey(tx_pk_bytes);
    
    // ✅ CORREÇÃO: Criar hash Blake3 corretamente como array fixo
    let mut hasher = Blake3Hasher::new();
    hasher.update(b"test_address");
    let tx_to_hash = hasher.finalize();
    let mut tx_to_bytes = [0u8; 2592];
    tx_to_bytes[..32].copy_from_slice(tx_to_hash.as_bytes()); // Blake3 gera 32 bytes
    let tx_to_pub = QrystalPublicKey(tx_to_bytes);

    // COMPLETE OS MAPAS E LISTAS COM O NÓ TRANSACIONADOR PQC
    secret_key_map.insert(tx_signer_public_key, tx_dilithium_sk.clone());
    genesis_stakes.push((tx_signer_public_key, 200));

    println!("\nNode Public Key: {}", hex::encode(node.public_key.as_ref())); 
    println!("Node Stake: {}", initial_stake);
    println!("🔐 Crypto: Dilithium5 PQC\n");

    // ----------------------------------------------------
    // 3. INICIALIZAR OU CARREGAR A BLOCKCHAIN (Injeção de DB e Mapas)
    // ----------------------------------------------------
    let db_manager_result = DBManager::new();
    if db_manager_result.is_err() {
        panic!("Falha crítica ao inicializar o DBManager: {}", db_manager_result.unwrap_err());
    }
    
    let db_manager_ref = db_manager_result.unwrap();

    let mut qrystal_chain = match Blockchain::load_from_disk(PERSISTENCE_PATH) {
        Ok(mut chain) => {
            println!("✅ Sucesso! Cadeia carregada de '{}'.", PERSISTENCE_PATH);
            
            // Injeção de DB e Chaves Secretas PQC
            chain.db_manager = Some(db_manager_ref);
            chain.dilithium_secret_key_map = secret_key_map.clone(); // 👈 MAPA PQC

            // CRÍTICO: Substitui o stakes_map carregado (pode estar obsoleto) pelo conjunto completo de 15 nós.
            chain.stakes_map.clear();
            for (pub_key, stake) in genesis_stakes.iter() {
                chain.stakes_map.insert(*pub_key, *stake);
            }

            chain
        },
        Err(e) => {
            println!("⚠️ Aviso: {}. Criando nova Blockchain (Gênesis)...", e);
            let mut chain = Blockchain::new(Some(db_manager_ref), min_stake, genesis_stakes);
            chain.dilithium_secret_key_map = secret_key_map.clone(); // 👈 MAPA PQC
        
            if let Err(save_e) = chain.save_to_disk(PERSISTENCE_PATH) {
                panic!("Falha ao salvar o Gênesis no disco: {}", save_e);
            }
            chain
        }
    };

    println!("--- Rede simulada com {} nós ---\n", qrystal_chain.stakes_map.len());
    println!("🔐 Todos os nós usando criptografia Pós-Quântica (Dilithium5)");

    // Obter chaves PQC do nó local
    // let dilithium_pk = /* obter do nó local */;

    // Inicializar rede P2P
    let bootstrap_nodes = vec![]; // 👈 Começar vazio para testes
    let (_, _, _, dilithium_sk, dilithium_pk) = &full_node_data[0];
    let p2p_network = P2PNetwork::new(
    public_key, 
    9333, 
    bootstrap_nodes,
    dilithium_sk.clone(),
    dilithium_pk.clone()
);

    match p2p_network.start() {
        Ok(()) => println!("🌐 Rede P2P inicializada na porta 9333"),
        Err(e) => println!("❌ Falha na rede P2P: {}", e),
    }

    println!("--- Iniciando o Loop de Consenso (Simulação) ---");

    // ----------------------------------------------------
    // 4. LOOP PRINCIPAL DE CONSENSO (SIMULAÇÃO) - ATUALIZADO PARA PQC
    // ----------------------------------------------------
    println!("--- Iniciando o Loop de Consenso (Simulação) ---");

    let start_height = qrystal_chain.get_latest_block().header.block_height + 1;
    for _block_num in start_height..=(start_height + 5) { 
        let latest_block = qrystal_chain.get_latest_block();
        let previous_hash = latest_block.header.calculate_hash();
        let next_height = latest_block.header.block_height + 1;

        println!("\n=======================================================");
        println!("--- TENTATIVA DE CRIAÇÃO: Bloco #{} (Base: {}) ---", next_height, hex::encode(previous_hash.as_ref().split_at(8).0));
        println!("=======================================================");

        // ----------------------------------------------------
        // 4.1. Seleção do Proposer e Comitê
        // ----------------------------------------------------
        let (proposer_entry, committee_nodes) = match qrystal_chain.select_next_committee(next_height) {
            Some((p, c)) => (p, c),
            None => {
                println!("❌ FALHA DE SELEÇÃO: Não há stakes suficientes para formar o Comitê BFT. Parando loop.");
                break;
            }
        };

        let proposer_pk = proposer_entry.node_id;
        println!("-> Proposer Escolhido para Bloco #{}: {}", next_height, hex::encode(proposer_pk.as_ref()));
        println!("-> Comitê BFT Escolhido ({} membros)", committee_nodes.len());
        
        // Obter o BlockCreator COMPLETO do Proposer selecionado
        let proposer_creator = all_creators.iter() 
            .chain(std::iter::once(&node)) // Adiciona o nó principal
            .find(|creator| creator.public_key == proposer_pk)
            .unwrap_or_else(|| {
                 panic!("ERRO CRÍTICO: Proposer selecionado não encontrado na lista de BlockCreators simulados.");
            });
        
        // ----------------------------------------------------
        // 4.2. CRIAÇÃO DE TRANSAÇÕES - AGORA COM ASSINATURA PQC
        // ----------------------------------------------------
        let pending_tx = if next_height == 1 {
            // ✅ CORREÇÃO: Assinatura como array fixo [u8; 4595]
            let signature_bytes = [0u8; 4595];
            
            let mut tx_to_sign = Transaction {
                from: tx_signer_public_key,
                to: tx_to_pub, 
                amount: 50,
                nonce: 1, 
                timestamp: 1700000000 + next_height as u64,
                signature: QrystalSignature(signature_bytes), // Array fixo
            };
            
            // 👇 ASSINATURA PQC (Dilithium)
            let msg_hash = tx_to_sign.calculate_hash_for_signing();
            let pqc_signature = dilithium_sign(&msg_hash.as_bytes(), &tx_dilithium_sk);
            let sig_bytes = pqc_signature.as_bytes();
            
            // ✅ CORREÇÃO: Copiar para array fixo
            let mut final_sig = [0u8; 4595];
            let copy_len = std::cmp::min(final_sig.len(), sig_bytes.len());
            final_sig[..copy_len].copy_from_slice(&sig_bytes[..copy_len]);
            tx_to_sign.signature = QrystalSignature(final_sig);
            
            println!("✅ Transação PQC assinada com Dilithium5! (para Bloco #1)");
            vec![tx_to_sign]
        } else {
            vec![]
        };

        // ----------------------------------------------------
        // 4.3. Proposta de Bloco (try_create_block) - JÁ USA PQC INTERNAMENTE
        // ----------------------------------------------------
        match proposer_creator.try_create_block(previous_hash, pending_tx, next_height) {
            Some(mut proposed_block) => {
                println!("✅ Bloco #{} proposto por {}", next_height, hex::encode(proposer_creator.public_key.as_ref()));
                
                // ----------------------------------------------------
                // 4.4. Simulação de Votação BFT - AGORA COM PQC
                // ----------------------------------------------------
                let quorum_needed: usize = (committee_nodes.len() * 2 / 3) + 1;
                let msg_to_vote_on = proposed_block.header.calculate_hash_for_voting();
                let mut finality_votes: Vec<QrystalSignature> = Vec::new();
                let mut votes_generated: usize = 0;

                for member_entry in committee_nodes.iter() {
                    if let Some(signing_key) = secret_key_map.get(&member_entry.node_id) {
                        // 👇 ASSINATURA PQC PARA VOTAÇÃO BFT
                        let pqc_signature = dilithium_sign(&msg_to_vote_on.as_bytes(), signing_key);
                        let sig_bytes = pqc_signature.as_bytes();
                        
                        // ✅ CORREÇÃO: Converter para array fixo
                        let mut final_sig = [0u8; 4595];
                        let copy_len = std::cmp::min(final_sig.len(), sig_bytes.len());
                        final_sig[..copy_len].copy_from_slice(&sig_bytes[..copy_len]);
                        finality_votes.push(QrystalSignature(final_sig));
                        
                        votes_generated += 1;
                        
                        if votes_generated >= quorum_needed {
                            break;
                        }
                    } else {
                        println!("⚠️ AVISO CRÍTICO: Chave secreta PQC do Comitê {} não encontrada.", hex::encode(member_entry.node_id.as_ref()));
                    }
                }

                if votes_generated < quorum_needed {
                    println!("❌ Falha na Votação: Apenas {}/{} votos. Bloco #{} rejeitado.", votes_generated, quorum_needed, next_height);
                    continue; 
                }

                // ----------------------------------------------------
                // 4.5. Adicionar Bloco (try_add_block) - VALIDAÇÃO PQC
                // ----------------------------------------------------
                proposed_block.header.finality_votes = finality_votes; 
                
                match qrystal_chain.try_add_block(proposed_block) {
                    Ok(()) => {
                        let new_block = qrystal_chain.get_latest_block();
                        println!("🎉 Bloco #{} FINALIZADO com PQC! (Votos: {}/{})", next_height, votes_generated, quorum_needed);
                        println!(" -> Novo Hash da Cadeia: {}", hex::encode(new_block.header.calculate_hash().as_ref()));
                        println!("🔐 Assinaturas PQC Validadas com Sucesso");

                        // 👇 ADICIONAR ESTA LINHA:
                        p2p_network.broadcast_block(&new_block); // 👈 BROADCAST DO BLOCO
                    },
                    Err(e) => {
                        println!("❌ Erro de Validação PQC: Bloco #{} falhou: {}", next_height, e);
                    }
                }
            },
            None => {
                println!("❌ Proposer {} NÃO elegível.", hex::encode(proposer_creator.public_key.as_ref()));
            }
        }
        
        thread::sleep(Duration::from_millis(50));
    }

    // ----------------------------------------------------
    // FASE FINAL: Salvando estado da Cadeia PQC
    // ----------------------------------------------------
    println!("\n--- FASE FINAL: Salvando estado da Cadeia PQC ---");
    match qrystal_chain.save_to_disk(PERSISTENCE_PATH) {
        Ok(()) => println!("💾 Sucesso! Blockchain PQC salva em '{}'.", PERSISTENCE_PATH),
        Err(e) => println!("❌ ERRO CRÍTICO: Falha ao salvar a cadeia PQC: {}", e),
    }
}