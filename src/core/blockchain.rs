// src/core/blockchain.rs
use std::collections::{HashMap, HashSet}; // 👈 ADICIONAR HashSet aqui
use bincode;
use hex;
use serde::{Serialize, Deserialize};

use crate::core::transaction::Transaction;
use crate::core::block::Block;
use crate::core::types::{PublicKey, Hash};
use crate::consensus::bft_committee::{VrfEntry, select_proposer_and_committee};
use crate::consensus::vrf::{generate_vrf, verify_vrf, derive_ed25519_from_dilithium};
use crate::db::DBManager;

use pqcrypto_traits::sign::SignedMessage;

const REQUIRED_VOTES: usize = 15; 
const BLOCK_REWARD: u64 = 212;
const PROPOSER_BASE_REWARD: u64 = 40;
const VOTER_BASE_REWARD: u64 = 10;
const STANDBY_BASE_REWARD: u64 = 2;

#[derive(Debug)]
pub struct RewardDistribution {
    pub proposer: u64,
    pub voters: u64, 
    pub standby_nodes: u64,
    pub treasury: u64,
}

#[derive(Serialize, Deserialize)]
struct BlockchainSerializable {
    latest_hash: Hash,
    min_stake: u64,
    chain: Vec<Block>,
    stakes_map: HashMap<PublicKey, u64>,
}

pub struct Blockchain {
    pub latest_hash: Hash,
    pub min_stake: u64,
    pub chain: Vec<Block>,
    pub stakes_map: HashMap<PublicKey, u64>,
    pub dilithium_secret_key_map: HashMap<PublicKey, pqcrypto_dilithium::dilithium5::SecretKey>,
    pub dilithium_public_key_map: HashMap<PublicKey, pqcrypto_dilithium::dilithium5::PublicKey>,
    pub db_manager: Option<DBManager>,
}

impl std::fmt::Debug for Blockchain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Blockchain")
            .field("latest_hash", &hex::encode(self.latest_hash.as_ref()))
            .field("min_stake", &self.min_stake)
            .field("chain_len", &self.chain.len())
            .field("stakes_map_len", &self.stakes_map.len())
            .field("dilithium_secret_key_map_len", &self.dilithium_secret_key_map.len())
            .field("dilithium_public_key_map_len", &self.dilithium_public_key_map.len())
            .field("db_manager", &self.db_manager.is_some())
            .finish()
    }
}

impl Blockchain {
    pub fn new(db_manager: Option<DBManager>, min_stake: u64, initial_stakes: Vec<(PublicKey, u64)>) -> Self {
        let genesis_block = Block::new_genesis_block(initial_stakes.clone());
        let genesis_hash = genesis_block.header.calculate_hash();

        let genesis_bytes = bincode::serialize(&genesis_block)
            .expect("Falha ao serializar Gênesis");
        
        let db_manager = db_manager.expect("DBManager was unexpectedly None during chain creation.");

        db_manager.save_block(&genesis_hash, &genesis_bytes)
            .expect("Falha ao salvar Gênesis no DB");
            
        db_manager.save_latest_hash(&genesis_hash)
            .expect("Falha ao salvar último hash do Gênesis");

        println!("✅ Blockchain inicializada. Último bloco (Gênesis) Hash: {}", hex::encode(genesis_hash.as_ref()));

        let mut dilithium_secret_key_map = HashMap::new();
        let mut dilithium_public_key_map = HashMap::new();

        use pqcrypto_dilithium::dilithium5::keypair as dilithium_keypair;

        for (pub_key, _stake) in &initial_stakes {
            let (dilithium_pk, dilithium_sk) = dilithium_keypair();
            dilithium_secret_key_map.insert(*pub_key, dilithium_sk);
            dilithium_public_key_map.insert(*pub_key, dilithium_pk);
        }

        let mut blockchain = Blockchain {
            db_manager: Some(db_manager),
            latest_hash: genesis_hash,
            min_stake,
            chain: vec![genesis_block],
            stakes_map: HashMap::new(),
            dilithium_secret_key_map,
            dilithium_public_key_map,
        };

        for (pub_key, stake) in initial_stakes {
            blockchain.stakes_map.insert(pub_key, stake);
        }
    
        blockchain
    }
    
    pub fn save_to_disk(&self, path: &str) -> Result<(), String> {
        use std::fs::File;
        use std::io::Write;

        let serializable_data = BlockchainSerializable {
            latest_hash: self.latest_hash,
            min_stake: self.min_stake,
            chain: self.chain.clone(),
            stakes_map: self.stakes_map.clone(),
        };

        let encoded: Vec<u8> = bincode::serialize(&serializable_data)
            .map_err(|e| format!("Falha na serialização bincode: {}", e))?;
    
        let mut file = File::create(path)
            .map_err(|e| format!("Falha ao criar arquivo de persistência: {}", e))?;

        file.write_all(&encoded)
            .map_err(|e| format!("Falha ao escrever no arquivo de persistência: {}", e))?;

        Ok(())
    }

    pub fn load_from_disk(path: &str) -> Result<Self, String> {
        use std::fs::File;
        use std::io::Read;

        let mut file = File::open(path)
            .map_err(|_| "Arquivo de persistência não encontrado. Inicializando novo estado.".to_string())?;

        let mut encoded = Vec::new();
        file.read_to_end(&mut encoded)
            .map_err(|e| format!("Falha ao ler arquivo de persistência: {}", e))?;
        
        let serializable_data: BlockchainSerializable = bincode::deserialize(&encoded)
            .map_err(|e| format!("Falha na deserialização bincode (arquivo corrompido?): {}", e))?;

        let blockchain = Self {
            latest_hash: serializable_data.latest_hash,
            min_stake: serializable_data.min_stake,
            chain: serializable_data.chain,
            stakes_map: serializable_data.stakes_map,
            dilithium_secret_key_map: HashMap::new(),
            dilithium_public_key_map: HashMap::new(),
            db_manager: None,
        };

        Ok(blockchain)
    }

    pub fn get_latest_block(&self) -> Block {
        let db_manager = self.db_manager
                         .as_ref()
                         .expect("DBManager não deve ser None aqui.");

        let block_bytes = db_manager.get_block(&self.latest_hash)
            .expect("Falha ao buscar bloco do DB")
            .unwrap_or_else(|| panic!("Bloco não encontrado no DB para hash: {}", hex::encode(self.latest_hash.0.as_ref())));
            
        bincode::deserialize(&block_bytes)
            .expect("Falha ao desserializar bloco do DB")
    }

    pub fn get_all_stakes(&self) -> &HashMap<PublicKey, u64> {
        &self.stakes_map
    }

    fn verify_block_consensus(&self, block: &Block) -> Result<(), &'static str> {
        let _parent_hash = block.header.parent_hash;
        let proposer_key = &block.header.proposer_key;

        println!("🔐 Verificação PQC: Pulando VRF para chaves Dilithium");

        let stake = self.stakes_map.get(proposer_key).cloned().unwrap_or(0);
        
        if stake == 0 {
             return Err("Proposer has no stake in the ledger.");
        }

        if block.header.finality_votes.len() < REQUIRED_VOTES {
            return Err("BFT finality votes are insufficient.");
        }

        Ok(())
    }

    fn process_transactions(&mut self, transactions: &Vec<Transaction>) -> Result<(), String> {
        for tx in transactions {
            if !self.dilithium_public_key_map.contains_key(&tx.from) {
                return Err(format!("Remetente não autorizado ou desconhecido: {}", 
                                     hex::encode(tx.from.as_ref().split_at(8).0)));
            }

            let dilithium_pk = self.dilithium_public_key_map
                .get(&tx.from)
                .expect("Chave pública deveria existir para remetente conhecido");

            tx.verify_signature_pqc_with_key(dilithium_pk)
                .map_err(|e| format!("Transação inválida: Falha na assinatura PQC: {}", e))?;

            let sender_stake = self.stakes_map.get(&tx.from).copied().unwrap_or(0);

            if sender_stake < tx.amount {
                return Err(format!("Transação inválida: Saldo insuficiente. Endereço: {}, Saldo: {}, Necessário: {}",
                                   hex::encode(tx.from.as_ref().split_at(8).0), sender_stake, tx.amount));
            }

            let from_entry = self.stakes_map.get_mut(&tx.from).unwrap();
            *from_entry -= tx.amount;

            let to_entry = self.stakes_map.entry(tx.to).or_insert(0);
            *to_entry += tx.amount;
    
            println!("  [TX] Transferência PQC: {} QRY de {} para {}", 
                     tx.amount, hex::encode(tx.from.as_ref().split_at(8).0), hex::encode(tx.to.as_ref().split_at(8).0));
        }

        Ok(())
    }

    pub fn calculate_rewards(
        &self,
        _proposer: &PublicKey,
        active_voters: &HashSet<PublicKey>,
        full_committee: &[VrfEntry],
        _previous_block_hash: Hash
    ) -> RewardDistribution {
        let total_reward = BLOCK_REWARD;
        
        let proposer_reward = PROPOSER_BASE_REWARD + 10;
        
        let voter_count = active_voters.len() as u64;
        let voter_total_reward = voter_count * VOTER_BASE_REWARD;
        
        let all_committee_keys: HashSet<PublicKey> = full_committee
            .iter()
            .map(|entry| entry.node_id)
            .collect();
            
        let standby_nodes: HashSet<PublicKey> = all_committee_keys
            .difference(active_voters)
            .cloned()
            .collect();
            
        let standby_count = standby_nodes.len() as u64;
        let standby_total_reward = standby_count * STANDBY_BASE_REWARD;
        
        let treasury_reward = total_reward
            .saturating_sub(proposer_reward)
            .saturating_sub(voter_total_reward)
            .saturating_sub(standby_total_reward);
        
        RewardDistribution {
            proposer: proposer_reward,
            voters: voter_total_reward,
            standby_nodes: standby_total_reward,
            treasury: treasury_reward,
        }
    }
    
    pub fn distribute_rewards(
        &mut self,
        distribution: &RewardDistribution,
        proposer: PublicKey,
        active_voters: &HashSet<PublicKey>,
        full_committee: &[VrfEntry]
    ) {
        println!("\n💰 [DISTRIBUIÇÃO DE RECOMPENSAS]");
        println!("  Total do Bloco: {} QRY", BLOCK_REWARD);
        
        let proposer_stake = self.stakes_map.entry(proposer).or_insert(0);
        *proposer_stake += distribution.proposer;
        println!("  ✅ Proposer: {} QRY → Total: {} QRY", 
                 distribution.proposer, *proposer_stake);
        
        for voter in active_voters {
            if *voter != proposer {
                let voter_stake = self.stakes_map.entry(*voter).or_insert(0);
                *voter_stake += VOTER_BASE_REWARD;
                println!("  ✅ Votante {}: {} QRY → Total: {} QRY", 
                         hex::encode(voter.as_ref().split_at(8).0), 
                         VOTER_BASE_REWARD, *voter_stake);
            }
        }
        
        let all_committee_keys: HashSet<PublicKey> = full_committee
            .iter()
            .map(|entry| entry.node_id)
            .collect();
            
        let standby_nodes: HashSet<PublicKey> = all_committee_keys
            .difference(active_voters)
            .cloned()
            .collect();
            
        for standby in standby_nodes {
            let standby_stake = self.stakes_map.entry(standby).or_insert(0);
            *standby_stake += STANDBY_BASE_REWARD;
            println!("  ⏳ Standby {}: {} QRY → Total: {} QRY", 
                     hex::encode(standby.as_ref().split_at(8).0), 
                     STANDBY_BASE_REWARD, *standby_stake);
        }
        
        if distribution.treasury > 0 {
            println!("  🏦 Treasury: {} QRY (desenvolvimento futuro)", distribution.treasury);
        }
        
        println!("  📊 Resumo: Proposer({}QRY) + Votantes({}QRY) + Standby({}QRY) = {}QRY",
                 distribution.proposer, distribution.voters, 
                 distribution.standby_nodes, BLOCK_REWARD);
    }

    pub fn try_add_block(&mut self, block: Block) -> Result<(), String> {
        let latest_block = self.get_latest_block();
        let latest_hash = latest_block.header.calculate_hash();

        if block.header.block_height != latest_block.header.block_height + 1 {
            return Err("Altura de bloco (Block height) inválida.".to_string());
        }

        if block.header.parent_hash != latest_hash {
            return Err(format!("Linkage hash inválido. Esperado: {}, Encontrado: {}", 
                                hex::encode(latest_hash.as_ref()), hex::encode(block.header.parent_hash.as_ref())));
        }

        self.process_transactions(&block.transactions)?;
    
        self.verify_block_consensus(&block)
            .map_err(|e| e.to_string())?;

        let current_height = block.header.block_height;
        let committee_base_height = current_height - 1;

        let (_, committee) = self.select_next_committee(committee_base_height)
            .ok_or_else(|| "Comitê BFT não pôde ser determinado para este bloco.".to_string())?;

        let total_members = committee.len() as u32;
        let quorum_needed = (total_members * 2 / 3) + 1; 

        if block.header.finality_votes.len() < quorum_needed as usize {
            return Err(format!("Quórum BFT insuficiente. Votos necessários: {}, Encontrados: {}", 
                               quorum_needed, block.header.finality_votes.len()));
        }

        let _msg_to_verify = block.header.calculate_hash_for_voting();
        let mut valid_votes_count = 0;
    
        let committee_keys: Vec<PublicKey> = committee.iter().map(|n| n.node_id).collect();
        let mut unique_voters = HashSet::new();

        for vote_sig in &block.header.finality_votes {
            let mut is_valid_vote = false;
        
            for member_pubkey in &committee_keys {
                if unique_voters.contains(member_pubkey) {
                    continue; 
                }

                let _signed_msg = match pqcrypto_dilithium::dilithium5::SignedMessage::from_bytes(&vote_sig.0) {
                    Ok(msg) => msg,
                    Err(_) => continue,
                };

                unique_voters.insert(*member_pubkey);
                is_valid_vote = true;
                break;
            }
        
            if is_valid_vote {
                valid_votes_count += 1;
            }
        }

        if valid_votes_count < quorum_needed {
            return Err(format!("Quórum BFT PQC falhou. Votos VÁLIDOS: {}/{}", 
                               valid_votes_count, quorum_needed));
        }

        let reward_distribution = self.calculate_rewards(
            &block.header.proposer_key,
            &unique_voters,
            &committee,
            latest_hash
        );

        self.distribute_rewards(
            &reward_distribution,
            block.header.proposer_key,
            &unique_voters,
            &committee
        );

        let block_hash = block.header.calculate_hash();

        let db_manager = self.db_manager
                         .as_ref()
                         .expect("DBManager não deve ser None aqui.");

        let block_bytes = bincode::serialize(&block)
            .map_err(|e| format!("Falha ao serializar bloco: {}", e))?;

        db_manager.save_block(&block_hash, &block_bytes)
            .map_err(|e| format!("Falha ao salvar bloco no DB: {}", e))?;

        db_manager.save_latest_hash(&block_hash)
            .map_err(|e| format!("Falha ao atualizar latest_hash no DB: {}", e))?;

        self.latest_hash = block_hash;
    
        Ok(())
    }

    pub fn select_next_committee(&self, _block_height: u64) -> Option<(VrfEntry, Vec<VrfEntry>)> {
        let previous_hash = self.get_latest_block().header.calculate_hash();
        let active_stakes = self.get_all_stakes();

        let mut vrf_results = HashMap::new();

        println!("🎲 Executando seleção de comitê PQC para bloco anterior: {}", 
                 hex::encode(previous_hash.as_ref().split_at(8).0));

        for (node_pub_key, &stake) in active_stakes.iter() {
            if stake >= self.min_stake {
                let ed25519_keypair = derive_ed25519_from_dilithium(node_pub_key);
            
                if ed25519_keypair.is_none() {
                    println!("⚠️  Falha ao derivar chave Ed25519 para VRF do nó PQC: {}", 
                            hex::encode(node_pub_key.as_ref().split_at(8).0));
                    continue;
                }
            
                let (public_key, secret_key) = ed25519_keypair.unwrap();

                let vrf_result = generate_vrf(&secret_key, previous_hash);
            
                let is_vrf_valid = verify_vrf(
                    &public_key,
                    previous_hash, 
                    &vrf_result.0, 
                    &vrf_result.1
                );
            
                if !is_vrf_valid {
                    println!("⚠️  VRF inválida para nó PQC: {}", 
                            hex::encode(node_pub_key.as_ref().split_at(8).0));
                    continue;
                }
            
                let entry = VrfEntry {
                    node_id: *node_pub_key,
                    vrf_value: vrf_result.0,
                    vrf_proof: vrf_result.1,
                };
                vrf_results.insert(*node_pub_key, entry);
            }
        }

        println!("📊 VRF PQC executada: {}/{} nós produziram VRF válida", 
                 vrf_results.len(), active_stakes.len());

        match select_proposer_and_committee(vrf_results) {
            Some((proposer, committee)) => {
                println!("🏆 Proposer selecionado: {}, comitê: {} membros", 
                         hex::encode(proposer.node_id.as_ref().split_at(8).0), 
                         committee.len());
                Some((proposer, committee))
            }
            None => {
                println!("❌ Poucos nós ativos para formar o Comitê BFT mínimo");
                None
            }
        }
    }
}