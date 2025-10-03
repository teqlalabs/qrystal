// src/db/mod.rs

// 1. Caminho de Importação ROCKSDB (Sem os ::)
// O Rust está sendo muito teimoso e a única forma de acessar dependências externas
// em módulos internos é o import direto (que só funciona se não houver conflito de nomes).
use rocksdb::{DB, Error}; 

// 2. Caminho de Importação CORE (Usando 'super' para ir para o módulo irmão)
// Se 'pub mod core;' está no main.rs, este caminho deve ser o correto.
use super::core::Hash; 

// Definimos o nome do diretório onde o DB será armazenado
const DB_PATH: &str = "qrystal_data"; 

// O DBManager encapsula a instância do RocksDB
// Note que agora usamos 'Error' em vez de 'rocksdb::Error'
#[derive(Debug)]
pub struct DBManager {
    pub db: DB,
}

impl DBManager {
    /// Tenta abrir a instância do RocksDB. Se não existir, ele a cria.
    pub fn new() -> Result<Self, Error> { // Usando o 'Error' importado
        let path = std::path::Path::new(DB_PATH); 
        
        if !path.exists() {
            std::fs::create_dir_all(path).expect("Falha ao criar diretório do DB.");
        }

        let db = DB::open_default(path)?;

        Ok(DBManager { db })
    }
    
    // Aplique 'Error' nos demais métodos
    pub fn save_block(&self, hash: &Hash, block_bytes: &[u8]) -> Result<(), Error> {
        self.db.put(hash.as_ref(), block_bytes)?;
        Ok(())
    }

    pub fn get_block(&self, hash: &Hash) -> Result<Option<Vec<u8>>, Error> {
        let block_bytes = self.db.get(hash.0)?;
        Ok(block_bytes)
    }

    pub fn save_latest_hash(&self, hash: &Hash) -> Result<(), Error> {
        self.db.put(b"LATEST_HASH", hash.0)?;
        Ok(())
    }

    pub fn get_latest_hash(&self) -> Result<Option<Hash>, Error> {
        let _result = self.db.get(b"LATEST_HASH")?;
        if let Some(bytes) = self.db.get(b"LATEST_HASH")? {
            let mut hash_array = [0u8; 32];
            hash_array.copy_from_slice(&bytes);
            Ok(Some(Hash(hash_array)))
        } else {
            Ok(None)
        }
    }
}

// NOVO: Implementação do trait Default
// Isso é o que a lógica de Deserialização chama quando o campo é #[serde(skip, default)].
impl Default for DBManager {
    fn default() -> Self {
        // CORREÇÃO CRÍTICA: Não tente abrir o DB aqui. 
        // Em vez disso, panique, ou crie uma instância Dummy se possível.
        // A maneira mais segura em um ambiente de teste/simulação:
        panic!("DBManager não deve ser inicializado via Default. Use DBManager::new()");
        
        // Se a sua struct puder ser inicializada com um placeholder seguro, use-o:
        // Exemplo: Se o DBManager for um wrapper de uma conexão que pode ser nula/placeholder.
    }
}