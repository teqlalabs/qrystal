// src/lib.rs (O NOVO MAPA DA SUA CRATE)

// Declaração de todos os módulos. Devem ser públicos para serem usados pelo main.rs
pub mod core;
pub mod db; 
pub mod consensus;
pub mod network;
// ... (outros módulos, se houver)

// Opcional: Re-exportar DBManager para acesso fácil no main.rs
pub use db::DBManager;
pub use core::Hash; // Re-exporte Hash para facilitar o uso
pub use network::handshake;