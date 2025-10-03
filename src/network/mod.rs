// src/network/mod.rs
pub mod p2p;
pub mod handshake;

pub use p2p::P2PNetwork;
pub use handshake::{PqcHandshake, HandshakeMessage, HandshakeResponse};