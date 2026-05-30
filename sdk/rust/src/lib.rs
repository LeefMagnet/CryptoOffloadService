pub mod client;
pub mod pool;

pub mod pb {
    pub mod v1 {
        tonic::include_proto!("cryptooffload.v1");
    }
}

pub use client::Client;
pub use pool::{Pool, PoolConfig};
