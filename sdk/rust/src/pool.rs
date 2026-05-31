use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tonic::transport::{Channel, Endpoint};

/// 连接池配置，语义对齐数据库/Redis 连接池。
#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub address: String,
    /// 最小空闲连接数
    pub min_idle: usize,
    /// 最大连接数（含使用中 + 空闲）
    pub max_open: usize,
    /// 连接最大存活时间，到期后归还时销毁
    pub max_lifetime: Duration,
    /// 空闲连接超时，后台回收
    pub idle_timeout: Duration,
    pub dial_timeout: Duration,
    /// 池耗尽时等待可用连接的最长时间
    pub acquire_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            address: "http://127.0.0.1:50051".to_string(),
            min_idle: 2,
            max_open: 16,
            max_lifetime: Duration::from_secs(30 * 60),
            idle_timeout: Duration::from_secs(5 * 60),
            dial_timeout: Duration::from_secs(5),
            acquire_timeout: Duration::from_secs(10),
        }
    }
}

struct PooledChannel {
    channel: Channel,
    created_at: Instant,
    last_used: Instant,
}

pub struct Pool {
    config: PoolConfig,
    idle: Mutex<Vec<PooledChannel>>,
    total: AtomicUsize,
    semaphore: Arc<Semaphore>,
}

impl Pool {
    pub fn new(config: PoolConfig) -> Arc<Self> {
        let max_open = config.max_open.max(1);
        Arc::new(Self {
            config,
            idle: Mutex::new(Vec::new()),
            total: AtomicUsize::new(0),
            semaphore: Arc::new(Semaphore::new(max_open)),
        })
    }

    pub async fn warmup(self: &Arc<Self>) -> Result<()> {
        let mut idle = self.idle.lock().await;
        while idle.len() < self.config.min_idle && self.total.load(Ordering::SeqCst) < self.config.max_open
        {
            let channel = self.dial().await?;
            self.total.fetch_add(1, Ordering::SeqCst);
            idle.push(PooledChannel {
                channel,
                created_at: Instant::now(),
                last_used: Instant::now(),
            });
        }
        Ok(())
    }

    pub async fn acquire(self: &Arc<Self>) -> Result<PooledConn> {
        let permit = tokio::time::timeout(
            self.config.acquire_timeout,
            self.semaphore.clone().acquire_owned(),
        )
        .await
        .map_err(|_| anyhow!("acquire connection timeout"))?
        .map_err(|_| anyhow!("connection pool closed"))?;

        if let Some(channel) = self.take_idle().await {
            return Ok(PooledConn {
                pool: self.clone(),
                channel: Some(channel),
                _permit: permit,
            });
        }

        let channel = self.dial().await?;
        self.total.fetch_add(1, Ordering::SeqCst);
        Ok(PooledConn {
            pool: self.clone(),
            channel: Some(channel),
            _permit: permit,
        })
    }

    async fn take_idle(&self) -> Option<Channel> {
        let mut idle = self.idle.lock().await;
        while let Some(entry) = idle.pop() {
            if entry.created_at.elapsed() > self.config.max_lifetime {
                self.total.fetch_sub(1, Ordering::SeqCst);
                continue;
            }
            if entry.last_used.elapsed() > self.config.idle_timeout {
                self.total.fetch_sub(1, Ordering::SeqCst);
                continue;
            }
            return Some(entry.channel);
        }
        None
    }

    async fn release(&self, channel: Channel) {
        let expired = self.config.max_lifetime;
        let should_keep = {
            let idle_len = self.idle.lock().await.len();
            idle_len < self.config.max_open
        };
        if !should_keep {
            self.total.fetch_sub(1, Ordering::SeqCst);
            return;
        }
        let _ = expired;
        let mut idle = self.idle.lock().await;
        idle.push(PooledChannel {
            channel,
            created_at: Instant::now(),
            last_used: Instant::now(),
        });
    }

    async fn dial(&self) -> Result<Channel> {
        Endpoint::from_shared(self.config.address.clone())
            .context("invalid address")?
            .connect_timeout(self.config.dial_timeout)
            .connect()
            .await
            .context("dial grpc")
    }
}

pub struct PooledConn {
    pool: Arc<Pool>,
    channel: Option<Channel>,
    _permit: OwnedSemaphorePermit,
}

impl PooledConn {
    pub fn channel(&self) -> Result<Channel> {
        self.channel
            .clone()
            .ok_or_else(|| anyhow!("connection already released"))
    }
}

impl Drop for PooledConn {
    fn drop(&mut self) {
        if let Some(channel) = self.channel.take() {
            let pool = self.pool.clone();
            tokio::spawn(async move {
                pool.release(channel).await;
            });
        }
    }
}
