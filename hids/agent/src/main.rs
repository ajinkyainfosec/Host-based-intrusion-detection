// sentinel-agent/src/main.rs
// Sentinel HIDS — Host Agent for Linux
// Monitors: processes, files, network, auth logs, syscalls

mod config;
mod fim;
mod process;
mod network;
mod auth;
mod rootkit;
mod sender;
mod models;

use anyhow::Result;
use tracing::{info, error};
use tracing_subscriber::EnvFilter;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};

#[tokio::main]
async fn main() -> Result<()> {
    // ── Logging ──
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive("sentinel_agent=info".parse()?))
        .with_target(false)
        .compact()
        .init();

    info!("🛡  Sentinel HIDS Agent v1.0.0 starting...");

    // ── Config ──
    let cfg = Arc::new(config::AgentConfig::load()?);
    info!("Agent ID  : {}", cfg.agent_id);
    info!("Hostname  : {}", cfg.hostname);
    info!("Server    : {}", cfg.server_url);

    // ── Event channel — all collectors send here ──
    let (tx, rx) = mpsc::channel::<models::Event>(4096);

    // ── Spawn collectors ──
    let handles = vec![
        // File Integrity Monitor
        tokio::spawn(fim::run(
            tx.clone(),
            cfg.clone(),
        )),
        // Process Monitor
        tokio::spawn(process::run(
            tx.clone(),
            cfg.clone(),
        )),
        // Network Monitor
        tokio::spawn(network::run(
            tx.clone(),
            cfg.clone(),
        )),
        // Auth Log Monitor
        tokio::spawn(auth::run(
            tx.clone(),
            cfg.clone(),
        )),
        // Rootkit Detector
        tokio::spawn(rootkit::run(
            tx.clone(),
            cfg.clone(),
        )),
    ];

    // ── Sender — batches events and ships to server ──
    tokio::spawn(sender::run(rx, cfg.clone()));

    // ── Health ticker ──
    let hcfg = cfg.clone();
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(30));
        loop {
            ticker.tick().await;
            info!("♥  Heartbeat — agent {} alive", hcfg.agent_id);
        }
    });

    // ── Wait for all collectors ──
    for handle in handles {
        if let Err(e) = handle.await {
            error!("Collector crashed: {:?}", e);
        }
    }

    Ok(())
}
