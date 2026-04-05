// sentinel-agent/src/sender.rs
// Event Sender — batches events and sends to server
// Also sends periodic heartbeat with CPU/MEM stats

use crate::{config::AgentConfig, models::{Event, Severity}};
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc::Receiver;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

pub async fn run(mut rx: Receiver<Event>, cfg: Arc<AgentConfig>) -> Result<()> {
    info!("Event sender started → {}", cfg.server_url);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let events_endpoint    = format!("{}/api/v1/events", cfg.server_url);
    let heartbeat_endpoint = format!("{}/api/v1/agents/{}/heartbeat", cfg.server_url, cfg.agent_id);

    let mut batch: Vec<Event> = Vec::with_capacity(cfg.batch_size);
    let mut send_ticker      = interval(Duration::from_millis(cfg.send_interval_ms));
    let mut heartbeat_ticker = interval(Duration::from_secs(15));

    loop {
	tokio::select! {
            Some(event) = rx.recv() => {
                // CRITICAL events bypass the batch timer completely —
                // they flush immediately so rootkit / ransomware alerts
                // reach the dashboard in milliseconds not 2 seconds
                let is_critical = matches!(event.severity, Severity::Critical);
                batch.push(event);
                if is_critical || batch.len() >= cfg.batch_size {
                    flush(&client, &events_endpoint, &cfg.api_key, &mut batch).await;
                }
            }
            _ = heartbeat_ticker.tick() => {
                send_heartbeat(&client, &heartbeat_endpoint, &cfg).await;
            }
        }
    }
}

async fn flush(client: &reqwest::Client, endpoint: &str, api_key: &str, batch: &mut Vec<Event>) {
    if batch.is_empty() { return; }
    debug!("Flushing {} events", batch.len());

    let payload = match serde_json::to_value(&*batch) {
        Ok(v)  => v,
        Err(e) => { error!("Serialization failed: {}", e); batch.clear(); return; }
    };

    for attempt in 1..=3u32 {
        match client
            .post(endpoint)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send().await
        {
            Ok(r) if r.status().is_success() => {
                debug!("Sent {} events (attempt {})", batch.len(), attempt);
                batch.clear();
                return;
            }
            Ok(r)  => warn!("Server {} (attempt {})", r.status(), attempt),
            Err(e) => warn!("Send failed: {} (attempt {})", e, attempt),
        }
        tokio::time::sleep(Duration::from_secs(2u64.pow(attempt))).await;
    }
    error!("Dropping {} events after 3 failed attempts", batch.len());
    batch.clear();
}

async fn send_heartbeat(client: &reqwest::Client, endpoint: &str, cfg: &AgentConfig) {
    // Read basic system stats
    let cpu_pct = read_cpu_pct();
    let mem_pct = read_mem_pct();

    let payload = serde_json::json!({
        "hostname":      cfg.hostname,
        "agent_version": "1.0.0",
        "cpu_pct":       cpu_pct,
        "mem_pct":       mem_pct,
        "os_name":       "Linux",
        "timestamp":     chrono::Utc::now().to_rfc3339(),
    });

    match client
        .post(endpoint)
        .header("Authorization", format!("Bearer {}", cfg.api_key))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send().await
    {
        Ok(r) if r.status().is_success() => debug!("Heartbeat OK"),
        Ok(r)  => warn!("Heartbeat {} from server", r.status()),
        Err(e) => warn!("Heartbeat failed: {}", e),
    }
}

fn read_cpu_pct() -> f32 {
    // Read /proc/stat for CPU usage approximation
    if let Ok(content) = std::fs::read_to_string("/proc/loadavg") {
        let parts: Vec<&str> = content.split_whitespace().collect();
        if let Some(load) = parts.first() {
            if let Ok(load1) = load.parse::<f32>() {
                // Rough approximation: load avg as % (capped at 100)
                return (load1 * 25.0).min(100.0);
            }
        }
    }
    0.0
}

fn read_mem_pct() -> f32 {
    // Read /proc/meminfo for memory usage
    if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
        let mut total = 0u64;
        let mut available = 0u64;
        for line in content.lines() {
            if line.starts_with("MemTotal:") {
                total = parse_kb(line);
            } else if line.starts_with("MemAvailable:") {
                available = parse_kb(line);
            }
        }
        if total > 0 {
            return ((total - available) as f32 / total as f32) * 100.0;
        }
    }
    0.0
}

fn parse_kb(line: &str) -> u64 {
    line.split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}
