// sentinel-agent/src/config.rs
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub agent_id:       String,
    pub hostname:       String,
    pub server_url:     String,
    pub api_key:        String,
    pub batch_size:     usize,
    pub send_interval_ms: u64,

    // FIM settings
    pub fim_watch_paths: Vec<String>,
    pub fim_exclude_paths: Vec<String>,
    pub fim_interval_secs: u64,

    // Process settings
    pub proc_scan_interval_secs: u64,
    pub suspicious_paths: Vec<String>,
    pub suspicious_comms: Vec<String>,

    // Network
    pub net_scan_interval_secs: u64,
    pub known_bad_ips: Vec<String>,
    pub suspicious_ports: Vec<u16>,

    // Auth
    pub auth_log_path: String,
    pub max_failed_logins: u32,
}

impl AgentConfig {
    pub fn load() -> Result<Self> {
        // Try to load from file first
        let config_path = std::env::var("SENTINEL_CONFIG")
            .unwrap_or_else(|_| "/etc/sentinel/agent.json".to_string());

        if let Ok(content) = fs::read_to_string(&config_path) {
            return serde_json::from_str(&content)
                .context("Failed to parse agent config");
        }

        // Fall back to defaults + env vars
        Ok(Self::default())
    }

    fn default() -> Self {
        let hostname = std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        Self {
            agent_id: std::env::var("SENTINEL_AGENT_ID")
                .unwrap_or_else(|_| Uuid::new_v4().to_string()),
            hostname,
            server_url: std::env::var("SENTINEL_SERVER_URL")
                .unwrap_or_else(|_| "http://localhost:8000".to_string()),
            api_key: std::env::var("SENTINEL_API_KEY")
                .unwrap_or_else(|_| "changeme".to_string()),

            batch_size:       100,
            send_interval_ms: 2000,

            fim_watch_paths: vec![
                "/etc".to_string(),
                "/usr/bin".to_string(),
                "/usr/sbin".to_string(),
                "/usr/lib".to_string(),
                "/boot".to_string(),
                "/root".to_string(),
                "/var/spool/cron".to_string(),
            ],
            fim_exclude_paths: vec![
                "/etc/mtab".to_string(),
                "/etc/resolv.conf".to_string(),
            ],
            fim_interval_secs: 30,

            proc_scan_interval_secs: 5,
            suspicious_paths: vec![
                "/tmp".to_string(),
                "/dev/shm".to_string(),
                "/var/tmp".to_string(),
                "/run/shm".to_string(),
            ],
            suspicious_comms: vec![
                "nc".to_string(), "ncat".to_string(), "netcat".to_string(),
                "nmap".to_string(), "masscan".to_string(),
                "hydra".to_string(), "medusa".to_string(),
                "mimikatz".to_string(), "msfconsole".to_string(),
                "python3 -c".to_string(), "bash -i".to_string(),
                "sh -i".to_string(), "perl -e".to_string(),
            ],

            net_scan_interval_secs: 10,
            known_bad_ips: vec![
                "185.220.101.47".to_string(),
                "45.33.32.156".to_string(),
            ],
            suspicious_ports: vec![4444, 5555, 1337, 31337, 6666, 6667, 9001],

            auth_log_path: "/var/log/auth.log".to_string(),
            max_failed_logins: 5,
        }
    }
}
