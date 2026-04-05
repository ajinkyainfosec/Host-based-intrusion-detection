// sentinel-agent/src/network.rs
// Network Monitor — reads /proc/net/tcp, /proc/net/tcp6, /proc/net/udp
// Detects: C2 connections, port scans, suspicious listening ports, known bad IPs

use crate::{config::AgentConfig, models::*};
use anyhow::Result;
use std::{
    collections::HashSet,
    fs,
    sync::Arc,
};
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Connection {
    local_addr:  String,
    local_port:  u16,
    remote_addr: String,
    remote_port: u16,
    state:       String,
    protocol:    String,
}

pub async fn run(tx: Sender<Event>, cfg: Arc<AgentConfig>) -> Result<()> {
    info!("Network monitor started");
    let mut seen: HashSet<Connection> = HashSet::new();
    let mut ticker = interval(Duration::from_secs(cfg.net_scan_interval_secs));

    loop {
        ticker.tick().await;

        let mut current: HashSet<Connection> = HashSet::new();
        current.extend(parse_proc_net("/proc/net/tcp",  "tcp",  false));
        current.extend(parse_proc_net("/proc/net/tcp6", "tcp6", false));
        current.extend(parse_proc_net("/proc/net/udp",  "udp",  false));

        // ── New connections ──
        for conn in current.difference(&seen) {
            let (suspicious, severity, reason) = analyze_connection(conn, &cfg);

            if suspicious {
                warn!("SUSPICIOUS CONN: {}:{} → {}:{} [{}]",
                    conn.local_addr, conn.local_port,
                    conn.remote_addr, conn.remote_port,
                    reason.as_deref().unwrap_or("?"));
            }

            if suspicious || conn.remote_addr != "0.0.0.0" {
                let event = Event::new(
                    &cfg.agent_id,
                    &cfg.hostname,
                    severity,
                    EventData::NetworkEvent {
                        local_addr:  conn.local_addr.clone(),
                        local_port:  conn.local_port,
                        remote_addr: conn.remote_addr.clone(),
                        remote_port: conn.remote_port,
                        protocol:    conn.protocol.clone(),
                        state:       conn.state.clone(),
                        pid:         None,
                        comm:        None,
                    },
                );

                let event = if suspicious {
                    event.with_mitre("Command and Control", "T1071", "Application Layer Protocol")
                         .with_tag("suspicious-connection")
                } else {
                    event.with_tag("new-connection")
                };

                let _ = tx.send(event).await;
            }
        }

        seen = current;
    }
}

fn analyze_connection(conn: &Connection, cfg: &AgentConfig) -> (bool, Severity, Option<String>) {
    // 1. Known bad IP
    if cfg.known_bad_ips.contains(&conn.remote_addr) {
        return (true, Severity::Critical,
            Some(format!("Known malicious IP: {}", conn.remote_addr)));
    }

    // 2. Suspicious remote port (common C2 ports)
    if cfg.suspicious_ports.contains(&conn.remote_port) {
        return (true, Severity::High,
            Some(format!("Suspicious port: {}", conn.remote_port)));
    }

    // 3. Suspicious listening port
    if conn.remote_addr == "0.0.0.0" && cfg.suspicious_ports.contains(&conn.local_port) {
        return (true, Severity::High,
            Some(format!("Suspicious listener on port: {}", conn.local_port)));
    }

    // 4. Connection to Tor-like ports
    let tor_ports = [9001u16, 9050, 9051, 9150];
    if tor_ports.contains(&conn.remote_port) {
        return (true, Severity::High, Some("Possible Tor connection".to_string()));
    }

    // 5. IRC ports (common C2 channel)
    let irc_ports = [6666u16, 6667, 6668, 6669, 6697];
    if irc_ports.contains(&conn.remote_port) {
        return (true, Severity::Medium, Some("IRC port — possible C2 channel".to_string()));
    }

    (false, Severity::Info, None)
}

fn parse_proc_net(path: &str, proto: &str, _v6: bool) -> Vec<Connection> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    content.lines().skip(1).filter_map(|line| {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 { return None; }

        let local  = hex_to_addr(parts[1])?;
        let remote = hex_to_addr(parts[2])?;
        let state  = tcp_state(parts[3]);

        Some(Connection {
            local_addr:  local.0,
            local_port:  local.1,
            remote_addr: remote.0,
            remote_port: remote.1,
            state,
            protocol: proto.to_string(),
        })
    }).collect()
}

fn hex_to_addr(hex: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 { return None; }

    let addr_hex = parts[0];
    let port = u16::from_str_radix(parts[1], 16).ok()?;

    // IPv4 — /proc/net/tcp stores address as little-endian hex
    if addr_hex.len() == 8 {
        let n = u32::from_str_radix(addr_hex, 16).ok()?;
        let ip = std::net::Ipv4Addr::from(n.to_le_bytes());
        return Some((ip.to_string(), port));
    }

    Some(("unknown".to_string(), port))
}

fn tcp_state(hex: &str) -> String {
    match hex {
        "01" => "ESTABLISHED", "02" => "SYN_SENT",
        "03" => "SYN_RECV",   "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",  "06" => "TIME_WAIT",
        "07" => "CLOSE",      "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",   "0A" => "LISTEN",
        "0B" => "CLOSING",    _    => "UNKNOWN",
    }.to_string()
}
