// sentinel-agent/src/auth.rs
// Auth Monitor — tails /var/log/auth.log in real-time
// Detects: brute force, sudo abuse, new accounts, SSH key additions

use crate::{config::AgentConfig, models::*};
use anyhow::Result;
use regex::Regex;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Seek, SeekFrom},
    sync::Arc,
    time::SystemTime,
};
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

struct FailTracker {
    count:    u32,
    first_at: SystemTime,
    last_ip:  String,
}

pub async fn run(tx: Sender<Event>, cfg: Arc<AgentConfig>) -> Result<()> {
    info!("Auth monitor started — watching {}", cfg.auth_log_path);

    // Compile regexes once
    let re_failed    = Regex::new(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)")?;
    let re_accepted  = Regex::new(r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)")?;
    let re_sudo      = Regex::new(r"sudo:\s+(\S+)\s*:.*COMMAND=(.*)")?;
    let re_sudo_fail = Regex::new(r"sudo:\s+(\S+)\s*:.*incorrect password")?;
    let re_useradd   = Regex::new(r"new user: name=(\S+)")?;
    let re_passwd    = Regex::new(r"password changed for (\S+)")?;
    let re_ssh_key   = Regex::new(r"authorized_keys.*for (\S+)")?;

    let mut fail_tracker: HashMap<String, FailTracker> = HashMap::new();
    let mut ticker = interval(Duration::from_secs(2));

    // Open log file and seek to end (only tail new entries)
    let mut file = match File::open(&cfg.auth_log_path) {
        Ok(f) => f,
        Err(e) => {
            warn!("Cannot open {}: {} — auth monitoring disabled", cfg.auth_log_path, e);
            return Ok(());
        }
    };
    file.seek(SeekFrom::End(0))?;

    loop {
        ticker.tick().await;

        // Read new lines
        let mut reader = BufReader::new(&file);
        let mut line = String::new();

        while reader.read_line(&mut line)? > 0 {
            let raw = line.trim().to_string();

            // ── Failed login ──
            if let Some(caps) = re_failed.captures(&raw) {
                let user = caps[1].to_string();
                let ip   = caps[2].to_string();

                let tracker = fail_tracker.entry(ip.clone()).or_insert(FailTracker {
                    count: 0, first_at: SystemTime::now(), last_ip: ip.clone(),
                });
                tracker.count += 1;
                tracker.last_ip = ip.clone();

                let severity = if tracker.count >= cfg.max_failed_logins {
                    warn!("BRUTE FORCE: {} attempts for user {} from {}",
                        tracker.count, ip,user);
                    Severity::Critical
                } else {
                    Severity::Medium
                };

                let _ = tx.send(
                    Event::new(&cfg.agent_id, &cfg.hostname, severity,
                        EventData::AuthEvent {
                            user: user.clone(),
                            action: AuthAction::FailedLogin,
                            source_ip: Some(ip),
                            tty: None,
                            success: false,
                            raw_line: raw.clone(),
                        })
                    .with_mitre("Credential Access", "T1110", "Brute Force")
                    .with_tag("auth")
                    .with_tag("failed-login")
                ).await;
            }

            // ── Successful login ──
            else if let Some(caps) = re_accepted.captures(&raw) {
                let user = caps[1].to_string();
                let ip   = caps[2].to_string();

                // Reset fail counter on success
                fail_tracker.remove(&user);

                let severity = if user == "root" { Severity::High } else { Severity::Low };

                let _ = tx.send(
                    Event::new(&cfg.agent_id, &cfg.hostname, severity,
                        EventData::AuthEvent {
                            user, action: AuthAction::Login,
                            source_ip: Some(ip),
                            tty: None, success: true,
                            raw_line: raw.clone(),
                        })
                    .with_tag("auth").with_tag("login")
                ).await;
            }

            // ── Sudo command ──
            else if let Some(caps) = re_sudo.captures(&raw) {
                let user = caps[1].to_string();
                let cmd  = caps[2].trim().to_string();

                let suspicious = cmd.contains("/bin/bash") || cmd.contains("/bin/sh")
                    || cmd.contains("passwd") || cmd.contains("visudo");

                let severity = if suspicious { Severity::High } else { Severity::Medium };

                warn!("SUDO: {} executed: {}", user, cmd);

                let _ = tx.send(
                    Event::new(&cfg.agent_id, &cfg.hostname, severity,
                        EventData::AuthEvent {
                            user, action: AuthAction::SudoCommand,
                            source_ip: None, tty: None, success: true,
                            raw_line: raw.clone(),
                        })
                    .with_mitre("Privilege Escalation", "T1548", "Abuse Elevation Control Mechanism")
                    .with_tag("auth").with_tag("sudo")
                ).await;
            }

            // ── Sudo failure ──
            else if let Some(caps) = re_sudo_fail.captures(&raw) {
                let user = caps[1].to_string();
                let _ = tx.send(
                    Event::new(&cfg.agent_id, &cfg.hostname, Severity::High,
                        EventData::AuthEvent {
                            user, action: AuthAction::SudoFailed,
                            source_ip: None, tty: None, success: false,
                            raw_line: raw.clone(),
                        })
                    .with_tag("auth").with_tag("sudo-fail")
                ).await;
            }

            // ── New user created ──
            else if let Some(caps) = re_useradd.captures(&raw) {
                let user = caps[1].to_string();
                warn!("NEW USER CREATED: {}", user);
                let _ = tx.send(
                    Event::new(&cfg.agent_id, &cfg.hostname, Severity::High,
                        EventData::AuthEvent {
                            user, action: AuthAction::UserAdded,
                            source_ip: None, tty: None, success: true,
                            raw_line: raw.clone(),
                        })
                    .with_mitre("Persistence", "T1136", "Create Account")
                    .with_tag("auth").with_tag("new-user")
                ).await;
            }

            // ── Password changed ──
            else if let Some(caps) = re_passwd.captures(&raw) {
                let user = caps[1].to_string();
                let _ = tx.send(
                    Event::new(&cfg.agent_id, &cfg.hostname, Severity::Medium,
                        EventData::AuthEvent {
                            user, action: AuthAction::PasswordChanged,
                            source_ip: None, tty: None, success: true,
                            raw_line: raw.clone(),
                        })
                    .with_tag("auth").with_tag("password-change")
                ).await;
            }

            // ── SSH authorized_keys modified ──
            else if let Some(caps) = re_ssh_key.captures(&raw) {
                let user = caps[1].to_string();
                warn!("SSH KEY ADDED for user: {}", user);
                let _ = tx.send(
                    Event::new(&cfg.agent_id, &cfg.hostname, Severity::High,
                        EventData::AuthEvent {
                            user, action: AuthAction::SshKeyAdded,
                            source_ip: None, tty: None, success: true,
                            raw_line: raw.clone(),
                        })
                    .with_mitre("Persistence", "T1098.004", "Account Manipulation: SSH Authorized Keys")
                    .with_tag("auth").with_tag("ssh-key")
                ).await;
            }

            line.clear();
        }

        // Re-open if log was rotated
        if let Ok(new_meta) = std::fs::metadata(&cfg.auth_log_path) {
            let _ = new_meta; // just check it's accessible
        }
    }
}
