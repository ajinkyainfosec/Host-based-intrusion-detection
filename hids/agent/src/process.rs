// sentinel-agent/src/process.rs
// Process Monitor — scans /proc every N seconds
// Detects: hidden PIDs, execution from /tmp, reverse shells, privilege escalation

use crate::{config::AgentConfig, models::*};
use anyhow::Result;
use std::{
    collections::{HashMap, HashSet},
    fs,
    sync::Arc,
};
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

// ── Known-safe executables — never generate suspicious process alerts ──
// Add any legitimate tools on your system that trigger false positives
const SAFE_EXECUTABLES: &[&str] = &[
    "/usr/bin/runc",
    "/usr/bin/containerd",
    "/usr/bin/containerd-shim",
    "/usr/bin/dockerd",
    "/usr/sbin/NetworkManager",
    "/usr/lib/systemd/systemd",
    "/usr/lib/systemd/systemd-journald",
    "/usr/lib/systemd/systemd-udevd",
    "/usr/bin/python3",
    "/usr/bin/python3.10",
    "/usr/bin/python3.11",
    "/usr/bin/perl",
    "/usr/sbin/sshd",
    "/usr/bin/ssh",
    "/usr/lib/openssh/sftp-server",
    "/usr/bin/gnome-shell",
    "/usr/bin/Xorg",
];

#[derive(Debug, Clone)]
struct ProcInfo {

    pid:     u32,
    ppid:    u32,
    comm:    String,
    cmdline: String,
    exe:     String,
    uid:     u32,
    gid:     u32,
}

pub async fn run(tx: Sender<Event>, cfg: Arc<AgentConfig>) -> Result<()> {
    info!("Process monitor started");
    let mut seen_pids: HashSet<u32> = HashSet::new();
    let mut ticker = interval(Duration::from_secs(cfg.proc_scan_interval_secs));

    loop {
        ticker.tick().await;

        let current = scan_procs();
        let current_pids: HashSet<u32> = current.keys().cloned().collect();

        // ── New processes ──
        for (pid, proc) in &current {
            if seen_pids.contains(pid) {
                continue;
            }

            let (suspicious, reason) = is_suspicious(proc, &cfg);

            let severity = if suspicious {
                if reason.as_deref().unwrap_or("").contains("root") || proc.uid == 0 {
                    Severity::Critical
                } else {
                    Severity::High
                }
            } else {
                Severity::Info
            };

            if suspicious {
                warn!("SUSPICIOUS PROCESS: pid={} cmd={} reason={:?}", pid, proc.cmdline, reason);
            }

            let event = Event::new(
                &cfg.agent_id,
                &cfg.hostname,
                severity,
                EventData::ProcessEvent {
                    pid:              proc.pid,
                    ppid:             proc.ppid,
                    comm:             proc.comm.clone(),
                    cmdline:          proc.cmdline.clone(),
                    exe:              proc.exe.clone(),
                    uid:              proc.uid,
                    gid:              proc.gid,
                    action:           if suspicious { ProcessAction::Suspicious } else { ProcessAction::Started },
                    suspicious,
                    suspicion_reason: reason.clone(),
                },
            );

            let event = if suspicious {
                event.with_mitre("Execution", "T1059", "Command and Scripting Interpreter")
                     .with_tag("suspicious-process")
            } else {
                event.with_tag("process-start")
            };

            let _ = tx.send(event).await;
        }

        // ── Exited processes ──
        for pid in seen_pids.difference(&current_pids) {
            let _ = tx.send(Event::new(
                &cfg.agent_id,
                &cfg.hostname,
                Severity::Info,
                EventData::ProcessEvent {
                    pid: *pid, ppid: 0,
                    comm: String::new(), cmdline: String::new(),
                    exe: String::new(), uid: 0, gid: 0,
                    action: ProcessAction::Exited,
                    suspicious: false, suspicion_reason: None,
                },
            ).with_tag("process-exit")).await;
        }

        seen_pids = current_pids;
    }
}

fn scan_procs() -> HashMap<u32, ProcInfo> {
    let mut map = HashMap::new();

    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return map,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let base = format!("/proc/{}", pid);

        let comm    = fs::read_to_string(format!("{}/comm", base)).unwrap_or_default().trim().to_string();
        let cmdline = fs::read_to_string(format!("{}/cmdline", base)).unwrap_or_default().replace('\0', " ").trim().to_string();
        let exe     = fs::read_link(format!("{}/exe", base)).map(|p| p.to_string_lossy().to_string()).unwrap_or_default();

        let (ppid, uid, gid) = parse_status(&format!("{}/status", base));

        map.insert(pid, ProcInfo { pid, ppid, comm, cmdline, exe, uid, gid });
    }

    map
}

fn parse_status(path: &str) -> (u32, u32, u32) {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return (0, 0, 0),
    };

    let mut ppid = 0u32;
    let mut uid  = 0u32;
    let mut gid  = 0u32;

    for line in content.lines() {
        if let Some(val) = line.strip_prefix("PPid:\t") {
            ppid = val.trim().parse().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("Uid:\t") {
            uid = val.split_whitespace().next().unwrap_or("0").parse().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("Gid:\t") {
            gid = val.split_whitespace().next().unwrap_or("0").parse().unwrap_or(0);
        }
    }

    (ppid, uid, gid)
}

fn is_suspicious(proc: &ProcInfo, cfg: &AgentConfig) -> (bool, Option<String>) {
    // ── Whitelist check — skip known-safe executables immediately ──
    for safe in SAFE_EXECUTABLES {
        if proc.exe.starts_with(safe) {
            return (false, None);
        }
    }

    let cmdline_lc = proc.cmdline.to_lowercase();
    let exe_lc     = proc.exe.to_lowercase();

    // 1. Execution from suspicious path

    // 1. Execution from suspicious path
    for path in &cfg.suspicious_paths {
        if exe_lc.starts_with(path) || proc.cmdline.starts_with(path.as_str()) {
            return (true, Some(format!("Execution from suspicious path: {}", path)));
        }
    }

    // 2. Suspicious command patterns
    let shell_patterns = [
        "bash -i", "sh -i", "sh -c",
        "python -c", "python3 -c",
        "perl -e", "ruby -e",
        "php -r", "lua -e",
        "/dev/tcp/", "/dev/udp/",
        "0>&1", "2>&1",
        "mkfifo", "mknod",
        "exec /bin/bash", "exec /bin/sh",
    ];
    for pat in &shell_patterns {
        if cmdline_lc.contains(pat) {
            return (true, Some(format!("Reverse shell pattern: {}", pat)));
        }
    }

    // 3. Suspicious comm names
    for comm in &cfg.suspicious_comms {
        if proc.comm.to_lowercase().contains(&comm.to_lowercase()) {
            return (true, Some(format!("Suspicious process name: {}", comm)));
        }
    }

    // 4. Root process with network listener from non-standard binary
    if proc.uid == 0 && exe_lc.contains("/tmp") {
        return (true, Some("Root process executing from /tmp".to_string()));
    }

    // 5. Kernel thread impersonation (name matches kernel thread but has exe)
    if (proc.comm.starts_with('[') && proc.comm.ends_with(']')) && !proc.exe.is_empty() {
        return (true, Some("Possible kernel thread impersonation".to_string()));
    }

    // 6. Base64 encoded payload in cmdline
    if cmdline_lc.contains("base64") && (cmdline_lc.contains("bash") || cmdline_lc.contains("eval")) {
        return (true, Some("Base64 encoded execution".to_string()));
    }

    (false, None)
}
