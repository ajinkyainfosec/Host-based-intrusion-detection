// sentinel-agent/src/rootkit.rs
// Rootkit Detection Collector — v3 (race condition hardened)

use crate::{config::AgentConfig, models::*};
use anyhow::Result;
use std::{
    collections::HashSet,
    fs,
    path::Path,
    sync::Arc,
    time::{Duration as StdDuration, Instant},
};
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration, sleep};
use tracing::{info, warn, error};

const PROC_CHECK_SECS:      u64 = 60;
const MODULE_CHECK_SECS:    u64 = 120;
const PORT_CHECK_SECS:      u64 = 60;
const KALLSYMS_CHECK_SECS:  u64 = 300;
const STABILITY_WINDOW_SECS: u64 = 3;

const SAFE_MODULES: &[&str] = &[
    // ── Filesystems ──────────────────────────────────────────
    "ext4", "xfs", "btrfs", "vfat", "tmpfs",
    // ── TCP/IP ───────────────────────────────────────────────
    "tcp_cubic", "ipv6", "af_packet", "unix",
    // ── Netfilter / iptables ─────────────────────────────────
    "iptable_filter", "iptable_nat", "iptable_mangle", "iptable_raw",
    "nf_conntrack", "nf_nat", "nf_defrag_ipv4", "nf_defrag_ipv6",
    "nf_tables", "nft_compat",
    "xt_conntrack", "xt_addrtype", "xt_mark", "xt_tcpudp",
    "xt_nat", "xt_multiport", "xt_comment", "xt_MASQUERADE",
    "ip_tables", "x_tables",
    // ── Docker networking ────────────────────────────────────
    "overlay", "br_netfilter", "veth", "bridge", "stp", "llc",
    "libcrc32c", "crc32c_generic",
    // ── Network diagnostics (ss, netstat, monitoring tools) ──
    "inet_diag",       // socket diagnostics used by ss/netstat
    "tcp_diag",        // TCP diagnostics used by ss/netstat
    "udp_diag",        // UDP diagnostics
    "unix_diag",       // Unix socket diagnostics
    "packet_diag",     // packet socket diagnostics
    // ── TLS / Crypto ─────────────────────────────────────────
    "tls",             // kernel TLS used by modern HTTPS
    // ── Netfilter conntrack ───────────────────────────────────
    "nfnetlink",       // Netfilter netlink interface
    "nfnetlink_log",   // Netfilter logging
    "nfnetlink_queue", // Netfilter queue
    "nf_conntrack_netlink", // conntrack via netlink
    // ── Virtualisation / cloud ───────────────────────────────
    "virtio_net", "virtio_blk", "virtio_pci", "virtio_balloon",
    "vmw_vsock_virtio_transport", "vmw_balloon",
    "e1000", "e1000e", "igb", "ixgbe", "vmxnet3",
    // ── Display / GPU ─────────────────────────────────────────
    "drm", "i915", "amdgpu", "nouveau", "ttm",
    "drm_vram_helper", // DRM VRAM memory management
    "vboxvideo",       // VirtualBox display driver
    // ── USB ──────────────────────────────────────────────────
    "usbcore", "usb_storage", "usb_common",
    "usbhid",          // USB HID devices
    "hid_generic",     // generic HID
    // ── Storage / RAID ───────────────────────────────────────
    "loop", "dm_mod", "raid0", "raid1", "raid6_pq", "raid10",
    "dm_mirror", "dm_region_hash", "dm_log",
    "dax",             // direct access filesystem
    // ── Security frameworks ──────────────────────────────────
    "selinux", "apparmor",
    // ── GPU ──────────────────────────────────────────────────
    "nvidia", "nvidia_modeset", "nvidia_uvm",
    // ── Network bonding ──────────────────────────────────────
    "8021q", "bonding", "team",
    // ── Input devices ────────────────────────────────────────
    "joydev",          // joystick device
    "mousedev",        // mouse device
    "input_leds",      // input LEDs
    "mac_hid",         // Mac HID support
    // ── Misc ─────────────────────────────────────────────────
    "binfmt_misc",     // misc binary formats
    "autofs4",         // automount filesystem
];

const ROOTKIT_SYMBOLS: &[&str] = &[
    "hide_pid", "hook_syscall", "fake_getdents",
    "hide_module", "rootkit_init", "azazel",
    "adore", "reptile", "diamorphine", "suterusu",
    "necro", "r77", "knark", "override_symbol",
];

pub async fn run(tx: Sender<Event>, cfg: Arc<AgentConfig>) -> Result<()> {
    info!("Rootkit detector started — waiting for module list to stabilise...");

    // Wait until module list stops changing for 30 seconds.
    // This handles systems that load modules slowly (Docker, VMs, services).
    // A real rootkit hides permanently — legitimate modules finish loading quickly.
    let mut prev = read_loaded_modules();
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let curr = read_loaded_modules();
        if curr == prev {
            info!("Rootkit: module list stable — taking baseline");
            break;
        }
        info!(
            "Rootkit: modules still loading ({} → {}) — waiting 30s more...",
            prev.len(), curr.len()
        );
        prev = curr;
    }

    let module_baseline = read_loaded_modules();
    info!("Rootkit: {} kernel modules in baseline", module_baseline.len());

    let tx1 = tx.clone(); let cfg1 = cfg.clone();
    let tx2 = tx.clone(); let cfg2 = cfg.clone();
    let tx3 = tx.clone(); let cfg3 = cfg.clone();
    let tx4 = tx.clone(); let cfg4 = cfg.clone();

    tokio::join!(
        hidden_process_loop(tx1, cfg1),
        kernel_module_loop(tx2, cfg2, module_baseline),
        hidden_port_loop(tx3, cfg3),
        kallsyms_loop(tx4, cfg4),
    );
    Ok(())
}

// ── Helper: read current /proc PID listing ────────────────────
fn read_proc_pids() -> HashSet<u32> {
    let mut pids = HashSet::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if let Ok(pid) = name.parse::<u32>() {
                    pids.insert(pid);
                }
            }
        }
    }
    pids
}

// ── Helper: thread vs process ─────────────────────────────────
fn is_thread(pid: u32) -> bool {
    let content = match fs::read_to_string(format!("/proc/{}/status", pid)) {
        Ok(c)  => c,
        Err(_) => return false,
    };
    let mut found_pid:  Option<u32> = None;
    let mut found_tgid: Option<u32> = None;
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("Pid:\t")  { found_pid  = v.trim().parse().ok(); }
        if let Some(v) = line.strip_prefix("Tgid:\t") { found_tgid = v.trim().parse().ok(); }
        if found_pid.is_some() && found_tgid.is_some() { break; }
    }
    match (found_pid, found_tgid) {
        (Some(p), Some(t)) => p != t,
        _ => false,
    }
}

// ═══════════════════════════════════════════════════════════════
// TECHNIQUE 1 — Hidden Process Detection
// ═══════════════════════════════════════════════════════════════
async fn hidden_process_loop(tx: Sender<Event>, cfg: Arc<AgentConfig>) {
    let mut alerted_pids:    HashSet<u32> = HashSet::new();
    let mut suspicious_pids: std::collections::HashMap<u32, Instant> =
        std::collections::HashMap::new();
    let mut ticker = interval(Duration::from_secs(PROC_CHECK_SECS));
    loop {
        ticker.tick().await;
        check_hidden_processes(
            &tx, &cfg, &mut alerted_pids, &mut suspicious_pids
        ).await;
    }
}

async fn check_hidden_processes(
    tx: &Sender<Event>,
    cfg: &AgentConfig,
    alerted_pids:    &mut HashSet<u32>,
    suspicious_pids: &mut std::collections::HashMap<u32, Instant>,
) {
    let proc_pids_snap1 = read_proc_pids();

    let mut candidates: Vec<u32> = Vec::new();
    for pid in 3u32..=32768 {
        if !Path::new(&format!("/proc/{}/status", pid)).exists() { continue; }
        if proc_pids_snap1.contains(&pid) { continue; }
        if alerted_pids.contains(&pid)    { continue; }
        if is_thread(pid)                 { continue; }
        candidates.push(pid);
    }

    if candidates.is_empty() {
        suspicious_pids.clear();
        return;
    }

    sleep(Duration::from_secs(STABILITY_WINDOW_SECS)).await;

    let proc_pids_snap2 = read_proc_pids();
    let now = Instant::now();

    for pid in candidates {
        if proc_pids_snap2.contains(&pid) {
            suspicious_pids.remove(&pid);
            continue;
        }

        suspicious_pids.entry(pid).or_insert(now);

        let first_seen = suspicious_pids[&pid];
        if now.duration_since(first_seen) < StdDuration::from_secs(STABILITY_WINDOW_SECS) {
            continue;
        }

        alerted_pids.insert(pid);
        suspicious_pids.remove(&pid);

        let comm = fs::read_to_string(format!("/proc/{}/comm", pid))
            .unwrap_or_default().trim().to_string();

        error!("[ROOTKIT] Confirmed hidden process! PID={} name={}", pid, comm);

        let _ = tx.send(
            Event::new(
                &cfg.agent_id, &cfg.hostname, Severity::Critical,
                EventData::RootkitEvent {
                    detection_method: "proc_readdir_vs_direct_access".to_string(),
                    description: format!(
                        "ROOTKIT CONFIRMED: Process PID {} ('{}') hidden from /proc for {}+ seconds.",
                        pid, comm, STABILITY_WINDOW_SECS
                    ),
                    details: serde_json::json!({
                        "hidden_pid":        pid,
                        "process_name":      comm,
                        "listed_in_proc":    false,
                        "direct_accessible": true,
                        "is_thread":         false,
                        "stability_check":   true,
                        "hidden_for_secs":   STABILITY_WINDOW_SECS,
                    }),
                }
            )
            .with_mitre("Defense Evasion", "T1014", "Rootkit")
            .with_tag("rootkit")
            .with_tag("hidden-process")
        ).await;
    }

    suspicious_pids.retain(|pid, _| {
        Path::new(&format!("/proc/{}/status", pid)).exists()
    });
    alerted_pids.retain(|pid| {
        Path::new(&format!("/proc/{}/status", pid)).exists()
    });
}

// ═══════════════════════════════════════════════════════════════
// TECHNIQUE 2 — Kernel Module Monitoring
// ═══════════════════════════════════════════════════════════════
async fn kernel_module_loop(
    tx: Sender<Event>, cfg: Arc<AgentConfig>, baseline: HashSet<String>
) {
    let mut alerted_modules: HashSet<String> = HashSet::new();
    let mut ticker = interval(Duration::from_secs(MODULE_CHECK_SECS));
    loop {
        ticker.tick().await;
        check_kernel_modules(&tx, &cfg, &baseline, &mut alerted_modules).await;
    }
}

fn read_loaded_modules() -> HashSet<String> {
    let mut modules = HashSet::new();
    if let Ok(content) = fs::read_to_string("/proc/modules") {
        for line in content.lines() {
            if let Some(name) = line.split_whitespace().next() {
                modules.insert(name.to_lowercase());
            }
        }
    }
    modules
}

async fn check_kernel_modules(
    tx: &Sender<Event>,
    cfg: &AgentConfig,
    baseline: &HashSet<String>,
    alerted_modules: &mut HashSet<String>,
) {
    let current = read_loaded_modules();
    for module in current.difference(baseline) {
        if alerted_modules.contains(module) { continue; }
        alerted_modules.insert(module.clone());

        let is_safe = SAFE_MODULES.iter().any(|&s| s == module.as_str());
        warn!("[ROOTKIT] New kernel module: {} (safe={})", module, is_safe);

        // Skip safe modules entirely — no alert at all
        if is_safe { continue; }

        let _ = tx.send(
            Event::new(
                &cfg.agent_id, &cfg.hostname, Severity::Critical,
                EventData::RootkitEvent {
                    detection_method: "proc_modules_baseline_diff".to_string(),
                    description: format!(
                        "New kernel module loaded after startup: '{}'.", module
                    ),
                    details: serde_json::json!({
                        "module_name":  module,
                        "in_safe_list": is_safe,
                    }),
                }
            )
            .with_mitre("Defense Evasion", "T1014", "Rootkit")
            .with_tag("rootkit")
            .with_tag("kernel-module")
        ).await;
    }
}

// ═══════════════════════════════════════════════════════════════
// TECHNIQUE 3 — Hidden Port Detection
// ═══════════════════════════════════════════════════════════════
async fn hidden_port_loop(tx: Sender<Event>, cfg: Arc<AgentConfig>) {
    let mut alerted_ports: HashSet<u16> = HashSet::new();
    let mut ticker = interval(Duration::from_secs(PORT_CHECK_SECS));
    loop {
        ticker.tick().await;
        check_hidden_ports(&tx, &cfg, &mut alerted_ports).await;
    }
}

async fn check_hidden_ports(
    tx: &Sender<Event>, cfg: &AgentConfig, alerted_ports: &mut HashSet<u16>,
) {
    let proc_ports = parse_proc_net_ports();
    let ss_ports   = get_ss_ports().await;

    for port in &ss_ports {
        if *port <= 1024                { continue; }
        if proc_ports.contains(port)   { continue; }
        if alerted_ports.contains(port){ continue; }
        alerted_ports.insert(*port);

        warn!("[ROOTKIT] Hidden port: {}", port);
        let _ = tx.send(
            Event::new(
                &cfg.agent_id, &cfg.hostname, Severity::Critical,
                EventData::RootkitEvent {
                    detection_method: "proc_net_tcp_vs_ss".to_string(),
                    description: format!(
                        "ROOTKIT: Port {} visible via ss but absent from /proc/net/tcp.",
                        port
                    ),
                    details: serde_json::json!({ "hidden_port": port }),
                }
            )
            .with_mitre("Defense Evasion", "T1014", "Rootkit")
            .with_tag("rootkit")
            .with_tag("hidden-port")
        ).await;
    }
    alerted_ports.retain(|p| ss_ports.contains(p));
}

fn parse_proc_net_ports() -> HashSet<u16> {
    let mut ports = HashSet::new();
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(local) = parts.get(1) {
                    if let Some(port_hex) = local.split(':').nth(1) {
                        if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                            ports.insert(port);
                        }
                    }
                }
            }
        }
    }
    ports
}

async fn get_ss_ports() -> HashSet<u16> {
    let mut ports = HashSet::new();
    if let Ok(output) = tokio::process::Command::new("ss")
        .args(["-tlnp"]).output().await
    {
        for line in String::from_utf8_lossy(&output.stdout).lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(local) = parts.get(3) {
                if let Some(p) = local.rsplit(':').next() {
                    if let Ok(port) = p.parse::<u16>() {
                        ports.insert(port);
                    }
                }
            }
        }
    }
    ports
}

// ═══════════════════════════════════════════════════════════════
// TECHNIQUE 4 — /proc/kallsyms Anomaly Scan
// ═══════════════════════════════════════════════════════════════
async fn kallsyms_loop(tx: Sender<Event>, cfg: Arc<AgentConfig>) {
    let mut alerted_symbols: HashSet<String> = HashSet::new();
    let mut ticker = interval(Duration::from_secs(KALLSYMS_CHECK_SECS));
    loop {
        ticker.tick().await;
        check_kallsyms(&tx, &cfg, &mut alerted_symbols).await;
    }
}

async fn check_kallsyms(
    tx: &Sender<Event>, cfg: &AgentConfig,
    alerted_symbols: &mut HashSet<String>,
) {
    let content = match fs::read_to_string("/proc/kallsyms") {
        Ok(c)  => c,
        Err(_) => return,
    };
    for line in content.lines() {
        let lower = line.to_lowercase();
        for sym in ROOTKIT_SYMBOLS {
            if lower.contains(sym) && !alerted_symbols.contains(*sym) {
                alerted_symbols.insert(sym.to_string());
                error!("[ROOTKIT] Suspicious kernel symbol: {}", sym);
                let _ = tx.send(
                    Event::new(
                        &cfg.agent_id, &cfg.hostname, Severity::Critical,
                        EventData::RootkitEvent {
                            detection_method: "kallsyms_known_rootkit_symbols".to_string(),
                            description: format!(
                                "ROOTKIT INDICATOR: Known rootkit symbol '{}' found in /proc/kallsyms.",
                                sym
                            ),
                            details: serde_json::json!({
                                "symbol_name": sym,
                                "entry": &line[..line.len().min(120)],
                            }),
                        }
                    )
                    .with_mitre("Defense Evasion", "T1014", "Rootkit")
                    .with_tag("rootkit")
                    .with_tag("kallsyms")
                ).await;
                break;
            }
        }
    }
}
