// sentinel-agent/src/fim.rs
use crate::{config::AgentConfig, models::*};
use anyhow::Result;
use inotify::{EventMask, Inotify, WatchMask};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs, io::Read, path::{Path, PathBuf}, sync::Arc, time::SystemTime};
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
struct FileState { sha256: String, size: u64, modified: SystemTime, uid: u32, gid: u32, mode: u32 }

#[derive(Debug, Clone)]
struct FileMeta { size: u64, modified: SystemTime, uid: u32, gid: u32, mode: u32 }

pub async fn run(tx: Sender<Event>, cfg: Arc<AgentConfig>) -> Result<()> {
    info!("FIM collector started — watching {} paths", cfg.fim_watch_paths.len());
    let mut baseline: HashMap<String, FileState> = HashMap::new();
    for watch_path in &cfg.fim_watch_paths {
        scan_dir_full(watch_path, &cfg.fim_exclude_paths, &mut baseline).await;
    }
    info!("FIM baseline: {} files indexed", baseline.len());
    let baseline = Arc::new(tokio::sync::Mutex::new(baseline));
    let tx_inotify = tx.clone();
    let cfg_inotify = cfg.clone();
    let bl_inotify = baseline.clone();
    tokio::spawn(async move {
        if let Err(e) = inotify_watcher(tx_inotify, cfg_inotify, bl_inotify).await {
            warn!("inotify watcher error: {} — falling back to polling only", e);
        }
    });
    polling_scanner(tx, cfg, baseline).await;
    Ok(())
}

async fn inotify_watcher(tx: Sender<Event>, cfg: Arc<AgentConfig>, baseline: Arc<tokio::sync::Mutex<HashMap<String, FileState>>>) -> Result<()> {
    let mut inotify = Inotify::init()?;
    let mut watched_dirs: Vec<String> = Vec::new();
    for watch_path in &cfg.fim_watch_paths {
        add_watches_recursive(&mut inotify, Path::new(watch_path), &cfg.fim_exclude_paths, &mut watched_dirs);
    }
    info!("inotify: watching {} directories for instant detection", watched_dirs.len());
    let mut buffer = [0u8; 65536];
    loop {
        match inotify.read_events(&mut buffer) {
            Ok(events) => {
                for event in events {
                    let name = match event.name {
                        Some(n) => n.to_string_lossy().to_string(),
                        None    => continue,
                    };
                    if cfg.fim_exclude_paths.iter().any(|ex| name.starts_with(ex)) { continue; }
                    if should_skip_file(&name) { continue; }
                    let mask = event.mask;
                    if let Some(path_str) = find_full_path(&name, &cfg.fim_watch_paths, &cfg.fim_exclude_paths) {
                        handle_inotify_event(&path_str, mask, &tx, &cfg, &baseline).await;
                    }
                }
            }
            Err(e) if e.raw_os_error() == Some(11) => {
    // EAGAIN — no events available yet, not a real error
    tokio::time::sleep(Duration::from_millis(150)).await;
}
Err(e) => {
    warn!("inotify read error: {}", e);
    tokio::time::sleep(Duration::from_millis(100)).await;
}
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn add_watches_recursive(inotify: &mut Inotify, dir: &Path, excludes: &[String], watched_dirs: &mut Vec<String>) {
    let dir_str = dir.to_string_lossy().to_string();
    if excludes.iter().any(|ex| dir_str.starts_with(ex)) { return; }
    let mask = WatchMask::CREATE | WatchMask::DELETE | WatchMask::MODIFY
        | WatchMask::CLOSE_WRITE | WatchMask::MOVED_FROM | WatchMask::MOVED_TO | WatchMask::ATTRIB;
    match inotify.watches().add(dir, mask) {
        Ok(_)  => { watched_dirs.push(dir_str.clone()); debug!("inotify watching: {}", dir_str); }
        Err(e) => { debug!("Cannot watch {}: {}", dir_str, e); return; }
    }
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && !path.is_symlink() {
                add_watches_recursive(inotify, &path, excludes, watched_dirs);
            }
        }
    }
}

async fn handle_inotify_event(
    path_str: &str, mask: EventMask,
    tx: &Sender<Event>, cfg: &Arc<AgentConfig>,
    baseline: &Arc<tokio::sync::Mutex<HashMap<String, FileState>>>,
) {
    let path = Path::new(path_str);

    if mask.contains(EventMask::DELETE) || mask.contains(EventMask::MOVED_FROM) {
        warn!("FIM [INSTANT]: DELETED → {}", path_str);
        let event = make_event(cfg, path_str, FileAction::Deleted, None, Severity::High)
            .with_mitre("Defense Evasion", "T1070", "Indicator Removal")
            .with_tag("fim").with_tag("deleted").with_tag("inotify");
        let _ = tx.send(event).await;
        let mut bl = baseline.lock().await;
        bl.remove(path_str);
        return;
    }

    if mask.contains(EventMask::CREATE) || mask.contains(EventMask::MOVED_TO) {
        if path.is_file() {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if let Some(state) = hash_file(path) {
                warn!("FIM [INSTANT]: CREATED → {}", path_str);
                let severity = if is_critical_path(path_str) { Severity::Critical } else { Severity::High };
                let event = make_event(cfg, path_str, FileAction::Created, Some(&state), severity)
                    .with_mitre("Persistence", "T1546", "Event Triggered Execution")
                    .with_tag("fim").with_tag("created").with_tag("inotify");
                let _ = tx.send(event).await;
                let mut bl = baseline.lock().await;
                bl.insert(path_str.to_string(), state);
            }
        }
        return;
    }

    if mask.contains(EventMask::ATTRIB) {
        if let Ok(meta) = fs::metadata(path) {
            use std::os::unix::fs::MetadataExt;
            let mode = meta.mode();
            // FIX 1: get old_mode in its own scope so borrow is dropped before tx.send
            let old_mode = {
                let bl = baseline.lock().await;
                bl.get(path_str).map(|s| s.mode).unwrap_or(0)
            }; // ← immutable borrow dropped here
            if mode != old_mode {
                warn!("FIM [INSTANT]: PERMISSION CHANGED → {} ({:o} → {:o})", path_str, old_mode, mode);
                let event = make_event(cfg, path_str, FileAction::PermissionChanged, None, Severity::Medium)
                    .with_tag("fim").with_tag("perm-change").with_tag("inotify");
                let _ = tx.send(event).await;
            }
        }
        return;
    }

    if mask.contains(EventMask::MODIFY) || mask.contains(EventMask::CLOSE_WRITE) {
        if !path.is_file() { return; }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let state = match hash_file(path) {
            Some(s) => s,
            None    => return,
        };

        let mut bl = baseline.lock().await;

        // FIX 2: clone the old sha256 first, then the immutable borrow ends,
        // allowing bl.insert (mutable borrow) to compile cleanly
        let old_sha256 = bl.get(path_str).map(|s| s.sha256.clone());

        match old_sha256 {
            Some(old) => {
                if state.sha256 != old {
                    let severity = if is_critical_path(path_str) { Severity::Critical } else { Severity::High };
                    warn!("FIM [INSTANT]: HASH CHANGED → {}", path_str);
                    let event = make_event(cfg, path_str, FileAction::HashChanged, Some(&state), severity)
                        .with_mitre("Defense Evasion", "T1036", "Masquerading")
                        .with_tag("fim").with_tag("hash-changed").with_tag("inotify");
                    let _ = tx.send(event).await;
                    bl.insert(path_str.to_string(), state);
                }
            }
            None => {
                let severity = if is_critical_path(path_str) { Severity::Critical } else { Severity::High };
                warn!("FIM [INSTANT]: NEW FILE → {}", path_str);
                let event = make_event(cfg, path_str, FileAction::Created, Some(&state), severity)
                    .with_tag("fim").with_tag("new-file").with_tag("inotify");
                let _ = tx.send(event).await;
                bl.insert(path_str.to_string(), state);
            }
        }
    }
}

async fn polling_scanner(tx: Sender<Event>, cfg: Arc<AgentConfig>, baseline: Arc<tokio::sync::Mutex<HashMap<String, FileState>>>) {
    let interval_secs = cfg.fim_interval_secs.min(30).max(5);
    let mut ticker = interval(Duration::from_secs(interval_secs));
    info!("FIM polling backup: every {}s", interval_secs);

    loop {
        ticker.tick().await;
        debug!("FIM polling scan running...");

        let mut current_meta: HashMap<String, FileMeta> = HashMap::new();
        for watch_path in &cfg.fim_watch_paths {
            stat_dir(watch_path, &cfg.fim_exclude_paths, &mut current_meta);
        }

        let mut bl = baseline.lock().await;

        let deleted: Vec<String> = bl.keys().filter(|p| !current_meta.contains_key(*p)).cloned().collect();
        for path in &deleted {
            warn!("FIM [POLL]: DELETED → {}", path);
            let event = make_event(&cfg, path, FileAction::Deleted, None, Severity::High)
                .with_mitre("Defense Evasion", "T1070", "Indicator Removal")
                .with_tag("fim").with_tag("deleted").with_tag("polling");
            let _ = tx.send(event).await;
            bl.remove(path);
        }

        let mut to_hash: Vec<String>  = Vec::new();
        let mut new_files: Vec<String> = Vec::new();
        // FIX 3: collect perm changes as owned data so we can mutably borrow bl after the loop
        let mut perm_changes: Vec<(String, FileState)> = Vec::new();

        for (path, meta) in &current_meta {
            if should_skip_file(path) { continue; }
            match bl.get(path) {
                None => { new_files.push(path.clone()); to_hash.push(path.clone()); }
                Some(old) => {
                    if meta.modified != old.modified || meta.size != old.size {
                        to_hash.push(path.clone());
                    } else if meta.mode != old.mode {
                        // Clone everything we need before loop ends
                        perm_changes.push((path.clone(), FileState {
                            sha256:   old.sha256.clone(),
                            size:     meta.size,
                            modified: meta.modified,
                            uid:      meta.uid,
                            gid:      meta.gid,
                            mode:     meta.mode,
                        }));
                    }
                }
            }
        }

        // Apply perm changes — safe now, no immutable borrow active
        for (path, new_state) in perm_changes {
            warn!("FIM [POLL]: PERM CHANGED → {}", path);
            let event = make_event(&cfg, &path, FileAction::PermissionChanged, None, Severity::Medium)
                .with_tag("fim").with_tag("perm-change").with_tag("polling");
            let _ = tx.send(event).await;
            bl.insert(path, new_state);
        }

        drop(bl);

        debug!("FIM poll: {}/{} files need re-hashing", to_hash.len(), current_meta.len());
        if to_hash.is_empty() { continue; }

        let paths  = to_hash.clone();
        let hashed: HashMap<String, Option<FileState>> =
            tokio::task::spawn_blocking(move || {
                paths.iter().map(|p| (p.clone(), hash_file(Path::new(p)))).collect()
            })
            .await
            .unwrap_or_default();

        let mut bl = baseline.lock().await;

        for path in &to_hash {
            let new_state = match hashed.get(path).and_then(|s| s.as_ref()) {
                Some(s) => s,
                None    => continue,
            };

            if new_files.contains(path) {
                let severity = if is_critical_path(path) { Severity::Critical } else { Severity::High };
                warn!("FIM [POLL]: NEW FILE → {}", path);
                let event = make_event(&cfg, path, FileAction::Created, Some(new_state), severity)
                    .with_tag("fim").with_tag("new-file").with_tag("polling");
                let _ = tx.send(event).await;
            } else {
                // FIX 4: clone old sha256 first, then bl.insert is safe
                let old_sha256 = bl.get(path).map(|s| s.sha256.clone());
                if let Some(old) = old_sha256 {
                    if new_state.sha256 != old {
                        let severity = if is_critical_path(path) { Severity::Critical } else { Severity::High };
                        warn!("FIM [POLL]: HASH CHANGED → {}", path);
                        let event = make_event(&cfg, path, FileAction::HashChanged, Some(new_state), severity)
                            .with_mitre("Defense Evasion", "T1036", "Masquerading")
                            .with_tag("fim").with_tag("hash-changed").with_tag("polling");
                        let _ = tx.send(event).await;
                    }
                }
            }

            bl.insert(path.clone(), new_state.clone());
        }

        bl.retain(|p, _| current_meta.contains_key(p));
        debug!("FIM poll complete — {} files tracked", bl.len());
    }
}

fn make_event(cfg: &AgentConfig, path: &str, action: FileAction, state: Option<&FileState>, severity: Severity) -> Event {
    Event::new(&cfg.agent_id, &cfg.hostname, severity, EventData::FileEvent {
        path:   path.to_string(), action,
        sha256: state.map(|s| s.sha256.clone()),
        size:   state.map(|s| s.size),
        uid:    state.map(|s| s.uid),
        gid:    state.map(|s| s.gid),
        mode:   state.map(|s| s.mode),
    })
}

fn find_full_path(name: &str, watch_paths: &[String], excludes: &[String]) -> Option<String> {
    for watch_path in watch_paths {
        let candidate = format!("{}/{}", watch_path.trim_end_matches('/'), name);
        if excludes.iter().any(|ex| candidate.starts_with(ex)) { continue; }
        if Path::new(&candidate).exists() { return Some(candidate); }
    }
    for watch_path in watch_paths {
        if let Some(found) = search_for_file(Path::new(watch_path), name, excludes) { return Some(found); }
    }
    None
}

fn search_for_file(dir: &Path, name: &str, excludes: &[String]) -> Option<String> {
    let dir_str = dir.to_string_lossy().to_string();
    if excludes.iter().any(|ex| dir_str.starts_with(ex)) { return None; }
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.file_name()?.to_string_lossy() == name && path.is_file() {
                return Some(path.to_string_lossy().to_string());
            }
            if path.is_dir() && !path.is_symlink() {
                if let Some(found) = search_for_file(&path, name, excludes) { return Some(found); }
            }
        }
    }
    None
}

fn should_skip_file(path: &str) -> bool {
    const SKIP_SUFFIXES: &[&str] = &[".swp",".swx",".tmp",".lock",".pid","~",".bak",".orig",".dpkg-new",".dpkg-old",".cache",".log"];
    const SKIP_CONTAINS: &[&str] = &["/.git/","/lost+found/","/__pycache__/","/recently-used","/thumbnails/"];
    let lower = path.to_lowercase();
    SKIP_SUFFIXES.iter().any(|s| lower.ends_with(s)) || SKIP_CONTAINS.iter().any(|s| lower.contains(s))
}

fn hash_file(path: &Path) -> Option<FileState> {
    let meta = fs::metadata(path).ok()?;
    if meta.len() > 52_428_800 { return None; }
    let mut file = fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    use std::os::unix::fs::MetadataExt;
    Some(FileState {
        sha256: hex::encode(hasher.finalize()), size: meta.len(),
        modified: meta.modified().ok()?,
        uid: meta.uid(), gid: meta.gid(), mode: meta.mode(),
    })
}

fn stat_dir(root: &str, excludes: &[String], map: &mut HashMap<String, FileMeta>) {
    let path = Path::new(root);
    if path.exists() { stat_walk(path, excludes, map); }
}

fn stat_walk(dir: &Path, excludes: &[String], map: &mut HashMap<String, FileMeta>) {
    let entries = match fs::read_dir(dir) { Ok(e) => e, Err(_) => return };
    for entry in entries.flatten() {
        let path = entry.path();
        let path_str = path.to_string_lossy().to_string();
        if excludes.iter().any(|ex| path_str.starts_with(ex)) { continue; }
        if path.is_symlink() { continue; }
        if path.is_dir() { stat_walk(&path, excludes, map); }
        else if path.is_file() {
            if let Ok(meta) = fs::metadata(&path) {
                use std::os::unix::fs::MetadataExt;
                if let Ok(modified) = meta.modified() {
                    map.insert(path_str, FileMeta { size: meta.len(), modified, uid: meta.uid(), gid: meta.gid(), mode: meta.mode() });
                }
            }
        }
    }
}

async fn scan_dir_full(root: &str, excludes: &[String], map: &mut HashMap<String, FileState>) {
    if !Path::new(root).exists() { return; }
    let root = root.to_string();
    let excludes = excludes.to_vec();
    let result = tokio::task::spawn_blocking(move || {
        let mut m = HashMap::new();
        walk_full(Path::new(&root), &excludes, &mut m);
        m
    }).await.unwrap_or_default();
    map.extend(result);
}

fn walk_full(dir: &Path, excludes: &[String], map: &mut HashMap<String, FileState>) {
    let entries = match fs::read_dir(dir) { Ok(e) => e, Err(_) => return };
    for entry in entries.flatten() {
        let path = entry.path();
        let path_str = path.to_string_lossy().to_string();
        if excludes.iter().any(|ex| path_str.starts_with(ex)) { continue; }
        if path.is_symlink() { continue; }
        if path.is_dir() { walk_full(&path, excludes, map); }
        else if path.is_file() {
            if !should_skip_file(&path_str) {
                if let Some(state) = hash_file(&path) { map.insert(path_str, state); }
            }
        }
    }
}

fn is_critical_path(path: &str) -> bool {
    const CRITICAL: &[&str] = &[
        "/etc/passwd","/etc/shadow","/etc/sudoers","/etc/hosts",
        "/etc/ssh/sshd_config","/etc/pam.d","/etc/cron","/etc/systemd",
        "/usr/bin/sudo","/usr/bin/su","/lib/x86_64-linux-gnu/libpam",
        "/boot/","/root/.ssh",
    ];
    CRITICAL.iter().any(|c| path.starts_with(c))
}
