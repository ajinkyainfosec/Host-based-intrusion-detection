// sentinel-agent/src/models.rs
// Shared event data structures sent from agent → server

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventData {
    // ── File Integrity ──
    FileEvent {
        path: String,
        action: FileAction,
        sha256: Option<String>,
        size: Option<u64>,
        uid: Option<u32>,
        gid: Option<u32>,
        mode: Option<u32>,
    },
    // ── Process ──
    ProcessEvent {
        pid: u32,
        ppid: u32,
        comm: String,
        cmdline: String,
        exe: String,
        uid: u32,
        gid: u32,
        action: ProcessAction,
        suspicious: bool,
        suspicion_reason: Option<String>,
    },
    // ── Network ──
    NetworkEvent {
        local_addr: String,
        local_port: u16,
        remote_addr: String,
        remote_port: u16,
        protocol: String,
        state: String,
        pid: Option<u32>,
        comm: Option<String>,
    },
    // ── Auth / Login ──
    AuthEvent {
        user: String,
        action: AuthAction,
        source_ip: Option<String>,
        tty: Option<String>,
        success: bool,
        raw_line: String,
    },
    // ── Heartbeat ──
    Heartbeat {
        cpu_pct: f32,
        mem_pct: f32,
        uptime_secs: u64,
        agent_version: String,
    },
    // ── Rootkit ──
    RootkitEvent {
        detection_method: String,
        description: String,
        details: serde_json::Value,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileAction {
    Created,
    Modified,
    Deleted,
    Renamed,
    PermissionChanged,
    HashChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessAction {
    Started,
    Exited,
    Suspicious,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthAction {
    Login,
    Logout,
    FailedLogin,
    SudoCommand,
    SudoFailed,
    UserAdded,
    UserDeleted,
    PasswordChanged,
    SshKeyAdded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id:         String,
    pub agent_id:   String,
    pub hostname:   String,
    pub timestamp:  DateTime<Utc>,
    pub severity:   Severity,
    pub data:       EventData,
    pub tags:       Vec<String>,
    pub mitre:      Option<MitreTechnique>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub tactic:         String,
    pub technique_id:   String,
    pub technique_name: String,
}

impl Event {
    pub fn new(agent_id: &str, hostname: &str, severity: Severity, data: EventData) -> Self {
        Self {
            id:        uuid::Uuid::new_v4().to_string(),
            agent_id:  agent_id.to_string(),
            hostname:  hostname.to_string(),
            timestamp: Utc::now(),
            severity,
            data,
            tags:      vec![],
            mitre:     None,
        }
    }

    pub fn with_mitre(mut self, tactic: &str, tid: &str, technique: &str) -> Self {
        self.mitre = Some(MitreTechnique {
            tactic:         tactic.to_string(),
            technique_id:   tid.to_string(),
            technique_name: technique.to_string(),
        });
        self
    }

    pub fn with_tag(mut self, tag: &str) -> Self {
        self.tags.push(tag.to_string());
        self
    }
}
