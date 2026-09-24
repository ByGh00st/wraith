//! Wraith Atomic State Management
//! Thread-safe state tracking with atomic disk transactions.

use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::config::STATE_FILE;
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum State {
    Idle,
    Arming,
    Active,
    Killed,
    Cleanup,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StateData {
    pub active: bool,
    /// Recorded session policy; older recovery records did not contain it.
    #[serde(default)]
    pub strict_hardening: bool,
    #[serde(default)]
    pub saved_files: std::collections::HashMap<String, crate::file_snapshot::FileSnapshot>,
    #[serde(default)]
    pub dns_configured: bool,
    #[serde(default)]
    pub tor_started: bool,
    #[serde(default)]
    pub stopped_tor_services: Vec<String>,
    #[serde(default)]
    pub saved_resolver: Option<String>,
    #[serde(default)]
    pub physical_fastpath_disabled: bool,
    pub state: Option<State>,
    pub pid: Option<u32>,
    #[serde(default)]
    pub process_identity: Option<crate::process_identity::ProcessIdentity>,
    pub ip: Option<String>,
    pub kill_switch: bool,
    pub mac_old: Option<String>,
    pub mac_new: Option<String>,
    pub mac_interface: Option<String>,
    pub target_interface: Option<String>,
    pub hostname_old: Option<String>,
    pub bridge_enabled: bool,
    pub bridge_count: usize,
    pub exit_profile: Option<String>,
    pub namespace_active: bool,
    #[serde(default)]
    pub kernel_sysctl_backup: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub browser_configured: bool,
    #[serde(default)]
    pub font_configured: bool,
    #[serde(default)]
    pub original_cgroup: Option<String>,
    pub browser_hardened: usize,
    pub saved_rules: Option<String>,
    #[serde(default)]
    pub saved_ipv6_rules: Option<String>,
    #[serde(default)]
    pub tcp_stack_backup: std::collections::HashMap<String, String>,
    pub machine_id_old: Option<String>,
    #[serde(default)]
    pub machine_id_backup: std::collections::HashMap<String, String>,
    pub tcp_stack_masked: bool,
    /// Active L4 TCP profile kind name (e.g. "Windows 11", "macOS")
    #[serde(default)]
    pub tcp_profile_kind: Option<String>,
    #[serde(default)]
    pub tls_profile: Option<String>,
    /// Serialized NetnsTcpSnapshot for 3-tier rollback
    #[serde(default)]
    pub tcp_snapshot_json: Option<String>,
    pub multihop_enabled: bool,
    pub wireguard_config: Option<String>,
    pub onion_service_active: bool,
    pub onion_hostname: Option<String>,
    pub traffic_shaper_active: bool,
    pub honeypot_active: bool,
    pub honeypot_lan_active: bool,
    pub display_jail_active: bool,
    #[serde(default)]
    pub vault_path: Option<String>,
}

pub struct StateManager {
    pub path: PathBuf,
}

impl Default for StateManager {
    fn default() -> Self {
        Self::new()
    }
}

impl StateManager {
    pub fn new() -> Self {
        Self {
            path: PathBuf::from(STATE_FILE),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn is_running(&self) -> bool {
        let Ok(data) = self.read_checked() else { return false; };
        let Some(pid) = data.pid else { return false; };
        #[cfg(target_os = "linux")]
        {
            crate::process_identity::SessionProcess::open(pid, data.process_identity.as_ref())
                .is_ok_and(|process| process.is_some())
        }
        #[cfg(not(target_os = "linux"))]
        { pid == std::process::id() }
    }

    pub fn is_active(&self) -> bool {
        let data = self.read();
        if !data.active {
            return false;
        }
        self.is_running()
    }

    pub fn claim(&self, mut data: StateData) -> Result<()> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("/var/run"));
        fs::create_dir_all(parent)?;
        if self.path.exists() {
            return Err(crate::error::WraithError::Configuration(
                "Session record already exists; run wraith stop to recover it before starting again".into(),
            ));
        }
        data.active = false;
        data.state = Some(State::Arming);
        data.pid = Some(std::process::id());
        #[cfg(target_os = "linux")]
        { data.process_identity = Some(crate::process_identity::capture(std::process::id())?); }
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        temp.write_all(serde_json::to_string_pretty(&data)?.as_bytes())?;
        temp.as_file().sync_all()?;
        temp.persist_noclobber(&self.path).map_err(|e| e.error)?;
        #[cfg(unix)] File::open(parent)?.sync_all()?;
        Ok(())
    }

    pub fn activate(&self, data: StateData) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut payload = data;
        payload.state = Some(payload.state.unwrap_or(State::Active));
        payload.active = payload.state == Some(State::Active);
        payload.pid = Some(std::process::id());
        #[cfg(target_os = "linux")]
        { payload.process_identity = Some(crate::process_identity::capture(std::process::id())?); }

        let serialized = serde_json::to_string_pretty(&payload)?;

        // Atomic write via tempfile in same directory
        let parent = self.path.parent().unwrap_or_else(|| Path::new("/var/run"));
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        temp.write_all(serialized.as_bytes())?;
        temp.as_file().sync_all()?;
        temp.persist(&self.path).map_err(|e| e.error)?;
        #[cfg(unix)] File::open(parent)?.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn finish_cleanup(&self, errors: &[String]) -> Result<()> {
        if !errors.is_empty() {
            return Err(crate::error::WraithError::Custom(format!("Cleanup incomplete; session record retained: {}", errors.join("; "))));
        }
        self.deactivate()
    }

    pub fn deactivate(&self) -> Result<()> {
        if self.path.exists() {
            fs::remove_file(&self.path)?;
        }
        Ok(())
    }

    pub fn read_checked(&self) -> Result<StateData> {
        Ok(serde_json::from_str(&fs::read_to_string(&self.path)?)?)
    }

    pub fn read(&self) -> StateData {
        if !self.path.exists() {
            return StateData::default();
        }

        match fs::read_to_string(&self.path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(data) => data,
                Err(e) => {
                    tracing::warn!("Failed deserializing state from {}: {e}", self.path.display());
                    StateData::default()
                }
            },
            Err(e) => {
                tracing::warn!("Failed reading state file from {}: {e}", self.path.display());
                StateData::default()
            }
        }
    }

    pub fn write_state_to_path(path: &Path, data: &StateData) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let serialized = serde_json::to_string_pretty(data)?;
        let mut file = File::create(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        file.write_all(serialized.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }

    pub fn read_state_from_path(path: &Path) -> StateData {
        if !path.exists() {
            return StateData::default();
        }
        match fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(data) => data,
                Err(e) => {
                    tracing::warn!("Failed deserializing state from {}: {e}", path.display());
                    StateData::default()
                }
            },
            Err(e) => {
                tracing::warn!("Failed reading state file from {}: {e}", path.display());
                StateData::default()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_policy_roundtrips_and_legacy_records_remain_recoverable() {
        let state = StateData { strict_hardening: true, ..Default::default() };
        let mut json = serde_json::to_value(&state).unwrap();
        assert!(serde_json::from_value::<StateData>(json.clone()).unwrap().strict_hardening);
        json.as_object_mut().unwrap().remove("strict_hardening");
        assert!(!serde_json::from_value::<StateData>(json).unwrap().strict_hardening);
    }

    #[test]
    fn stale_and_corrupt_records_cannot_be_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let manager = StateManager { path: dir.path().join("state") };
        for bytes in [b"{invalid recovery record".as_slice(), br#"{"pid":4294967295,"active":true}"#] {
            fs::write(&manager.path, bytes).unwrap();
            assert!(manager.claim(StateData::default()).is_err());
            assert_eq!(fs::read(&manager.path).unwrap(), bytes);
        }
    }

    #[test]
    fn incomplete_cleanup_preserves_recovery_record() {
        let dir = tempfile::tempdir().unwrap();
        let manager = StateManager { path: dir.path().join("state") };
        manager.claim(StateData::default()).unwrap();
        let before = fs::read(&manager.path).unwrap();
        assert!(manager.finish_cleanup(&["MAC restoration denied".into()]).is_err());
        assert_eq!(fs::read(&manager.path).unwrap(), before);
        manager.finish_cleanup(&[]).unwrap();
        assert!(!manager.is_active());
    }

    #[test]
    fn concurrent_session_claim_cannot_overwrite_owner() {
        let dir = tempfile::tempdir().unwrap();
        let manager = StateManager { path: dir.path().join("state") };
        manager.claim(StateData::default()).unwrap();
        let before = fs::read(&manager.path).unwrap();
        assert!(manager.claim(StateData::default()).is_err());
        assert_eq!(fs::read(&manager.path).unwrap(), before);
        manager.activate(StateData::default()).unwrap();
        assert!(manager.read().active);
    }

    #[test]
    fn test_state_data_tcp_persistence_roundtrip() {
        let mut state = StateData::default();
        state.tcp_stack_masked = true;
        state.tcp_profile_kind = Some("Windows 11".to_string());
        state.tcp_snapshot_json = Some(r#"{"namespace":"wraith_ns","values":{}}"#.to_string());

        let json = serde_json::to_string(&state).expect("serialize StateData");
        let decoded: StateData = serde_json::from_str(&json).expect("deserialize StateData");

        assert!(decoded.tcp_stack_masked);
        assert_eq!(decoded.tcp_profile_kind.as_deref(), Some("Windows 11"));
        assert!(decoded.tcp_snapshot_json.is_some());
    }
}
