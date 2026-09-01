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
    pub state: Option<State>,
    pub pid: Option<u32>,
    pub ip: Option<String>,
    pub kill_switch: bool,
    pub mac_old: Option<String>,
    pub mac_new: Option<String>,
    pub mac_interface: Option<String>,
    pub hostname_old: Option<String>,
    pub bridge_enabled: bool,
    pub bridge_count: usize,
    pub exit_profile: Option<String>,
    pub namespace_active: bool,
    pub browser_hardened: usize,
    pub saved_rules: Option<String>,
    pub machine_id_old: Option<String>,
    pub tcp_stack_masked: bool,
    pub multihop_enabled: bool,
    pub wireguard_config: Option<String>,
}

pub struct StateManager {
    path: PathBuf,
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

    pub fn is_active(&self) -> bool {
        self.path.exists()
    }

    pub fn activate(&self, data: StateData) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut payload = data;
        payload.active = true;
        payload.state = Some(State::Active);
        payload.pid = Some(std::process::id());

        let serialized = serde_json::to_string_pretty(&payload)?;

        // Atomic write via tempfile in same directory
        let parent = self.path.parent().unwrap_or_else(|| Path::new("/var/run"));
        let temp_path = parent.join(format!(".wraith.state.{}.tmp", std::process::id()));

        {
            let mut file = File::create(&temp_path)?;
            file.write_all(serialized.as_bytes())?;
            file.sync_all()?;
        }

        fs::rename(temp_path, &self.path)?;
        Ok(())
    }

    pub fn deactivate(&self) -> Result<()> {
        if self.path.exists() {
            fs::remove_file(&self.path)?;
        }
        Ok(())
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
