//! Wraith DMI, CPU & System Identity Cloaker
//! Randomizes /etc/machine-id and masks hardware identifiers to prevent local OS reconnaissance.

use rand::Rng;
use std::fs;
use std::path::Path;
use tracing::info;
use wraith_core::error::{Result, WraithError};

pub const MACHINE_ID_PATH: &str = "/etc/machine-id";
pub const DBUS_MACHINE_ID_PATH: &str = "/var/lib/dbus/machine-id";

pub fn generate_random_machine_id() -> String {
    let mut rng = rand::thread_rng();
    (0..16)
        .map(|_| format!("{:02x}", rng.gen::<u8>()))
        .collect::<Vec<_>>()
        .join("")
}

pub fn backup_machine_ids() -> Result<std::collections::HashMap<String, String>> {
    let mut backup = std::collections::HashMap::new();
    backup.insert(MACHINE_ID_PATH.into(), fs::read_to_string(MACHINE_ID_PATH)?);
    if Path::new(DBUS_MACHINE_ID_PATH).exists() {
        backup.insert(DBUS_MACHINE_ID_PATH.into(), fs::read_to_string(DBUS_MACHINE_ID_PATH)?);
    }
    Ok(backup)
}

pub fn restore_machine_ids(backup: &std::collections::HashMap<String, String>) -> Result<()> {
    let mut errors = Vec::new();
    for (path, content) in backup {
        if path != MACHINE_ID_PATH && path != DBUS_MACHINE_ID_PATH {
            errors.push(format!("Unknown machine-id backup: {path}"));
        } else if let Err(e) = fs::write(path, content) { errors.push(format!("{path}: {e}")); }
    }
    if errors.is_empty() { Ok(()) } else { Err(WraithError::Forensic(errors.join("; "))) }
}

pub fn rotate_machine_id() -> Result<(String, String)> {
    rotate_machine_id_with_journal(|_| Ok(()))
}

pub fn rotate_machine_id_with_journal(journal: impl FnOnce(&std::collections::HashMap<String, String>) -> Result<()>) -> Result<(String, String)> {
    let backup = backup_machine_ids()?;
    journal(&backup)?;
    let new_id = generate_random_machine_id();
    for path in backup.keys() {
        if let Err(e) = fs::write(path, format!("{new_id}\n")) {
            restore_machine_ids(&backup)?;
            return Err(e.into());
        }
    }
    info!("Rotated OS machine-id");
    Ok((backup[MACHINE_ID_PATH].trim().to_string(), new_id))
}

pub fn restore_machine_id(original_id: &str) -> Result<()> {
    if original_id.is_empty() || original_id == "unknown" {
        return Err(WraithError::Forensic("Original machine-id is unavailable".into()));
    }
    let mut backup = std::collections::HashMap::new();
    backup.insert(MACHINE_ID_PATH.into(), format!("{original_id}\n"));
    if Path::new(DBUS_MACHINE_ID_PATH).exists() { backup.insert(DBUS_MACHINE_ID_PATH.into(), format!("{original_id}\n")); }
    restore_machine_ids(&backup)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_machine_id_format() {
        let id = generate_random_machine_id();
        assert_eq!(id.len(), 32, "Machine ID must be exactly 32 hexadecimal characters");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()), "Machine ID must contain only valid hex characters");
    }
}
