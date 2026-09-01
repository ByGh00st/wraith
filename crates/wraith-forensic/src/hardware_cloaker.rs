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

pub fn rotate_machine_id() -> Result<(String, String)> {
    let old_id = fs::read_to_string(MACHINE_ID_PATH)
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string();

    let new_id = format!("{}\n", generate_random_machine_id());

    let machine_id_path = Path::new(MACHINE_ID_PATH);
    if machine_id_path.exists() {
        fs::write(machine_id_path, &new_id).map_err(|e| {
            WraithError::Forensic(format!("Failed rotating {MACHINE_ID_PATH}: {e}"))
        })?;
    }

    let dbus_path = Path::new(DBUS_MACHINE_ID_PATH);
    if dbus_path.exists() {
        if let Err(e) = fs::write(dbus_path, &new_id) {
            tracing::warn!("Failed writing to {DBUS_MACHINE_ID_PATH}: {e}");
        }
    }

    info!("Rotated OS machine-id: {old_id} -> {}", new_id.trim());
    Ok((old_id, new_id.trim().to_string()))
}

pub fn restore_machine_id(original_id: &str) -> Result<()> {
    if !original_id.is_empty() && original_id != "unknown" {
        let payload = format!("{original_id}\n");
        let machine_id_path = Path::new(MACHINE_ID_PATH);
        if machine_id_path.exists() {
            if let Err(e) = fs::write(machine_id_path, &payload) {
                tracing::warn!("Failed restoring {MACHINE_ID_PATH}: {e}");
            }
        }
        let dbus_path = Path::new(DBUS_MACHINE_ID_PATH);
        if dbus_path.exists() {
            if let Err(e) = fs::write(dbus_path, &payload) {
                tracing::warn!("Failed restoring {DBUS_MACHINE_ID_PATH}: {e}");
            }
        }
        info!("Restored original OS machine-id");
    }
    Ok(())
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
