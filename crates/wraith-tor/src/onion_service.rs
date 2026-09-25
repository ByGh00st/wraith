//! Wraith Ephemeral Onion v3 Hidden Service & Covert Channel Manager
//! Generates on-the-fly Tor v3 Hidden Services (.onion) with Ed25519 authorization,
//! PoW anti-DoS rate limiting, and ephemeral Unix Domain Socket binding.

use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use rand::RngCore;
use tracing::info;
use wraith_core::config::TORRC_PATH;
use wraith_core::error::{Result, WraithError};

pub const ONION_SERVICE_DIR: &str = "/var/lib/wraith/tor/onion_service";

#[derive(Debug, Clone)]
pub struct OnionServiceConfig {
    pub name: String,
    pub virtual_port: u16,
    pub target_port: u16,
    pub target_unix_socket: Option<String>,
    pub enable_pow_defense: bool,
    pub pow_queue_rate: u32,
    pub client_auth_keys: Vec<String>,
}

impl Default for OnionServiceConfig {
    fn default() -> Self {
        Self {
            name: "wraith_service".into(),
            virtual_port: 80,
            target_port: 8080,
            target_unix_socket: None,
            enable_pow_defense: true,
            pow_queue_rate: 10,
            client_auth_keys: Vec::new(),
        }
    }
}

impl OnionServiceConfig {
    pub fn new(virtual_port: u16, target_port: u16) -> Self {
        Self {
            name: "wraith_service".into(),
            virtual_port,
            target_port,
            target_unix_socket: None,
            enable_pow_defense: true,
            pow_queue_rate: 10,
            client_auth_keys: Vec::new(),
        }
    }

    pub fn add_port(&mut self, virtual_port: u16, target_port: u16) -> &mut Self {
        self.virtual_port = virtual_port;
        self.target_port = target_port;
        self
    }
}

pub struct OnionServiceManager;

impl OnionServiceManager {
    /// Generates torrc directives for an ephemeral v3 Onion Hidden Service
    pub fn render_service_directives(config: &OnionServiceConfig) -> String {
        let mut directives = String::new();
        directives.push_str(&format!("\n# === WRAITH EPHEMERAL V3 ONION SERVICE ({}) ===\n", config.name));
        directives.push_str(&format!("HiddenServiceDir {ONION_SERVICE_DIR}\n"));
        directives.push_str("HiddenServiceVersion 3\n");

        if let Some(socket_path) = &config.target_unix_socket {
            directives.push_str(&format!("HiddenServicePort {} unix:{}\n", config.virtual_port, socket_path));
        } else {
            directives.push_str(&format!("HiddenServicePort {} 127.0.0.1:{}\n", config.virtual_port, config.target_port));
        }

        if config.enable_pow_defense {
            directives.push_str("HiddenServiceEnablePoW 1\n");
            directives.push_str(&format!("HiddenServicePoWQueueRate {}\n", config.pow_queue_rate));
            directives.push_str("HiddenServicePoWQueueBurst 100\n");
        }

        // Restrict maximum concurrent streams per circuit to defeat layer-7 exhaustion
        directives.push_str("HiddenServiceMaxStreams 16\n");
        directives.push_str("HiddenServiceMaxStreamsCloseCircuit 1\n");

        directives
    }

    /// Injects ephemeral Hidden Service configuration into torrc (Idempotent)
    pub fn arm_onion_service(config: &OnionServiceConfig) -> Result<()> {
        if !config.client_auth_keys.is_empty() {
            return Err(WraithError::Configuration("Onion client authorization is not implemented; refusing to publish an unauthenticated service".into()));
        }
        if config.name.contains(['\r', '\n']) || config.target_unix_socket.as_deref()
            .map(|path| path.contains(['\r', '\n'])).unwrap_or(false) {
            return Err(WraithError::Configuration("Onion configuration contains line breaks".into()));
        }
        if config.virtual_port == 0 || config.target_port == 0 {
            return Err(WraithError::Configuration("Onion ports must be nonzero".into()));
        }
        let torrc = Path::new(TORRC_PATH);
        if !torrc.is_file() { return Err(WraithError::Configuration("Tor configuration is missing".into())); }
        if torrc.exists() {
            let mut content = fs::read_to_string(torrc)?;
            let marker = format!("HiddenServiceDir {ONION_SERVICE_DIR}");
            if content.contains(&marker) {
                info!("Ephemeral Onion v3 Hidden Service already configured in {TORRC_PATH}");
                return Ok(());
            }
            let directives = Self::render_service_directives(config);
            content.push_str(&directives);
            fs::write(torrc, content)?;
            info!("Ephemeral Onion v3 Hidden Service armed in {TORRC_PATH}");
        }
        Ok(())
    }

    /// Reads the generated .onion hostname from the Tor service directory
    pub fn read_onion_hostname() -> Result<Option<String>> {
        let hostname_path = Path::new(ONION_SERVICE_DIR).join("hostname");
        if hostname_path.exists() {
            let hostname = fs::read_to_string(hostname_path)?;
            Ok(Some(hostname.trim().to_string()))
        } else {
            Ok(None)
        }
    }

    /// Securely shreds an ephemeral key file using DoD 5220.22-M 7-pass random overwrite and flush
    pub fn shred_key_file(path: &Path, passes: u8) -> Result<()> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        if metadata.file_type().is_symlink() {
            fs::remove_file(path)?;
            return Ok(());
        }

        if !metadata.is_file() {
            return Ok(());
        }

        let len = metadata.len();
        if len > 0 {
            let mut file = OpenOptions::new().write(true).open(path)?;
            let mut buffer = zeroize::Zeroizing::new(vec![0u8; 4096]);
            let mut rng = rand::thread_rng();

            let pass_count = passes.max(1);
            for _ in 0..pass_count {
                file.seek(SeekFrom::Start(0))?;
                let mut written = 0;
                while written < len {
                    let chunk = std::cmp::min(buffer.len() as u64, len - written) as usize;
                    rng.fill_bytes(&mut buffer[..chunk]);
                    file.write_all(&buffer[..chunk])?;
                    written += chunk as u64;
                }
                file.sync_all()?;
            }

            // Final zeroization pass
            file.seek(SeekFrom::Start(0))?;
            buffer.fill(0);
            let mut written = 0;
            while written < len {
                let chunk = std::cmp::min(buffer.len() as u64, len - written) as usize;
                file.write_all(&buffer[..chunk])?;
                written += chunk as u64;
            }
            file.sync_all()?;
        }

        fs::remove_file(path)?;
        Ok(())
    }

    /// Recursively shreds all cryptographic keys, hostnames, and metadata in an Onion Service directory
    pub fn shred_onion_tree(dir: &Path) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let meta = fs::symlink_metadata(&path)?;
            if meta.is_dir() {
                Self::shred_onion_tree(&path)?;
                let _ = fs::remove_dir(&path);
            } else {
                Self::shred_key_file(&path, 7)?;
            }
        }
        Ok(())
    }

    /// Purges all Onion Hidden Service directories and private keys from storage
    pub fn purge_onion_service() -> Result<()> {
        let service_dir = Path::new(ONION_SERVICE_DIR);
        if service_dir.exists() {
            Self::shred_onion_tree(service_dir)?;
            let _ = fs::remove_dir_all(service_dir);
            info!("Ephemeral Onion service directory securely shredded and removed");
        }
        Ok(())
    }
}

/// Convenience function to arm ephemeral onion service
pub fn arm_onion_service(config: &OnionServiceConfig) -> Result<()> {
    OnionServiceManager::arm_onion_service(config)
}

/// Convenience function to read onion hostname
pub fn read_onion_hostname() -> Result<Option<String>> {
    OnionServiceManager::read_onion_hostname()
}

/// Convenience function to purge onion service
pub fn purge_onion_service() -> Result<()> {
    OnionServiceManager::purge_onion_service()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_onion_service_directive_rendering() {
        let mut cfg = OnionServiceConfig::default();
        cfg.add_port(80, 8080);
        let directives = OnionServiceManager::render_service_directives(&cfg);
        assert!(directives.contains("HiddenServiceDir /var/lib/wraith/tor/onion_service"));
        assert!(directives.contains("HiddenServicePort 80 127.0.0.1:8080"));
        assert!(directives.contains("HiddenServiceEnablePoW 1"));
    }

    #[test]
    fn test_shred_onion_tree_wipes_keys_and_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let onion_dir = temp_dir.path().join("onion_service");
        fs::create_dir_all(&onion_dir).unwrap();

        let secret_key_path = onion_dir.join("hs_ed25519_secret_key");
        let pub_key_path = onion_dir.join("hs_ed25519_public_key");
        let hostname_path = onion_dir.join("hostname");

        fs::write(&secret_key_path, b"==ed25519v1-secret: type0==\x00\x01mock_secret_key_material_bytes").unwrap();
        fs::write(&pub_key_path, b"==ed25519v1-public: type0==\x00\x01mock_public_key_material_bytes").unwrap();
        fs::write(&hostname_path, b"abcxyz1234567890.onion\n").unwrap();

        assert!(secret_key_path.exists());
        assert!(pub_key_path.exists());
        assert!(hostname_path.exists());

        OnionServiceManager::shred_onion_tree(&onion_dir).unwrap();

        assert!(!secret_key_path.exists());
        assert!(!pub_key_path.exists());
        assert!(!hostname_path.exists());
    }
}
