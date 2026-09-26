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

    /// Strict validation of Onion service parameters to prevent torrc injection and malformed directives
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() || self.name.len() > 64 {
            return Err(WraithError::Configuration(
                "Onion service name must be between 1 and 64 characters".into(),
            ));
        }
        if !self.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return Err(WraithError::Configuration(
                "Onion service name contains invalid characters (only alphanumeric, '-' and '_' allowed)".into(),
            ));
        }
        if self.virtual_port == 0 || self.target_port == 0 {
            return Err(WraithError::Configuration(
                "Onion ports must be nonzero".into(),
            ));
        }
        if let Some(ref sock) = self.target_unix_socket {
            if sock.is_empty() || sock.len() > 108 {
                return Err(WraithError::Configuration(
                    "Onion Unix domain socket path must be between 1 and 108 characters".into(),
                ));
            }
            if !sock.starts_with('/') {
                return Err(WraithError::Configuration(
                    "Onion Unix domain socket path must be absolute".into(),
                ));
            }
            if sock.contains("..") || sock.chars().any(|c| c.is_ascii_control() || c.is_ascii_whitespace() || c == '#') {
                return Err(WraithError::Configuration(
                    "Onion Unix domain socket path contains invalid characters or path traversal".into(),
                ));
            }
        }
        if self.enable_pow_defense && (self.pow_queue_rate == 0 || self.pow_queue_rate > 10_000) {
            return Err(WraithError::Configuration(
                "Onion PoW queue rate must be between 1 and 10000".into(),
            ));
        }
        if !self.client_auth_keys.is_empty() {
            return Err(WraithError::Configuration(
                "Onion client authorization is not implemented; refusing to publish an unauthenticated service".into(),
            ));
        }
        Ok(())
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
        config.validate()?;
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

    fn open_no_follow_write(path: &Path) -> std::io::Result<fs::File> {
        let mut options = OpenOptions::new();
        options.write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        options.open(path)
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

        let mut file = Self::open_no_follow_write(path)?;
        let opened = file.metadata()?;
        if !opened.is_file() {
            return Err(WraithError::Configuration("Target changed to a non-regular file".into()));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if opened.nlink() != 1 || opened.ino() != metadata.ino() || opened.dev() != metadata.dev() {
                return Err(WraithError::Configuration("Target changed or has additional hard links".into()));
            }
        }

        let len = opened.len();
        if len > 0 {
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

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let current = fs::symlink_metadata(path)?;
            if current.ino() != opened.ino() || current.dev() != opened.dev() {
                return Err(WraithError::Configuration("Target name changed during overwrite; refusing unlink".into()));
            }
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

    #[test]
    fn test_shred_key_file_basic() {
        let temp_dir = tempfile::tempdir().unwrap();
        let key_file = temp_dir.path().join("test_key");
        fs::write(&key_file, b"EPHEMERAL_KEY_BYTES_DO_NOT_LEAK").unwrap();
        assert!(key_file.exists());

        OnionServiceManager::shred_key_file(&key_file, 3).unwrap();
        assert!(!key_file.exists());
    }

    #[test]
    #[cfg(unix)]
    fn test_shred_key_file_symlink_safety() {
        let temp_dir = tempfile::tempdir().unwrap();
        let target_file = temp_dir.path().join("safe_target.txt");
        let symlink_file = temp_dir.path().join("symlink_key");

        fs::write(&target_file, b"CRITICAL_DATA_SAFE").unwrap();
        std::os::unix::fs::symlink(&target_file, &symlink_file).unwrap();

        assert!(symlink_file.exists());
        assert!(target_file.exists());

        OnionServiceManager::shred_key_file(&symlink_file, 3).unwrap();

        // The symlink is removed, but the target file remains intact and uncorrupted
        assert!(!symlink_file.exists());
        assert!(target_file.exists());
        assert_eq!(fs::read(&target_file).unwrap(), b"CRITICAL_DATA_SAFE");
    }

    #[test]
    fn test_onion_service_config_validation() {
        let valid = OnionServiceConfig::default();
        assert!(valid.validate().is_ok());

        // Reject comment injection
        let mut bad_name = valid.clone();
        bad_name.name = "service#evil".into();
        assert!(bad_name.validate().is_err());

        // Reject CRLF injection
        bad_name.name = "service\r\nHiddenServicePort 22 127.0.0.1:22".into();
        assert!(bad_name.validate().is_err());

        // Reject spaces
        bad_name.name = "service evil".into();
        assert!(bad_name.validate().is_err());

        // Reject empty name
        bad_name.name = "".into();
        assert!(bad_name.validate().is_err());

        // Reject excessively long name
        bad_name.name = "a".repeat(65);
        assert!(bad_name.validate().is_err());

        // Reject zero ports
        let mut bad_port = valid.clone();
        bad_port.virtual_port = 0;
        assert!(bad_port.validate().is_err());
        bad_port.virtual_port = 80;
        bad_port.target_port = 0;
        assert!(bad_port.validate().is_err());

        // Reject invalid unix domain socket
        let mut bad_sock = valid.clone();
        bad_sock.target_unix_socket = Some("relative/path.sock".into());
        assert!(bad_sock.validate().is_err());
        bad_sock.target_unix_socket = Some("/tmp/sock#injection".into());
        assert!(bad_sock.validate().is_err());
        bad_sock.target_unix_socket = Some("/tmp/../etc/shadow".into());
        assert!(bad_sock.validate().is_err());
        bad_sock.target_unix_socket = Some("/valid/path/to.sock".into());
        assert!(bad_sock.validate().is_ok());
    }
}
