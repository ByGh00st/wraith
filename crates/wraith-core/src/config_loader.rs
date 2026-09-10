//! Wraith Persistent Sovereign Configuration Engine (TOML Specification)
//! High-assurance hierarchical configuration parsed from /etc/wraith/config.toml
//! and ~/.config/wraith/config.toml with automatic legacy JSON migration and schema validation.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::info;
use crate::config::{CONFIG_DIR, CONFIG_FILE, CONFIG_FILE_LEGACY};
use crate::error::{Result, WraithError};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct NetworkSection {
    pub default_interface: Option<String>,
    pub wireguard_config: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DnsSection {
    pub transport: Option<String>,
    pub provider: Option<String>,
    pub upstream: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct TorSection {
    pub default_profile: Option<String>,
    pub bridge: Option<bool>,
    pub bridge_type: Option<String>,
    pub moat_transport: Option<String>,
    pub rotate_interval: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct HardeningSection {
    pub strict: Option<bool>,
    pub tcp_mask: Option<bool>,
    pub browser_shield: Option<bool>,
    pub honey_ports: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct GeneralSection {
    pub lang: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct WraithConfig {
    #[serde(default)]
    pub general: GeneralSection,
    #[serde(default)]
    pub network: NetworkSection,
    #[serde(default)]
    pub dns: DnsSection,
    #[serde(default)]
    pub tor: TorSection,
    #[serde(default)]
    pub hardening: HardeningSection,

    // Backward-compatibility flat accessors for legacy code paths
    pub default_interface: Option<String>,
    pub default_profile: Option<String>,
    pub bridge: Option<bool>,
    pub bridge_type: Option<String>,
    pub strict_hardening: Option<bool>,
    pub dns_transport: Option<String>,
    pub doh_upstream: Option<String>,
    pub rotate_interval: Option<u64>,
    pub lang: Option<String>,
}

impl WraithConfig {
    /// Synchronize flat compatibility fields with sectioned structures
    pub fn sync_sections(&mut self) {
        if self.default_interface.is_some() && self.network.default_interface.is_none() {
            self.network.default_interface = self.default_interface.clone();
        } else if self.network.default_interface.is_some() {
            self.default_interface = self.network.default_interface.clone();
        }

        if self.default_profile.is_some() && self.tor.default_profile.is_none() {
            self.tor.default_profile = self.default_profile.clone();
        } else if self.tor.default_profile.is_some() {
            self.default_profile = self.tor.default_profile.clone();
        }

        if self.bridge.is_some() && self.tor.bridge.is_none() {
            self.tor.bridge = self.bridge;
        } else if self.tor.bridge.is_some() {
            self.bridge = self.tor.bridge;
        }

        if self.bridge_type.is_some() && self.tor.bridge_type.is_none() {
            self.tor.bridge_type = self.bridge_type.clone();
        } else if self.tor.bridge_type.is_some() {
            self.bridge_type = self.tor.bridge_type.clone();
        }

        if self.rotate_interval.is_some() && self.tor.rotate_interval.is_none() {
            self.tor.rotate_interval = self.rotate_interval;
        } else if self.tor.rotate_interval.is_some() {
            self.rotate_interval = self.tor.rotate_interval;
        }

        if self.strict_hardening.is_some() && self.hardening.strict.is_none() {
            self.hardening.strict = self.strict_hardening;
        } else if self.hardening.strict.is_some() {
            self.strict_hardening = self.hardening.strict;
        }

        if self.dns_transport.is_some() && self.dns.transport.is_none() {
            self.dns.transport = self.dns_transport.clone();
        } else if self.dns.transport.is_some() {
            self.dns_transport = self.dns.transport.clone();
        }

        if self.doh_upstream.is_some() && self.dns.upstream.is_none() {
            self.dns.upstream = self.doh_upstream.clone();
        } else if self.dns.upstream.is_some() {
            self.doh_upstream = self.dns.upstream.clone();
        }

        if self.lang.is_some() && self.general.lang.is_none() {
            self.general.lang = self.lang.clone();
        } else if self.general.lang.is_some() {
            self.lang = self.general.lang.clone();
        }
    }

    /// Load persistent configuration from disk.
    /// Priority:
    /// 1. /etc/wraith/config.toml (system-wide TOML)
    /// 2. ~/.config/wraith/config.toml (user local TOML)
    /// 3. /etc/wraith/config.json (legacy migration)
    ///
    /// If no config exists, returns Default empty config.
    pub fn load() -> Result<Self> {
        let system_toml = Path::new(CONFIG_FILE);
        if system_toml.exists() {
            let data = fs::read_to_string(system_toml)?;
            let mut parsed: Self = toml::from_str(&data)
                .map_err(|e| WraithError::Configuration(format!("Failed parsing {CONFIG_FILE}: {e}")))?;
            parsed.sync_sections();
            return Ok(parsed);
        }

        if let Ok(home) = std::env::var("HOME") {
            let user_toml = PathBuf::from(&home).join(".config/wraith/config.toml");
            if user_toml.exists() {
                let data = fs::read_to_string(&user_toml)?;
                let mut parsed: Self = toml::from_str(&data)
                    .map_err(|e| WraithError::Configuration(format!("Failed parsing {user_toml:?}: {e}")))?;
                parsed.sync_sections();
                return Ok(parsed);
            }
        }

        // Automatic Legacy Migration from JSON
        let system_json = Path::new(CONFIG_FILE_LEGACY);
        if system_json.exists() {
            if let Ok(data) = fs::read_to_string(system_json) {
                if let Ok(mut parsed) = serde_json::from_str::<Self>(&data) {
                    parsed.sync_sections();
                    let _ = parsed.save();
                    info!("Auto-migrated legacy configuration {CONFIG_FILE_LEGACY} ➔ {CONFIG_FILE}");
                    return Ok(parsed);
                }
            }
        }

        Ok(Self::default())
    }

    /// Save configuration atomically in TOML format to /etc/wraith/config.toml (or ~/.config/wraith/config.toml)
    pub fn save(&mut self) -> Result<PathBuf> {
        self.sync_sections();
        let serialized = toml::to_string_pretty(self)
            .map_err(|e| WraithError::Configuration(format!("Failed serializing TOML: {e}")))?;

        // Try /etc/wraith first
        let target_path = if fs::create_dir_all(CONFIG_DIR).is_ok() {
            PathBuf::from(CONFIG_FILE)
        } else if let Ok(home) = std::env::var("HOME") {
            let user_dir = PathBuf::from(home).join(".config/wraith");
            let _ = fs::create_dir_all(&user_dir);
            user_dir.join("config.toml")
        } else {
            return Err(WraithError::Configuration(
                "Cannot determine target directory to store config.toml".into(),
            ));
        };

        let parent = target_path.parent().ok_or_else(|| WraithError::Configuration("Missing config directory".into()))?;
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        temp.write_all(serialized.as_bytes())?;
        temp.as_file().sync_all()?;
        temp.persist(&target_path).map_err(|e| e.error)?;
        info!("Saved persistent TOML configuration to {:?}", target_path);
        Ok(target_path)
    }

    /// Set individual key-value configuration
    pub fn set_key(&mut self, key: &str, value: &str) -> Result<()> {
        match key.to_lowercase().as_str() {
            "interface" | "nic" | "adapter" | "network.interface" => {
                self.network.default_interface = Some(value.to_string());
                self.default_interface = Some(value.to_string());
            }
            "profile" | "exit" | "tor.profile" => {
                self.tor.default_profile = Some(value.to_string());
                self.default_profile = Some(value.to_string());
            }
            "bridge" | "tor.bridge" => {
                let b = value.parse::<bool>().map_err(|_| {
                    WraithError::Configuration("Bridge setting must be true or false".into())
                })?;
                self.tor.bridge = Some(b);
                self.bridge = Some(b);
            }
            "bridge_type" | "bridge-type" | "tor.bridge_type" => {
                self.tor.bridge_type = Some(value.to_string());
                self.bridge_type = Some(value.to_string());
            }
            "moat_transport" | "moat" | "tor.moat_transport" => {
                self.tor.moat_transport = Some(value.to_string());
            }
            "strict" | "strict_hardening" | "full" | "hardening.strict" => {
                let b = value.parse::<bool>().map_err(|_| {
                    WraithError::Configuration("Strict setting must be true or false".into())
                })?;
                self.hardening.strict = Some(b);
                self.strict_hardening = Some(b);
            }
            "dns" | "dns_transport" | "dns.transport" => {
                self.dns.transport = Some(value.to_string());
                self.dns_transport = Some(value.to_string());
            }
            "provider" | "dns.provider" => {
                self.dns.provider = Some(value.to_string());
            }
            "doh" | "upstream" | "doh_upstream" | "dns.upstream" => {
                self.dns.upstream = Some(value.to_string());
                self.doh_upstream = Some(value.to_string());
            }
            "rotate_interval" | "rotate" | "interval" | "tor.rotate_interval" => {
                let n = value.parse::<u64>().map_err(|_| {
                    WraithError::Configuration("Rotate interval must be a valid integer".into())
                })?;
                self.tor.rotate_interval = Some(n);
                self.rotate_interval = Some(n);
            }
            "lang" | "language" | "general.lang" => {
                self.general.lang = Some(value.to_string());
                self.lang = Some(value.to_string());
            }
            _ => {
                return Err(WraithError::Configuration(format!(
                    "Unknown configuration key '{key}'"
                )));
            }
        }
        self.sync_sections();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_toml_config_set_and_sync() {
        let mut cfg = WraithConfig::default();
        cfg.set_key("network.interface", "wlan0").expect("Valid key");
        assert_eq!(cfg.network.default_interface.as_deref(), Some("wlan0"));
        assert_eq!(cfg.default_interface.as_deref(), Some("wlan0"));

        cfg.set_key("dns.provider", "quad9").expect("Valid key");
        assert_eq!(cfg.dns.provider.as_deref(), Some("quad9"));

        cfg.set_key("tor.bridge", "true").expect("Valid key");
        assert_eq!(cfg.tor.bridge, Some(true));
        assert_eq!(cfg.bridge, Some(true));

        assert!(cfg.set_key("invalid_key_xyz", "value").is_err());
    }

    #[test]
    fn test_toml_serialization_roundtrip() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("config.toml");

        let mut cfg = WraithConfig::default();
        cfg.set_key("interface", "eth0").unwrap();
        cfg.set_key("profile", "stealth").unwrap();
        cfg.set_key("strict", "true").unwrap();

        let toml_str = toml::to_string_pretty(&cfg).unwrap();
        fs::write(&file_path, &toml_str).unwrap();

        let read_back: WraithConfig =
            toml::from_str(&fs::read_to_string(&file_path).unwrap()).unwrap();
        assert_eq!(read_back.network.default_interface.as_deref(), Some("eth0"));
        assert_eq!(read_back.tor.default_profile.as_deref(), Some("stealth"));
        assert_eq!(read_back.hardening.strict, Some(true));
    }
}
