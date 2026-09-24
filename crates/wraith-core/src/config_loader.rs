//! Wraith Persistent Sovereign Configuration Engine (TOML Specification)
//! High-assurance hierarchical configuration parsed from /etc/wraith/config.toml
//! and ~/.config/wraith/config.toml with read-only legacy JSON loading and schema validation.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::info;
use crate::config::{CONFIG_FILE, CONFIG_FILE_LEGACY};
use crate::error::{Result, WraithError};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkSection {
    pub default_interface: Option<String>,
    pub wireguard_config: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsSection {
    pub transport: Option<String>,
    pub provider: Option<String>,
    pub upstream: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TorSection {
    pub default_profile: Option<String>,
    pub bridge: Option<bool>,
    pub bridge_type: Option<String>,
    pub moat_transport: Option<String>,
    pub rotate_interval: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HardeningSection {
    pub strict: Option<bool>,
    pub tcp_mask: Option<bool>,
    pub morph_l4: Option<String>,
    pub tls_profile: Option<String>,
    pub browser_shield: Option<bool>,
    pub honey_ports: Option<bool>,
    pub font_sandbox: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FontsSection {
    /// Whether font sandboxing is enabled by default
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// Whitelisted font family names permitted to be visible / resolved by applications
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_fonts: Option<Vec<String>>,

    /// Blacklisted font family names explicitly rejected from discovery / resolution
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_fonts: Option<Vec<String>>,

    /// Additional font directories or globs to reject in fontconfig
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_paths: Option<Vec<String>>,

    /// Custom generic monospace font alias preferences order
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_monospace: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GeneralSection {
    pub lang: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
    #[serde(default)]
    pub fonts: FontsSection,

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
        let font_enabled = self.fonts.enabled.or(self.hardening.font_sandbox);
        self.fonts.enabled = font_enabled;
        self.hardening.font_sandbox = font_enabled;
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

    /// Read-only load: system TOML, user TOML, then system legacy JSON.
    /// Malformed, unknown or unreadable settings never select empty defaults.
    pub fn load() -> Result<Self> {
        let user = user_config_path();
        Self::load_paths(Path::new(CONFIG_FILE), user.as_deref(), Path::new(CONFIG_FILE_LEGACY))
    }

    fn load_paths(system: &Path, user: Option<&Path>, legacy: &Path) -> Result<Self> {
        for path in std::iter::once(system).chain(user) {
            if let Some(data) = read_optional(path)? {
                return Self::parse_toml(&data).map_err(|e| WraithError::Configuration(format!("{}: {e}", path.display())));
            }
        }
        if let Some(data) = read_optional(legacy)? {
            let mut parsed: Self = serde_json::from_str(&data)
                .map_err(|e| WraithError::Configuration(format!("Invalid legacy configuration {}: {e}", legacy.display())))?;
            parsed.sync_sections();
            parsed.validate()?;
            return Ok(parsed);
        }
        Ok(Self::default())
    }

    pub fn parse_toml(data: &str) -> Result<Self> {
        let mut parsed: Self = toml::from_str(data)
            .map_err(|e| WraithError::Configuration(format!("Invalid TOML configuration: {e}")))?;
        parsed.sync_sections();
        parsed.validate()?;
        Ok(parsed)
    }

    pub fn validate(&self) -> Result<()> {
        let choice = |key: &str, value: Option<&str>, allowed: &[&str]| -> Result<()> {
            if let Some(value) = value {
                if !allowed.contains(&value.to_ascii_lowercase().as_str()) {
                    return Err(WraithError::Configuration(format!("Invalid {key}: {value}; expected {}", allowed.join(", "))));
                }
            }
            Ok(())
        };
        choice("tor.default_profile", self.tor.default_profile.as_deref(), &["stealth", "speed", "journalists", "research", "darkweb"])?;
        let transports = ["obfs4", "obfs", "snowflake", "snow", "webrtc", "meek", "meek-azure", "azure"];
        choice("tor.moat_transport", self.tor.moat_transport.as_deref(), &transports)?;
        if self.tor.bridge_type.as_deref().is_some_and(|v| !v.eq_ignore_ascii_case("moat")) {
            choice("tor.bridge_type", self.tor.bridge_type.as_deref(), &transports)?;
        }
        choice("hardening.morph_l4", self.hardening.morph_l4.as_deref(), &["auto", "windows", "windows11", "macos", "linux", "off"])?;
        choice("hardening.tls_profile", self.hardening.tls_profile.as_deref(), &["chrome", "firefox", "safari"])?;
        choice("dns.transport", self.dns.transport.as_deref(), &["doh"])?;
        if let Some(seconds) = self.tor.rotate_interval { validate_rotation_interval(seconds)?; }
        Ok(())
    }

    /// Save the configuration selected by load; never mask an unwritable system
    /// policy with an ignored user copy. New configurations may use a user fallback.
    pub fn save(&mut self) -> Result<PathBuf> {
        let user = user_config_path();
        self.save_paths(Path::new(CONFIG_FILE), user.as_deref(), Path::new(CONFIG_FILE_LEGACY))
    }

    fn save_paths(&mut self, system: &Path, user: Option<&Path>, legacy: &Path) -> Result<PathBuf> {
        self.sync_sections();
        self.validate()?;
        let serialized = toml::to_string_pretty(self)
            .map_err(|e| WraithError::Configuration(format!("Failed serializing TOML: {e}")))?;
        let target = if path_present(system)? { system }
            else if user.map(path_present).transpose()?.unwrap_or(false) { user.expect("existing user path") }
            else { system };
        match write_atomic(target, serialized.as_bytes()) {
            Ok(()) => {},
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied
                && target == system && !path_present(system)? && !path_present(legacy)? => {
                    let user = user.ok_or(error)?;
                    write_atomic(user, serialized.as_bytes())?;
                    return Ok(user.to_path_buf());
                }
            Err(error) => return Err(error.into()),
        }
        info!("Saved persistent TOML configuration to {:?}", target);
        Ok(target.to_path_buf())
    }

    pub fn get_key(&self, key: &str) -> Result<String> {
        let path = canonical_key(key)?;
        let json = serde_json::to_value(self)?;
        let mut value = &json;
        for component in path.split('.') { value = &value[component]; }
        Ok(match value {
            serde_json::Value::Null => "unset".into(),
            serde_json::Value::String(value) => value.clone(),
            serde_json::Value::Array(values) => values.iter().filter_map(|value| value.as_str()).collect::<Vec<_>>().join(", "),
            other => other.to_string(),
        })
    }

    pub fn set_key(&mut self, key: &str, value: &str) -> Result<()> {
        let mut candidate = self.clone();
        candidate.apply_key(canonical_key(key)?, value)?;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Set individual key-value configuration
    fn apply_key(&mut self, key: &str, value: &str) -> Result<()> {
        match key {
            "network.default_interface" => {
                self.network.default_interface = Some(value.to_string());
                self.default_interface = Some(value.to_string());
            }
            "tor.default_profile" => {
                self.tor.default_profile = Some(value.to_string());
                self.default_profile = Some(value.to_string());
            }
            "tor.bridge" => {
                let b = value.parse::<bool>().map_err(|_| {
                    WraithError::Configuration("Bridge setting must be true or false".into())
                })?;
                self.tor.bridge = Some(b);
                self.bridge = Some(b);
            }
            "tor.bridge_type" => {
                self.tor.bridge_type = Some(value.to_string());
                self.bridge_type = Some(value.to_string());
            }
            "tor.moat_transport" => {
                self.tor.moat_transport = Some(value.to_string());
            }
            "network.wireguard_config" => { self.network.wireguard_config = Some(value.into()); }
            "hardening.tcp_mask" | "hardening.browser_shield" | "hardening.honey_ports" => {
                let enabled = value.parse::<bool>().map_err(|_| WraithError::Configuration(format!("{key} must be true or false")))?;
                match key {
                    "hardening.tcp_mask" => self.hardening.tcp_mask = Some(enabled),
                    "hardening.browser_shield" => self.hardening.browser_shield = Some(enabled),
                    _ => self.hardening.honey_ports = Some(enabled),
                }
            }
            "hardening.strict" => {
                let b = value.parse::<bool>().map_err(|_| {
                    WraithError::Configuration("Strict setting must be true or false".into())
                })?;
                self.hardening.strict = Some(b);
                self.strict_hardening = Some(b);
            }
            "hardening.morph_l4" => {
                if !["auto", "windows", "windows11", "macos", "linux", "off"].contains(&value) {
                    return Err(WraithError::Configuration("L4 profile must be auto, windows, macos, linux or off".into()));
                }
                self.hardening.morph_l4 = Some(value.into());
            }
            "hardening.tls_profile" => {
                if !["chrome", "firefox", "safari"].contains(&value) {
                    return Err(WraithError::Configuration("TLS profile must be chrome, firefox or safari".into()));
                }
                self.hardening.tls_profile = Some(value.into());
            }
            "dns.transport" => {
                self.dns.transport = Some(value.to_string());
                self.dns_transport = Some(value.to_string());
            }
            "dns.provider" => {
                self.dns.provider = Some(value.to_string());
            }
            "dns.upstream" => {
                self.dns.upstream = Some(value.to_string());
                self.doh_upstream = Some(value.to_string());
            }
            "tor.rotate_interval" => {
                let n = value.parse::<u64>().map_err(|_| {
                    WraithError::Configuration("Rotate interval must be a valid integer".into())
                })?;
                self.tor.rotate_interval = Some(n);
                self.rotate_interval = Some(n);
            }
            "general.lang" => {
                self.general.lang = Some(value.to_string());
                self.lang = Some(value.to_string());
            }
            "fonts.enabled" => {
                let b = value.parse::<bool>().map_err(|_| {
                    WraithError::Configuration("Font sandbox setting must be true or false".into())
                })?;
                self.fonts.enabled = Some(b);
                self.hardening.font_sandbox = Some(b);
            }
            "fonts.allowed_fonts" => {
                let items: Vec<String> = value
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                self.fonts.allowed_fonts = if items.is_empty() { None } else { Some(items) };
            }
            "fonts.blocked_fonts" => {
                let items: Vec<String> = value
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                self.fonts.blocked_fonts = if items.is_empty() { None } else { Some(items) };
            }
            "fonts.blocked_paths" => {
                let items: Vec<String> = value
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                self.fonts.blocked_paths = if items.is_empty() { None } else { Some(items) };
            }
            "fonts.preferred_monospace" => {
                let items: Vec<String> = value
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                self.fonts.preferred_monospace = if items.is_empty() { None } else { Some(items) };
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

fn canonical_key(key: &str) -> Result<&'static str> {
    match key.to_ascii_lowercase().as_str() {
        "interface" | "nic" | "adapter" | "network.interface" | "network.default_interface" => Ok("network.default_interface"),
        "profile" | "exit" | "tor.profile" | "tor.default_profile" => Ok("tor.default_profile"),
        "bridge" | "tor.bridge" => Ok("tor.bridge"),
        "bridge_type" | "bridge-type" | "tor.bridge_type" => Ok("tor.bridge_type"),
        "moat_transport" | "moat" | "tor.moat_transport" => Ok("tor.moat_transport"),
        "strict" | "strict_hardening" | "full" | "hardening.strict" => Ok("hardening.strict"),
        "morph-l4" | "hardening.morph_l4" => Ok("hardening.morph_l4"),
        "tls-profile" | "hardening.tls_profile" => Ok("hardening.tls_profile"),
        "dns" | "dns_transport" | "dns.transport" => Ok("dns.transport"),
        "provider" | "dns.provider" => Ok("dns.provider"),
        "doh" | "upstream" | "doh_upstream" | "dns.upstream" => Ok("dns.upstream"),
        "rotate_interval" | "rotate" | "interval" | "tor.rotate_interval" => Ok("tor.rotate_interval"),
        "lang" | "language" | "general.lang" => Ok("general.lang"),
        "fonts.enabled" | "fonts" | "font_sandbox" | "hardening.font_sandbox" => Ok("fonts.enabled"),
        "fonts.allowed" | "fonts.allowed_fonts" | "allowed_fonts" => Ok("fonts.allowed_fonts"),
        "fonts.blocked" | "fonts.blocked_fonts" | "blocked_fonts" => Ok("fonts.blocked_fonts"),
        "fonts.blocked_paths" | "blocked_paths" => Ok("fonts.blocked_paths"),
        "fonts.monospace" | "fonts.preferred_monospace" | "preferred_monospace" => Ok("fonts.preferred_monospace"),
        "wireguard" | "wireguard_config" | "network.wireguard_config" => Ok("network.wireguard_config"),
        "tcp-mask" | "tcp_mask" | "hardening.tcp_mask" => Ok("hardening.tcp_mask"),
        "browser-shield" | "browser_shield" | "hardening.browser_shield" => Ok("hardening.browser_shield"),
        "honey-ports" | "honey_ports" | "hardening.honey_ports" => Ok("hardening.honey_ports"),
        _ => Err(WraithError::Configuration(format!("Unknown configuration key '{key}'"))),
    }
}

pub fn validate_rotation_interval(seconds: u64) -> Result<()> {
    if seconds == 0 || seconds > u32::MAX as u64 {
        return Err(WraithError::Configuration("Rotation interval must be 1..=4294967295 seconds; omit it to disable rotation".into()));
    }
    Ok(())
}

fn user_config_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config/wraith/config.toml"))
}

fn read_optional(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(data) => Ok(Some(data)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !path_present(path)? => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn path_present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| std::io::Error::other("Missing config directory"))?;
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(data)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    #[cfg(unix)] fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn invalid_or_unknown_config_is_never_replaced_by_defaults() {
        let dir = tempdir().unwrap();
        let system = dir.path().join("system.toml");
        let user = dir.path().join("user.toml");
        let legacy = dir.path().join("legacy.json");
        fs::write(&user, "[hardening]\nstrict = false").unwrap();
        for bad in ["[broken", "[hardening]\nstrcit = true", "[tor]\nrotate_interval = 0", "[tor]\nbridge_type = 'webtunnel'"] {
            fs::write(&system, bad).unwrap();
            assert!(WraithConfig::load_paths(&system, Some(&user), &legacy).is_err());
            assert_eq!(fs::read_to_string(&system).unwrap(), bad);
        }
        fs::remove_file(&system).unwrap();
        fs::remove_file(&user).unwrap();
        fs::write(&legacy, "{broken").unwrap();
        assert!(WraithConfig::load_paths(&system, Some(&user), &legacy).is_err());
        assert!(!system.exists());
    }

    #[test]
    fn legacy_loading_is_read_only_and_keeps_strict_settings() {
        let dir = tempdir().unwrap();
        let system = dir.path().join("config.toml");
        let legacy = dir.path().join("config.json");
        fs::write(&legacy, r#"{"strict_hardening":true,"rotate_interval":60}"#).unwrap();
        let config = WraithConfig::load_paths(&system, None, &legacy).unwrap();
        assert_eq!(config.hardening.strict, Some(true));
        assert_eq!(config.tor.rotate_interval, Some(60));
        assert!(!system.exists());
    }

    #[test]
    fn save_keeps_the_loaded_user_path_and_system_precedence() {
        let dir = tempdir().unwrap();
        let system = dir.path().join("system/config.toml");
        let user = dir.path().join("user/config.toml");
        let legacy = dir.path().join("legacy.json");
        fs::create_dir_all(system.parent().unwrap()).unwrap();
        fs::create_dir_all(user.parent().unwrap()).unwrap();
        fs::write(&user, "[hardening]\nstrict = true").unwrap();
        let mut config = WraithConfig::load_paths(&system, Some(&user), &legacy).unwrap();
        config.set_key("tls-profile", "safari").unwrap();
        assert_eq!(config.save_paths(&system, Some(&user), &legacy).unwrap(), user);
        assert!(!system.exists());
        fs::write(&system, "[hardening]\nstrict = false").unwrap();
        let mut config = WraithConfig::load_paths(&system, Some(&user), &legacy).unwrap();
        assert_eq!(config.hardening.strict, Some(false));
        config.set_key("morph-l4", "linux").unwrap();
        assert_eq!(config.save_paths(&system, Some(&user), &legacy).unwrap(), system);
        assert_eq!(WraithConfig::parse_toml(&fs::read_to_string(&user).unwrap()).unwrap().hardening.tls_profile.as_deref(), Some("safari"));
    }

    #[test]
    fn every_config_set_alias_has_a_matching_get_and_bad_values_are_atomic() {
        let mut config = WraithConfig::default();
        for (set, get, value) in [("network.interface", "network.default_interface", "eth0"),
            ("morph-l4", "hardening.morph_l4", "macos"), ("tls-profile", "hardening.tls_profile", "safari"),
            ("tcp-mask", "hardening.tcp_mask", "true"), ("browser-shield", "hardening.browser_shield", "true"),
            ("honey-ports", "hardening.honey_ports", "true"), ("wireguard", "network.wireguard_config", "/tmp/wg.conf"),
            ("language", "general.lang", "tr"), ("font_sandbox", "fonts.enabled", "true"),
            ("exit", "tor.default_profile", "stealth"), ("rotate", "tor.rotate_interval", "60")] {
            config.set_key(set, value).unwrap();
            assert_eq!(config.get_key(get).unwrap(), value);
            assert_eq!(config.get_key(set).unwrap(), value);
        }
        let original = config.clone();
        for (key, value) in [("rotate", "0"), ("rotate", "18446744073709551615"), ("bridge_type", "typo"), ("profile", "typo")] {
            assert!(config.set_key(key, value).is_err());
            assert_eq!(config, original);
        }
        assert!(config.get_key("unknown").is_err());
    }

    #[test]
    fn unreadable_config_type_does_not_fall_back() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::create_dir(&path).unwrap();
        assert!(WraithConfig::load_paths(&path, None, &dir.path().join("missing.json")).is_err());
    }

    #[test]
    fn l4_and_tls_settings_validate_and_roundtrip() {
        let mut config = WraithConfig::default();
        config.set_key("hardening.morph_l4", "auto").unwrap();
        config.set_key("hardening.tls_profile", "safari").unwrap();
        let decoded: WraithConfig = toml::from_str(&toml::to_string(&config).unwrap()).unwrap();
        assert_eq!(decoded.hardening.morph_l4.as_deref(), Some("auto"));
        assert_eq!(decoded.hardening.tls_profile.as_deref(), Some("safari"));
        assert!(config.set_key("hardening.morph_l4", "unknown").is_err());
        assert!(config.set_key("hardening.tls_profile", "unknown").is_err());
    }

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

    #[test]
    fn test_fonts_config_set_and_serialize() {
        let mut cfg = WraithConfig::default();
        cfg.set_key("fonts.allowed", "Hack, JetBrains Mono").unwrap();
        cfg.set_key("fonts.blocked", "Comic Sans, MesloLGS NF").unwrap();
        cfg.set_key("fonts.blocked_paths", "/opt/custom_fonts/*, /usr/share/fonts/extra/*").unwrap();
        cfg.set_key("fonts.monospace", "Hack, DejaVu Sans Mono").unwrap();

        assert_eq!(
            cfg.fonts.allowed_fonts,
            Some(vec!["Hack".to_string(), "JetBrains Mono".to_string()])
        );
        assert_eq!(
            cfg.fonts.blocked_fonts,
            Some(vec!["Comic Sans".to_string(), "MesloLGS NF".to_string()])
        );
        assert_eq!(
            cfg.fonts.blocked_paths,
            Some(vec!["/opt/custom_fonts/*".to_string(), "/usr/share/fonts/extra/*".to_string()])
        );
        assert_eq!(
            cfg.fonts.preferred_monospace,
            Some(vec!["Hack".to_string(), "DejaVu Sans Mono".to_string()])
        );

        let toml_str = toml::to_string_pretty(&cfg).unwrap();
        assert!(toml_str.contains("[fonts]"));
        assert!(toml_str.contains("allowed_fonts"));
        assert!(toml_str.contains("blocked_fonts"));

        let read_back: WraithConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(read_back.fonts, cfg.fonts);
    }
}
