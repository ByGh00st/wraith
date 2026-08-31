//! Wraith Multi-Chain & Exit Profile Engine
//! Enforces geographic routing, strict exit nodes, and Five Eyes exclusion.

use std::fs;
use std::path::Path;
use tracing::info;
use wraith_core::config::TORRC_PATH;
use wraith_core::error::{Result, WraithError};

use crate::control::TorControlClient;

#[derive(Debug, Clone)]
pub struct CountryProfile {
    pub name: &'static str,
    pub desc: &'static str,
    pub exclude: &'static str,
    pub exit_nodes: &'static str,
}

pub static COUNTRY_PROFILES: phf::Map<&'static str, CountryProfile> = phf::phf_map! {
    "stealth" => CountryProfile {
        name: "Maximum Stealth",
        desc: "Routes strictly through privacy-friendly non-cooperative jurisdictions",
        exclude: "{us},{gb},{au},{ca},{nz}", // Five Eyes
        exit_nodes: "{ch},{is},{ro},{md},{pa}",
    },
    "speed" => CountryProfile {
        name: "Speed Optimized",
        desc: "Fast exit nodes in high-bandwidth central European data centers",
        exclude: "",
        exit_nodes: "{de},{nl},{fr},{se},{fi}",
    },
    "journalists" => CountryProfile {
        name: "Press Freedom",
        desc: "Countries with top-tier constitutional press and speech protections",
        exclude: "{cn},{ru},{ir},{sa},{eg}",
        exit_nodes: "{no},{se},{fi},{dk},{nl}",
    },
    "research" => CountryProfile {
        name: "Research Mode",
        desc: "Academic and research-friendly nodes across diverse geographical zones",
        exclude: "",
        exit_nodes: "{de},{jp},{br},{za},{kr}",
    },
    "darkweb" => CountryProfile {
        name: "Dark Web Optimized",
        desc: "Optimized for .onion hidden services (excludes Five Eyes guards)",
        exclude: "{us},{gb}",
        exit_nodes: "",
    },
};

pub async fn apply_exit_profile(profile_key: &str) -> Result<CountryProfile> {
    let profile = COUNTRY_PROFILES
        .get(profile_key)
        .cloned()
        .ok_or_else(|| WraithError::Tor(format!("Unknown exit profile: {profile_key}")))?;

    let path = Path::new(TORRC_PATH);
    if !path.exists() {
        return Err(WraithError::Tor("torrc not found; start Wraith first".into()));
    }

    let content = fs::read_to_string(path)?;
    let mut lines: Vec<String> = content
        .lines()
        .filter(|l| {
            !l.starts_with("ExitNodes")
                && !l.starts_with("ExcludeExitNodes")
                && !l.starts_with("StrictNodes")
        })
        .map(|s| s.to_string())
        .collect();

    if !profile.exit_nodes.is_empty() {
        lines.push(format!("ExitNodes {}", profile.exit_nodes));
    }
    if !profile.exclude.is_empty() {
        lines.push(format!("ExcludeExitNodes {}", profile.exclude));
    }
    if !profile.exit_nodes.is_empty() || !profile.exclude.is_empty() {
        lines.push("StrictNodes 1".to_string());
    }

    fs::write(path, lines.join("\n") + "\n")?;

    // Signal Tor to reload and construct fresh circuit
    let mut client = TorControlClient::default();
    if client.connect().await.is_ok() {
        let _ = client.signal_hup().await;
        let _ = client.signal_newnym().await;
    }

    info!("Applied geographic exit profile: {}", profile.name);
    Ok(profile)
}
