//! Wraith System-Level Font Sandbox
//! Overrides fontconfig rules (/etc/fonts/local.conf) to prevent font discovery attacks by local applications.
//! Supports user-configurable whitelisting (allowed fonts) and blacklisting (blocked fonts/paths).

use std::fs;
use std::path::Path;
use tracing::info;
use wraith_core::config_loader::FontsSection;
use wraith_core::error::{Result, WraithError};

pub const FONT_CONFIG_PATH: &str = "/etc/fonts/local.conf";
pub const FONT_CONFIG_BACKUP: &str = "/etc/fonts/local.conf.wraith.bak";

pub const DEFAULT_MONOSPACE_FONTS: &[&str] = &[
    "Hack",
    "DejaVu Sans Mono",
    "Liberation Mono",
    "Noto Sans Mono",
    "Noto Sans CJK KR",
    "Noto Sans Symbols",
    "Noto Sans Symbols 2",
    "Noto Color Emoji",
];

pub const DEFAULT_SANS_FONTS: &[&str] = &[
    "Cantarell",
    "DejaVu Sans",
    "Liberation Sans",
    "Noto Sans",
    "Noto Sans CJK KR",
    "Noto Color Emoji",
];

pub const DEFAULT_SERIF_FONTS: &[&str] = &[
    "DejaVu Serif",
    "Liberation Serif",
    "Noto Serif",
];

pub const DEFAULT_BLOCKED_FONT_GLOBS: &[&str] = &[
    "/usr/local/share/fonts/*",
    "~/.fonts/*",
    "~/.local/share/fonts/*",
    "/root/.fonts/*",
    "/root/.local/share/fonts/*",
    "/home/*/.fonts/*",
    "/home/*/.local/share/fonts/*",
    "/var/lib/flatpak/exports/share/fonts/*",
    "/var/lib/snapd/desktop/fontconfig/*",
];

/// Legacy default fontconfig XML payload
pub const RESTRICTED_FONT_XML: &str = r#"<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<!-- WRAITH SYSTEM-LEVEL FONT ENUMERATION SHIELD (STRICT BASE ISOLATION) -->
<fontconfig>
  <description>Wraith System-Level Font Normalization & Anti-Fingerprint Shield</description>

  <!-- 1. Reject all custom, user-installed, Wine, Flatpak and third-party font paths -->
  <selectfont>
    <rejectfont>
      <glob>/usr/local/share/fonts/*</glob>
      <glob>~/.fonts/*</glob>
      <glob>~/.local/share/fonts/*</glob>
      <glob>/root/.fonts/*</glob>
      <glob>/root/.local/share/fonts/*</glob>
      <glob>/home/*/.fonts/*</glob>
      <glob>/home/*/.local/share/fonts/*</glob>
      <glob>/var/lib/flatpak/exports/share/fonts/*</glob>
      <glob>/var/lib/snapd/desktop/fontconfig/*</glob>
    </rejectfont>
  </selectfont>

  <!-- 2. Normalize and enforce default generic aliases to standard Kali/Linux fonts -->
  <alias>
    <family>monospace</family>
    <prefer>
      <family>Hack</family>
      <family>DejaVu Sans Mono</family>
      <family>Liberation Mono</family>
      <family>Noto Sans Mono</family>
      <family>Noto Sans CJK KR</family>
      <family>Noto Sans Symbols</family>
      <family>Noto Sans Symbols 2</family>
      <family>Noto Color Emoji</family>
    </prefer>
  </alias>

  <alias>
    <family>sans-serif</family>
    <prefer>
      <family>Cantarell</family>
      <family>DejaVu Sans</family>
      <family>Liberation Sans</family>
      <family>Noto Sans</family>
      <family>Noto Sans CJK KR</family>
      <family>Noto Color Emoji</family>
    </prefer>
  </alias>

  <alias>
    <family>serif</family>
    <prefer>
      <family>DejaVu Serif</family>
      <family>Liberation Serif</family>
      <family>Noto Serif</family>
    </prefer>
  </alias>
</fontconfig>
"#;

/// Dynamically generates fontconfig XML based on persistent configuration rules
pub fn generate_font_config_xml(config: Option<&FontsSection>) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n\
        <!DOCTYPE fontconfig SYSTEM \"fonts.dtd\">\n\
        <!-- WRAITH SYSTEM-LEVEL FONT ENUMERATION SHIELD (CONFIGURABLE ISOLATION) -->\n\
        <fontconfig>\n  \
          <description>Wraith System-Level Font Normalization & Anti-Fingerprint Shield</description>\n\n  \
          <!-- 1. Font Selection Rules: Rejection and Whitelist Acceptance -->\n  \
          <selectfont>\n    \
            <rejectfont>\n",
    );

    // 1. Default user directory reject globs
    for glob in DEFAULT_BLOCKED_FONT_GLOBS {
        xml.push_str(&format!("      <glob>{glob}</glob>\n"));
    }

    // 2. Custom user-defined blocked paths
    if let Some(cfg) = config {
        if let Some(blocked_paths) = &cfg.blocked_paths {
            for path in blocked_paths {
                xml.push_str(&format!("      <glob>{path}</glob>\n"));
            }
        }
        // 3. Custom user-defined blocked font families
        if let Some(blocked_fonts) = &cfg.blocked_fonts {
            for font in blocked_fonts {
                xml.push_str("      <pattern>\n");
                xml.push_str(&format!("        <patelt name=\"family\"><string>{font}</string></patelt>\n"));
                xml.push_str("      </pattern>\n");
            }
        }
    }

    xml.push_str("    </rejectfont>\n");

    // 4. Whitelisted / Allowed fonts explicitly permitted by the operator
    if let Some(cfg) = config {
        if let Some(allowed_fonts) = &cfg.allowed_fonts {
            if !allowed_fonts.is_empty() {
                xml.push_str("    <acceptfont>\n");
                for font in allowed_fonts {
                    xml.push_str("      <pattern>\n");
                    xml.push_str(&format!("        <patelt name=\"family\"><string>{font}</string></patelt>\n"));
                    xml.push_str("      </pattern>\n");
                }
                xml.push_str("    </acceptfont>\n");
            }
        }
    }

    xml.push_str("  </selectfont>\n\n  <!-- 2. Generic Font Aliases & Normalization -->\n  <alias>\n    <family>monospace</family>\n    <prefer>\n");

    // 5. Monospace preference order
    if let Some(preferred) = config.and_then(|c| c.preferred_monospace.as_ref()).filter(|p| !p.is_empty()) {
        for font in preferred {
            xml.push_str(&format!("      <family>{font}</family>\n"));
        }
    } else {
        for font in DEFAULT_MONOSPACE_FONTS {
            xml.push_str(&format!("      <family>{font}</family>\n"));
        }
    }

    xml.push_str("    </prefer>\n  </alias>\n\n  <alias>\n    <family>sans-serif</family>\n    <prefer>\n");
    for font in DEFAULT_SANS_FONTS {
        xml.push_str(&format!("      <family>{font}</family>\n"));
    }
    xml.push_str("    </prefer>\n  </alias>\n\n  <alias>\n    <family>serif</family>\n    <prefer>\n");
    for font in DEFAULT_SERIF_FONTS {
        xml.push_str(&format!("      <family>{font}</family>\n"));
    }
    xml.push_str("    </prefer>\n  </alias>\n</fontconfig>\n");

    xml
}

pub fn enforce_font_jail() -> Result<()> {
    let cfg = wraith_core::WraithConfig::load().ok().map(|c| c.fonts);
    enforce_font_jail_with_config(cfg.as_ref())
}

pub fn enforce_font_jail_with_config(config: Option<&FontsSection>) -> Result<()> {
    let target = Path::new(FONT_CONFIG_PATH);
    let backup = Path::new(FONT_CONFIG_BACKUP);

    if target.exists() && !backup.exists() {
        fs::copy(target, backup).map_err(|e| {
            WraithError::Forensic(format!("Failed backing up {FONT_CONFIG_PATH}: {e}"))
        })?;
    }

    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }

    let xml = generate_font_config_xml(config);
    fs::write(target, xml).map_err(|e| {
        WraithError::Forensic(format!("Failed writing font jail configuration: {e}"))
    })?;

    refresh_font_cache()?;

    info!("System-level font discovery restricted via fontconfig shield");
    Ok(())
}

pub fn restore_font_jail() -> Result<()> {
    let target = Path::new(FONT_CONFIG_PATH);
    let backup = Path::new(FONT_CONFIG_BACKUP);

    if backup.exists() {
        fs::rename(backup, target)?;
    } else if target.exists() {
        let content = fs::read_to_string(target)?;
        if content.contains("WRAITH SYSTEM-LEVEL FONT ENUMERATION SHIELD") {
            fs::remove_file(target)?;
        }
    }

    refresh_font_cache()
}

pub fn refresh_font_cache() -> Result<()> {
    let status = std::process::Command::new("fc-cache")
        .arg("-f")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if !status.success() {
        return Err(WraithError::Forensic("Font cache refresh failed".into()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_font_xml_generation() {
        let xml = generate_font_config_xml(None);
        assert!(xml.contains("WRAITH SYSTEM-LEVEL FONT ENUMERATION SHIELD"));
        assert!(xml.contains("<glob>/usr/local/share/fonts/*</glob>"));
        assert!(xml.contains("<glob>~/.local/share/fonts/*</glob>"));
        assert!(xml.contains("<family>Hack</family>"));
        assert!(!xml.contains("<acceptfont>"));
    }

    #[test]
    fn test_custom_font_xml_with_whitelist_and_blacklist() {
        let config = FontsSection {
            enabled: Some(true),
            allowed_fonts: Some(vec!["Hack".into(), "JetBrains Mono".into()]),
            blocked_fonts: Some(vec!["Comic Sans MS".into(), "MesloLGS NF".into()]),
            blocked_paths: Some(vec!["/opt/custom_fonts/*".into()]),
            preferred_monospace: Some(vec!["JetBrains Mono".into(), "Hack".into()]),
        };

        let xml = generate_font_config_xml(Some(&config));
        assert!(xml.contains("<acceptfont>"));
        assert!(xml.contains("<string>Hack</string>"));
        assert!(xml.contains("<string>JetBrains Mono</string>"));

        assert!(xml.contains("<string>Comic Sans MS</string>"));
        assert!(xml.contains("<string>MesloLGS NF</string>"));
        assert!(xml.contains("<glob>/opt/custom_fonts/*</glob>"));

        // Verify monospace preference starts with JetBrains Mono
        let mono_pos = xml.find("<family>monospace</family>").unwrap();
        let jb_pos = xml[mono_pos..].find("<family>JetBrains Mono</family>").unwrap();
        let hack_pos = xml[mono_pos..].find("<family>Hack</family>").unwrap();
        assert!(jb_pos < hack_pos);
    }
}
