//! Wraith System-Level Font Sandbox
//! Overrides fontconfig rules (/etc/fonts/local.conf) to prevent font discovery attacks by local applications.

use std::fs;
use std::path::Path;
use tracing::info;
use wraith_core::error::{Result, WraithError};

pub const FONT_CONFIG_PATH: &str = "/etc/fonts/local.conf";
pub const FONT_CONFIG_BACKUP: &str = "/etc/fonts/local.conf.wraith.bak";

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

pub fn enforce_font_jail() -> Result<()> {
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

    fs::write(target, RESTRICTED_FONT_XML).map_err(|e| {
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
        if content.contains("WRAITH SYSTEM-LEVEL FONT ENUMERATION SHIELD") { fs::remove_file(target)?; }
    }

    refresh_font_cache()
}

pub fn refresh_font_cache() -> Result<()> {
    let status = std::process::Command::new("fc-cache").arg("-f")
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status()?;
    if !status.success() { return Err(WraithError::Forensic("Font cache refresh failed".into())); }

    Ok(())
}
