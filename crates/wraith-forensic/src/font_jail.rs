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
<!-- WRAITH SYSTEM-LEVEL FONT ENUMERATION SHIELD -->
<fontconfig>
  <description>Wraith Base System Font Mask</description>
  <selectfont>
    <rejectfont>
      <pattern><patelt name="family"><string>Arial</string></patelt></pattern>
      <pattern><patelt name="family"><string>Helvetica</string></patelt></pattern>
      <pattern><patelt name="family"><string>Times New Roman</string></patelt></pattern>
      <pattern><patelt name="family"><string>Courier New</string></patelt></pattern>
      <pattern><patelt name="family"><string>Verdana</string></patelt></pattern>
      <pattern><patelt name="family"><string>Georgia</string></patelt></pattern>
      <pattern><patelt name="family"><string>Comic Sans MS</string></patelt></pattern>
      <pattern><patelt name="family"><string>Trebuchet MS</string></patelt></pattern>
      <pattern><patelt name="family"><string>Impact</string></patelt></pattern>
    </rejectfont>
  </selectfont>
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

    info!("System-level font discovery restricted via fontconfig shield");
    Ok(())
}

pub fn restore_font_jail() -> Result<()> {
    let target = Path::new(FONT_CONFIG_PATH);
    let backup = Path::new(FONT_CONFIG_BACKUP);

    if backup.exists() {
        if let Err(e) = fs::rename(backup, target) {
            tracing::warn!("Failed restoring font config from backup: {e}");
        } else {
            info!("Restored original font configuration");
        }
    } else if target.exists() {
        match fs::read_to_string(target) {
            Ok(content) => {
                if content.contains("WRAITH SYSTEM-LEVEL FONT ENUMERATION SHIELD") {
                    if let Err(e) = fs::remove_file(target) {
                        tracing::warn!("Failed removing font jail configuration: {e}");
                    } else {
                        info!("Removed font jail configuration");
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed reading font config at {FONT_CONFIG_PATH}: {e}");
            }
        }
    }
    Ok(())
}
