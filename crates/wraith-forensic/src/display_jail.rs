//! Wraith Virtual Display & Screen Resolution Normalization Jail
//! Spawns headless X11 virtual displays (Xvfb) with standardized 1920x1080@24bit resolution
//! to block monitor EDID and hardware multi-display discovery attacks.

use std::process::{Child, Command, Stdio};
use tracing::info;
use wraith_core::error::{Result, WraithError};

pub const DEFAULT_VIRTUAL_DISPLAY: &str = ":99";
pub const STANDARD_GEOMETRY: &str = "1920x1080x24";

pub struct VirtualDisplay {
    pub display_num: String,
    process: Option<Child>,
}

impl VirtualDisplay {
    pub fn spawn_standard(display: Option<&str>) -> Result<Self> {
        let disp = display.unwrap_or(DEFAULT_VIRTUAL_DISPLAY);

        // Check if Xvfb is available in PATH or standard system directories
        let xvfb_bin = if std::path::Path::new("/usr/bin/Xvfb").exists() {
            "/usr/bin/Xvfb"
        } else if std::path::Path::new("/usr/local/bin/Xvfb").exists() {
            "/usr/local/bin/Xvfb"
        } else if Command::new("which").arg("Xvfb").output().map(|o| o.status.success()).unwrap_or(false) {
            "Xvfb"
        } else {
            return Err(WraithError::Forensic(
                "Xvfb binary not found. Install with: sudo apt install xvfb".into(),
            ));
        };

        info!("Spawning standardized X11 Virtual Display on {} ({STANDARD_GEOMETRY})", disp);

        let child = Command::new(xvfb_bin)
            .args([disp, "-screen", "0", STANDARD_GEOMETRY, "-ac", "+extension", "RANDR"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| WraithError::Forensic(format!("Failed starting Xvfb on {disp}: {e}")))?;

        // Give Xvfb time to initialize socket in /tmp/.X11-unix/
        std::thread::sleep(std::time::Duration::from_millis(600));

        Ok(Self {
            display_num: disp.to_string(),
            process: Some(child),
        })
    }

    pub fn terminate(&mut self) {
        if let Some(mut proc) = self.process.take() {
            let _ = proc.kill();
            let _ = proc.wait();
            info!("Virtual display {} terminated", self.display_num);
        }
    }
}

impl Drop for VirtualDisplay {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtual_display_constants() {
        assert_eq!(DEFAULT_VIRTUAL_DISPLAY, ":99");
        assert_eq!(STANDARD_GEOMETRY, "1920x1080x24");
    }
}
