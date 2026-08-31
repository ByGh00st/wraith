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

        // Check if Xvfb is available
        if Command::new("which").arg("Xvfb").output().is_err() {
            return Err(WraithError::Forensic(
                "Xvfb binary not found. Install with: sudo apt install xvfb".into(),
            ));
        }

        info!("Spawning standardized X11 Virtual Display on {} ({STANDARD_GEOMETRY})", disp);

        let child = Command::new("Xvfb")
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
