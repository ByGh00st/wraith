//! Wraith Virtual Display & Screen Resolution Normalization Jail
//! Spawns headless X11 virtual displays (Xvfb) with standardized 1920x1080@24bit resolution
//! to block monitor EDID and hardware multi-display discovery attacks.

use std::process::{Child, Command, Stdio};
use tracing::info;
use std::io::Write;
use rand::RngCore;
use wraith_core::error::{Result, WraithError};

pub const DEFAULT_VIRTUAL_DISPLAY: &str = ":99";
pub const STANDARD_GEOMETRY: &str = "1920x1080x24";

pub struct VirtualDisplay {
    pub display_num: String,
    process: Option<Child>,
    authority: tempfile::NamedTempFile,
}

impl VirtualDisplay {
    pub fn spawn_standard(display: Option<&str>) -> Result<Self> {
        let disp = display.unwrap_or(DEFAULT_VIRTUAL_DISPLAY);
        if !valid_display(disp) {
            return Err(WraithError::Configuration("Display must be a local :NUMBER".into()));
        }
        let authority = tempfile::NamedTempFile::new()?;
        let mut cookie = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut cookie);
        let cookie_hex: String = cookie.iter().map(|b| format!("{b:02x}")).collect();
        let mut xauth = Command::new("xauth")
            .arg("-f").arg(authority.path()).arg("-q")
            .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
        let written = xauth.stdin.take().ok_or_else(|| WraithError::Forensic("xauth stdin unavailable".into()))?
            .write_all(format!("add {disp} MIT-MAGIC-COOKIE-1 {cookie_hex}\n").as_bytes());
        if written.is_err() { let _ = xauth.kill(); }
        let status = xauth.wait()?;
        written?;
        if !status.success() { return Err(WraithError::Forensic("Xauthority creation failed".into())); }


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

        let mut child = Command::new(xvfb_bin)
            .args([disp, "-screen", "0", STANDARD_GEOMETRY, "-nolisten", "tcp", "+extension", "RANDR"])
            .arg("-auth").arg(authority.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| WraithError::Forensic(format!("Failed starting Xvfb on {disp}: {e}")))?;

        // Give Xvfb time to initialize socket in /tmp/.X11-unix/
        std::thread::sleep(std::time::Duration::from_millis(600));

        match child.try_wait() {
            Ok(Some(status)) => return Err(WraithError::Forensic(format!("Xvfb exited during startup: {status}"))),
            Err(e) => { let _ = child.kill(); let _ = child.wait(); return Err(e.into()); }
            Ok(None) => {},
        }
        Ok(Self {
            display_num: disp.to_string(),
            process: Some(child),
            authority,
        })
    }

    /// Only clients explicitly given DISPLAY and this XAUTHORITY can connect.
    pub fn authority_path(&self) -> &std::path::Path { self.authority.path() }

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

fn valid_display(display: &str) -> bool {
    display.strip_prefix(':').is_some_and(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()) && number.parse::<u16>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_remote_and_argument_display_names() {
        assert!(valid_display(":99"));
        for invalid in ["", ":", "host:0", "-ac", ":0\nadd", ":999999"] { assert!(!valid_display(invalid)); }
    }

    #[test]
    fn test_virtual_display_constants() {
        assert_eq!(DEFAULT_VIRTUAL_DISPLAY, ":99");
        assert_eq!(STANDARD_GEOMETRY, "1920x1080x24");
    }
}
