//! Source synchronization never discards local work or executes Git as root.
use wraith_core::error::{Result, WraithError};

#[cfg(any(target_os = "linux", test))]
const UPSTREAM: &str = "https://github.com/ByGh00st/wraith.git";

#[cfg(any(target_os = "linux", test))]
fn official_remote(value: &str) -> bool {
    value.trim_end_matches('/') == UPSTREAM
        || value.trim_end_matches('/') == "https://github.com/ByGh00st/wraith"
}

#[cfg(target_os = "linux")]
pub fn update() -> Result<()> {
    use std::process::Command;
    let actor = if nix::unistd::geteuid().is_root() {
        let uid = std::env::var("SUDO_UID").ok().and_then(|s| s.parse::<u32>().ok())
            .filter(|uid| *uid != 0)
            .ok_or_else(|| WraithError::Configuration("Run wraith -u from a non-root account".into()))?;
        Some(nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .map_err(|e| WraithError::Configuration(e.to_string()))?
            .ok_or_else(|| WraithError::Configuration("Invoking user does not exist".into()))?)
    } else { None };
    let home = actor.as_ref().map(|user| user.dir.clone()).or_else(|| std::env::var_os("HOME").map(Into::into))
        .ok_or_else(|| WraithError::Configuration("User home unavailable".into()))?;
    let run = |args: &[&str]| -> Result<String> {
        let mut command = Command::new("/usr/bin/git");
        command.env_clear().env("HOME", &home).env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1").env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .args(["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "http.sslVerify=true"])
            .args(args);
        if let Some(user) = &actor {
            use std::os::unix::process::CommandExt;
            let (uid, gid) = (user.uid.as_raw(), user.gid.as_raw());
            // SAFETY: async-signal-safe syscall in the child, before exec.
            unsafe { command.pre_exec(move || {
                if libc::setgroups(0, std::ptr::null()) != 0 { return Err(std::io::Error::last_os_error()); }
                if libc::setgid(gid) != 0 || libc::setuid(uid) != 0 { return Err(std::io::Error::last_os_error()); }
                Ok(())
            }); }
        }
        let output = command.output()?;
        if !output.status.success() {
            return Err(WraithError::Command(format!("Git operation failed: {}", String::from_utf8_lossy(&output.stderr).trim())));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    };
    run(&["rev-parse", "--show-toplevel"])?;
    if !official_remote(&run(&["config", "--get", "remote.origin.url"])?) {
        return Err(WraithError::Configuration("This is not the official Wraith repository".into()));
    }
    if run(&["symbolic-ref", "--short", "HEAD"])? != "main" {
        return Err(WraithError::Configuration("Switch to main before updating; branches are never reset".into()));
    }
    if !run(&["status", "--porcelain", "--untracked-files=normal"])?.is_empty() {
        return Err(WraithError::Configuration("Working tree has local changes; commit or stash them before updating".into()));
    }
    if run(&["config", "--list"])?.lines().any(|line| {
        let key = line.split('=').next().unwrap_or("").to_ascii_lowercase();
        key.starts_with("url.") && key.ends_with(".insteadof")
    }) {
        return Err(WraithError::Configuration("Remove Git URL rewrite rules before updating".into()));
    }
    run(&["fetch", "--no-tags", "--no-recurse-submodules", UPSTREAM, "main"])?;
    run(&["merge", "--ff-only", "--no-edit", "FETCH_HEAD"])?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn update() -> Result<()> { Err(WraithError::UnsupportedPlatform) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn remote_must_be_the_exact_official_https_repository() {
        assert!(official_remote(UPSTREAM));
        for value in ["https://github.com/other/wraith.git", "ext::command", "https://github.com/ByGh00st/wraith.git.evil", "file:///tmp/wraith"] {
            assert!(!official_remote(value));
        }
    }
}
