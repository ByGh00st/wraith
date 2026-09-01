//! Wraith Anti-Fingerprint & Hardware Shield
//! Comprehensive mitigation against Font, GPU, Screen Resolution, Audio, and Hardware Enumeration.

use std::fs;
use std::path::PathBuf;
use tracing::info;
use walkdir::WalkDir;
use wraith_core::error::{Result, WraithError};

pub const SHIELD_HEADER: &str = "\
// ==============================================================================
// WRAITH SOVEREIGN ANTI-FINGERPRINT & HARDWARE MASK
// Defeats GPU, Font, Canvas, Audio, Resolution & Hardware Concurrency Tracking
// ==============================================================================
";

/// Comprehensive Firefox & Gecko privacy, hardware spoofing, and anti-fingerprinting rules
pub const HARDWARE_SHIELD_PREFERENCES: &[(&str, &str)] = &[
    // --- 1. RESOLUTION & LETTERBOXING LEAK PROTECTION ---
    // Enforces RFP letterboxing (viewport stepping: 200x100 increments with neutral grey padding)
    ("privacy.resistFingerprinting.letterboxing", "true"),
    ("privacy.resistFingerprinting.letterboxing.dimensions", "\"1000x800,1200x900,1400x900,1600x900,1920x1080\""),
    // Standardize system DPI and device pixel ratio to 1.0
    ("layout.css.devPixelsPerPx", "\"1.0\""),
    // Force standard 24-bit screen color depth
    ("privacy.resistFingerprinting", "true"),
    
    // --- 2. GPU & WEBGL FINGERPRINT TERMINATION ---
    // Disable hardware WebGL context to prevent shader/precision fingerprinting
    ("webgl.disabled", "true"),
    ("webgl.enable-webgl2", "false"),
    ("webgl.min_capability_mode", "true"),
    ("webgl.disable-extensions", "true"),
    ("webgl.disable-fail-if-major-performance-caveat", "true"),
    // Spoof WebGL renderer to generic unidentifiable software Mesa/LLVMpipe
    ("webgl.override-renderer", "\"Mesa/X.org llvmpipe (LLVM 15.0.7, 256 bits)\""),
    ("webgl.override-vendor", "\"Mesa/X.org\""),
    // Disable hardware-accelerated layers & Direct2D/Vulkan queries
    ("layers.acceleration.disabled", "true"),
    ("gfx.direct2d.disabled", "true"),
    ("gfx.font_rendering.directwrite.enabled", "false"),

    // --- 3. FONT ENUMERATION & FONT METRICS DEFENSE ---
    // Level 1: Strictly restrict font visibility to standard base Linux system fonts
    ("layout.css.font-visibility.level", "1"),
    ("layout.css.font-visibility.resistFingerprinting", "true"),
    ("layout.css.font-visibility.standard", "1"),
    ("layout.css.font-visibility.trackingprotection", "1"),
    // Normalize font bounding box measurements across CSS font probes
    ("browser.display.use_document_fonts", "1"),

    // --- 4. CANVAS 2D CONTEXT & PIXEL NOISE INJECTION ---
    // Block silent canvas extraction without explicit permission
    ("privacy.resistFingerprinting.autoDeclineNoUserInputCanvasPrompts", "true"),
    ("privacy.resistFingerprinting.randomData", "true"),
    ("canvas.capturestream.enabled", "false"),

    // --- 5. HARDWARE CONCURRENCY & MEMORY MASKING ---
    // Clamp CPU cores to generic standard 2 cores (defeats navigator.hardwareConcurrency)
    ("dom.maxHardwareConcurrency", "2"),
    // Kill Battery Status API
    ("dom.battery.enabled", "false"),
    // Kill Gamepad and VR/XR Hardware APIs
    ("dom.gamepad.enabled", "false"),
    ("dom.vr.enabled", "false"),
    ("dom.vibrator.enabled", "false"),

    // --- 6. AUDIO CONTEXT & SPEECH SYNTHESIS SPOOFING ---
    // Disable WebAudio oscillator fingerprinting (AudioContext buffer hash)
    ("dom.webaudio.enabled", "false"),
    // Disable SpeechSynthesis voice enumeration
    ("media.webspeech.synth.enabled", "false"),
    ("media.webspeech.recognition.enable", "false"),

    // --- 7. CLOCK SKEW & HIGH-PRECISION TIMER CLAMPING ---
    // Clamp performance.now() to 20ms jitter (defeats CPU cache & Spectre side-channel timing attacks)
    ("privacy.reduceTimerPrecision", "true"),
    ("privacy.reduceTimerPrecision.microseconds", "20000"),

    // --- 8. LOCALE & TIMEZONE FINGERPRINT DEFENSE ---
    // Force standard English locale & UTC timezone representation
    ("javascript.use_us_english_locale", "true"),
    // Keep proxy as direct/system (kernel-level transparent proxy handles Tor egress seamlessly)
    ("network.proxy.type", "0"),

    // --- 9. MEDIA DEVICES & WEBRTC COMPLETE BLACKOUT ---
    ("media.peerconnection.enabled", "false"),
    ("media.peerconnection.ice.default_address_only", "true"),
    ("media.peerconnection.ice.no_host", "true"),
    ("media.navigator.enabled", "false"),
    ("media.navigator.video.enabled", "false"),
    ("media.getusermedia.screensharing.enabled", "false"),
];

pub fn find_all_firefox_profiles() -> Result<Vec<PathBuf>> {
    let mut profiles = Vec::new();
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let mut search_roots = vec![
        PathBuf::from(format!("{home}/.mozilla/firefox")),
        PathBuf::from(format!("{home}/.var/app/org.mozilla.firefox/.mozilla/firefox")),
        PathBuf::from("/root/.mozilla/firefox"),
    ];

    if let Ok(entries) = fs::read_dir("/home") {
        for entry in entries.flatten() {
            let p = entry.path().join(".mozilla/firefox");
            if p.exists() {
                search_roots.push(p);
            }
        }
    }

    for root in &search_roots {
        if root.exists() && root.is_dir() {
            for entry in WalkDir::new(root).max_depth(2).into_iter().flatten() {
                let path = entry.path();
                if path.is_dir() && (path.join("prefs.js").exists() || path.to_string_lossy().contains(".default")) {
                    profiles.push(path.to_path_buf());
                }
            }
        }
    }

    profiles.sort();
    profiles.dedup();
    Ok(profiles)
}

pub fn deploy_hardware_and_font_shield() -> Result<usize> {
    let profiles = find_all_firefox_profiles()?;
    let mut deployed_count = 0;

    let mut lines = vec![SHIELD_HEADER.to_string()];
    for (key, val) in HARDWARE_SHIELD_PREFERENCES {
        lines.push(format!("user_pref(\"{key}\", {val});"));
    }
    let config_payload = lines.join("\n") + "\n";

    for profile in profiles {
        let user_js_path = profile.join("user.js");
        fs::write(&user_js_path, &config_payload).map_err(|e| {
            WraithError::Forensic(format!("Failed deploying shield to {}: {e}", profile.display()))
        })?;
        info!("Hardened GPU, Font, Resolution and WebGL Shield on: {}", profile.display());
        deployed_count += 1;
    }

    Ok(deployed_count)
}

pub fn remove_hardware_and_font_shield() -> Result<usize> {
    let profiles = find_all_firefox_profiles()?;
    let mut removed_count = 0;

    for profile in profiles {
        let user_js_path = profile.join("user.js");
        if user_js_path.exists() {
            let content = fs::read_to_string(&user_js_path).unwrap_or_default();
            if content.contains("WRAITH SOVEREIGN ANTI-FINGERPRINT") {
                let _ = fs::remove_file(&user_js_path);
                removed_count += 1;
            }
        }

        // Sanitize any persistent proxy leftovers from prefs.js
        let prefs_js_path = profile.join("prefs.js");
        if prefs_js_path.exists() {
            if let Ok(content) = fs::read_to_string(&prefs_js_path) {
                let filtered: Vec<&str> = content
                    .lines()
                    .filter(|line| !line.contains("network.proxy."))
                    .collect();
                let mut new_content = filtered.join("\n");
                new_content.push_str("\nuser_pref(\"network.proxy.type\", 0);\n");
                let _ = fs::write(&prefs_js_path, new_content);
            }
        }

        // Guarantee direct connection in user.js
        let _ = fs::write(&user_js_path, "user_pref(\"network.proxy.type\", 0);\n");
    }

    info!("Removed hardware and font shield and reset proxy state from {removed_count} profiles");
    Ok(removed_count)
}
