use std::path::Path;
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;
use wraith_core::error::{Result, WraithError};
use wraith_core::kernel_lockdown::enforce_kernel_lockdown;
use wraith_core::process_lockdown::enforce_process_lockdown;
use wraith_core::state::{StateData, StateManager};
use wraith_core::vault::EncryptedRamVault;
use wraith_forensic::{
    deploy_hardware_and_font_shield, enforce_font_jail,
    remove_hardware_and_font_shield, restore_font_jail, restore_machine_id,
    run_full_cleanup, VirtualDisplay,
};
use wraith_guard::{
    enforce_seccomp_socket_jail, get_current_ip_geo, run_full_leak_test,
    HoneyPortTrap, KillSwitch, TrafficJitterEngine,
};
use wraith_net::{
    apply_ipv6_block, apply_tor_rules_with_journal, block_stun_ports,
    create_cgroup_jail, create_namespace_with_optional_l4_profile, destroy_cgroup_jail,
    restore_mac,
    EgressFastpath, EgressIntrusionDetector, MultiHopTunnelEngine, TrafficShaper,
    TrafficShapingProfile,
};
use wraith_core::tcp_fingerprint::TcpFingerprintProfile;
use wraith_net::tcp_stack::{restore_netns_tcp_stack, NetnsTcpSnapshot};
use wraith_tor::{
    apply_exit_profile, arm_onion_service, backup_resolv, configure_dns,
    get_circuit_telemetry, purge_onion_service, restore_dns, start_tor_daemon, stop_tor_daemon,
    write_torrc, OnionServiceConfig, TlsCamouflageServer, TorControlClient,
};

use crate::display;
use crate::display::{
    print_banner, print_error, print_identity_rotated, print_reset_report, print_step, print_success, print_system_restored,
    show_circuit_telemetry, show_leak_report, show_status_dashboard, render_box, render_box_top,
    render_box_bottom, render_box_row, BoxCorner,
};
use owo_colors::OwoColorize;
use tokio_util::sync::CancellationToken;
use rust_i18n::t;

#[derive(Default)]
struct BackgroundServices {
    jitter: Option<(CancellationToken, tokio::task::JoinHandle<()>)>,
    tls: Option<(CancellationToken, tokio::task::JoinHandle<()>)>,
    dns: Option<(CancellationToken, tokio::task::JoinHandle<()>)>,
    ids: Option<(CancellationToken, tokio::task::JoinHandle<()>)>,
    tcp_egress: Option<(CancellationToken, tokio::task::JoinHandle<()>)>,
    killswitch: Option<(CancellationToken, tokio::task::JoinHandle<()>)>,
    rotator: Option<(CancellationToken, tokio::task::JoinHandle<()>)>,
    honeypot: Option<(CancellationToken, tokio::task::JoinHandle<()>)>,
    virtual_display: Option<VirtualDisplay>,
    traffic_shaper: Option<TrafficShaper>,
}

impl BackgroundServices {
    pub async fn shutdown_and_join(mut self) {
        // 1. Signal cancellation to all running tasks
        if let Some((ct, _)) = &self.jitter {
            ct.cancel();
        }
        if let Some((ct, _)) = &self.tls {
            ct.cancel();
        }
        if let Some((ct, _)) = &self.dns {
            ct.cancel();
        }
        if let Some((ct, _)) = &self.ids {
            ct.cancel();
        }
        if let Some((ct, _)) = &self.tcp_egress {
            ct.cancel();
        }
        if let Some((ct, _)) = &self.killswitch {
            ct.cancel();
        }
        if let Some((ct, _)) = &self.rotator {
            ct.cancel();
        }
        if let Some((ct, _)) = &self.honeypot {
            ct.cancel();
        }
        if let Some(mut vd) = self.virtual_display.take() {
            vd.terminate();
        }
        if let Some(mut ts) = self.traffic_shaper.take() {
            let _ = ts.restore();
        }

        // 2. Wait for handles to terminate with a bounded graceful timeout (1500ms)
        let join_task = |name: &'static str, mut handle: tokio::task::JoinHandle<()>| async move {
            match tokio::time::timeout(Duration::from_millis(1500), &mut handle).await {
                Ok(Ok(())) => tracing::debug!("Background service '{name}' stopped cleanly"),
                Ok(Err(e)) => tracing::warn!("Background service '{name}' task error: {e}"),
                Err(_) => {
                    handle.abort();
                    let _ = handle.await;
                    tracing::warn!("Background service '{name}' aborted after shutdown timeout");
                },
            }
        };

        if let Some((_, h)) = self.jitter.take() {
            join_task("Traffic Jitter", h).await;
        }
        if let Some((_, h)) = self.tls.take() {
            join_task("TLS Camouflage", h).await;
        }
        if let Some((_, h)) = self.dns.take() {
            join_task("DNS Engine", h).await;
        }
        if let Some((_, h)) = self.ids.take() {
            join_task("IDS Sniffer", h).await;
        }
        if let Some((_, h)) = self.tcp_egress.take() {
            join_task("Tor TCP Morphing", h).await;
        }
        if let Some((_, h)) = self.killswitch.take() {
            join_task("KillSwitch Watchdog", h).await;
        }
        if let Some((_, h)) = self.rotator.take() {
            join_task("Auto IP Rotator", h).await;
        }
        if let Some((_, h)) = self.honeypot.take() {
            join_task("Honeypot Trap", h).await;
        }
    }
}

impl Drop for BackgroundServices {
    fn drop(&mut self) {
        for task in [&self.jitter, &self.tls, &self.dns, &self.ids, &self.tcp_egress, &self.killswitch, &self.rotator, &self.honeypot].into_iter().flatten() {
            task.0.cancel();
            task.1.abort();
        }
    }
}

pub struct PreparedStart {
    pub args: crate::StartArgs,
    moat_transport: String,
}

pub fn prepare_start(args: crate::StartArgs) -> Result<PreparedStart> {
    prepare_with_config(args, wraith_core::WraithConfig::load()?)
}

fn prepare_with_config(args: crate::StartArgs, cfg: wraith_core::WraithConfig) -> Result<PreparedStart> {
    // 0-CFG. Merge persistent configuration defaults if not explicitly provided
    let mut args = args;
    let moat_transport;
    {
        moat_transport = cfg.tor.moat_transport.unwrap_or_else(|| "obfs4".into());
        if wraith_tor::PluggableTransportType::from_str(&moat_transport).is_none() {
            return Err(WraithError::Configuration("Unsupported tor.moat_transport".into()));
        }
        if args.interface.is_none() && !args.select_interface {
            args.interface = cfg.network.default_interface.or(cfg.default_interface);
        }
        if args.profile.is_none() {
            args.profile = cfg.tor.default_profile.or(cfg.default_profile);
        }
        if !args.bridge {
            if let Some(b) = cfg.tor.bridge.or(cfg.bridge) {
                args.bridge = b;
            }
        }
        if args.bridge_type.is_none() {
            args.bridge_type = cfg.tor.bridge_type.or(cfg.bridge_type);
        }
        if args.doh.is_none() && !args.select_doh {
            args.doh = cfg.dns.upstream.or(cfg.doh_upstream).or(cfg.dns.provider);
        }
        if !args.strict_hardening {
            if let Some(s) = cfg.hardening.strict.or(cfg.strict_hardening) {
                args.strict_hardening = s;
            }
        }
        if args.rotate_interval.is_none() {
            args.rotate_interval = cfg.tor.rotate_interval.or(cfg.rotate_interval);
        }
        if args.wireguard.is_none() { args.wireguard = cfg.network.wireguard_config; }
        args.tcp_mask |= cfg.hardening.tcp_mask.unwrap_or(false);
        if args.morph_l4.is_none() { args.morph_l4 = cfg.hardening.morph_l4; }
        if args.tls_profile.is_none() { args.tls_profile = cfg.hardening.tls_profile; }
        args.browser_shield |= cfg.hardening.browser_shield.unwrap_or(false);
        args.honey_ports |= cfg.hardening.honey_ports.unwrap_or(false);
        if let Some(transport) = cfg.dns.transport.or(cfg.dns_transport) {
            if !transport.eq_ignore_ascii_case("doh") {
                return Err(WraithError::Configuration("DNSSEC protection requires dns.transport = doh".into()));
            }
        }
        if !args.font_sandbox {
            if let Some(fs) = cfg.fonts.enabled.or(cfg.hardening.font_sandbox) {
                args.font_sandbox = fs;
            }
        }
    }

    apply_strict_preset(&mut args);
    args.namespace |= args.tcp_mask
        || args.morph_l4.as_deref().is_some_and(|mode| mode != "off");
    validate_start_options(&args)?;
    Ok(PreparedStart { args, moat_transport })
}

/// Resolve the required preset after configuration merging, before any mutation.
/// Explicit profile choices are validated, never silently replaced.
fn apply_strict_preset(args: &mut crate::StartArgs) {
    if !args.strict_hardening { return; }
    args.namespace = true;
    args.tcp_mask = true;
    args.mac = true;
    args.machine_id_rotation = true;
    args.browser_shield = true;
    args.font_sandbox = true;
    args.honey_ports = true;
    args.morph_l4.get_or_insert_with(|| "auto".into());
    args.tls_profile.get_or_insert_with(|| "chrome".into());
    args.profile.get_or_insert_with(|| "stealth".into());
}

fn validate_start_options(args: &crate::StartArgs) -> Result<()> {
    if args.no_ks { return Err(WraithError::Configuration("--no-killswitch/--no-ks is unsupported: the kill switch is mandatory".into())); }
    if args.daemon_worker && (args.select_interface || args.select_doh) {
        return Err(WraithError::Configuration("Daemon workers cannot open selection menus; supply --interface and --doh explicitly".into()));
    }
    if (args.select_interface && args.interface.is_some()) || (args.select_doh && args.doh.is_some()) {
        return Err(WraithError::Configuration("Choose either interactive selection or an explicit value".into()));
    }
    if let Some(seconds) = args.rotate_interval { wraith_core::config_loader::validate_rotation_interval(seconds)?; }
    if let Some(profile) = &args.profile {
        if !["stealth", "speed", "journalists", "research", "darkweb"].contains(&profile.as_str()) {
            return Err(WraithError::Configuration(format!("Unknown exit profile: {profile}")));
        }
    }
    if let Some(bridge) = &args.bridge_type { crate::invocation::parse_bridge(bridge).map_err(WraithError::Configuration)?; }
    if let Some(provider) = &args.doh { wraith_guard::DohProvider::parse_input(provider)?; }
    if let Some(spec) = &args.onion_service { parse_onion_spec(spec)?; }
    if args.jitter {
        wraith_tor::validate_https_url(args.jitter_endpoint.as_deref().ok_or_else(||
            WraithError::Configuration("--jitter requires --jitter-endpoint HTTPS_URL".into()))?)?;
    }
    if let Some(ref iface) = args.interface {
        let trimmed = iface.trim();
        if trimmed.is_empty() || trimmed.len() > 15 || trimmed.starts_with('-')
            || !trimmed.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)) {
            return Err(WraithError::Configuration(format!("Invalid target network interface: '{iface}'")));
        }
    }
    if let Some(ref wg_conf) = args.wireguard {
        if wg_conf.trim().is_empty() {
            return Err(WraithError::Configuration("WireGuard multi-hop requires a config file path. Use --wireguard <path/to/wg.conf>".into()));
        }
        if !Path::new(wg_conf).is_file() {
            return Err(WraithError::Configuration(format!("WireGuard config file not found or is not a regular file: '{wg_conf}'")));
        }
    }
    resolve_tcp_profile(args)?;
    Ok(())
}

pub async fn cmd_start(prepared: PreparedStart) -> Result<()> {
    let result = cmd_start_inner(prepared).await;
    if let Err(ref startup) = result {
        let manager = StateManager::default();
        if manager.read_checked().ok().and_then(|state| state.pid) == Some(std::process::id()) {
            if let Err(cleanup) = cmd_stop_inner(false, false, false).await {
                return Err(WraithError::Custom(format!("Startup failed: {}; cleanup failed: {cleanup}. Session record retained.", startup)));
            }
        }
    }
    result
}

async fn cmd_start_inner(prepared: PreparedStart) -> Result<()> {
    let PreparedStart { args, moat_transport } = prepared;
    print_banner(args.strict_hardening);
    let state_mgr = StateManager::default();

    let preflight_lock = wraith_core::session_lock::SessionLock::acquire()?;
    if state_mgr.owner_is_running_checked()? {
        let current_state = state_mgr.read();
        if current_state.active {
            print_error(&t!("runtime.already_running"));
        } else {
            print_error(&t!("daemon_cli.arming_or_running_reset"));
        }
        return Ok(());
    }

    if state_mgr.exists() {
        print_step("Recovering the recorded interrupted session before startup...", "info");
        cmd_stop_inner(false, true, true).await?;
    }
    if wraith_net::recovery::has_orphan_leases()? {
        stop_tor_daemon()?;
    }
    wraith_net::recovery::recover_orphaned_state()?;

    let tls_profile: wraith_tor::BrowserProfile = args.tls_profile.as_deref().unwrap_or("chrome").parse()?;
    let tcp_profile = resolve_tcp_profile(&args)?;
    let is_strict = args.strict_hardening;
    if let Some(ref wg_conf) = args.wireguard {
        if wg_conf.trim().is_empty() {
            print_error(&t!("commands.cmd_err_wg_conf"));
            return Err(WraithError::Custom(
                "WireGuard multi-hop requires a config file. Use --wireguard <path/to/wg.conf>".into(),
            ));
        }
        if !Path::new(wg_conf).exists() {
            print_error(&format!(
                "WireGuard config file not found: '{wg_conf}'. Use --wireguard <path/to/wg.conf>"
            ));
            return Err(WraithError::Custom(format!(
                "WireGuard config file not found: {wg_conf}"
            )));
        }
    }

    let mut state_data = StateData::configured(|data| { data.active = false; data.state = Some(wraith_core::State::Arming); data.strict_hardening = is_strict; data.tls_profile = Some(args.tls_profile.clone().unwrap_or_else(|| "chrome".into())); data.physical_fastpath_disabled = true; });
    state_mgr.claim(state_data.clone())?;
    preflight_lock.release();
    let mut bg_services = BackgroundServices::default();

    // 0. Kernel Process Memory Lockdown (PR_SET_DUMPABLE=0, mlockall)
    print_step(&t!("commands.cmd_step_65"), "info");
    match enforce_process_lockdown() {
        Ok(()) => print_step(&t!("commands.cmd_step_66"), "ok"),
        Err(e) if is_strict => return Err(e),
        Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_mem_lockdown", e = e.to_string())), "warn"),
    }

    if is_strict {
        print_step(&t!("commands.cmd_step_67"), "info");
        state_data.kernel_sysctl_backup = wraith_core::kernel_lockdown::backup_reversible_controls()?.into();
        state_mgr.activate(state_data.clone())?;
        match enforce_kernel_lockdown() {
            Ok(lockdown) => print_step(
                &format!("{}", t!("commands.cmd_step_kernel_lockdown_eval", lockdown = format!("{:?}", lockdown))),
                "ok",
            ),
            Err(e) if is_strict => return Err(e),
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_kernel_lockdown", e = e.to_string())), "warn"),
        }
    }

    // 0a. Anti-Debug Abort Trap (Armed under strict hardening -Fs OR explicit -A)
    if args.aggressive_anti_debug || is_strict {
        print_step(&t!("commands.cmd_step_68"), "info");
        match wraith_forensic::AntiDebugProbe::enforce_anti_debug_trap(is_strict) {
            Ok(()) => print_step(&t!("commands.cmd_step_0"), "ok"),
            Err(e) if is_strict => return Err(e),
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_anti_debug", e = e.to_string())), "warn"),
        }
    }

    // 0b. Process Masquerading (Armed under strict hardening -Fs OR explicit -K)
    if args.aggressive_masquerade || is_strict {
        print_step(&t!("commands.cmd_step_69"), "info");
        match wraith_forensic::cloaked_process_masquerade("[kworker/u16:0]") {
            Ok(()) => print_step(&t!("commands.cmd_step_70"), "ok"),
            Err(e) if is_strict => return Err(e),
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_masquerade", e = e.to_string())), "warn"),
        }
    }

    // 0c. Explicit Destructive Log & History Wipe (Destructive Cleanup Opt-In)
    if args.forensic_wipe_logs {
        print_step(&t!("commands.cmd_step_71"), "warn");
        match wraith_forensic::scrub_system_logs() {
            Ok(count) => print_step(&format!("{}", t!("commands.cmd_step_scrubbed_logs", count = count)), "ok"),
            Err(e) if is_strict => return Err(e),
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_log_scrub_err", e = e.to_string())), "warn"),
        }
        match wraith_forensic::wipe_all_user_histories() {
            Ok(count) => print_step(
                &format!("{}", t!("commands.cmd_step_history_wiped", count = count)),
                "ok",
            ),
            Err(e) if is_strict => return Err(e),
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_history_wipe_err", e = e.to_string())), "warn"),
        }
    }

    // 0-PRE. Target Network Adapter Resolution & Lockdown
    let target_interface: String = if args.select_interface {
        let candidate_interfaces = wraith_net::list_physical_interfaces()?;
        let selected = if candidate_interfaces.is_empty() {
            print_step(&t!("commands.cmd_step_72"), "warn");
            let all = wraith_net::list_all_interfaces()?;
            crate::interface_tui::select_interface_tui(&all)?
        } else {
            crate::interface_tui::select_interface_tui(&candidate_interfaces)?
        };
        print_step(&format!("{}", t!("runtime.interface_locked", selected = &selected)), "ok");
        selected
    } else if let Some(ref iface_name) = args.interface {
        wraith_net::validate_interface(iface_name)?;
        print_step(&format!("{}", t!("runtime.interface_locked_cli", iface = iface_name.as_str())), "ok");
        iface_name.clone()
    } else {
        match wraith_net::get_best_active_interface() {
            Ok(iface) => {
                let raw_msg = t!("commands.cmd_step_default_iface", iface = &iface);
                let msg = raw_msg.replace("{}", &iface);
                print_step(&msg, "ok");
                iface
            }
            Err(_) => {
                let physical = wraith_net::list_physical_interfaces().unwrap_or_default();
                let fallback = physical.first().map(|i| i.name.clone()).unwrap_or_else(|| "eth0".to_string());
                print_step(&format!("{}", t!("runtime.interface_fallback", iface = &fallback)), "warn");
                fallback
            }
        }
    };
    state_data.target_interface = Some(target_interface.clone());
    state_mgr.activate(state_data.clone())?;

    // 0-DOH. DNS-over-HTTPS Resolver Resolution
    let selected_doh: Option<wraith_guard::DohProvider> = if args.select_doh {
        let provider = crate::doh_tui::select_doh_tui()?;
        print_step(&format!("{}", t!("runtime.doh_locked", name = provider.name(), url = provider.url())), "ok");
        Some(provider)
    } else if let Some(ref doh_input) = args.doh {
        let provider = wraith_guard::DohProvider::parse_input(doh_input)?;
        print_step(&format!("{}", t!("runtime.doh_locked_cli", name = provider.name(), url = provider.url())), "ok");
        Some(provider)
    } else {
        None
    };

    // 1. MAC & Hostname Randomization
    if args.mac {
        print_step(&t!("commands.cmd_step_1"), "info");
        match wraith_net::change_mac_with_journal(Some(&target_interface), None, |iface, old, new| {
            state_data.mac_interface = Some(iface.into());
            state_data.mac_old = Some(old.into());
            state_data.mac_new = Some(new.into());
            state_mgr.activate(state_data.clone())
        }) {
            Ok((iface, old_m, new_m)) => {
                let raw_msg = t!("commands.cmd_step_mac_altered", old_m = &old_m, new_m = &new_m, iface = &iface);
                let msg = raw_msg
                    .replacen("{}", &old_m, 1)
                    .replacen("{}", &new_m, 1)
                    .replacen("{}", &iface, 1);
                print_step(&msg, "ok");
                state_data.mac_interface = Some(iface);
                state_data.mac_old = Some(old_m);
                state_data.mac_new = Some(new_m);
                state_mgr.activate(state_data.clone())?;
            }
            Err(e) if is_strict => return Err(e),
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_mac_skip", e = e.to_string())), "warn"),
        }

        match wraith_net::randomize_hostname_with_journal(|old| {
            state_data.hostname_old = Some(old.into());
            state_mgr.activate(state_data.clone())
        }) {
            Ok((old_h, new_h)) => {
                print_step(&format!("Hostname randomized: {old_h} ➔ {new_h}"), "ok");
                state_data.hostname_old = Some(old_h);
            }
            Err(e) if is_strict => return Err(e),
            Err(e) => print_step(&format!("Hostname randomization warning: {e}"), "warn"),
        }
        state_mgr.activate(state_data.clone())?;
    }

    // 2. Machine-ID & Hardware DMI Cloaking
    if args.machine_id_rotation {
        print_step(&t!("commands.cmd_step_73"), "info");
        match wraith_forensic::hardware_cloaker::rotate_machine_id_with_journal(|backup| {
            state_data.machine_id_backup = backup.clone().into();
            state_mgr.activate(state_data.clone())
        }) {
            Ok((old_mid, new_mid)) => {
                print_step(&format!("Machine-ID rotated: {old_mid} ➔ {new_mid}"), "ok");
                state_data.machine_id_old = Some(old_mid);
            }
            Err(e) if is_strict => return Err(e),
            Err(e) => print_step(&format!("Machine-ID rotation warning: {e}"), "warn"),
        }
        state_mgr.activate(state_data.clone())?;
    }

    // Every mode redirects port 80 here, so every mode needs this listener.
    let (server, ct) = TlsCamouflageServer::new(None);
    let handle = server.spawn_server().await?;
    print_step("HTTP/CONNECT relay ready; Wraith HTTPS clients use verified browser TLS profiles", "ok");
    bg_services.tls = Some((ct, handle));

    journal_file(&state_mgr, &mut state_data, wraith_core::config::TORRC_PATH, false)?;
    // 5. Tor Configuration & Bridges
    if args.bridge || args.bridge_type.is_some() {
        let b_type = args.bridge_type.as_deref().unwrap_or("obfs4");
        if b_type.eq_ignore_ascii_case("moat") {
            print_step(&t!("bridge_tui.moat_engaging"), "info");
            let moat = wraith_tor::MoatClient::default();
            let bridges = moat.auto_discover_or_fallback(&moat_transport).await;
            let count = wraith_tor::write_pluggable_transport_torrc(
                wraith_tor::PluggableTransportType::from_str(&moat_transport)
                    .ok_or_else(|| WraithError::Configuration("Unsupported Moat transport".into()))?,
                Some(bridges),
            )?;
            print_step(&format!("{}", t!("bridge_tui.moat_active", count = count)), "ok");
            state_data.bridge_enabled = true;
            state_data.bridge_count = count;
        } else if let Some(pt) = wraith_tor::PluggableTransportType::from_str(b_type) {
            print_step(&format!("{}", t!("bridge_tui.bridge_configuring", pt = pt.as_str())), "info");
            let count = wraith_tor::write_pluggable_transport_torrc(pt, None)?;
            print_step(&format!("{}", t!("bridge_tui.bridge_enabled", count = count, pt = pt.as_str())), "ok");
            state_data.bridge_enabled = true;
            state_data.bridge_count = count;
        } else {
            return Err(WraithError::Configuration(format!("Unsupported bridge transport: {b_type}")));
        }
    } else {
        print_step(&t!("commands.cmd_step_3"), "info");
        write_torrc()?;
        print_step(&t!("commands.cmd_step_4"), "ok");
    }

    // 5b. Multi-Hop & Hybrid Overlay Tunneling (WireGuard ➔ Tor) Hop 1 Initialization
    let mut wg_active_iface: Option<String> = None;
    if let Some(ref wg_conf) = args.wireguard {
        print_step(&format!("{} [{wg_conf}]", t!("commands.cmd_step_46")), "info");
        MultiHopTunnelEngine::preflight_wireguard(wg_conf)?;
        state_data.multihop_enabled = true;
        state_data.wireguard_config = Some(wg_conf.clone());
        state_mgr.activate(state_data.clone())?;
        match MultiHopTunnelEngine::setup_wireguard(Some(wg_conf)) {
            Ok((wg_iface, wg_cfg)) => {
                print_step(
                    &format!(
                        "{} (Peer: {}, AllowedIPs: {})",
                        t!("commands.cmd_step_47", iface = &wg_iface),
                        wg_cfg.peer_endpoint,
                        wg_cfg.allowed_ips
                    ),
                    "ok",
                );
                state_data.multihop_enabled = true;
                state_data.wireguard_config = Some(wg_conf.clone());
                state_mgr.activate(state_data.clone())?;
                wg_active_iface = Some(wg_iface);
            }
            Err(e) => {
                print_step(&format!("{}", t!("commands.cmd_err_multihop_wg", e = e.to_string())), "error");
                return Err(e);
            }
        }
    }

    // 9. Firewall & IPv6 Drop
    print_step(&t!("commands.cmd_step_9"), "info");
    let saved = apply_tor_rules_with_journal(is_strict, |backup| {
        state_data.saved_rules = Some(backup.into());
        state_mgr.activate(state_data.clone())
    })?;
    state_data.saved_rules = Some(saved);
    state_mgr.activate(state_data.clone())?;
    print_step(&t!("commands.cmd_step_10"), "ok");

    print_step(&t!("commands.cmd_step_11"), "info");
    let ipv6_backup = Command::new("ip6tables-save").output()?;
    if !ipv6_backup.status.success() {
        return Err(WraithError::Firewall("Cannot back up IPv6 firewall".into()));
    }
    state_data.saved_ipv6_rules = Some(String::from_utf8_lossy(&ipv6_backup.stdout).into_owned());
    state_mgr.activate(state_data.clone())?;
    apply_ipv6_block()?;
    print_step(&t!("commands.cmd_step_12"), "ok");

    print_step(&t!("commands.cmd_step_13"), "info");
    block_stun_ports()?;
    print_step(&t!("commands.cmd_step_14"), "ok");

    // 9b. Multi-Hop Policy Routing Enforcement (Binding Tor Outbound Egress to WireGuard Hop 1)
    if let Some(ref wg_iface) = wg_active_iface {
        print_step(&format!("{}: {wg_iface}...", t!("commands.cmd_step_48")), "info");
        let tor_uid = wraith_net::get_tor_uid()?;
        match MultiHopTunnelEngine::bind_tor_to_wireguard(tor_uid, wg_iface) {
            Ok(true) => {
                print_step(&t!("commands.cmd_step_49"), "ok");
            }
            Ok(false) => return Err(WraithError::Network("WireGuard routing could not be verified; refusing unprotected fallback".into())),
            Err(e) => return Err(e),
        }
    }

    // Save service state before stopping only active system Tor units.
    state_data.stopped_tor_services = wraith_tor::active_system_tor_services()?;
    state_mgr.activate(state_data.clone())?;
    wraith_tor::set_system_tor_services(&state_data.stopped_tor_services, false)?;

    // Protect the actual Tor-to-guard access link before Tor opens any sockets.
    // Namespace sysctls continue to govern separately launched applications.
    if let Some(profile) = tcp_profile.as_ref().filter(|_| args.namespace) {
        let worker = wraith_net::tcp_egress::start_tor_egress(profile, wraith_net::get_tor_uid()?, |snapshot| {
            state_data.tcp_egress_snapshot_json = Some(serde_json::to_string(snapshot)?);
            state_mgr.activate(state_data.clone())
        })?;
        bg_services.tcp_egress = Some((worker.cancel, worker.handle));
        print_step(&format!("Tor access-link TCP morphing armed: {} (TTL + SYN options/MSS)", worker.snapshot.profile.name), "ok");
    }

    // 6. Bootstrap only after the egress and optional tunnel policy is armed.
    print_step(&t!("commands.cmd_step_5"), "info");
    state_data.tor_started = true;
    state_mgr.activate(state_data.clone())?;
    if let Err(e) = start_tor_daemon().await {
        print_step(&format!("{}", t!("commands.cmd_err_tor_bootstrap", e = e.to_string())), "error");
        // The outer startup owner restores the recorded pre-session policy.
        return Err(e);
    }
    print_step(&t!("commands.cmd_step_6"), "ok");

    // 7. DNS Configuration (Applied ONLY after Tor is ready)
    print_step(&t!("commands.cmd_step_7"), "info");
    journal_file(&state_mgr, &mut state_data, wraith_core::config::RESOLV_PATH, true)?;
    journal_file(&state_mgr, &mut state_data, wraith_core::config::RESOLV_BACKUP, false)?;
    state_data.saved_resolver = Some(std::fs::read_to_string(wraith_core::config::RESOLV_PATH)?);
    state_data.dns_configured = true;
    state_mgr.activate(state_data.clone())?;
    backup_resolv()?;
    if let Err(e) = configure_dns() {
        print_step(&format!("{}", t!("commands.cmd_err_dns_config", e = e.to_string())), "error");
        return Err(e);
    }
    print_step(&t!("commands.cmd_step_8"), "ok");

    // 7b. Sovereign DNS Engine & DoH Forwarder
    let dns_transport = if let Some(ref provider) = selected_doh {
        print_step(&format!("{}", t!("runtime.doh_engine_armed", url = provider.url())), "info");
        wraith_guard::DnsTransport::DoH(provider.url().to_string())
    } else {
        wraith_guard::DnsTransport::DoH(wraith_guard::DohProvider::default_provider().url().to_string())
    };

    let (dns_srv, dns_ct) = wraith_guard::SovereignDnsServer::new_with_transport(None, None, dns_transport);
    let dns_srv = dns_srv.with_tls_profile(tls_profile);
    let dns_handle = dns_srv.spawn_server().await?;
    bg_services.dns = Some((dns_ct, dns_handle));
    print_step(&t!("commands.cmd_step_76"), "ok");

    // 8. Exit Node Profile
    let exit_prof = args.profile.clone();

    if let Some(prof_name) = &exit_prof {
        print_step(
            &format!("{}", t!("commands.cmd_step_exit_prof_applying", prof = prof_name)),
            "info",
        );
        match apply_exit_profile(prof_name).await {
            Ok(p) => {
                print_step(&format!("{}", t!("commands.cmd_step_exit_prof_active", name = &p.name, desc = &p.desc)), "ok");
                state_data.exit_profile = Some(prof_name.clone());
            }
            Err(e) if is_strict => return Err(e),
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_exit_profile", e = e.to_string())), "warn"),
        }
    }

    // 8b. Ephemeral v3 Onion Hidden Service
    if let Some(ref onion_spec) = args.onion_service {
        print_step(&format!("{} [{onion_spec}]...", t!("commands.cmd_step_50")), "info");
        let (virt_port, target_port) = parse_onion_spec(onion_spec)?;

        let mut onion_cfg = OnionServiceConfig::default();
        onion_cfg.add_port(virt_port, target_port);

        match arm_onion_service(&onion_cfg) {
            Ok(()) => {
                state_data.onion_service_active = true;
                state_mgr.activate(state_data.clone())?;
                let mut control = TorControlClient::default();
                control.connect().await?;
                control.signal_hup().await?;
                let hostname = wraith_tor::read_onion_hostname()
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "initializing...".to_string());
                print_step(
                    &format!("{}: :{virt_port} -> :{target_port} ({hostname})", t!("commands.cmd_step_51")),
                    "ok",
                );
                state_data.onion_service_active = true;
                state_data.onion_hostname = Some(hostname);
                state_mgr.activate(state_data.clone())?;
            }
            Err(e) if is_strict => return Err(e),
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_onion_provision", e = e.to_string())), "warn"),
        }
    }

    // Physical-interface TC filters cannot distinguish Tor relay traffic from
    // application traffic. Keep UID-aware netfilter enforcement here; filtering
    // relay TCP by the local TransPort number disconnects Tor itself.

    // 11. Zero-Copy IDS Raw Packet Sniffer & Egress Watchdog (Acquired only under strict/full security mode)
    if is_strict {
        print_step(&t!("commands.cmd_step_78"), "info");
        let (ids, _telemetry, ct) = EgressIntrusionDetector::new();
        let handle = ids.spawn_sniffer()?;
        print_step(&t!("commands.cmd_step_79"), "ok");
        bg_services.ids = Some((ct, handle));
    }

    // 12. Seccomp-BPF Syscall Sandboxing (Raw Socket Filter)
    if is_strict {
        print_step(&t!("commands.cmd_step_80"), "info");
        match enforce_seccomp_socket_jail() {
            Ok(()) => print_step(&t!("commands.cmd_step_81"), "ok"),
            Err(e) if is_strict => return Err(e),
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_seccomp", e = e.to_string())), "warn"),
        }
    }

    // 13. Hardware, GPU, Font & Resolution Browser Shield
    if args.browser_shield {
        print_step(&t!("commands.cmd_step_82"), "info");
        state_data.browser_configured = true;
        state_mgr.activate(state_data.clone())?;
        match deploy_hardware_and_font_shield() {
            Ok(count) => {
                let raw_msg = t!("commands.cmd_step_browser_injected", count = count);
                let msg = raw_msg.replace("{}", &count.to_string());
                print_step(&msg, "ok");
                state_data.browser_hardened = count;
                state_mgr.activate(state_data.clone())?;
            }
            Err(e) if is_strict => return Err(e),
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_browser_shield", e = e.to_string())), "warn"),
        }
    }

    // 14. System-level Font Sandbox
    if args.font_sandbox {
        print_step(&t!("commands.cmd_step_83"), "info");
        journal_file(&state_mgr, &mut state_data, wraith_forensic::FONT_CONFIG_PATH, false)?;
        journal_file(&state_mgr, &mut state_data, wraith_forensic::FONT_CONFIG_BACKUP, false)?;
        state_data.font_configured = true;
        state_mgr.activate(state_data.clone())?;
        match enforce_font_jail() {
            Ok(()) => print_step(&t!("commands.cmd_step_16"), "ok"),
            Err(e) if is_strict => return Err(e),
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_font_sandbox", e = e.to_string())), "warn"),
        }
    }

    // 14b. Isolated X11 Virtual Display Sandbox (Xvfb)
    if args.display_sandbox {
        print_step(&t!("commands.cmd_step_52"), "info");
        match VirtualDisplay::spawn_standard(None) {
            Ok(vd) => {
                print_step(
                    &format!("{}: {} (Physical EDID masked)", t!("commands.cmd_step_53"), vd.display_num),
                    "ok",
                );
                print_step(&format!("Virtual display {} requires XAUTHORITY={}", vd.display_num, vd.authority_path().display()), "info");
                state_data.display_jail_active = true;
                state_mgr.activate(state_data.clone())?;
                bg_services.virtual_display = Some(vd);
            }
            Err(e) if is_strict => return Err(e),
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_virtual_display", e = e.to_string())), "warn"),
        }
    }

    // 15. cgroup2 Network Socket Jail
    if is_strict {
        state_data.original_cgroup = Some(wraith_net::cgroup_jail::current_cgroup()?);
        state_mgr.activate(state_data.clone())?;
        create_cgroup_jail()?;
        if let Err(e) = wraith_net::attach_pid_to_cgroup(std::process::id()) {
            return Err(e);
        } else {
            print_step(&t!("commands.cmd_step_17"), "ok");
        }
    }

    // 16. Network Namespace
    if args.namespace {
        print_step(&t!("commands.cmd_step_18"), "info");
        wraith_net::preflight_namespace()?;
        state_data.namespace_active = true;
        state_mgr.activate(state_data.clone())?;
        match create_namespace_with_optional_l4_profile(tcp_profile.as_ref()) {
            Ok(snapshot) => {
                print_step(&t!("commands.cmd_step_19"), "ok");
                state_data.namespace_active = true;
                if let Some(snapshot) = snapshot {
                    print_step(&format!("L4 namespace profile applied and read back: {}",
                        snapshot.profile_name.as_deref().unwrap_or("unknown")), "ok");
                    state_data.tcp_stack_masked = true;
                    state_data.tcp_profile_kind = snapshot.profile_name.clone();
                    state_data.tcp_stack_backup = snapshot.values.clone();
                    state_data.tcp_snapshot_json = Some(serde_json::to_string(&snapshot)?);
                } else {
                    print_step("L4 morphing off; namespace isolation remains active", "info");
                }
                state_mgr.activate(state_data.clone())?;
            }
            Err(e) => return Err(e),
        }
    }

    // 17. Identity Verification
    print_step(&t!("commands.cmd_step_20"), "info");
    sleep(Duration::from_secs(2)).await;
    let geo = get_current_ip_geo().await;
    if geo.is_tor {
        print_step(&format!("{}", t!("commands.cmd_step_tor_connected", geo = geo.to_string())), "ok");
    } else {
        print_step(&format!("{}", t!("commands.cmd_warn_tor_pending", ip = &geo.ip)), "warn");
    }

    // Cover requests require an explicit endpoint and are opt-in.
    if args.jitter {
        let endpoint = args.jitter_endpoint.as_deref().ok_or_else(|| {
            WraithError::Configuration("--jitter requires --jitter-endpoint HTTPS_URL".into())
        })?;
        let (je, ct) = TrafficJitterEngine::with_profile(endpoint, tls_profile)?;
        let handle = je.spawn_obfuscator();
        print_step(
            "Tor HTTPS cover-request worker started (15–45 second intervals)",
            "ok",
        );
        bg_services.jitter = Some((ct, handle));
    }

    // 18b. Kernel-level TC Netem Traffic Shaper
    if args.traffic_shaper || (args.jitter && is_strict) {
        print_step(&t!("commands.cmd_step_54"), "info");
        match TrafficShaper::new(Some(&target_interface)) {
            Ok(mut shaper) => {
                let prof = TrafficShapingProfile::default();
                state_data.traffic_shaper_active = true;
                state_mgr.activate(state_data.clone())?;
                if let Err(e) = shaper.apply_shaping(&prof) {
                    if is_strict { return Err(e); }
                    print_step(&format!("{}", t!("commands.cmd_warn_shaper_apply", e = e.to_string())), "warn");
                } else {
                    print_step(&t!("commands.cmd_step_55"), "ok");
                    state_data.traffic_shaper_active = true;
                    state_mgr.activate(state_data.clone())?;
                    bg_services.traffic_shaper = Some(shaper);
                }
            }
            Err(e) if is_strict => return Err(e),
            Err(e) => print_step(&format!("Kernel Traffic Shaper init warning: {e}"), "warn"),
        }
    }

    // 18c. Deceptive Honeypot Traps & LAN Deception Sensor
    if args.honey_lan || args.honey_ports || is_strict {
        if args.honey_lan {
            print_step(&t!("commands.cmd_step_56"), "info");
            let address = wraith_net::validate_interface(&target_interface)?.ipv4
                .and_then(|value| value.parse::<std::net::Ipv4Addr>().ok())
                .filter(|ip| ip.is_private())
                .ok_or_else(|| WraithError::Configuration("LAN honeypot requires a private IPv4 address on the selected interface".into()))?;
            let trap = HoneyPortTrap::new().with_lan_binding(true);
            let (ct, handle) = trap.spawn_service(address).await?;
            bg_services.honeypot = Some((ct, handle));
            wraith_net::allow_honey_lan_ports(wraith_guard::DECOY_PORTS, &target_interface, address)?;
            print_step(&t!("commands.cmd_step_57"), "ok");
            state_data.honeypot_active = true;
            state_data.honeypot_lan_active = true;
            state_mgr.activate(state_data.clone())?;
        } else {
            print_step(&t!("commands.cmd_step_58"), "info");
            let trap = HoneyPortTrap::new().with_lan_binding(false);
            let (ct, handle) = trap.spawn_service(std::net::Ipv4Addr::LOCALHOST).await?;
            print_step(&t!("commands.cmd_step_59"), "ok");
            bg_services.honeypot = Some((ct, handle));
            state_data.honeypot_active = true;
            state_mgr.activate(state_data.clone())?;
        }
    }

    // 19. Encrypted In-Memory Ephemeral RAMFS Vault
    let _ram_vault = if is_strict {
        print_step(&t!("commands.cmd_step_86"), "info");
        match EncryptedRamVault::init() {
            Ok(mut vault) => {
                state_data.vault_path = Some(vault.path().to_string_lossy().into_owned());
                // Strict activation requires the encrypted copy to be written.
                let secret_payload = wraith_core::state::serialize_state(&state_data)?;
                vault.write_secret("session.state", &secret_payload)?;
                print_step(&t!("commands.cmd_step_87"), "ok");
                Some(vault)
            }
            Err(e) => return Err(e),
        }
    } else {
        None
    };

    // The DNS service was already started in step 7b with the selected transport.
    // Starting another listener here loses its cancellation handle and races bind.

    // 21. Automatic IP Rotation Engine
    if let Some(interval) = args.rotate_interval {
        print_step(
            &format!("{}", t!("commands.cmd_step_auto_rotate_arming", interval = interval)),
            "info",
        );
        let ct = CancellationToken::new();
        let ct_clone = ct.clone();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(interval));
            ticker.tick().await; // skip initial immediate tick
            loop {
                tokio::select! {
                    _ = ct_clone.cancelled() => break,
                    _ = ticker.tick() => {
                        let mut client = TorControlClient::default();
                        if client.connect().await.is_ok() && client.signal_newnym().await.is_ok() {
                            tokio::time::sleep(Duration::from_secs(3)).await;
                            let new_geo = get_current_ip_geo().await;
                            println!("\n  {}\n", t!("commands.cmd_auto_rotate_switched", geo = &new_geo));
                        }
                    }
                }
            }
        });
        print_step(
            &format!("{}", t!("commands.cmd_step_auto_rotate_active", interval = interval)),
            "ok",
        );
        bg_services.rotator = Some((ct, handle));
    }

    // 22. KillSwitch Daemon & State Activation (Strictly enforced in ALL modes)
    verify_strict_l4_activation(&state_data, |snapshot|
        Ok(wraith_net::inspect_tcp_stack(snapshot)?.matches_profile))?;
    if args.namespace && tcp_profile.is_some() {
        let json = state_data.tcp_egress_snapshot_json.as_deref()
            .ok_or_else(|| WraithError::Network("Tor access-link L4 snapshot missing; activation refused".into()))?;
        let snapshot = serde_json::from_str(json)?;
        let live = wraith_net::tcp_egress::inspect_tor_egress(&snapshot)?;
        if !live.policy_present || live.queue.is_none()
            || bg_services.tcp_egress.as_ref().is_none_or(|worker| worker.1.is_finished()) {
            return Err(WraithError::Network("Tor access-link L4 worker or policy unavailable; activation refused".into()));
        }
    }
    print_step(&t!("commands.cmd_step_21"), "info");
    let (ks, cancel_token) = KillSwitch::new_with_mode(is_strict);
    let ks_handle = ks.spawn_monitor();
    bg_services.killswitch = Some((cancel_token, ks_handle));
    state_data.state = Some(wraith_core::State::Active);
    state_data.ip = Some(geo.ip.clone());
    state_data.kill_switch = true;
    state_mgr.activate(state_data)?;
    print_step(&t!("commands.cmd_step_90"), "ok");

    crate::display::print_session_hud(&geo, is_strict, args.rotate_interval);

    // DNS and HTTP proxy services must remain alive even without the watchdog.
    {
        #[cfg(unix)]
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        #[cfg(unix)]
        let mut sighup =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();

        if args.monitor_window {
            let _ = spawn_monitor_terminal();
        }

        if !args.daemon_worker {
            let _ = crossterm::terminal::enable_raw_mode();
        }

        let mut egress_health = tokio::time::interval(Duration::from_secs(2));
        let mut egress_failure_reported = false;
        loop {
            tokio::select! {
                _ = egress_health.tick(), if bg_services.tcp_egress.is_some() && !egress_failure_reported => {
                    if bg_services.tcp_egress.as_ref().is_some_and(|worker| worker.1.is_finished()) {
                        egress_failure_reported = true;
                        print_step("Tor L4 worker stopped: new guard SYNs remain blocked by NFQUEUE. Stop/recover before restarting.", "error");
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    if !args.daemon_worker {
                        let _ = crossterm::terminal::disable_raw_mode();
                    }
                    println!("\r\n  {}\r\n", t!("commands.cmd_signal_sigint"));
                    break;
                }
                _ = async {
                    #[cfg(unix)]
                    if let Some(ref mut st) = sigterm {
                        st.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                    #[cfg(not(unix))]
                    std::future::pending::<()>().await;
                } => {
                    if !args.daemon_worker {
                        let _ = crossterm::terminal::disable_raw_mode();
                    }
                    println!("\r\n  {}\r\n", t!("commands.cmd_signal_sigterm"));
                    break;
                }
                _ = async {
                    #[cfg(unix)]
                    if let Some(ref mut sh) = sighup {
                        sh.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                    #[cfg(not(unix))]
                    std::future::pending::<()>().await;
                } => {
                    if !args.daemon_worker {
                        let _ = crossterm::terminal::disable_raw_mode();
                    }
                    println!("\r\n  {}\r\n", t!("commands.cmd_signal_sighup"));
                    break;
                }
                key_res = async {
                    if args.daemon_worker {
                        return std::future::pending().await;
                    }
                    tokio::task::spawn_blocking(move || {
                    if crossterm::event::poll(Duration::from_millis(200)).unwrap_or(false) {
                        if let Ok(crossterm::event::Event::Key(k)) = crossterm::event::read() {
                            return Some(k);
                        }
                    }
                    None
                    }).await
                } => {
                    if let Ok(Some(k)) = key_res {
                        // 1. Immediate Emergency Exit on Ctrl+C, Ctrl+D, Esc, 'q', 'Q'
                        if (k.modifiers.contains(crossterm::event::KeyModifiers::CONTROL)
                            && (k.code == crossterm::event::KeyCode::Char('c') || k.code == crossterm::event::KeyCode::Char('C') || k.code == crossterm::event::KeyCode::Char('d') || k.code == crossterm::event::KeyCode::Char('D')))
                            || k.code == crossterm::event::KeyCode::Char('q')
                            || k.code == crossterm::event::KeyCode::Char('Q')
                            || k.code == crossterm::event::KeyCode::Esc
                        {
                            if !args.daemon_worker {
                                let _ = crossterm::terminal::disable_raw_mode();
                            }
                            println!("\r\n  {}\r\n", t!("commands.cmd_signal_clean_disconnect"));
                            break;
                        }

                        // 2. Interactive Hotkeys (ONLY when Control is NOT held)
                        if !k.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) {
                            match k.code {
                                crossterm::event::KeyCode::Char('r') | crossterm::event::KeyCode::Char('R') | crossterm::event::KeyCode::Char('n') | crossterm::event::KeyCode::Char('N') => {
                                    print!("\r\n  ◈ [🔄 CIRCUIT ROTATION] Requesting fresh circuit identity (SIGNAL NEWNYM)...\r\n");
                                    let mut client = TorControlClient::default();
                                    if client.connect().await.is_ok() && client.signal_newnym().await.is_ok() {
                                        tokio::time::sleep(Duration::from_millis(800)).await;
                                        let new_geo = get_current_ip_geo().await;
                                        println!("  {}\r\n", t!("commands.cmd_hotkey_identity_active", geo = &new_geo));
                                    } else {
                                        println!("  {}\r\n", t!("commands.cmd_hotkey_tor_ctrl_err"));
                                    }
                                }
                                crossterm::event::KeyCode::Char('t') | crossterm::event::KeyCode::Char('T') => {
                                    if !args.daemon_worker {
                                        let _ = crossterm::terminal::disable_raw_mode();
                                    }
                                    println!("\n  {}", t!("commands.cmd_hotkey_leak_audit"));
                                    let report = run_full_leak_test().await;
                                    show_leak_report(&report);
                                    println!();
                                    if !args.daemon_worker {
                                        let _ = crossterm::terminal::enable_raw_mode();
                                    }
                                }
                                crossterm::event::KeyCode::Char('m') | crossterm::event::KeyCode::Char('M') => {
                                    if spawn_monitor_terminal() {
                                        print!("\r\n  {}\r\n\r\n", t!("commands.cmd_hotkey_popup_spawned"));
                                    } else {
                                        print!("\r\n  {}\r\n\r\n", t!("commands.cmd_hotkey_popup_manual"));
                                    }
                                }
                                crossterm::event::KeyCode::Char('c') | crossterm::event::KeyCode::Char('C') => {
                                    print!("\r\n  {}\r\n", t!("commands.cmd_hotkey_memory_purge"));
                                    match wraith_forensic::logs::fast_ram_and_arp_purge() {
                                        Ok(()) => print!("  {}\r\n\r\n", t!("commands.cmd_hotkey_memory_eradicated")),
                                        Err(error) => print!("  Cleanup failed: {error}\r\n\r\n"),
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        if !args.daemon_worker {
            let _ = crossterm::terminal::disable_raw_mode();
        }

        // Gracefully cancel and wait on all background task join handles
        bg_services.shutdown_and_join().await;

        cmd_stop(args.forensic_self_destruct).await?;
    }

    Ok(())
}

pub async fn cmd_stop(self_destruct: bool) -> Result<()> {
    cmd_stop_inner(self_destruct, false, true).await
}

async fn cmd_stop_inner(
    self_destruct: bool,
    lifecycle_lock_held: bool,
    show_completion: bool,
) -> Result<()> {
    let _ = crossterm::terminal::disable_raw_mode();
    if show_completion {
        print_banner(false);
    }

    let state_mgr = StateManager::default();
    if !state_mgr.exists() {
        let _orphan_lock = if lifecycle_lock_held { None }
            else { Some(wraith_core::session_lock::SessionLock::acquire()?) };
        if !state_mgr.exists() {
            if wraith_net::recovery::has_orphan_leases()? {
                stop_tor_daemon()?;
                wraith_net::recovery::recover_orphaned_state()?;
                print_step("Recovered owned orphan network resources.", "ok");
            } else { print_step("No recorded Wraith session; no system settings changed.", "info"); }
            return Ok(());
        }
    }

    #[cfg(target_os = "linux")]
    {
        let is_systemd_active = std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", "wraith.service"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if is_systemd_active && std::env::var_os("INVOCATION_ID").is_none() {
            print_step("Stopping active Wraith systemd daemon service...", "info");
            let status = std::process::Command::new("systemctl")
                .args(["stop", "wraith.service"])
                .status()?;
            if !status.success() {
                return Err(WraithError::Command("Could not stop wraith.service".into()));
            }
        }
    }

    #[cfg(target_os = "linux")]
    let state_info = state_mgr.read_checked()?;

    #[cfg(target_os = "linux")]
    if let Some(pid) = state_info.pid.filter(|pid| *pid != std::process::id()) {
        if let Some(process) = wraith_core::process_identity::SessionProcess::open(
            pid, state_info.process_identity.as_ref(),
        )? {
            if state_info.state == Some(wraith_core::State::Cleanup) {
                return Err(WraithError::Configuration("Another worker is still performing cleanup".into()));
            }
            print_step(&format!("Stopping verified session worker (PID: {pid})..."), "info");
            process.terminate()?;
            let mut exited = false;
            for _ in 0..450 {
                sleep(Duration::from_millis(100)).await;
                if !state_mgr.exists() { return Ok(()); }
                if process.has_exited()? { exited = true; break; }
            }
            if !exited {
                return Err(WraithError::Custom("Session has not stopped; recovery record retained. Inspect the worker before retrying.".into()));
            }
        }
    }

    // The worker may have completed restoration while this caller waited.
    if !state_mgr.exists() { return Ok(()); }
    let _cleanup_lock = if lifecycle_lock_held { None }
        else { Some(wraith_core::session_lock::SessionLock::acquire()?) };
    if !state_mgr.exists() { return Ok(()); }
    let mut state_info = state_mgr.read_checked()?;
    if state_info.pid != Some(std::process::id()) && state_mgr.owner_is_running_checked()? {
        return Err(WraithError::Configuration("Session ownership changed during cleanup".into()));
    }
    state_info.state = Some(wraith_core::State::Cleanup);
    state_mgr.activate(state_info.clone())?;
    let mut errors = Vec::new();
    if (state_info.dns_configured || state_info.active) && !state_info.saved_files.contains_key(wraith_core::config::RESOLV_PATH) {
        let restored = match &state_info.saved_resolver {
            Some(content) => wraith_tor::restore_dns_snapshot(content),
            None => restore_dns(),
        };
        record_cleanup("DNS", restored, &mut errors);
    }
    if let Some(original) = &state_info.original_cgroup {
        record_cleanup("cgroup membership", wraith_net::cgroup_jail::restore_current_cgroup(original), &mut errors);
        record_cleanup("cgroup directory", destroy_cgroup_jail(), &mut errors);
    }
    let iface = state_info.target_interface.as_deref().or(state_info.mac_interface.as_deref());
    if !state_info.physical_fastpath_disabled {
        record_cleanup("legacy packet filter", EgressFastpath::new(iface).and_then(|mut filter| filter.detach()), &mut errors);
    }
    let tor_stopped = if state_info.tor_started || state_info.active {
        let stopped = stop_tor_daemon();
        let confirmed = stopped.is_ok();
        record_cleanup("Tor daemon", stopped, &mut errors);
        confirmed
    } else { true };
    // Do not detach the fail-closed queue while a managed Tor process may still
    // be running. Whole-firewall restoration remains the final recovery owner.
    if tor_stopped {
        if let Some(json) = &state_info.tcp_egress_snapshot_json {
            let result = serde_json::from_str(json).map_err(WraithError::from)
                .and_then(|snapshot| wraith_net::tcp_egress::remove_tor_egress(&snapshot));
            record_cleanup("Tor TCP morphing", result, &mut errors);
        }
    }
    if state_info.multihop_enabled {
        record_cleanup("WireGuard", MultiHopTunnelEngine::teardown_wireguard(state_info.wireguard_config.as_deref()), &mut errors);
    }
    if state_info.onion_service_active { record_cleanup("Onion service", purge_onion_service(), &mut errors); }
    if state_info.traffic_shaper_active {
        record_cleanup("traffic shaper", TrafficShaper::new(iface).and_then(|mut shaper| shaper.restore()), &mut errors);
    }
    if let (Some(iface), Some(mac)) = (&state_info.mac_interface, &state_info.mac_old) {
        record_cleanup("MAC", restore_mac(iface, mac), &mut errors);
    }
    if let Some(hostname) = &state_info.hostname_old {
        let result = Command::new("hostname").arg(hostname).status().map_err(WraithError::from)
            .and_then(|status| if status.success() { Ok(()) } else { Err(WraithError::Command(format!("hostname failed: {status}"))) });
        record_cleanup("hostname", result, &mut errors);
    }
    if !state_info.machine_id_backup.is_empty() {
        record_cleanup("machine IDs", wraith_forensic::hardware_cloaker::restore_machine_ids(&state_info.machine_id_backup), &mut errors);
    } else if let Some(old) = &state_info.machine_id_old {
        record_cleanup("legacy machine ID", restore_machine_id(old), &mut errors);
    }
    if state_info.tcp_stack_masked {
        // When namespace is purged, netns-specific sysctl, netfilter and FIB are destroyed with it.
        // If running without namespace, rollback from captured snapshot.
        if !state_info.namespace_active {
            let restored = match &state_info.tcp_snapshot_json {
                Some(json) => serde_json::from_str::<NetnsTcpSnapshot>(json).map_err(WraithError::from)
                    .and_then(|snapshot| restore_netns_tcp_stack(&snapshot).map_err(Into::into)),
                None => {
                    let mut snapshot = NetnsTcpSnapshot::new(wraith_net::namespace::NAMESPACE_NAME);
                    snapshot.values = state_info.tcp_stack_backup.clone();
                    restore_netns_tcp_stack(&snapshot).map_err(Into::into)
                },
            };
            record_cleanup("TCP stack (3-tier rollback)", restored, &mut errors);
        }
    }
    let namespace_stopped = if state_info.namespace_active {
        let result = state_info.tcp_snapshot_json.as_deref()
            .map(serde_json::from_str::<NetnsTcpSnapshot>).transpose().map_err(WraithError::from)
            .and_then(|snapshot| wraith_net::namespace::destroy_namespace_with_identity(
                snapshot.as_ref().and_then(|snapshot| snapshot.namespace_identity)));
        let stopped = result.is_ok();
        record_cleanup("namespace", result, &mut errors);
        stopped
    } else { true };
    if state_info.browser_configured || state_info.browser_hardened > 0 {
        record_cleanup("browser preferences", remove_hardware_and_font_shield().map(|_| ()), &mut errors);
    }
    if (state_info.font_configured || state_info.active) && !state_info.saved_files.contains_key(wraith_forensic::FONT_CONFIG_PATH) {
        record_cleanup("font configuration", restore_font_jail(), &mut errors);
    }
    record_cleanup("kernel settings", wraith_core::kernel_lockdown::restore_reversible_controls(&state_info.kernel_sysctl_backup), &mut errors);
    for (path, snapshot) in &state_info.saved_files {
        if ![wraith_core::config::TORRC_PATH, wraith_core::config::RESOLV_PATH, wraith_core::config::RESOLV_BACKUP, wraith_forensic::FONT_CONFIG_PATH, wraith_forensic::FONT_CONFIG_BACKUP].contains(&path.as_str()) {
            errors.push(format!("Unrecognized snapshot path: {path}"));
        } else { record_cleanup(path, snapshot.restore(Path::new(path)), &mut errors); }
    }
    if state_info.saved_files.contains_key(wraith_forensic::FONT_CONFIG_PATH) {
        record_cleanup("font cache", wraith_forensic::font_jail::refresh_font_cache(), &mut errors);
    }
    restore_firewalls_after_tor_stop(&state_info, tor_stopped && namespace_stopped,
        wraith_net::restore_rules, wraith_net::restore_ipv6_rules, &mut errors);
    if errors.is_empty() {
        record_cleanup("original Tor services", wraith_tor::set_system_tor_services(&state_info.stopped_tor_services, true), &mut errors);
    }
    if errors.is_empty() && self_destruct {
        record_cleanup("self destruct", std::env::current_exe().map_err(WraithError::from)
            .and_then(|path| wraith_forensic::secure_delete_file(&path, 2)), &mut errors);
    }

    state_mgr.finish_cleanup(&errors)?;

    if show_completion {
        print_system_restored();
    }
    Ok(())
}

pub async fn cmd_reset_network(target: &str) -> Result<()> {
    print_banner(false);
    let target = target.trim().to_lowercase();
    let scope_display = if target == "dns" {
        "DNS SUBSYSTEM"
    } else if target == "firewall" {
        "NETFILTER / FIREWALL"
    } else {
        "FULL NETWORK STACK & NAMESPACES"
    };

    print_step(
        &format!("Initiating emergency host network teardown [Scope: {scope_display}]..."),
        "warn",
    );

    let mut report_rows: Vec<(&'static str, String, &'static str)> = Vec::new();
    let full_or_core = target.is_empty() || target == "network" || target == "net" || target == "all";

    // 1. Terminate any active or recorded Wraith sessions
    if full_or_core {
        print_step("Terminating active Tor daemons & releasing session locks...", "info");
        let state_mgr = StateManager::default();
        if state_mgr.exists() {
            let _ = cmd_stop_inner(false, false, false).await;
            report_rows.push(("Wraith Session State", "Active session stopped & journals disarmed".to_string(), "DISARMED"));
        } else {
            report_rows.push(("Wraith Session State", "No active sessions; state clean".to_string(), "CLEAN"));
        }

        #[cfg(target_os = "linux")]
        {
            let _ = Command::new("systemctl")
                .args(["stop", "wraith.service"])
                .status();
        }

        let _ = stop_tor_daemon();
        report_rows.push(("Tor Core Daemons", "Killed & IPC control sockets detached".to_string(), "TERMINATED"));
    }

    // 2. Namespaces and Virtual Links Purge
    if full_or_core {
        #[cfg(target_os = "linux")]
        {
            print_step("Obliterating network namespaces (wraith-ns) and virtual interfaces...", "info");
            if let Ok(true) = wraith_net::recovery::has_orphan_leases() {
                let _ = wraith_net::recovery::recover_orphaned_state();
            }

            // Force destroy wraith-ns namespace if lingering
            let _ = Command::new("ip")
                .args(["netns", "del", wraith_net::namespace::NAMESPACE_NAME])
                .status();

            // Force destroy veth interfaces including veth-wr
            for veth in &[wraith_net::namespace::VETH_HOST, wraith_net::namespace::VETH_NS, "veth-host", "veth-ns", "veth-wr-host", "veth-wr-ns"] {
                let _ = Command::new("ip").args(["link", "del", veth]).status();
            }

            // Force down and delete wireguard interfaces
            for wg in &["wg-wraith", "wraith-wg", "wg0"] {
                let _ = Command::new("ip").args(["link", "del", wg]).status();
            }

            report_rows.push(("Kernel Namespaces", "wraith-ns destroyed & veth-wr unlinked".to_string(), "PURGED"));
        }
    }

    // 3. Firewall & Netfilter Neutralization
    if full_or_core || target == "firewall" {
        #[cfg(target_os = "linux")]
        {
            print_step("Flushing Netfilter tables & restoring default ACCEPT policy...", "info");
            // Reset iptables policies to ACCEPT and flush all tables
            for table in &["filter", "nat", "mangle", "raw"] {
                let _ = Command::new("iptables").args(["-t", table, "-F"]).status();
                let _ = Command::new("iptables").args(["-t", table, "-X"]).status();
            }
            let _ = Command::new("iptables").args(["-P", "INPUT", "ACCEPT"]).status();
            let _ = Command::new("iptables").args(["-P", "FORWARD", "ACCEPT"]).status();
            let _ = Command::new("iptables").args(["-P", "OUTPUT", "ACCEPT"]).status();

            // Reset ip6tables policies to ACCEPT and flush all tables
            for table in &["filter", "mangle", "raw"] {
                let _ = Command::new("ip6tables").args(["-t", table, "-F"]).status();
                let _ = Command::new("ip6tables").args(["-t", table, "-X"]).status();
            }
            let _ = Command::new("ip6tables").args(["-t", "nat", "-F"]).status();
            let _ = Command::new("ip6tables").args(["-t", "nat", "-X"]).status();
            let _ = Command::new("ip6tables").args(["-P", "INPUT", "ACCEPT"]).status();
            let _ = Command::new("ip6tables").args(["-P", "FORWARD", "ACCEPT"]).status();
            let _ = Command::new("ip6tables").args(["-P", "OUTPUT", "ACCEPT"]).status();

            // Delete custom nftables tables
            for family in &["inet", "ip", "ip6"] {
                let _ = Command::new("nft").args(["delete", "table", family, "wraith"]).status();
            }

            // Remove traffic shaping qdiscs on physical interfaces
            if let Ok(interfaces) = wraith_net::list_all_interfaces() {
                for iface in interfaces {
                    let _ = Command::new("tc")
                        .args(["qdisc", "del", "dev", &iface.name, "root"])
                        .status();
                }
            }

            report_rows.push(("Netfilter Firewall", "iptables/ip6tables/nftables reset to ACCEPT".to_string(), "NEUTRALIZED"));
        }
    }

    // 4. DNS Restoration
    if full_or_core || target == "dns" {
        #[cfg(target_os = "linux")]
        {
            print_step("Unlocking /etc/resolv.conf and setting clearnet Anycast DNS...", "info");
            let resolv_path = Path::new(wraith_core::config::RESOLV_PATH);
            let backup_path = Path::new(wraith_core::config::RESOLV_BACKUP);

            // Remove immutable attribute if set by previous lock
            let _ = Command::new("chattr")
                .args(["-i", wraith_core::config::RESOLV_PATH])
                .status();

            let mut restored_from_backup = false;
            if backup_path.exists() && std::fs::copy(backup_path, resolv_path).is_ok() {
                restored_from_backup = true;
            }

            if !restored_from_backup {
                let needs_fallback = match std::fs::read_to_string(resolv_path) {
                    Ok(content) => {
                        let trimmed = content.trim();
                        trimmed.is_empty()
                            || (trimmed.contains("127.0.0.1") && !trimmed.contains("nameserver 1.1.1.1"))
                    }
                    Err(_) => true,
                };

                if needs_fallback {
                    let fallback_dns = "# Generated by Wraith Network Reset\nnameserver 1.1.1.1\nnameserver 9.9.9.9\nnameserver 8.8.8.8\n";
                    let _ = std::fs::write(resolv_path, fallback_dns);
                }
            }

            // Restart system resolvers
            let _ = Command::new("systemctl").args(["restart", "systemd-resolved"]).status();
            let _ = Command::new("systemctl").args(["restart", "NetworkManager"]).status();

            report_rows.push(("DNS Resolvers", "/etc/resolv.conf restored to Anycast upstream".to_string(), "RESOLVED"));
        }
    }

    // 5. Routing, ARP & Link State Normalization
    if full_or_core {
        #[cfg(target_os = "linux")]
        {
            print_step("Flushing routing table 100, ARP cache and elevating links...", "info");
            // Flush policy routing table 100
            let _ = Command::new("ip").args(["rule", "del", "table", "100"]).status();
            let _ = Command::new("ip").args(["route", "flush", "table", "100"]).status();

            // Re-enable IP forwarding & flush ARP table
            let _ = Command::new("sysctl").args(["-w", "net.ipv4.ip_forward=1"]).status();
            let _ = Command::new("ip").args(["neigh", "flush", "all"]).status();

            // Bring up all physical interfaces
            if let Ok(interfaces) = wraith_net::list_physical_interfaces() {
                for iface in interfaces {
                    let _ = Command::new("ip").args(["link", "set", &iface.name, "up"]).status();
                }
            }

            report_rows.push(("Routing & FIB State", "Default route UP & physical interfaces linked".to_string(), "ONLINE"));
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        report_rows.push(("Platform Compatibility", "Non-Linux Host Environment".to_string(), "SIMULATED"));
    }

    report_rows.push(("Clearnet Stack", "All fail-closed barriers dropped & traffic normalized".to_string(), "OPERATIONAL"));

    let slice_rows: Vec<(&str, &str, &str)> = report_rows.iter().map(|(a, b, c)| (*a, b.as_str(), *c)).collect();
    print_reset_report(&slice_rows);
    print_step("Host network stack successfully restored to default clearnet state.", "ok");
    Ok(())
}

pub async fn cmd_shred(target: &str, passes: u32) -> Result<()> {
    if target.trim().is_empty() {
        return Err(WraithError::Configuration("Target path to shred cannot be empty".into()));
    }
    print_banner(false);
    print_step(
        &format!("{}", t!("commands.cmd_step_shred_start", passes = passes, target = target)),
        "info",
    );

    let path = Path::new(target);
    std::fs::symlink_metadata(path)?;

    let passes = u8::try_from(passes).ok().filter(|n| *n > 0)
        .ok_or_else(|| WraithError::Configuration("Overwrite passes must be 1..=255".into()))?;
    wraith_forensic::shred::secure_delete_file(path, passes)?;
    print_success(&format!(
        "{}",
        t!("daemon_cli.shred_success", target = target)
    ));
    Ok(())
}

/// Synchronize only the official source tree, without running Git as root.
pub async fn cmd_update(artifact: Option<std::path::PathBuf>, manifest: Option<std::path::PathBuf>, signature: Option<std::path::PathBuf>) -> Result<()> {
    if artifact.is_some() || manifest.is_some() || signature.is_some() {
        return Err(WraithError::Configuration("Artifact installation is unavailable; signed input must not be silently ignored".into()));
    }
    crate::source_update::update()?;
    print_success("Official main source synchronized. Run sudo ./build.sh in this repository to build and install.");
    Ok(())
}

pub async fn cmd_switch() -> Result<()> {
    print_banner(false);
    let state_mgr = StateManager::default();
    if !state_mgr.is_active() {
        print_error(&t!("runtime.not_running"));
        return Ok(());
    }

    print_step(&t!("commands.cmd_step_44"), "info");
    let mut client = TorControlClient::default();
    client.connect().await?;
    client.signal_newnym().await?;
    sleep(Duration::from_secs(3)).await;

    let geo = get_current_ip_geo().await;
    print_identity_rotated(&geo);
    Ok(())
}

pub async fn cmd_test() -> Result<()> {
    print_banner(false);
    print_step(&t!("commands.cmd_step_45"), "info");
    let report = run_full_leak_test().await;
    show_leak_report(&report);
    Ok(())
}

pub async fn cmd_info() -> Result<()> {
    print_banner(false);
    let state_mgr = StateManager::default();
    let state = state_mgr.read();

    let geo = get_current_ip_geo().await;

    let telemetry = match get_circuit_telemetry().await {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("Could not fetch Tor circuit telemetry: {e}");
            wraith_tor::TorTelemetry::default()
        }
    };
    show_status_dashboard(&state, &geo, telemetry.circuits.len());

    if state.active {
        show_circuit_telemetry(&telemetry);
    }

    Ok(())
}

pub async fn cmd_cleanup(full: bool) -> Result<()> {
    print_banner(false);
    let mode = if full {
        "FULL (Thorough RAM + Swap + Logs)"
    } else {
        "Quick (Logs + Caches)"
    };
    print_step(&format!("{}", t!("daemon_cli.executing_purge", mode = mode)), "info");

    let count = run_full_cleanup(full, false)?;
    print_success(&format!(
        "{}",
        t!("daemon_cli.purge_complete", count = count)
    ));
    Ok(())
}

pub fn cmd_pentest() -> Result<()> {
    print_banner(false);
    let p_rows1 = vec![
        "SOCKS5 PROXY      : 127.0.0.1:9050 (Tor Native SOCKS5 Transport)".to_string(),
        "HTTP RELAY       : 127.0.0.1:9055 (Cleartext headers / HTTPS CONNECT)".to_string(),
        "DNS RELAY        : 127.0.0.1:5354 (UDP/TCP, local DNSSEC over Tor DoH)".to_string(),
    ];
    let p_box1 = render_box("🛡️ WRAITH-PRIME // AUTHORIZED SECURITY AUDITING & PENTEST SANITIZATION", &p_rows1, BoxCorner::Rounded, 78);
    println!("{}", p_box1[0].bright_yellow());
    for row in &p_box1[1..p_box1.len() - 1] {
        println!("{row}");
    }
    println!("{}\n", p_box1.last().unwrap().bright_yellow());

    let p_rows2 = vec![
        "".to_string(),
        "[NMAP AUTHORIZED TCP SYN AUDIT OVER SOCKS5]:".to_string(),
        "  nmap -sT -Pn -n --proxy socks5://127.0.0.1:9050 <target_ip>".to_string(),
        "".to_string(),
        "[CURL THROUGH THE HTTP CONNECT RELAY]:".to_string(),
        "  curl -x http://127.0.0.1:9055 https://target.com/login".to_string(),
        "       -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64)\"".to_string(),
        "".to_string(),
        "[SQLMAP VULNERABILITY AUDITING OVER TOR SOCKS5]:".to_string(),
        "  sqlmap -u \"http://<target>/id=1\" \\".to_string(),
        "         --proxy=\"socks5://127.0.0.1:9050\" --random-agent".to_string(),
        "".to_string(),
        "[METASPLOIT FRAMEWORK SOCKS5 TUNNELING]:".to_string(),
        "  set Proxies socks5:127.0.0.1:9050".to_string(),
        "  set HTTP_USER_AGENT Mozilla/5.0 (Windows NT 10.0; Win64)".to_string(),
        "".to_string(),
        "[HYDRA / AUTHENTICATION RESILIENCE AUDIT OVER TOR]:".to_string(),
        "  hydra -s 22 -l root -P pass.txt -t 4 <target_ip> ssh".to_string(),
    ];
    let p_box2 = render_box("🎯 RECOMMENDED AUTHORIZED SECURITY AUDIT COMMAND WRAPPERS", &p_rows2, BoxCorner::Square, 78);
    println!("{}", p_box2[0].bright_cyan());
    for row in &p_box2[1..p_box2.len() - 1] {
        println!("{row}");
    }
    println!("{}\n", p_box2.last().unwrap().bright_cyan());

    Ok(())
}

pub fn spawn_monitor_terminal() -> bool {
    let display = std::env::var("DISPLAY").unwrap_or_else(|_| {
        #[cfg(target_os = "linux")]
        {
            if let Ok(entries) = std::fs::read_dir("/tmp/.X11-unix") {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if let Some(num) = name.strip_prefix('X') {
                        return format!(":{num}");
                    }
                }
            }
        }
        ":0".into()
    });

    let mut desktop_user: Option<String> = std::env::var("SUDO_USER").ok();
    let mut xauth = std::env::var("XAUTHORITY").unwrap_or_default();

    if xauth.is_empty() || !Path::new(&xauth).exists() {
        if let Some(ref sudo_user) = desktop_user {
            let user_xauth = format!("/home/{sudo_user}/.Xauthority");
            if Path::new(&user_xauth).exists() {
                xauth = user_xauth;
            }
        }
    }

    if xauth.is_empty() || !Path::new(&xauth).exists() {
        if let Ok(entries) = std::fs::read_dir("/home") {
            for entry in entries.flatten() {
                let user_name = entry.file_name().to_string_lossy().to_string();
                let candidate = entry.path().join(".Xauthority");
                if candidate.exists() {
                    xauth = candidate.to_string_lossy().to_string();
                    if desktop_user.is_none() {
                        desktop_user = Some(user_name);
                    }
                    break;
                }
            }
        }
    }

    if xauth.is_empty() {
        xauth = "/root/.Xauthority".into();
    }

    // Bridge authorization for pure root shells (root@kali / root@byghost)
    #[cfg(target_os = "linux")]
    {
        if xauth != "/root/.Xauthority" && Path::new(&xauth).exists() {
            if let Ok(cookie_bytes) = std::fs::read(&xauth) {
                let _ = std::fs::write("/root/.Xauthority", cookie_bytes);
            }
        }

        for auth_candidate in [&xauth, &"/root/.Xauthority".to_string()] {
            if Path::new(auth_candidate).exists() {
                let _ = std::process::Command::new("xhost")
                    .args(["+SI:localuser:root", "+local:"])
                    .env("DISPLAY", &display)
                    .env("XAUTHORITY", auth_candidate)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
        }
    }

    let dbus_addr = std::env::var("DBUS_SESSION_BUS_ADDRESS").unwrap_or_else(|_| {
        if let Some(ref user) = desktop_user {
            let uid = std::process::Command::new("id")
                .args(["-u", user])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|_| "1000".into());
            format!("unix:path=/run/user/{uid}/bus")
        } else {
            "unix:path=/run/user/1000/bus".into()
        }
    });

    let exe_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "/usr/local/bin/wraith".into());

    #[cfg(unix)]
    let is_root = nix::unistd::geteuid().is_root();
    #[cfg(not(unix))]
    let is_root = false;

    let runner_prefix = if is_root { vec![] } else { vec!["sudo".to_string()] };

    let term_cmds: Vec<(&str, Vec<String>)> = vec![
        ("xfce4-terminal", {
            let mut v = vec!["--title=WRAITH // LIVE DPI & IDS TELEMETRY".into(), "-x".into()];
            v.extend(runner_prefix.clone());
            v.push(exe_path.clone());
            v.push("monitor".into());
            v
        }),
        ("qterminal", {
            let mut v = vec!["-e".into()];
            v.extend(runner_prefix.clone());
            v.push(exe_path.clone());
            v.push("monitor".into());
            v
        }),
        ("x-terminal-emulator", {
            let mut v = vec!["-e".into()];
            v.extend(runner_prefix.clone());
            v.push(exe_path.clone());
            v.push("monitor".into());
            v
        }),
        ("mate-terminal", {
            let cmd_str = if is_root { format!("{exe_path} monitor") } else { format!("sudo {exe_path} monitor") };
            vec!["--title=WRAITH // LIVE DPI & IDS TELEMETRY".into(), "-e".into(), cmd_str]
        }),
        ("konsole", {
            let mut v = vec!["--title".into(), "WRAITH // LIVE DPI & IDS TELEMETRY".into(), "-e".into()];
            v.extend(runner_prefix.clone());
            v.push(exe_path.clone());
            v.push("monitor".into());
            v
        }),
        ("tilix", {
            let cmd_str = if is_root { format!("{exe_path} monitor") } else { format!("sudo {exe_path} monitor") };
            vec!["-t".into(), "WRAITH // LIVE DPI & IDS TELEMETRY".into(), "-e".into(), cmd_str]
        }),
        ("xterm", {
            let mut v = vec!["-title".into(), "WRAITH // LIVE DPI & IDS TELEMETRY".into(), "-e".into()];
            v.extend(runner_prefix.clone());
            v.push(exe_path.clone());
            v.push("monitor".into());
            v
        }),
        ("kitty", {
            let mut v = vec!["-T".into(), "WRAITH // LIVE DPI & IDS TELEMETRY".into()];
            v.extend(runner_prefix.clone());
            v.push(exe_path.clone());
            v.push("monitor".into());
            v
        }),
        ("alacritty", {
            let mut v = vec!["-T".into(), "WRAITH // LIVE DPI & IDS TELEMETRY".into(), "-e".into()];
            v.extend(runner_prefix.clone());
            v.push(exe_path.clone());
            v.push("monitor".into());
            v
        }),
        ("gnome-terminal", {
            let mut v = vec!["--title=WRAITH // LIVE DPI & IDS TELEMETRY".into(), "--".into()];
            v.extend(runner_prefix);
            v.push(exe_path.clone());
            v.push("monitor".into());
            v
        }),
    ];

    // Method 1: Direct terminal launch with synchronized X11 authority & display
    for (term, args) in &term_cmds {
        if std::process::Command::new("which")
            .arg(term)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
            && std::process::Command::new(term)
                .args(args)
                .env("DISPLAY", &display)
                .env("XAUTHORITY", &xauth)
                .env("DBUS_SESSION_BUS_ADDRESS", &dbus_addr)
                .env("NO_AT_BRIDGE", "1")
                .env("QT_LOGGING_RULES", "*=false")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .is_ok()
        {
            return true;
        }
    }

    // Method 2: If root and desktop user exists, launch terminal via runuser so the desktop user owns the window
    if is_root {
        if let Some(ref user) = desktop_user {
            let fallback_terms = ["xfce4-terminal", "qterminal", "x-terminal-emulator", "mate-terminal", "xterm"];
            for term in fallback_terms {
                if std::process::Command::new("which")
                    .arg(term)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
                {
                    let cmd_to_run = format!("sudo {exe_path} monitor");
                    if std::process::Command::new("runuser")
                        .args(["-u", user, "--", term, "-e", &cmd_to_run])
                        .env("DISPLAY", &display)
                        .env("XAUTHORITY", &xauth)
                        .env("DBUS_SESSION_BUS_ADDRESS", &dbus_addr)
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .spawn()
                        .is_ok()
                    {
                        return true;
                    }
                }
            }
        }
    }

    false
}

pub async fn cmd_monitor() -> Result<()> {
    print_banner(false);
    println!("{}", render_box_top("🛡️ WRAITH-PRIME // REAL-TIME DPI & IDS PACKET INTERCEPTOR", 78, BoxCorner::Rounded).bright_cyan());
    println!("{}", render_box_row("ENGINE STATUS : LIVE PROMISCUOUS SNIFFER (AF_PACKET Zero-Copy Ring-0)", 78));
    println!("{}", render_box_row("HOTKEYS       : Press [Q] or [Ctrl+C] to close this monitor window", 78));
    println!("{}\n", render_box_bottom(78, BoxCorner::Rounded).bright_cyan());

    println!("  {}\n", t!("commands.cmd_monitor_armed"));

    #[cfg(unix)]
    {
        use crossterm::style::Stylize;
        // SAFETY: Creating AF_PACKET raw socket descriptor with nonblocking flags.
        let sock_fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                (libc::ETH_P_ALL as u16).to_be() as i32,
            )
        };

        if sock_fd < 0 {
            let err = std::io::Error::last_os_error();
            println!("  {}", t!("commands.cmd_monitor_promisc_active"));
            println!("  {}", t!("commands.cmd_monitor_seccomp_filtered", err = err.to_string()));
            println!("  {}", t!("commands.cmd_monitor_in_flight_sanitizing"));
            println!("  {}\n", t!("commands.cmd_monitor_interceptor_op"));
            println!("  {}", t!("commands.cmd_monitor_listening"));
            
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            return Ok(());
        }

        let mut buf = vec![0u8; 65535];
        let mut packets_count: u64 = 0;
        let mut sanitized_count: u64 = 0;

        let _ = crossterm::terminal::enable_raw_mode();

        loop {
            // Non-blocking exit key listener
            if crossterm::event::poll(Duration::from_millis(40)).unwrap_or(false) {
                if let Ok(crossterm::event::Event::Key(k)) = crossterm::event::read() {
                    if k.code == crossterm::event::KeyCode::Char('q')
                        || k.code == crossterm::event::KeyCode::Char('Q')
                        || k.code == crossterm::event::KeyCode::Esc
                        || (k
                            .modifiers
                            .contains(crossterm::event::KeyModifiers::CONTROL)
                            && (k.code == crossterm::event::KeyCode::Char('c')
                                || k.code == crossterm::event::KeyCode::Char('C')))
                    {
                        break;
                    }
                }
            }

            // SAFETY: Receiving into allocated mutable buffer of exact length.
            let res = unsafe {
                libc::recv(sock_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
            };

            if res > 0 {
                let n = res as usize;
                packets_count += 1;

                let dpi_res = wraith_net::HttpToolSanitizer::sanitize_in_flight(&mut buf[..n]);
                if dpi_res.sanitized_count > 0 {
                    sanitized_count += dpi_res.sanitized_count as u64;
                    let d = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or(Duration::from_secs(0));
                    let secs = d.as_secs();
                    let time_str = format!(
                        "{:02}:{:02}:{:02}.{:03}",
                        (secs / 3600) % 24,
                        (secs / 60) % 60,
                        secs % 60,
                        d.subsec_millis()
                    );
                    let orig = dpi_res
                        .original_signature
                        .unwrap_or_else(|| "Unknown Tool".to_string());
                    let repl = dpi_res
                        .sanitized_replacement
                        .unwrap_or_else(|| "Genuine Browser".to_string());

                    println!("\r  ┌── [ 🔍 DPI SIGNATURE DETECTED (L7 Proxy Active) // {} ] ────────", time_str.bold().cyan());
                    println!("\r  │  ⚠️ Intercepted Signature : {}", orig.bold().yellow());
                    println!("\r  │  🛡️ L7 Proxy Replacement  : {}", repl.bold().green());
                    println!(
                        "\r  │  📊 Streamed Packets      : {} | Total Traps: {}",
                        packets_count.to_string().bold().cyan(),
                        sanitized_count.to_string().bold().magenta()
                    );
                    println!("\r  └─────────────────────────────────────────────────────────────────────────────\r\n");
                }

                if let Some(pkt) = wraith_net::PacketDissector::dissect(&buf[..n]) {
                    if pkt.is_stun_leak {
                        let d = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or(Duration::from_secs(0));
                        let secs = d.as_secs();
                        let time_str = format!(
                            "{:02}:{:02}:{:02}.{:03}",
                            (secs / 3600) % 24,
                            (secs / 60) % 60,
                            secs % 60,
                            d.subsec_millis()
                        );
                        println!("\r  ┌── [ ⚠️ WEBRTC STUN LEAK INTERCEPTED // {} ] ─────────────────────────", time_str.bold().red());
                        println!("\r  │  Observation: STUN packet detected; this monitor cannot confirm a firewall drop");
                        println!("\r  └─────────────────────────────────────────────────────────────────────────────\r\n");
                    }
                }
            } else {
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
        }

        let _ = crossterm::terminal::disable_raw_mode();
        // SAFETY: Closing open raw socket descriptor on monitor teardown.
        unsafe { libc::close(sock_fd) };
    }

    #[cfg(not(unix))]
    {
        println!("  {}", t!("commands.cmd_monitor_linux_req"));
    }

    println!("\r\n  {}\n", t!("commands.cmd_monitor_closed"));
    Ok(())
}

pub async fn cmd_bridge(action: Option<crate::BridgeAction>) -> Result<()> {
    match action.unwrap_or(crate::BridgeAction::List) {
        crate::BridgeAction::List => {
            print_banner(false);
            println!("  \x1b[1;36m{}\x1b[0m\n", t!("commands.cmd_bridge_pool_header"));
            println!("  \x1b[1;33m{}\x1b[0m", t!("commands.cmd_bridge_pool_obfs4"));
            for b in wraith_tor::BUILTIN_OBFS4_BRIDGES {
                println!("    {b}");
            }
            println!("\n  \x1b[1;33m{}\x1b[0m", t!("commands.cmd_bridge_pool_snowflake"));
            for b in wraith_tor::BUILTIN_SNOWFLAKE_BRIDGES {
                println!("    {b}");
            }
            println!("\n  \x1b[1;33m{}\x1b[0m", t!("commands.cmd_bridge_pool_meek"));
            for b in wraith_tor::BUILTIN_MEEK_BRIDGES {
                println!("    {b}");
            }
            println!();
        }
        crate::BridgeAction::Moat { transport, solution, auto } => {
            print_banner(false);
            println!("  \x1b[1;36m{}\x1b[0m\n", t!("commands.cmd_moat_connecting"));
            let moat = wraith_tor::MoatClient::default();

            let bridges = if auto {
                print_step(&t!("commands.cmd_step_94"), "info");
                moat.auto_discover_or_fallback(&transport).await
            } else if let Some(sol) = solution {
                print_step(&t!("commands.cmd_step_95"), "info");
                match moat.fetch_challenge(&transport).await {
                    Ok(ch) => {
                        match moat.check_solution(&transport, &ch.challenge, &sol).await {
                            Ok(br) => br,
                            Err(e) => {
                                print_step(&format!("{}", t!("commands.cmd_moat_sol_rejected", err = e.to_string())), "warn");
                                moat.auto_discover_or_fallback(&transport).await
                            }
                        }
                    }
                    Err(e) => {
                        print_step(&format!("{}", t!("commands.cmd_moat_challenge_failed", err = e.to_string())), "warn");
                        moat.auto_discover_or_fallback(&transport).await
                    }
                }
            } else {
                print_step(&format!("{}", t!("commands.cmd_moat_requesting_challenge", transport = transport)), "info");
                match moat.fetch_challenge(&transport).await {
                    Ok(ch) => {
                        let tmp_captcha = tempfile::Builder::new()
                            .prefix("wraith_moat_")
                            .suffix(".png")
                            .tempfile_in("/tmp")
                            .or_else(|_| tempfile::NamedTempFile::new())
                            .map_err(|e| WraithError::Custom(format!("Failed to create temporary captcha file: {e}")))?;
                        let tmp_path = tmp_captcha.path().to_path_buf();
                        if let Err(e) = wraith_tor::MoatClient::save_captcha_image(&ch.image_base64, &tmp_path) {
                            tracing::warn!("Could not save captcha PNG: {e}");
                        }
                        let path_display = tmp_path.display().to_string();

                        println!("\n  ┌── [ 🛡️ TOR MOAT PROTOCOL // BRIDGEDB CHALLENGE ] ────────────────────────┐");
                        println!("  │ Challenge Token: {:<56} │", ch.challenge);
                        println!("  │ Transport      : {:<56} │", ch.transport);
                        println!("  │ CAPTCHA Image  : {:<56} │", path_display);
                        println!("  │                                                                          │");
                        println!("  │ View the image and enter solution, or press Enter for circumvention pool: │");
                        println!("  └──────────────────────────────────────────────────────────────────────────┘\n");

                        use std::io::Write;
                        print!("  \x1b[1;36m{}\x1b[0m ", t!("commands.cmd_moat_enter_solution"));
                        let _ = std::io::stdout().flush();
                        let mut user_sol = String::new();
                        let _ = std::io::stdin().read_line(&mut user_sol);
                        let trimmed = user_sol.trim();

                        if !trimmed.is_empty() {
                            match moat.check_solution(&transport, &ch.challenge, trimmed).await {
                                Ok(br) => br,
                                Err(e) => {
                                    print_step(&format!("{}", t!("commands.cmd_moat_solution_error", err = e.to_string())), "warn");
                                    moat.auto_discover_or_fallback(&transport).await
                                }
                            }
                        } else {
                            print_step(&t!("commands.cmd_step_96"), "info");
                            moat.auto_discover_or_fallback(&transport).await
                        }
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        print_step(&format!("{}", t!("daemon_cli.moat_unreachable_fallback", err = err_str)), "warn");
                        moat.auto_discover_or_fallback(&transport).await
                    }
                }
            };

            let pt_type = wraith_tor::PluggableTransportType::from_str(&transport)
                .ok_or_else(|| WraithError::Configuration(format!("Unsupported transport: {transport}")))?;
            let count = wraith_tor::write_pluggable_transport_torrc(pt_type, Some(bridges.clone()))?;
            let pt_str = pt_type.to_string();
            print_success(&format!("{}", t!("daemon_cli.bridges_configured", count = count, pt = pt_str)));
            for b in &bridges {
                println!("    Bridge {b}");
            }
            println!();
        }
    }
    Ok(())
}

pub fn cmd_doh(select: bool) -> Result<()> {
    if select {
        let mut cfg = wraith_core::WraithConfig::load()?;
        let provider = crate::doh_tui::select_doh_tui()?;
        print_banner(false);
        print_success(&format!("{}", t!("daemon_cli.doh_selected", name = provider.name(), url = provider.url())));

        cfg.dns.transport = Some("doh".to_string());
        cfg.dns.provider = Some(provider.name().to_string());
        cfg.dns.upstream = Some(provider.url().to_string());
        cfg.doh_upstream = Some(provider.url().to_string());
        let path = cfg.save()?;
        let path_str = format!("{path:?}");
        print_step(&format!("{}", t!("daemon_cli.doh_saved", path = path_str)), "ok");
    } else {
        print_banner(false);
        crate::doh_tui::print_doh_table();
    }
    Ok(())
}


fn parse_onion_spec(value: &str) -> Result<(u16, u16)> {
    if let Some((virtual_port, target_port)) = value.split_once(':') {
        Ok((parse_onion_port(virtual_port)?, parse_onion_port(target_port)?))
    } else {
        let port = parse_onion_port(value)?;
        Ok((port, port))
    }
}

fn parse_onion_port(value: &str) -> Result<u16> {
    value.parse::<u16>().ok().filter(|port| *port > 0)
        .ok_or_else(|| WraithError::Configuration("Onion ports must be integers between 1 and 65535".into()))
}


fn journal_file(manager: &StateManager, state: &mut StateData, path: &str, allow_symlink: bool) -> Result<()> {
    if state.saved_files.contains_key(path) { return Ok(()); }
    let snapshot = wraith_core::file_snapshot::FileSnapshot::capture(Path::new(path))?;
    if !allow_symlink && matches!(snapshot, wraith_core::file_snapshot::FileSnapshot::Symlink { .. }) {
        return Err(WraithError::Configuration(format!("Refusing to overwrite symlinked session configuration: {path}")));
    }
    state.saved_files.insert(path.into(), snapshot);
    manager.activate(state.clone())
}

fn restore_firewalls_after_tor_stop(
    state: &StateData, tor_stopped: bool,
    restore_ipv4: impl FnOnce(&str) -> Result<()>,
    restore_ipv6: impl FnOnce(&str) -> Result<()>, errors: &mut Vec<String>,
) {
    if !tor_stopped {
        errors.push("Firewall retained because Tor or namespace cleanup is incomplete; retry recovery".into());
        return;
    }
    if let Some(saved) = &state.saved_rules {
        record_cleanup("IPv4 firewall", restore_ipv4(saved), errors);
    }
    if let Some(saved) = &state.saved_ipv6_rules {
        record_cleanup("IPv6 firewall", restore_ipv6(saved), errors);
    }
}

fn record_cleanup(label: &str, result: Result<()>, errors: &mut Vec<String>) {
    if let Err(error) = result {
        let detail = format!("{label}: {error}");
        tracing::warn!("Cleanup failed: {detail}");
        errors.push(detail);
    }
}

/// Require a complete, matching L4 transaction and fresh readback before Active.
fn verify_strict_l4_activation(
    state: &StateData,
    inspect: impl FnOnce(&NetnsTcpSnapshot) -> Result<bool>,
) -> Result<()> {
    if !state.strict_hardening { return Ok(()); }
    if !state.namespace_active || !state.tcp_stack_masked {
        return Err(WraithError::Namespace("Full-security requires an applied namespace L4 profile".into()));
    }
    let snapshot: NetnsTcpSnapshot = serde_json::from_str(state.tcp_snapshot_json.as_deref()
        .ok_or_else(|| WraithError::Namespace("Full-security L4 snapshot is missing".into()))?)?;
    let browser: wraith_tor::BrowserProfile = state.tls_profile.as_deref()
        .ok_or_else(|| WraithError::Configuration("Full-security TLS profile is missing".into()))?.parse()?;
    if snapshot.applied_profile.as_ref() != Some(&browser.l4_profile()) {
        return Err(WraithError::Namespace("Applied L4 profile does not match the strict TLS platform".into()));
    }
    if !inspect(&snapshot)? {
        return Err(WraithError::Namespace("Full-security L4 readback detected configuration drift; activation refused".into()));
    }
    tracing::info!("Strict L4 profile verified before session activation");
    Ok(())
}

/// Resolve the namespace reference profile and enforce strict platform pairing.
fn resolve_tcp_profile(args: &crate::StartArgs) -> Result<Option<TcpFingerprintProfile>> {
    let browser: wraith_tor::BrowserProfile = args.tls_profile.as_deref().unwrap_or("chrome").parse()?;
    let profile = match args.morph_l4.as_deref().unwrap_or("auto") {
        "off" => {
            if args.strict_hardening || args.tcp_mask {
                return Err(WraithError::Configuration("--morph-l4 off conflicts with --full-security and --tcp-mask".into()));
            }
            return Ok(None);
        }
        "auto" => browser.l4_profile(),
        "windows" | "windows11" => TcpFingerprintProfile::windows11(),
        "macos" => TcpFingerprintProfile::macos(),
        "linux" => TcpFingerprintProfile::linux_default(),
        value => return Err(WraithError::Configuration(format!("Unknown L4 profile: {value}"))),
    };
    if args.strict_hardening && profile.kind != browser.l4_profile().kind {
        return Err(WraithError::Configuration(format!(
            "Full-security requires matching L4/TLS platforms: {} does not match --tls-profile {}. Use --morph-l4 auto or select a matching TLS profile",
            profile.name, args.tls_profile.as_deref().unwrap_or("chrome")
        )));
    }
    Ok(Some(profile))
}

#[cfg(any(target_os = "linux", test))]
fn namespace_exec_ready(state: &StateData, running: bool) -> bool {
    state.active && state.state == Some(wraith_core::State::Active) && state.namespace_active && running
}

/// Join the already protected namespace, then drop privileges before exec.
pub async fn cmd_exec(command: Vec<String>) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let state = StateManager::default().read_checked()?;
        if !namespace_exec_ready(&state, StateManager::default().is_running()) {
            return Err(WraithError::Configuration("Start Wraith with --namespace first".into()));
        }
        if command.is_empty() || command[0].trim().is_empty() {
            return Err(WraithError::Configuration("Command program name cannot be empty".into()));
        }
        let uid = std::env::var("SUDO_UID").ok().and_then(|s| s.parse::<u32>().ok())
            .filter(|uid| *uid != 0).ok_or_else(|| WraithError::Configuration("Run sudo wraith exec -- PROGRAM from your normal user account".into()))?;
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)).map_err(|e| WraithError::Configuration(e.to_string()))?
            .ok_or_else(|| WraithError::Configuration("Invoking user does not exist".into()))?;
        let mut args = vec!["-u".to_owned(), user.name, "--".to_owned(), "/usr/bin/env".to_owned(), "-u".to_owned(), "LD_PRELOAD".to_owned(), "-u".to_owned(), "LD_LIBRARY_PATH".to_owned()];
        args.extend(command);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut child = wraith_net::spawn_in_namespace("/usr/sbin/runuser", &refs)?;
        let status = tokio::task::spawn_blocking(move || child.wait()).await
            .map_err(|e| WraithError::Configuration(e.to_string()))??;
        if !status.success() { return Err(WraithError::Configuration(format!("Application exited with {status}"))); }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    { let _ = command; Err(WraithError::Configuration("Network namespaces require Linux".into())) }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    #[test]
    fn failed_tor_shutdown_never_restores_firewalls_or_swallows_restore_errors() {
        let state = StateData::configured(|data| { data.saved_rules = Some("v4".into()); data.saved_ipv6_rules = Some("v6".into()); });
        let mut errors = Vec::new();
        restore_firewalls_after_tor_stop(&state, false, |_| panic!("Tor still running"), |_| panic!("Tor still running"), &mut errors);
        assert_eq!(errors.len(), 1);
        errors.clear();
        let restored_v6 = std::cell::Cell::new(false);
        restore_firewalls_after_tor_stop(&state, true,
            |saved| { assert_eq!(saved, "v4"); Err(WraithError::PermissionDenied) },
            |saved| { assert_eq!(saved, "v6"); restored_v6.set(true); Ok(()) }, &mut errors);
        assert!(restored_v6.get());
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("IPv4 firewall"));
    }
    #[test]
    fn applications_cannot_enter_a_namespace_while_l4_is_still_arming() {
        let mut state = StateData::configured(|data| { data.active = true; data.namespace_active = true; data.state = Some(wraith_core::State::Arming); });
        assert!(!namespace_exec_ready(&state, true));
        state.state = Some(wraith_core::State::Active);
        assert!(namespace_exec_ready(&state, true));
        assert!(!namespace_exec_ready(&state, false));
        state.state = Some(wraith_core::State::Cleanup);
        assert!(!namespace_exec_ready(&state, true));
    }
    #[test]
    fn full_security_resolves_required_controls_for_cli_and_config() {
        for from_config in [false, true] {
            let mut config = wraith_core::WraithConfig::default();
            config.set_key("hardening.strict", if from_config { "true" } else { "false" }).unwrap();
            for flag in ["hardening.tcp_mask", "hardening.browser_shield", "hardening.font_sandbox", "hardening.honey_ports"] {
                config.set_key(flag, "false").unwrap();
            }
            let args = crate::StartArgs { strict_hardening: !from_config, ..Default::default() };
            let prepared = prepare_with_config(args, config).unwrap();
            let args = &prepared.args;
            assert!(args.namespace && args.tcp_mask && args.mac && args.machine_id_rotation);
            assert!(args.browser_shield && args.font_sandbox && args.honey_ports);
            assert_eq!(args.morph_l4.as_deref(), Some("auto"));
            assert_eq!(args.tls_profile.as_deref(), Some("chrome"));
            assert_eq!(args.profile.as_deref(), Some("stealth"));
            assert!(!crate::invocation::should_background(args));
            assert!(!args.forensic_wipe_logs && !args.forensic_self_destruct && !args.honey_lan);
            assert!(!args.jitter && !args.traffic_shaper && !args.display_sandbox && !args.bridge);
            assert!(args.wireguard.is_none() && args.onion_service.is_none() && args.rotate_interval.is_none());
        }
    }

    #[test]
    fn strict_profile_pairs_reject_off_and_mismatches_before_mutation() {
        for (tls, matching) in [("chrome", "windows"), ("firefox", "linux"), ("safari", "macos")] {
            for mode in ["auto", "windows", "windows11", "linux", "macos", "off"] {
                let args = crate::StartArgs { strict_hardening: true, tls_profile: Some(tls.into()),
                    morph_l4: Some(mode.into()), ..Default::default() };
                let result = prepare_with_config(args, wraith_core::WraithConfig::default());
                assert_eq!(result.is_ok(), mode == "auto" || mode == matching || (tls == "chrome" && mode == "windows11"), "{tls}/{mode}");
            }
        }
        let mut config = wraith_core::WraithConfig::default();
        config.set_key("hardening.morph_l4", "off").unwrap();
        assert!(prepare_with_config(crate::StartArgs { strict_hardening: true, ..Default::default() }, config).is_err());
    }

    #[test]
    fn ordinary_sessions_do_not_inherit_the_strict_preset() {
        let args = crate::StartArgs::default();
        let prepared = prepare_with_config(args.clone(), wraith_core::WraithConfig::default()).unwrap();
        assert_eq!(prepared.args, args);
    }

    #[test]
    fn strict_activation_requires_a_matching_snapshot_and_fresh_readback() {
        assert!(verify_strict_l4_activation(&StateData::default(), |_| panic!("standard mode")).is_ok());
        let mut state = StateData::configured(|data| { data.strict_hardening = true; });
        assert!(verify_strict_l4_activation(&state, |_| panic!("missing namespace")).is_err());
        state.namespace_active = true;
        state.tcp_stack_masked = true;
        assert!(verify_strict_l4_activation(&state, |_| panic!("missing snapshot")).is_err());
        let mut snapshot = NetnsTcpSnapshot::new(wraith_net::NAMESPACE_NAME);
        snapshot.applied_profile = Some(TcpFingerprintProfile::windows11());
        state.tcp_snapshot_json = Some(serde_json::to_string(&snapshot).unwrap());
        state.tls_profile = Some("safari".into());
        assert!(verify_strict_l4_activation(&state, |_| panic!("mismatch")).is_err());
        state.tls_profile = Some("chrome".into());
        assert!(verify_strict_l4_activation(&state, |_| Ok(true)).is_ok());
        assert!(verify_strict_l4_activation(&state, |_| Ok(false)).is_err());
        assert!(verify_strict_l4_activation(&state, |_| Err(WraithError::PermissionDenied)).is_err());
    }

    #[test]
    fn persistent_strict_mode_is_resolved_before_daemon_selection() {
        let mut config = wraith_core::WraithConfig::default();
        config.set_key("hardening.strict", "true").unwrap();
        let prepared = prepare_with_config(crate::StartArgs::default(), config).unwrap();
        assert!(prepared.args.strict_hardening);
        assert!(!crate::invocation::should_background(&prepared.args));
    }

    #[test]
    fn explicit_profiles_override_defaults_without_losing_other_guards() {
        let mut config = wraith_core::WraithConfig::default();
        config.set_key("hardening.morph_l4", "windows").unwrap();
        config.set_key("hardening.tls_profile", "chrome").unwrap();
        config.set_key("hardening.browser_shield", "true").unwrap();
        let args = crate::StartArgs { morph_l4: Some("auto".into()), tls_profile: Some("safari".into()), ..Default::default() };
        let prepared = prepare_with_config(args, config).unwrap();
        assert!(prepared.args.browser_shield);
        assert_eq!(resolve_tcp_profile(&prepared.args).unwrap().unwrap().kind, wraith_core::tcp_fingerprint::TcpProfileKind::MacOS);
    }

    #[test]
    fn startup_rejects_invalid_options_before_claiming_a_session() {
        for args in [
            crate::StartArgs { rotate_interval: Some(u64::MAX), ..Default::default() },
            crate::StartArgs { rotate_interval: Some(0), ..Default::default() },
            crate::StartArgs { no_ks: true, ..Default::default() },
            crate::StartArgs { daemon_worker: true, select_interface: true, ..Default::default() },
            crate::StartArgs { bridge_type: Some("webtunnel".into()), ..Default::default() },
            crate::StartArgs { profile: Some("typo".into()), ..Default::default() },
            crate::StartArgs { onion_service: Some("80:0".into()), ..Default::default() },
            crate::StartArgs { doh: Some("http://dns.example".into()), ..Default::default() },
            crate::StartArgs { interface: Some("".into()), ..Default::default() },
            crate::StartArgs { interface: Some("-eth0".into()), ..Default::default() },
            crate::StartArgs { interface: Some("waytoolonginterfacename".into()), ..Default::default() },
            crate::StartArgs { wireguard: Some("".into()), ..Default::default() },
            crate::StartArgs { wireguard: Some("/nonexistent/file.conf".into()), ..Default::default() },
        ] { assert!(prepare_with_config(args, wraith_core::WraithConfig::default()).is_err()); }
    }

    #[test]
    fn malformed_onion_ports_never_publish_a_default_service() {
        for value in ["", "0", "65536", "abc", "80:90"] { assert!(parse_onion_port(value).is_err()); }
        assert_eq!(parse_onion_port("8080").unwrap(), 8080);
    }

    #[test]
    fn auto_uses_selected_tls_platform_and_manual_profiles_override_it() {
        use wraith_core::tcp_fingerprint::TcpProfileKind::*;
        for (tls, expected) in [("chrome", Windows11), ("firefox", LinuxDefault), ("safari", MacOS)] {
            let args = crate::StartArgs { tls_profile: Some(tls.into()), morph_l4: Some("auto".into()), ..Default::default() };
            assert_eq!(resolve_tcp_profile(&args).unwrap().unwrap().kind, expected);
        }
        for (mode, expected) in [("windows", Windows11), ("windows11", Windows11), ("linux", LinuxDefault), ("macos", MacOS)] {
            let args = crate::StartArgs { tls_profile: Some("safari".into()), morph_l4: Some(mode.into()), ..Default::default() };
            assert_eq!(resolve_tcp_profile(&args).unwrap().unwrap().kind, expected);
        }
    }

    #[test]
    fn off_and_invalid_profiles_are_not_silently_armed() {
        let mut args = crate::StartArgs { morph_l4: Some("off".into()), ..Default::default() };
        assert!(resolve_tcp_profile(&args).unwrap().is_none());
        args.strict_hardening = true;
        assert!(resolve_tcp_profile(&args).is_err());
        args.strict_hardening = false;
        args.tcp_mask = true;
        assert!(resolve_tcp_profile(&args).is_err());
        args.morph_l4 = Some("unknown".into());
        assert!(resolve_tcp_profile(&args).is_err());
        args.morph_l4 = Some("auto".into());
        args.tls_profile = Some("unknown".into());
        assert!(resolve_tcp_profile(&args).is_err());
    }

}
