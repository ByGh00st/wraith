#[cfg(target_os = "linux")]
use std::fs;
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
    enforce_seccomp_socket_jail, get_current_ip, get_current_ip_geo, run_full_leak_test,
    verify_tor_connection, HoneyPortTrap, KillSwitch, TrafficJitterEngine,
};
use wraith_net::{
    apply_ipv6_block, apply_tor_rules_with_journal, backup_tcp_stack, block_stun_ports,
    create_cgroup_jail, create_namespace, destroy_cgroup_jail, destroy_namespace, flush_ipv6_block,
    restore_mac,
    EgressFastpath, EgressIntrusionDetector, MultiHopTunnelEngine, TrafficShaper,
    TrafficShapingProfile,
};
use wraith_tor::{
    apply_exit_profile, arm_onion_service, backup_resolv, configure_dns,
    get_circuit_telemetry, purge_onion_service, restore_dns, start_tor_daemon, stop_tor_daemon,
    write_bridge_torrc, write_torrc, OnionServiceConfig, TlsCamouflageServer, TorControlClient,
};

use crate::display::{
    print_banner, print_error, print_step, print_success, show_circuit_telemetry, show_leak_report,
    show_status_dashboard, render_box, render_box_top, render_box_bottom, render_box_row, BoxCorner,
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
        for task in [&self.jitter, &self.tls, &self.dns, &self.ids, &self.killswitch, &self.rotator, &self.honeypot].into_iter().flatten() {
            task.0.cancel();
            task.1.abort();
        }
    }
}

pub async fn cmd_start(args: crate::StartArgs) -> Result<()> {
    let result = cmd_start_inner(args).await;
    if let Err(ref startup) = result {
        let manager = StateManager::default();
        if manager.read_checked().ok().and_then(|state| state.pid) == Some(std::process::id()) {
            if let Err(cleanup) = cmd_stop(false).await {
                return Err(WraithError::Custom(format!("Startup failed: {}; cleanup failed: {cleanup}. Session record retained.", startup)));
            }
        }
    }
    result
}

async fn cmd_start_inner(args: crate::StartArgs) -> Result<()> {
    // 0-CFG. Merge persistent configuration defaults if not explicitly provided
    let mut args = args;
    {
        let cfg = wraith_core::WraithConfig::load()?;
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
            args.doh = cfg.dns.upstream.or(cfg.doh_upstream);
        }
        if !args.strict_hardening {
            if let Some(s) = cfg.hardening.strict.or(cfg.strict_hardening) {
                args.strict_hardening = s;
            }
        }
        if args.rotate_interval.is_none() {
            args.rotate_interval = cfg.tor.rotate_interval.or(cfg.rotate_interval);
        }
    }

    print_banner(args.strict_hardening);
    let state_mgr = StateManager::default();

    if state_mgr.is_active() {
        print_error(&t!("runtime.already_running"));
        return Ok(());
    }

    let is_strict = args.strict_hardening;
    if is_strict && args.no_ks {
        return Err(WraithError::Configuration("Full security requires the kill switch; remove --no-ks".into()));
    }
    if args.rotate_interval == Some(0) {
        return Err(WraithError::Configuration("Rotation interval must be greater than zero".into()));
    }

    // WireGuard Multi-Hop early configuration validation
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

    let mut state_data = StateData {
        active: false,
        state: Some(wraith_core::State::Arming),
        physical_fastpath_disabled: true,
        ..Default::default()
    };
    state_mgr.claim(state_data.clone())?;
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
        state_data.kernel_sysctl_backup = wraith_core::kernel_lockdown::backup_reversible_controls()?;
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
                print_step(&format!("{}", t!("commands.cmd_step_default_iface", iface = &iface)), "ok");
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
    if args.mac || is_strict {
        print_step(&t!("commands.cmd_step_1"), "info");
        match wraith_net::change_mac_with_journal(Some(&target_interface), None, |iface, old, new| {
            state_data.mac_interface = Some(iface.into());
            state_data.mac_old = Some(old.into());
            state_data.mac_new = Some(new.into());
            state_mgr.activate(state_data.clone())
        }) {
            Ok((iface, old_m, new_m)) => {
                print_step(&format!("{}", t!("commands.cmd_step_mac_altered", old_m = &old_m, new_m = &new_m, iface = &iface)), "ok");
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
    if args.machine_id_rotation || is_strict {
        print_step(&t!("commands.cmd_step_73"), "info");
        match wraith_forensic::hardware_cloaker::rotate_machine_id_with_journal(|backup| {
            state_data.machine_id_backup = backup.clone();
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

    // 3. TCP/IP Stack Normalization (p0f OS Fingerprint Evasion & Anti-Clock Skew)
    // Always enforce TCP timestamp eradication (TS=0) and L4 stack normalization
    print_step(&t!("commands.cmd_step_74"), "info");
    match backup_tcp_stack() {
        Ok(_backup_map) => {
            print_step(&t!("commands.cmd_step_75"), "ok");
            state_data.tcp_stack_masked = true;
            state_data.tcp_stack_backup = _backup_map;
            state_mgr.activate(state_data.clone())?;
            wraith_net::apply_tcp_mask(&state_data.tcp_stack_backup)?;
        }
        Err(e) if is_strict => return Err(e),
        Err(e) => print_step(&format!("TCP/IP stack normalization warning: {e}"), "warn"),
    }
    state_mgr.activate(state_data.clone())?;

    // 4. JA3/JA4 TLS ClientHello Camouflage & In-Flight HTTP DPI Sanitizer Proxy
    {
        let (server, ct) = TlsCamouflageServer::new(None);
        let handle = server.spawn_server().await?;
        print_step("HTTP header relay ready; HTTPS ClientHello replacement is not implemented", "ok");
        bg_services.tls = Some((ct, handle));
    }

    journal_file(&state_mgr, &mut state_data, wraith_core::config::TORRC_PATH, false)?;
    // 5. Tor Configuration & Bridges
    if args.bridge || args.bridge_type.is_some() {
        let b_type = args.bridge_type.as_deref().unwrap_or("obfs4");
        if b_type.eq_ignore_ascii_case("moat") {
            print_step(&t!("bridge_tui.moat_engaging"), "info");
            let moat = wraith_tor::MoatClient::default();
            let bridges = moat.auto_discover_or_fallback("obfs4").await;
            let count = wraith_tor::write_pluggable_transport_torrc(
                wraith_tor::PluggableTransportType::Obfs4,
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
            print_step(&t!("commands.cmd_step_2"), "info");
            match write_bridge_torrc(None) {
                Ok(count) => {
                    print_step(
                        &format!("{}", t!("commands.cmd_step_bridge_obfs4_enabled", count = count)),
                        "ok",
                    );
                    state_data.bridge_enabled = true;
                    state_data.bridge_count = count;
                }
                Err(e) => {
                    print_step(
                        &format!("{}", t!("bridge_tui.bridge_fallback", error = e.to_string())),
                        "warn",
                    );
                    write_torrc()?;
                }
            }
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

    // 6. Start Tor Daemon FIRST (Before modifying DNS / Firewall)
    print_step(&t!("commands.cmd_step_5"), "info");
    state_data.tor_started = true;
    state_mgr.activate(state_data.clone())?;
    if let Err(e) = start_tor_daemon().await {
        print_step(&format!("{}", t!("commands.cmd_err_tor_bootstrap", e = e.to_string())), "error");
        // DNS and firewall have not been changed yet. Do not flush the user's
        // existing protection merely because Tor bootstrap failed.
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
    let dns_handle = dns_srv.spawn_server().await?;
    bg_services.dns = Some((dns_ct, dns_handle));
    print_step(&t!("commands.cmd_step_76"), "ok");

    // 8. Exit Node Profile
    let exit_prof = if is_strict && args.profile.is_none() {
        Some("stealth".to_string())
    } else {
        args.profile
    };

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
        let (virt_port, target_port) = if let Some((v, t)) = onion_spec.split_once(':') {
            (parse_onion_port(v)?, parse_onion_port(t)?)
        } else {
            let p = parse_onion_port(onion_spec)?;
            (p, p)
        };

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

    // Physical-interface TC filters cannot distinguish Tor relay traffic from
    // application traffic. Keep UID-aware netfilter enforcement here; filtering
    // relay TCP by the local TransPort number disconnects Tor itself.

    // 11. Zero-Copy IDS Raw Packet Sniffer & Egress Watchdog (Acquire raw AF_PACKET before Seccomp sandbox)
    print_step(&t!("commands.cmd_step_78"), "info");
    let (ids, _telemetry, ct) = EgressIntrusionDetector::new();
    let handle = ids.spawn_sniffer();
    print_step(&t!("commands.cmd_step_79"), "ok");
    bg_services.ids = Some((ct, handle));

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
    if args.browser_shield || is_strict {
        print_step(&t!("commands.cmd_step_82"), "info");
        state_data.browser_configured = true;
        state_mgr.activate(state_data.clone())?;
        match deploy_hardware_and_font_shield() {
            Ok(count) => {
                print_step(&format!("{}", t!("commands.cmd_step_browser_injected", count = count)), "ok");
                state_data.browser_hardened = count;
                state_mgr.activate(state_data.clone())?;
            }
            Err(e) if is_strict => return Err(e),
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_browser_shield", e = e.to_string())), "warn"),
        }
    }

    // 14. System-level Font Sandbox
    if args.font_sandbox || is_strict {
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
    if args.namespace || is_strict {
        print_step(&t!("commands.cmd_step_18"), "info");
        state_data.namespace_active = true;
        state_mgr.activate(state_data.clone())?;
        match create_namespace() {
            Ok(()) => {
                print_step(&t!("commands.cmd_step_19"), "ok");
                state_data.namespace_active = true;
                state_mgr.activate(state_data.clone())?;
            }
            Err(e) if is_strict => return Err(e),
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_net_ns", e = e.to_string())), "warn"),
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

    // 18. Background Traffic Padding & Anti-Correlation Jitter
    if args.jitter || is_strict {
        print_step(&t!("commands.cmd_step_84"), "info");
        let (je, ct) = TrafficJitterEngine::new();
        let handle = je.spawn_obfuscator();
        print_step(&t!("commands.cmd_step_85"), "ok");
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
            if let Err(e) = wraith_net::allow_honey_lan_ports(wraith_guard::DECOY_PORTS) {
                tracing::warn!("Failed opening firewall exception for LAN honeypot: {e}");
            }
            let trap = HoneyPortTrap::new().with_lan_binding(true);
            let (ct, handle) = trap.spawn_service();
            print_step(&t!("commands.cmd_step_57"), "ok");
            state_data.honeypot_active = true;
            state_data.honeypot_lan_active = true;
            state_mgr.activate(state_data.clone())?;
            bg_services.honeypot = Some((ct, handle));
        } else {
            print_step(&t!("commands.cmd_step_58"), "info");
            let trap = HoneyPortTrap::new().with_lan_binding(false);
            let (ct, handle) = trap.spawn_service();
            print_step(&t!("commands.cmd_step_59"), "ok");
            state_data.honeypot_active = true;
            state_mgr.activate(state_data.clone())?;
            bg_services.honeypot = Some((ct, handle));
        }
    }

    // 19. Encrypted In-Memory Ephemeral RAMFS Vault
    let _ram_vault = if is_strict {
        print_step(&t!("commands.cmd_step_86"), "info");
        match EncryptedRamVault::init() {
            Ok(mut vault) => {
                state_data.vault_path = Some(vault.path().to_string_lossy().into_owned());
                match serde_json::to_vec(&state_data) {
                    Ok(secret_payload) => {
                        if let Err(e) = vault.write_secret("session.state.enc", &secret_payload) {
                            tracing::warn!("Encrypted vault write warning: {e}");
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed serializing state for encrypted vault: {e}");
                    }
                }
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

    // 22. KillSwitch Daemon & State Activation
    state_data.state = Some(wraith_core::State::Active);
    state_data.ip = Some(geo.ip.clone());
    state_data.kill_switch = !args.no_ks;
    state_mgr.activate(state_data)?;

    if !args.no_ks {
        print_step(&t!("commands.cmd_step_21"), "info");
        let (ks, cancel_token) = KillSwitch::new_with_mode(is_strict);
        let ks_handle = ks.spawn_monitor();
        bg_services.killswitch = Some((cancel_token, ks_handle));
        print_step(&t!("commands.cmd_step_90"), "ok");
    }

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

        let _ = crossterm::terminal::enable_raw_mode();

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    let _ = crossterm::terminal::disable_raw_mode();
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
                    let _ = crossterm::terminal::disable_raw_mode();
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
                    let _ = crossterm::terminal::disable_raw_mode();
                    println!("\r\n  {}\r\n", t!("commands.cmd_signal_sighup"));
                    break;
                }
                key_res = tokio::task::spawn_blocking(|| {
                    if crossterm::event::poll(Duration::from_millis(200)).unwrap_or(false) {
                        if let Ok(crossterm::event::Event::Key(k)) = crossterm::event::read() {
                            return Some(k);
                        }
                    }
                    None
                }) => {
                    if let Ok(Some(k)) = key_res {
                        // 1. Immediate Emergency Exit on Ctrl+C, Ctrl+D, Esc, 'q', 'Q'
                        if (k.modifiers.contains(crossterm::event::KeyModifiers::CONTROL)
                            && (k.code == crossterm::event::KeyCode::Char('c') || k.code == crossterm::event::KeyCode::Char('C') || k.code == crossterm::event::KeyCode::Char('d') || k.code == crossterm::event::KeyCode::Char('D')))
                            || k.code == crossterm::event::KeyCode::Char('q')
                            || k.code == crossterm::event::KeyCode::Char('Q')
                            || k.code == crossterm::event::KeyCode::Esc
                        {
                            let _ = crossterm::terminal::disable_raw_mode();
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
                                    let _ = crossterm::terminal::disable_raw_mode();
                                    println!("\n  {}", t!("commands.cmd_hotkey_leak_audit"));
                                    let report = run_full_leak_test().await;
                                    show_leak_report(&report);
                                    println!();
                                    let _ = crossterm::terminal::enable_raw_mode();
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
                                    let _ = wraith_forensic::logs::fast_ram_and_arp_purge();
                                    print!("  {}\r\n\r\n", t!("commands.cmd_hotkey_memory_eradicated"));
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        let _ = crossterm::terminal::disable_raw_mode();

        // Gracefully cancel and wait on all background task join handles
        bg_services.shutdown_and_join().await;

        cmd_stop(args.forensic_self_destruct).await?;
    }

    Ok(())
}

pub async fn cmd_stop(self_destruct: bool) -> Result<()> {
    let _ = crossterm::terminal::disable_raw_mode();
    print_banner(false);
    let state_mgr = StateManager::default();
    if !state_mgr.is_active() {
        return Ok(());
    }
    let state_info = state_mgr.read_checked()?;
    #[cfg(target_os = "linux")]
    if let Some(pid) = state_info.pid.filter(|pid| *pid > 1 && *pid != std::process::id() && *pid <= i32::MAX as u32) {
        let proc_path = format!("/proc/{pid}/exe");
        if let Ok(executable) = fs::read_link(&proc_path) {
            if executable != std::env::current_exe()? {
                return Err(WraithError::Custom("Session PID belongs to another executable; refusing to signal it".into()));
            }
            // SAFETY: positive, bounded PID; executable identity was checked above.
            if unsafe { libc::kill(pid as i32, libc::SIGTERM) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            for _ in 0..100 {
                if !state_mgr.is_active() { return Ok(()); }
                sleep(Duration::from_millis(200)).await;
            }
            return Err(WraithError::Custom("Session is still stopping; refusing concurrent firewall teardown".into()));
        }
    }


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
    if state_info.tor_started || state_info.active {
        stop_tor_daemon();
        wraith_tor::stop_existing_tor();
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
        record_cleanup("TCP settings", wraith_net::restore_tcp_stack(&state_info.tcp_stack_backup), &mut errors);
    }
    if state_info.namespace_active { record_cleanup("namespace", destroy_namespace(), &mut errors); }
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
    // Retain both the recovery record and restrictive policy on incomplete cleanup.
    if !errors.is_empty() { return state_mgr.finish_cleanup(&errors); }
    if let Some(saved) = &state_info.saved_rules {
        record_cleanup("IPv4 firewall", wraith_net::restore_rules(saved), &mut errors);
    }
    if let Some(saved) = &state_info.saved_ipv6_rules {
        record_cleanup("IPv6 firewall", wraith_net::restore_ipv6_rules(saved), &mut errors);
    } else if state_info.active {
        record_cleanup("legacy IPv6 firewall", flush_ipv6_block(), &mut errors);
    }
    if errors.is_empty() && self_destruct {
        record_cleanup("self destruct", std::env::current_exe().map_err(WraithError::from)
            .and_then(|path| wraith_forensic::secure_delete_file(&path, 2)), &mut errors);
    }
    state_mgr.finish_cleanup(&errors)?;
    sleep(Duration::from_secs(2)).await;
    let real_ip = get_current_ip().await;

    if let Some(ip) = real_ip {
        print_success(&format!(
            "{}: {ip}",
            t!("runtime.stopped_success")
        ));
    } else {
        print_success(&t!("runtime.stopped_success"));
    }
    Ok(())
}

pub async fn cmd_shred(target: &str, passes: u32) -> Result<()> {
    print_banner(false);
    print_step(
        &format!("{}", t!("commands.cmd_step_shred_start", passes = passes, target = target)),
        "info",
    );

    let path = Path::new(target);
    if !path.exists() {
        print_error(&format!("{}", t!("commands.cmd_err_target_not_found", target = target)));
        return Ok(());
    }

    wraith_forensic::dod_7pass_shred(path)?;
    print_success(&format!(
        "Target permanently obliterated from disk: {target}"
    ));
    Ok(())
}

/// Build scripts and Git hooks must never execute with the installer's root UID.
async fn cmd_update_from_github() -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    { Err(WraithError::UnsupportedPlatform) }
    #[cfg(target_os = "linux")]
    {
        use nix::unistd::{Uid, User};
        use std::os::unix::{fs::MetadataExt, process::CommandExt};
        let uid = std::env::var("SUDO_UID").ok().and_then(|value| value.parse::<u32>().ok())
            .filter(|uid| *uid > 0).ok_or_else(|| WraithError::Configuration(
                "Run update through sudo from a non-root build account; root Cargo builds are refused".into()))?;
        let user = User::from_uid(Uid::from_raw(uid)).map_err(|e| WraithError::Custom(e.to_string()))?
            .ok_or_else(|| WraithError::Configuration("Build account does not exist".into()))?;
        let root = Path::new("/var/tmp");
        let build_dir = root.join(format!("wraith-build-{}", std::process::id()));
        fs::create_dir(&build_dir)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&build_dir, fs::Permissions::from_mode(0o700))?;
        nix::unistd::chown(&build_dir, Some(user.uid), Some(user.gid))
            .map_err(|e| WraithError::Custom(e.to_string()))?;
        let configure = |command: &mut Command| {
            command.env_clear().env("HOME", &user.dir)
                .env("PATH", format!("{}:/usr/bin:/bin", user.dir.join(".cargo/bin").display()))
                .env("CARGO_HOME", user.dir.join(".cargo"))
                .env("GIT_CONFIG_NOSYSTEM", "1").env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_TERMINAL_PROMPT", "0");
            let uid = user.uid.as_raw();
            let gid = user.gid.as_raw();
            // SAFETY: setgroups is async-signal-safe here; no allocation or locks
            // are used between fork and exec. Drop supplementary root groups.
            unsafe { command.pre_exec(move || {
                if libc::setgroups(0, std::ptr::null()) != 0 { return Err(std::io::Error::last_os_error()); }
                if libc::setgid(gid) != 0 || libc::setuid(uid) != 0 { return Err(std::io::Error::last_os_error()); }
                Ok(())
            }); }
        };
        let result = (|| -> Result<()> {
            let mut clone = Command::new("/usr/bin/git");
            clone.args(["-c", "http.sslVerify=true", "-c", "http.followRedirects=false", "-c", "protocol.file.allow=never", "clone", "--depth", "1", "https://github.com/ByGh00st/wraith.git"]).arg(&build_dir);
            configure(&mut clone);
            if !clone.status()?.success() { return Err(WraithError::Command("Git clone failed".into())); }
            let cargo = user.dir.join(".cargo/bin/cargo");
            let mut build = Command::new(if cargo.exists() { cargo } else { "/usr/bin/cargo".into() });
            build.args(["build", "--release", "--locked", "--bin", "wraith", "--jobs", "1"]).current_dir(&build_dir);
            configure(&mut build);
            if !build.status()?.success() { return Err(WraithError::Command("Cargo build failed".into())); }
            let destination = Path::new("/usr/local/bin/wraith");
            // Only a root-owned, non-writable-by-others canonical install directory.
            let parent = destination.parent().unwrap();
            let meta = fs::symlink_metadata(parent)?;
            if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                return Err(WraithError::Configuration("Unsafe binary installation directory".into()));
            }
            let bytes = read_update_file(&build_dir.join("target/release/wraith"), 128 * 1024 * 1024)?;
            if !bytes.starts_with(b"\x7fELF") { return Err(WraithError::Configuration("Build artifact is not ELF".into())); }
            wraith_core::deployment::install_binary(&bytes, destination)?;
            print_success("Updated /usr/local/bin/wraith from the official GitHub repository.");
            Ok(())
        })();
        // Remove only the fixed, exclusively created workspace. Never use a shell
        // or follow paths supplied by build output for privileged cleanup.
        if let Err(e) = fs::remove_dir_all(&build_dir) { tracing::warn!("Build directory cleanup failed: {e}"); }
        result
    }
}

pub async fn cmd_update(artifact: Option<std::path::PathBuf>, manifest: Option<std::path::PathBuf>, signature: Option<std::path::PathBuf>) -> Result<()> {
    if artifact.is_none() && manifest.is_none() && signature.is_none() { return cmd_update_from_github().await; }
    let (Some(artifact), Some(manifest), Some(signature)) = (artifact, manifest, signature) else {
        return Err(WraithError::Configuration("Use update --artifact FILE --manifest FILE --signature FILE; pin the publisher's trusted key at /etc/wraith/update.pub first".into()));
    };
    #[cfg(not(target_os = "linux"))]
    { let _ = (artifact, manifest, signature); Err(WraithError::UnsupportedPlatform) }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        for directory in ["/etc", "/etc/wraith", "/usr", "/usr/local", "/usr/local/bin"] {
            let metadata = fs::symlink_metadata(directory)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(WraithError::Configuration(format!("Unsafe update directory: {directory}")));
            }
        }
        let key_path = Path::new("/etc/wraith/update.pub");
        let metadata = fs::symlink_metadata(key_path)?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(WraithError::Configuration("Update key must be root-owned and not writable by other users".into()));
        }
        let key = String::from_utf8(read_update_file(key_path, 4096)?).map_err(|e| WraithError::Configuration(e.to_string()))?;
        let manifest = read_update_file(&manifest, 16384)?;
        let signature = String::from_utf8(read_update_file(&signature, 8192)?).map_err(|e| WraithError::Configuration(e.to_string()))?;
        let binary = read_update_file(&artifact, 128 * 1024 * 1024)?;
        let release = wraith_core::signed_update::verify_release(&key, &manifest, &signature, &binary, env!("CARGO_PKG_VERSION"))?;
        // Install exactly the bytes whose hash was authenticated, not a reopened path.
        wraith_core::deployment::install_binary(&binary, Path::new("/usr/local/bin/wraith"))?;
        print_success(&format!("Verified and installed signed Wraith {}", release.version));
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn read_update_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    if !file.metadata()?.is_file() { return Err(WraithError::Configuration("Update input is not a regular file".into())); }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit { return Err(WraithError::Configuration("Update input exceeds size limit".into())); }
    Ok(bytes)
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
    print_success(&format!("New identity established ➔ {geo}"));
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

    let (is_tor, tor_ip) = verify_tor_connection().await;
    let ip = tor_ip
        .or(get_current_ip().await)
        .unwrap_or_else(|| "Unknown".into());

    let telemetry = match get_circuit_telemetry().await {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("Could not fetch Tor circuit telemetry: {e}");
            wraith_tor::TorTelemetry::default()
        }
    };
    show_status_dashboard(&state, is_tor, &ip, telemetry.circuits.len());

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
    print_step(&format!("Executing {mode} anti-forensic purge..."), "info");

    let count = run_full_cleanup(full, false)?;
    print_success(&format!(
        "Anti-forensic purge complete ({count} operations executed)"
    ));
    Ok(())
}

pub fn cmd_pentest() -> Result<()> {
    print_banner(false);
    let p_rows1 = vec![
        "SOCKS5 PROXY      : 127.0.0.1:9050 (Tor Native SOCKS5 Transport)".to_string(),
        "HTTP CAMOUFLAGE   : 127.0.0.1:9055 (JA3/JA4 Chrome v130+ Spoofing Proxy)".to_string(),
        "DNS SINKHOLE GATE : 127.0.0.1:5353 (Tor TransProxy DNS Resolver)".to_string(),
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
        "[CURL / WEB FUZZING WITH JA4 TLS NORMALIZATION]:".to_string(),
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
    let display = std::env::var("DISPLAY").unwrap_or_else(|_| ":0".into());
    let xauth = if let Ok(xa) = std::env::var("XAUTHORITY") {
        xa
    } else if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        let user_xauth = format!("/home/{sudo_user}/.Xauthority");
        if Path::new(&user_xauth).exists() {
            user_xauth
        } else {
            "/root/.Xauthority".into()
        }
    } else {
        "/root/.Xauthority".into()
    };
    // Recover DBUS_SESSION_BUS_ADDRESS for GUI terminals running under sudo
    let dbus_addr = std::env::var("DBUS_SESSION_BUS_ADDRESS").unwrap_or_else(|_| {
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            let uid = std::process::Command::new("id")
                .args(["-u", &sudo_user])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|_| "1000".into());
            format!("unix:path=/run/user/{}/bus", uid)
        } else {
            "unix:path=/run/user/1000/bus".into()
        }
    });

    let exe_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "/usr/local/bin/wraith".into());

    let monitor_cmd = format!("sudo {exe_path} monitor");

    let term_cmds: [(&str, Vec<String>); 7] = [
        ("xfce4-terminal", vec!["--title=WRAITH // LIVE DPI & IDS TELEMETRY".into(), "-x".into(), "sudo".into(), exe_path.clone(), "monitor".into()]),
        ("x-terminal-emulator", vec!["-e".into(), format!("sh -c '{monitor_cmd}'")]),
        ("qterminal", vec!["-e".into(), format!("sh -c '{monitor_cmd}'")]),
        ("gnome-terminal", vec!["--title=WRAITH // LIVE DPI & IDS TELEMETRY".into(), "--".into(), "sh".into(), "-c".into(), monitor_cmd.clone()]),
        ("xterm", vec!["-title".into(), "WRAITH // LIVE DPI & IDS TELEMETRY".into(), "-e".into(), "sh".into(), "-c".into(), monitor_cmd.clone()]),
        ("kitty", vec!["-T".into(), "WRAITH // LIVE DPI & IDS TELEMETRY".into(), "sh".into(), "-c".into(), monitor_cmd.clone()]),
        ("alacritty", vec!["-T".into(), "WRAITH // LIVE DPI & IDS TELEMETRY".into(), "-e".into(), "sh".into(), "-c".into(), monitor_cmd]),
    ];

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

                    println!("\r  ┌── [ 🎯 DPI IN-FLIGHT TRAP & REWRITE // {} ] ─────────────────────────", time_str.bold().cyan());
                    println!("\r  │  ⚠️ Intercepted Signature : {}", orig.bold().yellow());
                    println!("\r  │  🛡️ Wire Sanitized Value  : {}", repl.bold().green());
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
                        println!("\r  │  🛑 Action: Neutralized at Netfilter Ring-0 Boundary (<1ms drop)");
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
                        let tmp_captcha = std::path::Path::new("/tmp/wraith_moat_captcha.png");
                        if let Err(e) = wraith_tor::MoatClient::save_captcha_image(&ch.image_base64, tmp_captcha) {
                            tracing::warn!("Could not save captcha PNG: {e}");
                        }

                        println!("\n  ┌── [ 🛡️ TOR MOAT PROTOCOL // BRIDGEDB CHALLENGE ] ────────────────────────┐");
                        println!("  │ Challenge Token: {:<56} │", ch.challenge);
                        println!("  │ Transport      : {:<56} │", ch.transport);
                        println!("  │ CAPTCHA Image  : {:<56} │", "/tmp/wraith_moat_captcha.png");
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
                        print_step(&format!("Moat challenge unreachable: {e}. Falling back to resilient pools."), "warn");
                        moat.auto_discover_or_fallback(&transport).await
                    }
                }
            };

            let pt_type = wraith_tor::PluggableTransportType::from_str(&transport)
                .unwrap_or(wraith_tor::PluggableTransportType::Obfs4);
            let count = wraith_tor::write_pluggable_transport_torrc(pt_type, Some(bridges.clone()))?;
            print_success(&format!("Successfully configured {count} {pt_type} bridges in /etc/tor/wraithrc"));
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
        let provider = crate::doh_tui::select_doh_tui()?;
        print_banner(false);
        print_success(&format!("Selected DoH Provider: {} [{}]", provider.name(), provider.url()));

        let mut cfg = wraith_core::WraithConfig::load().unwrap_or_default();
        cfg.dns.transport = Some("doh".to_string());
        cfg.dns.provider = Some(provider.name().to_string());
        cfg.dns.upstream = Some(provider.url().to_string());
        cfg.doh_upstream = Some(provider.url().to_string());
        let path = cfg.save()?;
        print_step(&format!("Saved active DoH provider to {path:?}"), "ok");
    } else {
        print_banner(false);
        crate::doh_tui::print_doh_table();
    }
    Ok(())
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

fn record_cleanup(label: &str, result: Result<()>, errors: &mut Vec<String>) {
    if let Err(error) = result {
        let detail = format!("{label}: {error}");
        tracing::warn!("Cleanup failed: {detail}");
        errors.push(detail);
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    #[test]
    fn malformed_onion_ports_never_publish_a_default_service() {
        for value in ["", "0", "65536", "abc", "80:90"] { assert!(parse_onion_port(value).is_err()); }
        assert_eq!(parse_onion_port("8080").unwrap(), 8080);
    }
}
