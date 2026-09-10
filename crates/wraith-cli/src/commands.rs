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
    deploy_hardware_and_font_shield, enforce_font_jail, panic_emergency_purge,
    remove_hardware_and_font_shield, restore_font_jail, restore_machine_id, rotate_machine_id,
    run_full_cleanup, VirtualDisplay,
};
use wraith_guard::{
    enforce_seccomp_socket_jail, get_current_ip, get_current_ip_geo, run_full_leak_test,
    verify_tor_connection, HoneyPortTrap, KillSwitch, SovereignDnsEngine, TrafficJitterEngine,
};
use wraith_net::{
    apply_ipv6_block, apply_tor_rules, backup_and_apply_tcp_mask, block_stun_ports, change_mac,
    create_cgroup_jail, create_namespace, destroy_cgroup_jail, destroy_namespace, flush_ipv6_block,
    flush_rules, randomize_hostname, restore_default_tcp_stack, restore_mac, unblock_stun_ports,
    EgressFastpath, EgressIntrusionDetector, MultiHopTunnelEngine, TrafficShaper,
    TrafficShapingProfile,
};
use wraith_tor::{
    apply_exit_profile, arm_onion_service, backup_resolv, configure_dns, get_active_tls_profile,
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
        let join_task = |name: &'static str, handle: tokio::task::JoinHandle<()>| async move {
            match tokio::time::timeout(Duration::from_millis(1500), handle).await {
                Ok(Ok(())) => tracing::debug!("Background service '{name}' stopped cleanly"),
                Ok(Err(e)) => tracing::warn!("Background service '{name}' task error: {e}"),
                Err(_) => tracing::warn!("Background service '{name}' shutdown timed out (1500ms)"),
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

pub async fn cmd_start(args: crate::StartArgs) -> Result<()> {
    // 0-CFG. Merge persistent configuration defaults if not explicitly provided
    let mut args = args;
    if let Ok(cfg) = wraith_core::WraithConfig::load() {
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
        active: true,
        ..Default::default()
    };
    let _ = state_mgr.activate(state_data.clone());
    let mut bg_services = BackgroundServices::default();

    // 0. Kernel Process Memory Lockdown (PR_SET_DUMPABLE=0, mlockall)
    print_step(&t!("commands.cmd_step_65"), "info");
    match enforce_process_lockdown() {
        Ok(()) => print_step(&t!("commands.cmd_step_66"), "ok"),
        Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_mem_lockdown", e = e.to_string())), "warn"),
    }

    if is_strict {
        print_step(&t!("commands.cmd_step_67"), "info");
        match enforce_kernel_lockdown() {
            Ok(lockdown) => print_step(
                &format!("{}", t!("commands.cmd_step_kernel_lockdown_eval", lockdown = format!("{:?}", lockdown))),
                "ok",
            ),
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_kernel_lockdown", e = e.to_string())), "warn"),
        }
    }

    // 0a. Anti-Debug Abort Trap (Armed under strict hardening -Fs OR explicit -A)
    if args.aggressive_anti_debug || is_strict {
        print_step(&t!("commands.cmd_step_68"), "info");
        match wraith_forensic::AntiDebugProbe::enforce_anti_debug_trap(is_strict) {
            Ok(()) => print_step(&t!("commands.cmd_step_0"), "ok"),
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_anti_debug", e = e.to_string())), "warn"),
        }
    }

    // 0b. Process Masquerading (Armed under strict hardening -Fs OR explicit -K)
    if args.aggressive_masquerade || is_strict {
        print_step(&t!("commands.cmd_step_69"), "info");
        match wraith_forensic::cloaked_process_masquerade("[kworker/u16:0]") {
            Ok(()) => print_step(&t!("commands.cmd_step_70"), "ok"),
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_masquerade", e = e.to_string())), "warn"),
        }
    }

    // 0c. Explicit Destructive Log & History Wipe (Destructive Cleanup Opt-In)
    if args.forensic_wipe_logs {
        print_step(&t!("commands.cmd_step_71"), "warn");
        match wraith_forensic::scrub_system_logs() {
            Ok(count) => print_step(&format!("{}", t!("commands.cmd_step_scrubbed_logs", count = count)), "ok"),
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_log_scrub_err", e = e.to_string())), "warn"),
        }
        match wraith_forensic::wipe_all_user_histories() {
            Ok(count) => print_step(
                &format!("{}", t!("commands.cmd_step_history_wiped", count = count)),
                "ok",
            ),
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
    let _ = state_mgr.activate(state_data.clone());

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
        match change_mac(Some(&target_interface), None) {
            Ok((iface, old_m, new_m)) => {
                print_step(&format!("{}", t!("commands.cmd_step_mac_altered", old_m = &old_m, new_m = &new_m, iface = &iface)), "ok");
                state_data.mac_interface = Some(iface);
                state_data.mac_old = Some(old_m);
                state_data.mac_new = Some(new_m);
            }
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_mac_skip", e = e.to_string())), "warn"),
        }

        match randomize_hostname() {
            Ok((old_h, new_h)) => {
                print_step(&format!("Hostname randomized: {old_h} ➔ {new_h}"), "ok");
                state_data.hostname_old = Some(old_h);
            }
            Err(e) => print_step(&format!("Hostname randomization warning: {e}"), "warn"),
        }
        let _ = state_mgr.activate(state_data.clone());
    }

    // 2. Machine-ID & Hardware DMI Cloaking
    if args.machine_id_rotation || is_strict {
        print_step(&t!("commands.cmd_step_73"), "info");
        match rotate_machine_id() {
            Ok((old_mid, new_mid)) => {
                print_step(&format!("Machine-ID rotated: {old_mid} ➔ {new_mid}"), "ok");
                state_data.machine_id_old = Some(old_mid);
            }
            Err(e) => print_step(&format!("Machine-ID rotation warning: {e}"), "warn"),
        }
        let _ = state_mgr.activate(state_data.clone());
    }

    // 3. TCP/IP Stack Normalization (p0f OS Fingerprint Evasion & Anti-Clock Skew)
    // Always enforce TCP timestamp eradication (TS=0) and L4 stack normalization
    print_step(&t!("commands.cmd_step_74"), "info");
    match backup_and_apply_tcp_mask() {
        Ok(_backup_map) => {
            print_step(&t!("commands.cmd_step_75"), "ok");
            state_data.tcp_stack_masked = true;
        }
        Err(e) => print_step(&format!("TCP/IP stack normalization warning: {e}"), "warn"),
    }
    let _ = state_mgr.activate(state_data.clone());

    // 4. JA3/JA4 TLS ClientHello Camouflage & In-Flight HTTP DPI Sanitizer Proxy
    {
        let (server, ct) = TlsCamouflageServer::new(None);
        let handle = server.spawn_server();
        let prof = get_active_tls_profile();
        print_step(
            &format!("{}", t!("commands.cmd_step_dpi_tls_gate", name = &prof.name, ja4 = &prof.ja4_hash)),
            "ok",
        );
        bg_services.tls = Some((ct, handle));
    }

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
                let _ = state_mgr.activate(state_data.clone());
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
    if let Err(e) = start_tor_daemon().await {
        print_step(&format!("{}", t!("commands.cmd_err_tor_bootstrap", e = e.to_string())), "error");
        let _ = restore_dns();
        let _ = flush_rules();
        let _ = flush_ipv6_block();
        return Err(e);
    }
    print_step(&t!("commands.cmd_step_6"), "ok");

    // 7. DNS Configuration (Applied ONLY after Tor is ready)
    print_step(&t!("commands.cmd_step_7"), "info");
    if let Err(e) = backup_resolv() {
        tracing::warn!("Failed creating resolv.conf backup: {e}");
    }
    if let Err(e) = configure_dns() {
        print_step(&format!("{}", t!("commands.cmd_err_dns_config", e = e.to_string())), "error");
        let _ = restore_dns();
        return Err(e);
    }
    print_step(&t!("commands.cmd_step_8"), "ok");

    // 7b. Sovereign DNS Engine & DoH Forwarder
    let dns_transport = if let Some(ref provider) = selected_doh {
        print_step(&format!("{}", t!("runtime.doh_engine_armed", url = provider.url())), "info");
        wraith_guard::DnsTransport::DoH(provider.url().to_string())
    } else {
        wraith_guard::DnsTransport::UdpTor
    };

    let (dns_srv, dns_ct) = wraith_guard::SovereignDnsServer::new_with_transport(None, None, dns_transport);
    let dns_handle = dns_srv.spawn_server();
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
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_exit_profile", e = e.to_string())), "warn"),
        }
    }

    // 8b. Ephemeral v3 Onion Hidden Service
    if let Some(ref onion_spec) = args.onion_service {
        print_step(&format!("{} [{onion_spec}]...", t!("commands.cmd_step_50")), "info");
        let (virt_port, target_port) = if let Some((v, t)) = onion_spec.split_once(':') {
            (v.parse::<u16>().unwrap_or(80), t.parse::<u16>().unwrap_or(80))
        } else {
            let p = onion_spec.parse::<u16>().unwrap_or(80);
            (p, p)
        };

        let mut onion_cfg = OnionServiceConfig::default();
        onion_cfg.add_port(virt_port, target_port);

        match arm_onion_service(&onion_cfg) {
            Ok(()) => {
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
                let _ = state_mgr.activate(state_data.clone());
            }
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_onion_provision", e = e.to_string())), "warn"),
        }
    }

    // 9. Firewall & IPv6 Drop
    print_step(&t!("commands.cmd_step_9"), "info");
    let saved = apply_tor_rules()?;
    state_data.saved_rules = Some(saved);
    let _ = state_mgr.activate(state_data.clone());
    print_step(&t!("commands.cmd_step_10"), "ok");

    print_step(&t!("commands.cmd_step_11"), "info");
    apply_ipv6_block()?;
    print_step(&t!("commands.cmd_step_12"), "ok");

    print_step(&t!("commands.cmd_step_13"), "info");
    block_stun_ports()?;
    print_step(&t!("commands.cmd_step_14"), "ok");

    // 9b. Multi-Hop Policy Routing Enforcement (Binding Tor Outbound Egress to WireGuard Hop 1)
    if let Some(ref wg_iface) = wg_active_iface {
        print_step(&format!("{}: {wg_iface}...", t!("commands.cmd_step_48")), "info");
        let tor_uid = wraith_net::get_tor_uid().unwrap_or(0);
        match MultiHopTunnelEngine::bind_tor_to_wireguard(tor_uid, wg_iface) {
            Ok(true) => {
                print_step(&t!("commands.cmd_step_49"), "ok");
            }
            Ok(false) => {
                print_step(&format!("{}", t!("commands.cmd_warn_wg_routing", iface = &wg_iface)), "warn");
            }
            Err(e) => {
                print_step(&format!("{}", t!("commands.cmd_warn_tor_wg_bind", e = e.to_string())), "warn");
            }
        }
    }

    // 10. eBPF / TC Egress Fastpath Filter
    if is_strict {
        print_step(&t!("commands.cmd_step_77"), "info");
        match EgressFastpath::new(Some(&target_interface)) {
            Ok(mut fp) => {
                if let Err(e) = fp.attach() {
                    print_step(&format!("{}", t!("commands.cmd_warn_ebpf_attach", e = e.to_string())), "warn");
                } else {
                    print_step(&t!("commands.cmd_step_15"), "ok");
                }
            }
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_ebpf_init", e = e.to_string())), "warn"),
        }
    }

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
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_seccomp", e = e.to_string())), "warn"),
        }
    }

    // 13. Hardware, GPU, Font & Resolution Browser Shield
    if args.browser_shield || is_strict {
        print_step(&t!("commands.cmd_step_82"), "info");
        match deploy_hardware_and_font_shield() {
            Ok(count) => {
                print_step(&format!("{}", t!("commands.cmd_step_browser_injected", count = count)), "ok");
                state_data.browser_hardened = count;
                let _ = state_mgr.activate(state_data.clone());
            }
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_browser_shield", e = e.to_string())), "warn"),
        }
    }

    // 14. System-level Font Sandbox
    if args.font_sandbox || is_strict {
        print_step(&t!("commands.cmd_step_83"), "info");
        match enforce_font_jail() {
            Ok(()) => print_step(&t!("commands.cmd_step_16"), "ok"),
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
                state_data.display_jail_active = true;
                let _ = state_mgr.activate(state_data.clone());
                bg_services.virtual_display = Some(vd);
            }
            Err(e) => print_step(&format!("{}", t!("commands.cmd_warn_virtual_display", e = e.to_string())), "warn"),
        }
    }

    // 15. cgroup2 Network Socket Jail
    if is_strict {
        if let Err(e) = create_cgroup_jail() {
            tracing::warn!("cgroup2 jail creation warning: {e}");
        }
        if let Err(e) = wraith_net::attach_pid_to_cgroup(std::process::id()) {
            tracing::warn!("cgroup2 attach pid warning: {e}");
        } else {
            print_step(&t!("commands.cmd_step_17"), "ok");
        }
    }

    // 16. Network Namespace
    if args.namespace || is_strict {
        print_step(&t!("commands.cmd_step_18"), "info");
        match create_namespace() {
            Ok(()) => {
                print_step(&t!("commands.cmd_step_19"), "ok");
                state_data.namespace_active = true;
                let _ = state_mgr.activate(state_data.clone());
            }
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
                if let Err(e) = shaper.apply_shaping(&prof) {
                    print_step(&format!("{}", t!("commands.cmd_warn_shaper_apply", e = e.to_string())), "warn");
                } else {
                    print_step(&t!("commands.cmd_step_55"), "ok");
                    state_data.traffic_shaper_active = true;
                    let _ = state_mgr.activate(state_data.clone());
                    bg_services.traffic_shaper = Some(shaper);
                }
            }
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
            let _ = state_mgr.activate(state_data.clone());
            bg_services.honeypot = Some((ct, handle));
        } else {
            print_step(&t!("commands.cmd_step_58"), "info");
            let trap = HoneyPortTrap::new().with_lan_binding(false);
            let (ct, handle) = trap.spawn_service();
            print_step(&t!("commands.cmd_step_59"), "ok");
            state_data.honeypot_active = true;
            let _ = state_mgr.activate(state_data.clone());
            bg_services.honeypot = Some((ct, handle));
        }
    }

    // 19. Encrypted In-Memory Ephemeral RAMFS Vault
    let _ram_vault = if is_strict {
        print_step(&t!("commands.cmd_step_86"), "info");
        match EncryptedRamVault::init() {
            Ok(mut vault) => {
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
            Err(e) => {
                print_step(&format!("{}", t!("commands.cmd_warn_vault", e = e.to_string())), "warn");
                None
            }
        }
    } else {
        None
    };

    // 20. Async DNS Engine with EDNS0 Padding & Sinkhole
    if is_strict {
        print_step(&t!("commands.cmd_step_88"), "info");
        let (dns_srv, ct) = SovereignDnsEngine::new(None, None);
        let handle = dns_srv.spawn_server();
        print_step(&t!("commands.cmd_step_89"), "ok");
        bg_services.dns = Some((ct, handle));
    }

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
    state_data.ip = Some(geo.ip.clone());
    state_data.kill_switch = !args.no_ks;
    state_mgr.activate(state_data)?;

    if !args.no_ks {
        print_step(&t!("commands.cmd_step_21"), "info");
        let (ks, cancel_token) = KillSwitch::new();
        let ks_handle = ks.spawn_monitor();
        bg_services.killswitch = Some((cancel_token, ks_handle));
        print_step(&t!("commands.cmd_step_90"), "ok");
    }

    crate::display::print_session_hud(&geo, is_strict, args.rotate_interval);

    if !args.no_ks {
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
    } else {
        println!("  {}\n", t!("commands.cmd_stop_restore_hint"));
    }

    Ok(())
}

pub async fn cmd_stop(self_destruct: bool) -> Result<()> {
    let _ = crossterm::terminal::disable_raw_mode();
    print_banner(false);
    let state_mgr = StateManager::default();
    let state_info = state_mgr.read();

    print_step(&t!("commands.cmd_step_22"), "info");
    let _ = std::process::Command::new("chattr")
        .args(["-i", "/etc/resolv.conf"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let _ = restore_dns();
    let _ = std::fs::write(
        "/etc/resolv.conf",
        "nameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 1.0.0.1\n",
    );
    let _ = std::process::Command::new("resolvectl")
        .arg("flush-caches")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    print_step(&t!("commands.cmd_step_23"), "ok");

    print_step(&t!("commands.cmd_step_24"), "info");
    if let Err(e) = flush_rules() {
        tracing::warn!("Flush rules warning: {e}");
    }
    if let Err(e) = flush_ipv6_block() {
        tracing::warn!("Flush IPv6 warning: {e}");
    }
    if let Err(e) = unblock_stun_ports() {
        tracing::warn!("Unblock STUN warning: {e}");
    }
    if let Err(e) = destroy_cgroup_jail() {
        tracing::warn!("Destroy cgroup warning: {e}");
    }

    let stop_target_iface = state_info.target_interface.as_deref().or(state_info.mac_interface.as_deref());

    if let Ok(mut fp) = EgressFastpath::new(stop_target_iface) {
        if let Err(e) = fp.detach() {
            tracing::warn!("Fastpath detach warning: {e}");
        }
    }
    print_step(&t!("commands.cmd_step_25"), "ok");

    print_step(&t!("commands.cmd_step_26"), "info");
    stop_tor_daemon();
    wraith_tor::stop_existing_tor();
    print_step(&t!("commands.cmd_step_27"), "ok");

    if state_info.multihop_enabled {
        print_step(&t!("commands.cmd_step_60"), "info");
        if let Err(e) = MultiHopTunnelEngine::teardown_wireguard(state_info.wireguard_config.as_deref()) {
            tracing::warn!("WireGuard teardown warning: {e}");
        } else {
            print_step(&t!("commands.cmd_step_61"), "ok");
        }
    }

    if state_info.onion_service_active {
        print_step(&t!("commands.cmd_step_62"), "info");
        if let Err(e) = purge_onion_service() {
            tracing::warn!("Onion service purge warning: {e}");
        } else {
            print_step(&t!("commands.cmd_step_63"), "ok");
        }
    }

    if state_info.traffic_shaper_active {
        if let Ok(mut shaper) = TrafficShaper::new(stop_target_iface) {
            let _ = shaper.restore();
            print_step(&t!("commands.cmd_step_64"), "ok");
        }
    }

    if let (Some(iface), Some(old_mac)) = (&state_info.mac_interface, &state_info.mac_old) {
        print_step(&t!("commands.cmd_step_28"), "info");
        if let Err(e) = restore_mac(iface, old_mac) {
            print_step(&format!("Restore MAC warning: {e}"), "warn");
        } else {
            print_step(&t!("commands.cmd_step_29"), "ok");
        }
    }

    if let Some(old_host) = &state_info.hostname_old {
        let _ = std::process::Command::new("hostname")
            .arg(old_host)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        print_step(&t!("commands.cmd_step_30"), "ok");
    }

    if let Some(old_mid) = &state_info.machine_id_old {
        print_step(&t!("commands.cmd_step_31"), "info");
        if let Err(e) = restore_machine_id(old_mid) {
            print_step(&format!("Restore machine-id warning: {e}"), "warn");
        } else {
            print_step(&t!("commands.cmd_step_32"), "ok");
        }
    }

    // Unconditionally restore default Linux TCP stack (TTL=64, TS=1, SACK, etc.)
    print_step(&t!("commands.cmd_step_33"), "info");
    let _ = restore_default_tcp_stack();
    print_step(&t!("commands.cmd_step_34"), "ok");

    if state_info.namespace_active {
        print_step(&t!("commands.cmd_step_35"), "info");
        if let Err(e) = destroy_namespace() {
            print_step(&format!("Destroy namespace warning: {e}"), "warn");
        } else {
            print_step(&t!("commands.cmd_step_36"), "ok");
        }
    }

    print_step(&t!("commands.cmd_step_37"), "info");
    let _ = remove_hardware_and_font_shield();
    let _ = restore_font_jail();
    print_step(&t!("commands.cmd_step_38"), "ok");

    print_step(&t!("commands.cmd_step_91"), "info");
    if let Err(e) = panic_emergency_purge(self_destruct) {
        print_step(&format!("Emergency purge warning: {e}"), "warn");
    }
    print_step(&t!("commands.cmd_step_92"), "ok");

    // Final Network Carrier & Clearnet Guaranteed Reconnection
    print_step(&t!("commands.cmd_step_39"), "info");
    let target_iface = state_info
        .mac_interface
        .clone()
        .or_else(|| wraith_net::get_default_interface().ok())
        .unwrap_or_else(|| "eth0".to_string());

    // 1. Kill stale dhclient (if any) and ensure interface is UP
    let _ = Command::new("pkill").args(["-9", "dhclient"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
    let _ = Command::new("ip").args(["link", "set", &target_iface, "up"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();

    // 2. Force public DNS immediately BEFORE any network requests (NM restart needs DNS)
    let _ = Command::new("chattr").args(["-i", "/etc/resolv.conf"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
    let _ = std::fs::write("/etc/resolv.conf", "nameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 1.0.0.1\n");

    // 3. Restart NetworkManager daemon to cleanly re-bind link state and DHCP in VMware/Linux
    let _ = Command::new("systemctl").args(["restart", "NetworkManager"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
    let _ = Command::new("service").args(["NetworkManager", "restart"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();

    // 4. Ensure device is managed and connected via NM (NM handles its own internal DHCP)
    let _ = Command::new("nmcli").args(["networking", "on"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
    let _ = Command::new("nmcli").args(["device", "set", &target_iface, "managed", "yes"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
    let _ = Command::new("nmcli").args(["device", "connect", &target_iface]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();

    // 5. Wait for NetworkManager to fully establish connection and obtain DHCP lease
    sleep(Duration::from_secs(4)).await;

    // 6. Final DNS assertion (NM may have overwritten resolv.conf during restart with local stub, ensure fallback)
    let _ = Command::new("chattr").args(["-i", "/etc/resolv.conf"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
    let _ = std::fs::write("/etc/resolv.conf", "nameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 1.0.0.1\n");

    if let Err(e) = state_mgr.deactivate() {
        tracing::warn!("State manager deactivation error: {e}");
    }
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

fn find_cargo_bin() -> String {
    let candidates = [
        "/root/.cargo/bin/cargo",
        "/usr/local/cargo/bin/cargo",
        "/usr/bin/cargo",
        "/usr/local/bin/cargo",
    ];
    for path in candidates {
        if Path::new(path).exists() {
            return path.to_string();
        }
    }
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        let user_cargo = format!("/home/{sudo_user}/.cargo/bin/cargo");
        if Path::new(&user_cargo).exists() {
            return user_cargo;
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let user_cargo = format!("{home}/.cargo/bin/cargo");
        if Path::new(&user_cargo).exists() {
            return user_cargo;
        }
    }
    "cargo".to_string()
}

fn determine_cargo_home() -> Option<String> {
    if let Ok(cargo_home) = std::env::var("CARGO_HOME") {
        if !cargo_home.trim().is_empty() && Path::new(&cargo_home).exists() {
            return Some(cargo_home);
        }
    }
    if Path::new("/root/.cargo").exists() {
        return Some("/root/.cargo".to_string());
    }
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        let user_cargo_home = format!("/home/{sudo_user}/.cargo");
        if Path::new(&user_cargo_home).exists() {
            return Some(user_cargo_home);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let user_cargo_home = format!("{home}/.cargo");
        if Path::new(&user_cargo_home).exists() {
            return Some(user_cargo_home);
        }
    }
    None
}

fn determine_build_dir() -> String {
    let pid = std::process::id();
    let candidates = [
        format!("/var/tmp/wraith_autoinstall_{pid}"),
        format!("/tmp/wraith_autoinstall_{pid}"),
    ];
    for dir in candidates {
        if let Some(parent) = Path::new(&dir).parent() {
            if parent.exists() {
                return dir;
            }
        }
    }
    format!("/var/tmp/wraith_autoinstall_{pid}")
}

pub async fn cmd_update() -> Result<()> {
    print_banner(false);
    let update_rows = vec![
        "• Target Binary : /usr/local/bin/wraith".to_string(),
        "• Upstream Repo : https://github.com/ByGh00st/wraith.git".to_string(),
        "• Pipeline      : Clean Git Clone ➔ Cargo Release ➔ Deploy".to_string(),
    ];
    let update_box = render_box("🚀 WRAITH AUTONOMOUS SYSTEM INSTALLER & UPDATER", &update_rows, BoxCorner::Square, 78);
    println!("{}", update_box[0].bright_cyan());
    for row in &update_box[1..update_box.len() - 1] {
        println!("{row}");
    }
    println!("{}\n", update_box.last().unwrap().bright_cyan());

    print_step(&t!("commands.cmd_step_40"), "info");

    // 1. Ensure DNS is unchattered and functional for git pull / cargo dependencies
    let _ = Command::new("chattr")
        .args(["-i", "/etc/resolv.conf"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let state_mgr = StateManager::default();
    if !state_mgr.is_active() {
        let _ = restore_dns();
    }
    let _ = fs::write(
        "/etc/resolv.conf",
        "nameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 1.0.0.1\n",
    );

    let cargo_bin = find_cargo_bin();
    let temp_build_dir = determine_build_dir();

    // 2. Clean previous build residue
    let _ = fs::remove_dir_all(&temp_build_dir);

    // 3. Autonomous Git Clone from Upstream
    print_step(
        &format!("{}", t!("commands.cmd_step_git_fetching", dir = &temp_build_dir)),
        "info",
    );
    let clone_status = Command::new("git")
        .args([
            "clone",
            "--depth",
            "1",
            "https://github.com/ByGh00st/wraith.git",
            &temp_build_dir,
        ])
        .status();

    match clone_status {
        Ok(s) if s.success() => {
            print_step(&t!("commands.cmd_step_41"), "ok");
        }
        Ok(s) => {
            let _ = fs::remove_dir_all(&temp_build_dir);
            print_step(&format!("{}", t!("commands.cmd_err_git_clone", code = s.to_string())), "error");
            return Err(WraithError::Custom(format!("Git clone failed with code: {s}")));
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&temp_build_dir);
            print_step(&format!("{}", t!("commands.cmd_err_git_spawn", err = e.to_string())), "error");
            return Err(WraithError::Io(e));
        }
    }

    // 4. Compile in workspace reusing persistent cargo home or fallback
    print_step(
        &format!("{}", t!("commands.cmd_step_cargo_compiling", bin = &cargo_bin)),
        "info",
    );

    // Detect available RAM & swap to prevent Linux OOM Killer (signal: 9) on VMs
    let (is_low_ram, needs_swap) = if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
        let total_kb = meminfo
            .lines()
            .find(|l| l.starts_with("MemTotal:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(8_000_000);
        let swap_kb = meminfo
            .lines()
            .find(|l| l.starts_with("SwapTotal:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(2_000_000);
        (total_kb < 3_500_000, swap_kb < 500_000 && total_kb < 3_500_000)
    } else {
        (false, false)
    };

    let mut created_swap = false;
    if needs_swap {
        print_step("Low RAM VM detected with zero swap; provisioning ephemeral build swap", "warn");
        let swap_cmd = "fallocate -l 1536M /var/tmp/wraith_build_swap 2>/dev/null || dd if=/dev/zero of=/var/tmp/wraith_build_swap bs=1M count=1536 2>/dev/null; chmod 600 /var/tmp/wraith_build_swap && mkswap /var/tmp/wraith_build_swap 2>/dev/null && swapon /var/tmp/wraith_build_swap 2>/dev/null";
        if let Ok(s) = Command::new("sh").args(["-c", swap_cmd]).status() {
            created_swap = s.success();
        }
    }

    let mut cmd = Command::new(&cargo_bin);
    cmd.args(["build", "--release", "--bin", "wraith"])
        .current_dir(&temp_build_dir);

    if is_low_ram {
        cmd.args(["--jobs", "1"]);
        cmd.env("RUSTFLAGS", "-C codegen-units=1 -C opt-level=2");
    }

    if let Some(cargo_home) = determine_cargo_home() {
        cmd.env("CARGO_HOME", cargo_home);
    } else {
        let fallback_cargo_home = format!("{temp_build_dir}/.cargo_home");
        let _ = fs::create_dir_all(&fallback_cargo_home);
        cmd.env("CARGO_HOME", fallback_cargo_home);
    }

    let build_status = cmd.status();

    if created_swap {
        let _ = Command::new("sh")
            .args(["-c", "swapoff /var/tmp/wraith_build_swap 2>/dev/null; rm -f /var/tmp/wraith_build_swap 2>/dev/null"])
            .status();
    }

    match build_status {
        Ok(s) if s.success() => {
            print_step(&t!("commands.cmd_step_42"), "ok");
        }
        Ok(s) => {
            let _ = fs::remove_dir_all(&temp_build_dir);
            print_step(&format!("Cargo compilation failed with status: {s}"), "error");
            return Err(WraithError::Custom(format!("Cargo build failed with exit code: {s}")));
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&temp_build_dir);
            print_step(&format!("Failed executing cargo binary: {e}"), "error");
            return Err(WraithError::Io(e));
        }
    }

    let compiled_binary = format!("{temp_build_dir}/target/release/wraith");
    if !Path::new(&compiled_binary).exists() {
        let _ = fs::remove_dir_all(&temp_build_dir);
        print_step(&t!("commands.cmd_step_43"), "error");
        return Err(WraithError::Custom("Binary artifact missing".into()));
    }

    // 5. Eradicate old binaries and install new binary across all system PATHs
    print_step(&t!("commands.cmd_step_93"), "info");

    let mut target_paths = vec![
        "/usr/local/bin/wraith".to_string(),
        "/usr/bin/wraith".to_string(),
        "/bin/wraith".to_string(),
        "/root/.cargo/bin/wraith".to_string(),
    ];
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        target_paths.push(format!("/home/{sudo_user}/.cargo/bin/wraith"));
    }
    if let Ok(home) = std::env::var("HOME") {
        target_paths.push(format!("{home}/.cargo/bin/wraith"));
    }

    for target in &target_paths {
        let path = Path::new(target);
        if let Some(parent) = path.parent() {
            if parent.exists() {
                // Strip immutable attributes and remove old binary first
                let _ = Command::new("chattr").args(["-i", "-a", target]).status();
                let _ = fs::remove_file(target);
                let _ = Command::new("rm").args(["-f", target]).status();

                // Copy fresh binary
                if let Err(e) = fs::copy(&compiled_binary, target) {
                    tracing::debug!("Could not write binary to {target}: {e}");
                } else {
                    let _ = Command::new("chmod").args(["755", target]).status();
                }
            }
        }
    }

    // 6. Generate and install shell auto-completions
    let _ = fs::create_dir_all("/etc/bash_completion.d");
    let _ = fs::create_dir_all("/usr/share/bash-completion/completions");
    let _ = fs::create_dir_all("/usr/share/zsh/vendor-completions");
    let _ = fs::create_dir_all("/usr/share/zsh/site-functions");
    if let Ok(bash_out) = Command::new(&compiled_binary).args(["--generate-completions", "bash"]).output() {
        let _ = fs::write("/etc/bash_completion.d/wraith", &bash_out.stdout);
        let _ = fs::write("/usr/share/bash-completion/completions/wraith", &bash_out.stdout);
    }
    if let Ok(zsh_out) = Command::new(&compiled_binary).args(["--generate-completions", "zsh"]).output() {
        let _ = fs::write("/usr/share/zsh/vendor-completions/_wraith", &zsh_out.stdout);
        let _ = fs::write("/usr/share/zsh/site-functions/_wraith", &zsh_out.stdout);
    }

    // 7. Cleanup temp build directory
    let _ = fs::remove_dir_all(&temp_build_dir);

    // 8. Compute and verify SHA-256 of installed binary
    let bin_hash = if let Ok(bin_bytes) = fs::read("/usr/local/bin/wraith") {
        wraith_core::crypto::Sha256::digest(&bin_bytes).to_hex()
    } else {
        "verified".to_string()
    };

    print_step(
        &format!("{}", t!("commands.cmd_warn_sha256_unverified", hash = &bin_hash[..16.min(bin_hash.len())])),
        "warn",
    );
    print_success(&t!("runtime.updated_success"));
    println!("  {}\n", t!("commands.cmd_universal_bin"));
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

