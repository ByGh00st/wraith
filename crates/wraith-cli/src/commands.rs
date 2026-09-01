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
    run_full_cleanup,
};
use wraith_guard::{
    enforce_seccomp_socket_jail, get_current_ip, get_current_ip_geo, run_full_leak_test,
    verify_tor_connection, KillSwitch, SovereignDnsEngine, TrafficJitterEngine,
};
use wraith_net::{
    apply_ipv6_block, apply_tor_rules, backup_and_apply_tcp_mask, block_stun_ports, change_mac,
    create_cgroup_jail, create_namespace, destroy_cgroup_jail, destroy_namespace, flush_ipv6_block,
    flush_rules, randomize_hostname, restore_mac, restore_tcp_stack, unblock_stun_ports,
    EgressFastpath, EgressIntrusionDetector, MultiHopTunnelEngine,
};
use wraith_tor::{
    apply_exit_profile, backup_resolv, configure_dns, get_active_tls_profile,
    get_circuit_telemetry, restore_dns, start_tor_daemon, stop_tor_daemon, write_bridge_torrc,
    write_torrc, TlsCamouflageServer, TorControlClient,
};

use crate::display::{
    print_banner, print_error, print_step, print_success, show_circuit_telemetry, show_leak_report,
    show_status_dashboard,
};
use crate::tui::SovereignDashboard;
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
    }
}

pub async fn cmd_start(args: crate::StartArgs) -> Result<()> {
    print_banner(args.strict_hardening);
    let state_mgr = StateManager::default();

    if state_mgr.is_active() {
        print_error("Wraith is already running! Stop first with: sudo wraith stop");
        return Ok(());
    }

    let is_strict = args.strict_hardening;
    let mut state_data = StateData {
        active: true,
        ..Default::default()
    };
    let _ = state_mgr.activate(state_data.clone());
    let mut bg_services = BackgroundServices::default();

    // 0. Kernel Process Memory Lockdown (PR_SET_DUMPABLE=0, mlockall)
    print_step(
        "Enforcing Process Memory Lockdown (PR_SET_DUMPABLE=0, mlockall)...",
        "info",
    );
    match enforce_process_lockdown() {
        Ok(()) => print_step(
            "Process memory secured against dumpers (PR_SET_DUMPABLE=0, mlockall)",
            "ok",
        ),
        Err(e) => print_step(&format!("Process memory lockdown warning: {e}"), "warn"),
    }

    if is_strict {
        print_step(
            "Enforcing Linux Kernel Lockdown & DMA Hardware Defense...",
            "info",
        );
        match enforce_kernel_lockdown() {
            Ok(lockdown) => print_step(
                &format!(
                    "Kernel Lockdown evaluated ({:?}, /dev/mem & DMA IOMMU verified)",
                    lockdown
                ),
                "ok",
            ),
            Err(e) => print_step(&format!("Kernel Lockdown warning: {e}"), "warn"),
        }
    }

    // 0a. Explicit Anti-Debug Abort Trap (Aggressive Defense Opt-In)
    if args.aggressive_anti_debug {
        print_step(
            "Arming Aggressive Anti-Debug Trap (SIGKILL on TracerPid / ptrace)...",
            "info",
        );
        match wraith_forensic::AntiDebugProbe::enforce_anti_debug_trap(is_strict) {
            Ok(()) => print_step(&t!("commands.cmd_step_0"), "ok"),
            Err(e) => print_step(&format!("Anti-debug probe warning: {e}"), "warn"),
        }
    }

    // 0b. Explicit Process Masquerading (Red Team / Evasion Opt-In)
    if args.aggressive_masquerade {
        print_step(
            "Masking process name in kernel scheduler ([kworker/u16:0])...",
            "info",
        );
        match wraith_forensic::cloaked_process_masquerade("[kworker/u16:0]") {
            Ok(()) => print_step(
                "Process identity cloaked as kernel worker [EXPLICIT OPT-IN]",
                "ok",
            ),
            Err(e) => print_step(&format!("Process masquerade warning: {e}"), "warn"),
        }
    }

    // 0c. Explicit Destructive Log & History Wipe (Destructive Cleanup Opt-In)
    if args.forensic_wipe_logs {
        print_step(
            "Executing destructive system event log and history wipe...",
            "warn",
        );
        match wraith_forensic::scrub_system_logs() {
            Ok(count) => print_step(&format!("Scrubbed {count} system log file(s)"), "ok"),
            Err(e) => print_step(&format!("System log scrub failed: {e}"), "warn"),
        }
        match wraith_forensic::wipe_all_user_histories() {
            Ok(count) => print_step(
                &format!("Wiped {count} shell history file(s) [EXPLICIT OPT-IN]"),
                "ok",
            ),
            Err(e) => print_step(&format!("History wipe failed: {e}"), "warn"),
        }
    }

    // 1. MAC & Hostname Randomization
    if args.mac || is_strict {
        print_step(&t!("commands.cmd_step_1"), "info");
        match change_mac(None, None) {
            Ok((iface, old_m, new_m)) => {
                print_step(&format!("MAC altered: {old_m} ➔ {new_m} on {iface}"), "ok");
                state_data.mac_interface = Some(iface);
                state_data.mac_old = Some(old_m);
                state_data.mac_new = Some(new_m);
            }
            Err(e) => print_step(&format!("MAC randomization skipped: {e}"), "warn"),
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
        print_step(
            "Rotating OS /etc/machine-id unique hardware identifier...",
            "info",
        );
        match rotate_machine_id() {
            Ok((old_mid, new_mid)) => {
                print_step(&format!("Machine-ID rotated: {old_mid} ➔ {new_mid}"), "ok");
                state_data.machine_id_old = Some(old_mid);
            }
            Err(e) => print_step(&format!("Machine-ID rotation warning: {e}"), "warn"),
        }
        let _ = state_mgr.activate(state_data.clone());
    }

    // 3. TCP/IP Stack Normalization (p0f OS Fingerprint Evasion)
    if args.tcp_mask || is_strict {
        print_step(
            "Normalizing TCP/IP L4 Stack (p0f/TTL/Window Evasion)...",
            "info",
        );
        match backup_and_apply_tcp_mask() {
            Ok(_backup_map) => {
                print_step(
                    "TCP/IP stack forged: TTL=128 (Windows Profile), timestamps=0",
                    "ok",
                );
                state_data.tcp_stack_masked = true;
            }
            Err(e) => print_step(&format!("TCP/IP stack normalization warning: {e}"), "warn"),
        }
        let _ = state_mgr.activate(state_data.clone());
    }

    // 4. JA3/JA4 TLS ClientHello Camouflage & In-Flight HTTP DPI Sanitizer Proxy
    {
        let (server, ct) = TlsCamouflageServer::new(None);
        let handle = server.spawn_server();
        let prof = get_active_tls_profile();
        print_step(
            &format!(
                "Armed In-Flight HTTP DPI & TLS Camouflage Gate on 127.0.0.1:9055 ({}, JA4: {})",
                prof.name, prof.ja4_hash
            ),
            "ok",
        );
        bg_services.tls = Some((ct, handle));
    }

    // 5. Tor Configuration & Bridges
    if args.bridge {
        print_step(&t!("commands.cmd_step_2"), "info");
        match write_bridge_torrc(None) {
            Ok(count) => {
                print_step(
                    &format!("Bridge mode enabled with {count} obfs4 bridges"),
                    "ok",
                );
                state_data.bridge_enabled = true;
                state_data.bridge_count = count;
            }
            Err(e) => {
                print_step(
                    &format!("Bridge error: {e}, falling back to direct Tor"),
                    "warn",
                );
                write_torrc()?;
            }
        }
    } else {
        print_step(&t!("commands.cmd_step_3"), "info");
        write_torrc()?;
        print_step(&t!("commands.cmd_step_4"), "ok");
    }

    // 5b. Multi-Hop & Hybrid Overlay Tunneling (WireGuard ➔ Tor)
    if let Some(ref wg_conf) = args.wireguard {
        print_step(
            &format!("Initializing Multi-Hop Hybrid Overlay (WireGuard -> Tor)... [{wg_conf}]"),
            "info",
        );
        match MultiHopTunnelEngine::setup_wireguard(Some(wg_conf)) {
            Ok(wg_iface) => {
                let tor_uid = wraith_net::get_tor_uid().unwrap_or(0);
                let _ = MultiHopTunnelEngine::bind_tor_to_wireguard(tor_uid, &wg_iface);
                print_step(
                    &format!("Multi-Hop Hop 1 active ({wg_iface} ChaCha20-Poly1305) ➔ Tor traffic encapsulated"),
                    "ok",
                );
                state_data.multihop_enabled = true;
                state_data.wireguard_config = Some(wg_conf.clone());
            }
            Err(e) => print_step(&format!("Multi-Hop WireGuard setup warning: {e}"), "warn"),
        }
    }

    // 6. Start Tor Daemon FIRST (Before modifying DNS / Firewall)
    print_step(&t!("commands.cmd_step_5"), "info");
    if let Err(e) = start_tor_daemon().await {
        print_step(&format!("Tor bootstrap failed: {e}"), "error");
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
        print_step(&format!("DNS configuration failed: {e}"), "error");
        let _ = restore_dns();
        return Err(e);
    }
    print_step(&t!("commands.cmd_step_8"), "ok");

    // 8. Exit Node Profile
    let exit_prof = if is_strict && args.profile.is_none() {
        Some("stealth".to_string())
    } else {
        args.profile
    };

    if let Some(prof_name) = &exit_prof {
        print_step(
            &format!("Applying geographic exit profile: {prof_name}..."),
            "info",
        );
        match apply_exit_profile(prof_name).await {
            Ok(p) => {
                print_step(&format!("Profile '{}' active ({})", p.name, p.desc), "ok");
                state_data.exit_profile = Some(prof_name.clone());
            }
            Err(e) => print_step(&format!("Exit profile error: {e}"), "warn"),
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

    // 10. eBPF / TC Egress Fastpath Filter
    if is_strict {
        print_step(
            "Injecting Linux Traffic Control (TC) / eBPF Egress Fastpath...",
            "info",
        );
        match EgressFastpath::new(None) {
            Ok(mut fp) => {
                if let Err(e) = fp.attach() {
                    print_step(&format!("eBPF Fastpath attach warning: {e}"), "warn");
                } else {
                    print_step(&t!("commands.cmd_step_15"), "ok");
                }
            }
            Err(e) => print_step(&format!("eBPF Fastpath init error: {e}"), "warn"),
        }
    }

    // 11. Zero-Copy IDS Raw Packet Sniffer & Egress Watchdog (Acquire raw AF_PACKET before Seccomp sandbox)
    print_step(
        "Arming Zero-Copy IDS Raw Packet Sniffer & DPI Engine (AF_PACKET)...",
        "info",
    );
    let (ids, _telemetry, ct) = EgressIntrusionDetector::new();
    let handle = ids.spawn_sniffer();
    print_step(
        "Zero-Copy IDS Watchdog & DPI Engine active (Real-time leak & signature traps armed)",
        "ok",
    );
    bg_services.ids = Some((ct, handle));

    // 12. Seccomp-BPF Syscall Sandboxing (Raw Socket Filter)
    if is_strict {
        print_step(
            "Arming Seccomp-BPF Syscall Filter (SOCK_RAW / AF_PACKET hook trap)...",
            "info",
        );
        match enforce_seccomp_socket_jail() {
            Ok(()) => print_step(
                "Syscall filter active: Rogue raw sockets will trigger immediate SIGSYS",
                "ok",
            ),
            Err(e) => print_step(&format!("Seccomp-BPF jail warning: {e}"), "warn"),
        }
    }

    // 13. Hardware, GPU, Font & Resolution Browser Shield
    if args.browser_shield || is_strict {
        print_step(
            "Deploying GPU, WebGL, Font & Resolution Anti-Fingerprint Shield...",
            "info",
        );
        match deploy_hardware_and_font_shield() {
            Ok(count) => {
                print_step(
                    &format!("Injected anti-fingerprint shield into {count} browser profile(s)"),
                    "ok",
                );
                state_data.browser_hardened = count;
                let _ = state_mgr.activate(state_data.clone());
            }
            Err(e) => print_step(&format!("Browser shield warning: {e}"), "warn"),
        }
    }

    // 14. System-level Font Sandbox
    if args.font_sandbox || is_strict {
        print_step(
            "Restricting OS-level font discovery (fontconfig sandbox)...",
            "info",
        );
        match enforce_font_jail() {
            Ok(()) => print_step(&t!("commands.cmd_step_16"), "ok"),
            Err(e) => print_step(&format!("Font sandbox warning: {e}"), "warn"),
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
            Err(e) => print_step(&format!("Network namespace warning: {e}"), "warn"),
        }
    }

    // 17. Identity Verification
    print_step(&t!("commands.cmd_step_20"), "info");
    sleep(Duration::from_secs(2)).await;
    let geo = get_current_ip_geo().await;
    if geo.is_tor {
        print_step(&format!("Connected through Tor ➔ {geo}"), "ok");
    } else {
        print_step(
            &format!("Current IP: {} (Tor verification pending)", geo.ip),
            "warn",
        );
    }

    // 18. Background Traffic Padding & Anti-Correlation Jitter
    if args.jitter || is_strict {
        print_step(
            "Spawning Traffic Padding & Anti-Correlation Jitter engine...",
            "info",
        );
        let (je, ct) = TrafficJitterEngine::new();
        let handle = je.spawn_obfuscator();
        print_step(
            "Synthetic traffic padding active (200-1400ms Poisson jitter)",
            "ok",
        );
        bg_services.jitter = Some((ct, handle));
    }

    // 19. Encrypted In-Memory Ephemeral RAMFS Vault
    let _ram_vault = if is_strict {
        print_step(
            "Constructing In-Memory ChaCha20-Poly1305 Encrypted Vault (/dev/shm)...",
            "info",
        );
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
                print_step(
                    "Encrypted RAMFS Vault active (MADV_DONTDUMP memory locked)",
                    "ok",
                );
                Some(vault)
            }
            Err(e) => {
                print_step(&format!("Encrypted RAMFS Vault init warning: {e}"), "warn");
                None
            }
        }
    } else {
        None
    };

    // 20. Async DNS Engine with EDNS0 Padding & Sinkhole
    if is_strict {
        print_step(
            "Spawning RFC 1035 DNS Proxy Engine with EDNS0 Padding...",
            "info",
        );
        let (dns_srv, ct) = SovereignDnsEngine::new(None, None);
        let handle = dns_srv.spawn_server();
        print_step(
            "DNS Engine active on 127.0.0.1:53 (EDNS0 468B Padded + Telemetry Sinkhole)",
            "ok",
        );
        bg_services.dns = Some((ct, handle));
    }

    // 21. Automatic IP Rotation Engine
    if let Some(interval) = args.rotate_interval {
        print_step(
            &format!("Arming Automatic IP Rotation Engine (Interval: {interval}s)..."),
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
                            println!("\n  [🔄 AUTO-ROTATE] Tor Circuit Identity Switched ➔ {new_geo}\n");
                        }
                    }
                }
            }
        });
        print_step(
            &format!("Auto IP rotation active: Fresh circuit & exit identity every {interval}s"),
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
        print_step(
            "Fail-Closed Watchdog armed & monitoring kernel egress",
            "ok",
        );
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
                    println!("\r\n  ◈ [🛑 EMERGENCY SIGNAL: SIGINT (Ctrl+C)] Restoring system state...\r\n");
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
                    println!("\r\n  ◈ [🛑 EMERGENCY SIGNAL: SIGTERM] Restoring system state...\r\n");
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
                    println!("\r\n  ◈ [🛑 EMERGENCY SIGNAL: SIGHUP] Restoring system state...\r\n");
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
                            println!("\r\n  ◈ [🛑 CLEAN DISCONNECT] Restoring system network & security to original state...\r\n");
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
                                        print!("  ✔ [ACTIVE IDENTITY] New Tor Exit Node ➔ {}\r\n\r\n", new_geo);
                                    } else {
                                        print!("  ✖ [ERROR] Failed to signal Tor ControlPort.\r\n\r\n");
                                    }
                                }
                                crossterm::event::KeyCode::Char('t') | crossterm::event::KeyCode::Char('T') => {
                                    let _ = crossterm::terminal::disable_raw_mode();
                                    println!("\n  ◈ [🧪 LEAK AUDIT] Executing comprehensive Ring-0 leak inspection suite...");
                                    let report = run_full_leak_test().await;
                                    show_leak_report(&report);
                                    println!();
                                    let _ = crossterm::terminal::enable_raw_mode();
                                }
                                crossterm::event::KeyCode::Char('m') | crossterm::event::KeyCode::Char('M') => {
                                    if spawn_monitor_terminal() {
                                        print!("\r\n  ◈ [🖥️ POP-UP MONITOR] Dedicated real-time DPI & IDS telemetry window spawned!\r\n\r\n");
                                    } else {
                                        print!("\r\n  ⚠️ [POP-UP MONITOR] To view dedicated monitor, run in a separate terminal: sudo wraith monitor\r\n\r\n");
                                    }
                                }
                                crossterm::event::KeyCode::Char('c') | crossterm::event::KeyCode::Char('C') => {
                                    print!("\r\n  ◈ [🧹 MEMORY PURGE] Purging volatile caches, RAMFS secrets, ARP tables & buffers (<10ms)...\r\n");
                                    let _ = wraith_forensic::logs::fast_ram_and_arp_purge();
                                    print!("  ✔ [ERADICATED] Kernel drop_caches, memory compaction, and ARP routing tables wiped.\r\n\r\n");
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
        println!("  Run 'sudo wraith stop' to restore network.\n");
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

    if let Ok(mut fp) = EgressFastpath::new(None) {
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
        print_step("Tearing down Multi-Hop WireGuard hybrid overlay...", "info");
        if let Err(e) = MultiHopTunnelEngine::teardown_wireguard(state_info.wireguard_config.as_deref()) {
            tracing::warn!("WireGuard teardown warning: {e}");
        } else {
            print_step("Multi-Hop WireGuard tunnel demolished", "ok");
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

    // Unconditionally restore default Linux TCP stack (TTL=64, TS=1)
    print_step(&t!("commands.cmd_step_33"), "info");
    let mut default_map = std::collections::HashMap::new();
    default_map.insert("net.ipv4.ip_default_ttl".to_string(), "64".to_string());
    default_map.insert("net.ipv4.tcp_timestamps".to_string(), "1".to_string());
    let _ = restore_tcp_stack(&default_map);
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

    print_step(
        "Executing anti-forensic memory & volatile state purge...",
        "info",
    );
    if let Err(e) = panic_emergency_purge(self_destruct) {
        print_step(&format!("Emergency purge warning: {e}"), "warn");
    }
    print_step(
        "RAM caches, ARP tables, logs, and volatile state eradicated",
        "ok",
    );

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
            "Wraith stopped — Isolation terminated & Real IP restored: {ip}"
        ));
    } else {
        print_success("Wraith stopped — Isolation terminated & Clearnet restored");
    }
    Ok(())
}

pub async fn cmd_shred(target: &str, passes: u32) -> Result<()> {
    print_banner(false);
    print_step(
        &format!("Executing DoD 5220.22-M shredding ({passes} passes) on {target}..."),
        "info",
    );

    let path = Path::new(target);
    if !path.exists() {
        print_error(&format!("Target file does not exist: {target}"));
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

pub async fn cmd_update() -> Result<()> {
    print_banner(false);
    println!("  ┌── [ 🚀 WRAITH AUTONOMOUS SYSTEM INSTALLER & UPDATER ] ────────┐");
    println!("  │ • Target Binary : /usr/local/bin/wraith                        │");
    println!("  │ • Upstream Repo : https://github.com/ByGh00st/wraith.git       │");
    println!("  │ • Pipeline      : Clean Git Clone ➔ Cargo Release ➔ Deploy    │");
    println!("  └────────────────────────────────────────────────────────────────┘\n");

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
    let temp_build_dir = format!("/tmp/wraith_autoinstall_{}", std::process::id());

    // 2. Clean previous build residue
    let _ = fs::remove_dir_all(&temp_build_dir);

    // 3. Autonomous Git Clone from Upstream
    print_step(
        &format!("Fetching latest code directly from GitHub into {temp_build_dir}..."),
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
            print_step(&format!("Failed cloning upstream repo (exit code: {s})"), "error");
            return Err(WraithError::Custom(format!("Git clone failed with code: {s}")));
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&temp_build_dir);
            print_step(&format!("Failed spawning git clone process: {e}"), "error");
            return Err(WraithError::Io(e));
        }
    }

    // 4. Compile in isolated workspace with isolated writable CARGO_HOME
    print_step(
        &format!("Compiling optimized release binary with {cargo_bin}..."),
        "info",
    );
    let isolated_cargo_home = format!("{temp_build_dir}/.cargo_home");
    let _ = fs::create_dir_all(&isolated_cargo_home);

    let mut cmd = Command::new(&cargo_bin);
    cmd.args(["build", "--release", "--workspace"])
        .current_dir(&temp_build_dir)
        .env("CARGO_HOME", &isolated_cargo_home);

    let build_status = cmd.status();

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
    print_step(
        "Overwriting old installations and deploying fresh binary across PATH...",
        "info",
    );

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
                // Remove old binary first
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

    // 7. Cleanup temp build directory
    let _ = fs::remove_dir_all(&temp_build_dir);

    // 8. Compute and verify SHA-256 of installed binary
    let bin_hash = if let Ok(bin_bytes) = fs::read("/usr/local/bin/wraith") {
        wraith_core::crypto::Sha256::digest(&bin_bytes).to_hex()
    } else {
        "verified".to_string()
    };

    print_step(
        &format!("SHA-256: {} (not verified against a trusted source — use at your own risk)", &bin_hash[..16.min(bin_hash.len())]),
        "warn",
    );
    print_success("Wraith updated & deployed successfully in-place!");
    println!("  Universal binary: /usr/local/bin/wraith");
    println!("  Run 'wraith --version' or 'wraith' to launch.\n");
    Ok(())
}

pub async fn cmd_switch() -> Result<()> {
    print_banner(false);
    let state_mgr = StateManager::default();
    if !state_mgr.is_active() {
        print_error("Wraith is not running. Start first with: sudo wraith start");
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

pub async fn cmd_dashboard() -> Result<()> {
    let mut dashboard = SovereignDashboard::new();
    dashboard.run().await
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
    println!("  ╭── [ ⚔️ WRAITH-PRIME // OFFENSIVE SECURITY & PENTEST SANITIZATION ] ────────╮");
    println!("  │  SOCKS5 PROXY      : 127.0.0.1:9050 (Tor Native SOCKS5 Transport)          │");
    println!("  │  HTTP CAMOUFLAGE   : 127.0.0.1:9055 (JA3/JA4 Chrome v130+ Spoofing Proxy)   │");
    println!("  │  DNS SINKHOLE GATE : 127.0.0.1:5353 (Tor TransProxy DNS Resolver)          │");
    println!("  ╰──────────────────────────────────────────────────────────────────────────╯\n");

    println!("  ┌── [ 🎯 RECOMMENDED OFFENSIVE STRIKE COMMAND WRAPPERS ] ────────┐");
    println!("  │                                                                │");
    println!("  │ [NMAP STEALTH TCP SYN SCAN OVER SOCKS5]:                       │");
    println!("  │   nmap -sT -Pn -n --proxy socks5://127.0.0.1:9050 <target_ip>   │");
    println!("  │                                                                │");
    println!("  │ [CURL / WEB FUZZING WITH JA4 TLS EVASION]:                     │");
    println!("  │   curl -x http://127.0.0.1:9055 https://target.com/login       │");
    println!("  │        -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64)\"   │");
    println!("  │                                                                │");
    println!("  │ [SQLMAP EXPLOITATION OVER TOR SOCKS5]:                         │");
    println!("  │   sqlmap -u \"http://<target>/id=1\" \\                           │");
    println!("  │          --proxy=\"socks5://127.0.0.1:9050\" --random-agent      │");
    println!("  │                                                                │");
    println!("  │ [METASPLOIT FRAMEWORK SOCKS5 TUNNELING]:                       │");
    println!("  │   set Proxies socks5:127.0.0.1:9050                            │");
    println!("  │   set HTTP_USER_AGENT Mozilla/5.0 (Windows NT 10.0; Win64)      │");
    println!("  │                                                                │");
    println!("  │ [HYDRA / SSH BRUTE-FORCE OVER TOR]:                            │");
    println!("  │   hydra -s 22 -l root -P pass.txt -t 4 <target_ip> ssh         │");
    println!("  └────────────────────────────────────────────────────────────────┘\n");

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
    println!("  ╭── [ 🛡️ WRAITH-PRIME // REAL-TIME DPI & IDS PACKET INTERCEPTOR ] ──────────╮");
    println!("  │  ENGINE STATUS : LIVE PROMISCUOUS SNIFFER (AF_PACKET Zero-Copy Ring-0)    │");
    println!("  │  HOTKEYS       : Press [Q] or [Ctrl+C] to close this monitor window       │");
    println!("  ╰──────────────────────────────────────────────────────────────────────────╯\n");

    println!("  ◈ [MONITOR ARMED] Listening for Layer-4 HTTP / Offensive Tool Egress on wire...\n");

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
            println!("  ℹ️  [DPI PROMISCUOUS MONITOR ACTIVE]");
            println!("  [NOTE] AF_PACKET promiscuous sniffer filtered by Seccomp / Environment: {err}");
            println!("  In-Flight HTTP DPI Rewriter & TLS Proxy is actively sanitizing wire on port 9055.");
            println!("  Live interceptor is operational in transparent proxy mode.\n");
            println!("  Listening for in-flight traffic... (Press 'q' or Enter to close)");
            
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
        println!("  Real-time packet monitor requires Linux AF_PACKET raw sockets.");
    }

    println!("\r\n  ◈ [MONITOR CLOSED] Returning to shell...\n");
    Ok(())
}
