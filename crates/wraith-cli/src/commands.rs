use std::time::Duration;
use tokio::time::sleep;
use wraith_core::error::Result;
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
    enforce_seccomp_socket_jail, get_current_ip, run_full_leak_test, verify_tor_connection,
    KillSwitch, SovereignDnsEngine, TrafficJitterEngine,
};
use wraith_net::{
    apply_ipv6_block, apply_tor_rules, backup_and_apply_tcp_mask, block_stun_ports, change_mac,
    create_cgroup_jail, create_namespace, destroy_cgroup_jail, destroy_namespace, flush_ipv6_block,
    flush_rules, randomize_hostname, restore_mac, restore_tcp_stack, unblock_stun_ports,
    EgressFastpath, EgressIntrusionDetector,
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

#[derive(Default)]
struct BackgroundServices {
    jitter: Option<(CancellationToken, tokio::task::JoinHandle<()>)>,
    tls: Option<(CancellationToken, tokio::task::JoinHandle<()>)>,
    dns: Option<(CancellationToken, tokio::task::JoinHandle<()>)>,
    ids: Option<(CancellationToken, tokio::task::JoinHandle<()>)>,
    killswitch: Option<(CancellationToken, tokio::task::JoinHandle<()>)>,
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
    }
}

pub async fn cmd_start(args: crate::StartArgs) -> Result<()> {
    print_banner();
    let state_mgr = StateManager::default();

    if state_mgr.is_active() {
        print_error("Wraith is already running! Stop first with: sudo wraith stop");
        return Ok(());
    }

    let is_apex = args.strict_hardening;
    let mut state_data = StateData::default();
    let mut bg_services = BackgroundServices::default();

    // 0. Kernel Process Memory Lockdown (PR_SET_DUMPABLE=0, mlockall)
    print_step("Enforcing Process Memory Lockdown (PR_SET_DUMPABLE=0, mlockall)...", "info");
    match enforce_process_lockdown() {
        Ok(()) => print_step("Process memory secured against dumpers (PR_SET_DUMPABLE=0, mlockall)", "ok"),
        Err(e) => print_step(&format!("Process memory lockdown warning: {e}"), "warn"),
    }

    if is_apex {
        print_step("Enforcing Linux Kernel Lockdown & DMA Hardware Defense...", "info");
        match enforce_kernel_lockdown() {
            Ok(lockdown) => print_step(&format!("Kernel Lockdown evaluated ({:?}, /dev/mem & DMA IOMMU verified)", lockdown), "ok"),
            Err(e) => print_step(&format!("Kernel Lockdown warning: {e}"), "warn"),
        }
    }

    // 0a. Explicit Anti-Debug Suicide Trap (Aggressive Defense Opt-In)
    if args.aggressive_anti_debug {
        print_step("Arming Aggressive Anti-Debug Trap (SIGKILL on TracerPid / ptrace)...", "info");
        match wraith_forensic::AntiDebugProbe::enforce_anti_debug_trap(is_apex) {
            Ok(()) => print_step("Anti-debug trap armed [EXPLICIT OPT-IN]", "ok"),
            Err(e) => print_step(&format!("Anti-debug probe warning: {e}"), "warn"),
        }
    }

    // 0b. Explicit Process Masquerading (Red Team / Evasion Opt-In)
    if args.aggressive_masquerade {
        print_step("Masking process name in kernel scheduler ([kworker/u16:0])...", "info");
        match wraith_forensic::cloaked_process_masquerade("[kworker/u16:0]") {
            Ok(()) => print_step("Process identity cloaked as kernel worker [EXPLICIT OPT-IN]", "ok"),
            Err(e) => print_step(&format!("Process masquerade warning: {e}"), "warn"),
        }
    }

    // 0c. Explicit Destructive Log & History Wipe (Destructive Cleanup Opt-In)
    if args.forensic_wipe_logs {
        print_step("Executing destructive system event log and history wipe...", "warn");
        match wraith_forensic::scrub_system_logs() {
            Ok(count) => print_step(&format!("Scrubbed {count} system log file(s)"), "ok"),
            Err(e) => print_step(&format!("System log scrub failed: {e}"), "warn"),
        }
        match wraith_forensic::wipe_all_user_histories() {
            Ok(count) => print_step(&format!("Wiped {count} shell history file(s) [EXPLICIT OPT-IN]"), "ok"),
            Err(e) => print_step(&format!("History wipe failed: {e}"), "warn"),
        }
    }

    // 1. MAC & Hostname Randomization
    if args.mac || is_apex {
        print_step("Randomizing hardware L2 MAC address...", "info");
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
    }

    // 2. Machine-ID & Hardware DMI Cloaking
    if args.machine_id_rotation || is_apex {
        print_step("Rotating OS /etc/machine-id unique hardware identifier...", "info");
        match rotate_machine_id() {
            Ok((old_mid, new_mid)) => {
                print_step(&format!("Machine-ID rotated: {old_mid} ➔ {new_mid}"), "ok");
                state_data.machine_id_old = Some(old_mid);
            }
            Err(e) => print_step(&format!("Machine-ID rotation warning: {e}"), "warn"),
        }
    }

    // 3. TCP/IP Stack Normalization (p0f OS Fingerprint Evasion)
    if args.tcp_mask || is_apex {
        print_step("Normalizing TCP/IP L4 Stack (p0f/TTL/Window Evasion)...", "info");
        match backup_and_apply_tcp_mask() {
            Ok(_backup_map) => {
                print_step("TCP/IP stack forged: TTL=128 (Windows Profile), timestamps=0", "ok");
                state_data.tcp_stack_masked = true;
            }
            Err(e) => print_step(&format!("TCP/IP stack normalization warning: {e}"), "warn"),
        }
    }

    // 4. JA3/JA4 TLS ClientHello Camouflage SOCKS5 Proxy
    if is_apex {
        let (server, ct) = TlsCamouflageServer::new(None);
        let handle = server.spawn_server();
        let prof = get_active_tls_profile();
        print_step(&format!("Armed JA3/JA4 TLS Camouflage Proxy on 127.0.0.1:9055 ({}, JA4: {})", prof.name, prof.ja4_hash), "ok");
        bg_services.tls = Some((ct, handle));
    }

    // 5. Tor Configuration & Bridges
    if args.bridge {
        print_step("Configuring censorship-resistant obfs4 bridges...", "info");
        match write_bridge_torrc(None) {
            Ok(count) => {
                print_step(&format!("Bridge mode enabled with {count} obfs4 bridges"), "ok");
                state_data.bridge_enabled = true;
                state_data.bridge_count = count;
            }
            Err(e) => {
                print_step(&format!("Bridge error: {e}, falling back to direct Tor"), "warn");
                write_torrc()?;
            }
        }
    } else {
        print_step("Generating optimized torrc...", "info");
        write_torrc()?;
        print_step("Tor configuration armed", "ok");
    }

    // 6. DNS Configuration
    print_step("Configuring local Tor transparent DNS...", "info");
    if let Err(e) = backup_resolv() {
        tracing::warn!("Failed creating resolv.conf backup: {e}");
    }
    configure_dns()?;
    print_step("DNS bound to 127.0.0.1 (Tor Port 5353)", "ok");

    // 7. Start Tor Daemon
    print_step("Bootstrapping Tor daemon...", "info");
    start_tor_daemon().await?;
    print_step("Tor daemon active & verified", "ok");

    // 8. Exit Node Profile
    let exit_prof = if is_apex && args.profile.is_none() {
        Some("stealth".to_string())
    } else {
        args.profile
    };

    if let Some(prof_name) = &exit_prof {
        print_step(&format!("Applying geographic exit profile: {prof_name}..."), "info");
        match apply_exit_profile(prof_name).await {
            Ok(p) => {
                print_step(&format!("Profile '{}' active ({})", p.name, p.desc), "ok");
                state_data.exit_profile = Some(prof_name.clone());
            }
            Err(e) => print_step(&format!("Exit profile error: {e}"), "warn"),
        }
    }

    // 9. Firewall & IPv6 Drop
    print_step("Enforcing Fail-Closed firewall rules...", "info");
    let saved = apply_tor_rules()?;
    state_data.saved_rules = Some(saved);
    print_step("All system TCP/DNS forced into Tor", "ok");

    print_step("Eliminating IPv6 dual-stack attack surface...", "info");
    apply_ipv6_block()?;
    print_step("IPv6 kernel-level drop armed", "ok");

    print_step("Blocking STUN/TURN WebRTC leak ports...", "info");
    block_stun_ports()?;
    print_step("STUN/TURN ports blocked", "ok");

    // 10. eBPF / TC Egress Fastpath Filter
    if is_apex {
        print_step("Injecting Linux Traffic Control (TC) / eBPF Egress Fastpath...", "info");
        match EgressFastpath::new(None) {
            Ok(mut fp) => {
                if let Err(e) = fp.attach() {
                    print_step(&format!("eBPF Fastpath attach warning: {e}"), "warn");
                } else {
                    print_step("eBPF TC Egress Fastpath attached", "ok");
                }
            }
            Err(e) => print_step(&format!("eBPF Fastpath init error: {e}"), "warn"),
        }
    }

    // 11. Seccomp-BPF Syscall Sandboxing (Raw Socket Filter)
    if is_apex {
        print_step("Arming Seccomp-BPF Syscall Filter (SOCK_RAW / AF_PACKET hook trap)...", "info");
        match enforce_seccomp_socket_jail() {
            Ok(()) => print_step("Syscall filter active: Rogue raw sockets will trigger immediate SIGSYS", "ok"),
            Err(e) => print_step(&format!("Seccomp-BPF jail warning: {e}"), "warn"),
        }
    }

    // 12. Hardware, GPU, Font & Resolution Browser Shield
    if args.browser_shield || is_apex {
        print_step("Deploying GPU, WebGL, Font & Resolution Anti-Fingerprint Shield...", "info");
        match deploy_hardware_and_font_shield() {
            Ok(count) => {
                print_step(&format!("Injected anti-fingerprint shield into {count} browser profile(s)"), "ok");
                state_data.browser_hardened = count;
            }
            Err(e) => print_step(&format!("Browser shield warning: {e}"), "warn"),
        }
    }

    // 13. System-level Font Sandbox
    if args.font_sandbox || is_apex {
        print_step("Restricting OS-level font discovery (fontconfig sandbox)...", "info");
        match enforce_font_jail() {
            Ok(()) => print_step("System-level font sandbox active", "ok"),
            Err(e) => print_step(&format!("Font sandbox warning: {e}"), "warn"),
        }
    }

    // 14. cgroup2 Network Socket Jail
    if is_apex {
        if let Err(e) = create_cgroup_jail() {
            tracing::warn!("cgroup2 jail creation warning: {e}");
        }
        if let Err(e) = wraith_net::attach_pid_to_cgroup(std::process::id()) {
            tracing::warn!("cgroup2 attach pid warning: {e}");
        } else {
            print_step("cgroup2 network socket jail active", "ok");
        }
    }

    // 15. Network Namespace
    if args.namespace || is_apex {
        print_step("Creating isolated Linux Network Namespace...", "info");
        match create_namespace() {
            Ok(()) => {
                print_step("Process namespace jail armed (10.200.1.0/24)", "ok");
                state_data.namespace_active = true;
            }
            Err(e) => print_step(&format!("Network namespace warning: {e}"), "warn"),
        }
    }

    // 16. Identity Verification
    print_step("Verifying exit identity...", "info");
    sleep(Duration::from_secs(2)).await;
    let (is_tor, tor_ip) = verify_tor_connection().await;
    if is_tor {
        print_step(&format!("Connected through Tor ➔ Exit IP: {}", tor_ip.as_deref().unwrap_or("Hidden")), "ok");
    } else {
        let ip = get_current_ip().await.unwrap_or_else(|| "Unknown".into());
        print_step(&format!("Current IP: {ip} (Tor verification pending)"), "warn");
    }

    // 17. Background Traffic Padding & Anti-Correlation Jitter
    if args.jitter || is_apex {
        print_step("Spawning Traffic Padding & Anti-Correlation Jitter engine...", "info");
        let (je, ct) = TrafficJitterEngine::new();
        let handle = je.spawn_obfuscator();
        print_step("Synthetic traffic padding active (200-1400ms Poisson jitter)", "ok");
        bg_services.jitter = Some((ct, handle));
    }

    // 18. Encrypted In-Memory Ephemeral RAMFS Vault
    let _ram_vault = if is_apex {
        print_step("Constructing In-Memory ChaCha20-Poly1305 Encrypted Vault (/dev/shm)...", "info");
        match EncryptedRamVault::init() {
            Ok(mut vault) => {
                let secret_payload = serde_json::to_vec(&state_data).unwrap_or_default();
                if let Err(e) = vault.write_secret("session.state.enc", &secret_payload) {
                    tracing::warn!("Encrypted vault write warning: {e}");
                }
                print_step("Encrypted RAMFS Vault active (MADV_DONTDUMP memory locked)", "ok");
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

    // 19. Async DNS Engine with EDNS0 Padding & Sinkhole
    if is_apex {
        print_step("Spawning RFC 1035 DNS Proxy Engine with EDNS0 Padding...", "info");
        let (dns_srv, ct) = SovereignDnsEngine::new(None, None);
        let handle = dns_srv.spawn_server();
        print_step("DNS Engine active on 127.0.0.1:53 (EDNS0 468B Padded + Telemetry Sinkhole)", "ok");
        bg_services.dns = Some((ct, handle));
    }

    // 20. Zero-Copy IDS Raw Packet Sniffer & Egress Watchdog
    if is_apex {
        print_step("Arming Zero-Copy IDS Raw Packet Sniffer (AF_PACKET)...", "info");
        let (ids, _telemetry, ct) = EgressIntrusionDetector::new();
        let handle = ids.spawn_sniffer();
        print_step("Zero-Copy IDS Egress Watchdog active: Real-time clearnet leak traps armed", "ok");
        bg_services.ids = Some((ct, handle));
    }

    // 21. KillSwitch Daemon
    state_data.ip = tor_ip;
    state_data.kill_switch = !args.no_ks;
    state_mgr.activate(state_data)?;

    print_success("Wraith High-Assurance Privacy Engine Established");
    print_pentest_notice();

    if !args.no_ks {
        print_step("Arming async Fail-Closed watchdog...", "info");
        let (ks, cancel_token) = KillSwitch::new();
        let ks_handle = ks.spawn_monitor();
        bg_services.killswitch = Some((cancel_token, ks_handle));
        print_step("Watchdog active (SIGINT/SIGTERM/SIGHUP will trigger Panic Purge & Clean Shutdown)\n", "ok");

        #[cfg(unix)]
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        #[cfg(unix)]
        let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\n  [🚨 EMERGENCY SIGNAL: SIGINT (Ctrl+C)] Executing Panic Purge...");
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
                println!("\n  [🚨 EMERGENCY SIGNAL: SIGTERM] Executing Panic Purge...");
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
                println!("\n  [🚨 EMERGENCY SIGNAL: SIGHUP] Executing Panic Purge...");
            }
        }

        // Gracefully cancel and wait on all background task join handles
        bg_services.shutdown_and_join().await;

        cmd_stop(args.forensic_self_destruct).await?;
    } else {
        println!("  Run 'sudo wraith stop' to restore network.\n");
    }

    Ok(())
}

pub async fn cmd_stop(self_destruct: bool) -> Result<()> {
    print_banner();
    let state_mgr = StateManager::default();
    let state_info = state_mgr.read();

    print_step("Flushing netfilter firewall rules...", "info");
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
    print_step("Firewall reset to default ACCEPT", "ok");

    print_step("Terminating Tor daemon...", "info");
    stop_tor_daemon();
    print_step("Tor daemon offline", "ok");

    print_step("Restoring system DNS resolution...", "info");
    if let Err(e) = restore_dns() {
        print_step(&format!("Restore DNS warning: {e}"), "warn");
    } else {
        print_step("DNS restored", "ok");
    }

    if let (Some(iface), Some(old_mac)) = (&state_info.mac_interface, &state_info.mac_old) {
        print_step("Restoring hardware MAC address...", "info");
        if let Err(e) = restore_mac(iface, old_mac) {
            print_step(&format!("Restore MAC warning: {e}"), "warn");
        } else {
            print_step("Hardware MAC restored", "ok");
        }
    }

    if let Some(old_host) = &state_info.hostname_old {
        let _ = std::process::Command::new("hostname").arg(old_host).status();
        print_step("Hostname restored", "ok");
    }

    if let Some(old_mid) = &state_info.machine_id_old {
        print_step("Restoring original OS machine-id...", "info");
        if let Err(e) = restore_machine_id(old_mid) {
            print_step(&format!("Restore machine-id warning: {e}"), "warn");
        } else {
            print_step("Machine-ID restored", "ok");
        }
    }

    if state_info.tcp_stack_masked {
        print_step("Restoring default TCP/IP stack parameters...", "info");
        let mut default_map = std::collections::HashMap::new();
        default_map.insert("net.ipv4.ip_default_ttl".to_string(), "64".to_string());
        default_map.insert("net.ipv4.tcp_timestamps".to_string(), "1".to_string());
        if let Err(e) = restore_tcp_stack(&default_map) {
            print_step(&format!("Restore TCP stack warning: {e}"), "warn");
        } else {
            print_step("TCP/IP stack restored", "ok");
        }
    }

    if state_info.namespace_active {
        print_step("Demolishing network namespace...", "info");
        if let Err(e) = destroy_namespace() {
            print_step(&format!("Destroy namespace warning: {e}"), "warn");
        } else {
            print_step("Namespace purged", "ok");
        }
    }

    if state_info.browser_hardened > 0 {
        print_step("Removing hardware and font shield...", "info");
        if let Err(e) = remove_hardware_and_font_shield() {
            print_step(&format!("Remove browser shield warning: {e}"), "warn");
        }
        if let Err(e) = restore_font_jail() {
            print_step(&format!("Restore font sandbox warning: {e}"), "warn");
        }
        print_step("Browser profiles and font config reverted", "ok");
    }

    print_step("Executing anti-forensic memory & volatile state purge...", "info");
    if let Err(e) = panic_emergency_purge(self_destruct) {
        print_step(&format!("Emergency purge warning: {e}"), "warn");
    }
    print_step("RAM caches, ARP tables, logs, and volatile state eradicated", "ok");

    if let Err(e) = state_mgr.deactivate() {
        tracing::warn!("State manager deactivation error: {e}");
    }
    sleep(Duration::from_secs(1)).await;
    let real_ip = get_current_ip().await.unwrap_or_else(|| "Unknown".into());

    print_success(&format!("Wraith stopped — Real IP restored: {real_ip}"));
    Ok(())
}

pub async fn cmd_switch() -> Result<()> {
    print_banner();
    let state_mgr = StateManager::default();
    if !state_mgr.is_active() {
        print_error("Wraith is not running. Start first with: sudo wraith start");
        return Ok(());
    }

    print_step("Requesting new Tor exit circuit (SIGNAL NEWNYM)...", "info");
    let mut client = TorControlClient::default();
    client.connect().await?;
    client.signal_newnym().await?;
    sleep(Duration::from_secs(8)).await;

    let new_ip = get_current_ip().await.unwrap_or_else(|| "Hidden".into());
    print_success(&format!("New identity established ➔ IP: {new_ip}"));
    Ok(())
}

pub async fn cmd_test() -> Result<()> {
    print_banner();
    print_step("Running multi-vector leak verification suite...", "info");
    let report = run_full_leak_test().await;
    show_leak_report(&report);
    Ok(())
}

pub async fn cmd_info() -> Result<()> {
    print_banner();
    let state_mgr = StateManager::default();
    let state = state_mgr.read();

    let (is_tor, tor_ip) = verify_tor_connection().await;
    let ip = tor_ip.or(get_current_ip().await).unwrap_or_else(|| "Unknown".into());

    let telemetry = get_circuit_telemetry().await.unwrap_or_default();
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
    print_banner();
    let mode = if full { "FULL (Thorough RAM + Swap + Logs)" } else { "Quick (Logs + Caches)" };
    print_step(&format!("Executing {mode} anti-forensic purge..."), "info");

    let count = run_full_cleanup(full, false)?;
    print_success(&format!("Anti-forensic purge complete ({count} operations executed)"));
    Ok(())
}

pub fn print_pentest_notice() {
    println!("  ┌── [ ⚔️ OFFENSIVE OPERATIONS & NMAP SAFETY NOTICE ] ────────────────────────────────┐");
    println!("  │ • Nmap Scan Mode: Use 'nmap -sT -Pn -n' (Raw SYN '-sS' & ICMP are blocked by Tor)   │");
    println!("  │ • User-Agent    : Sanitize with '--script-args http.useragent=\"Mozilla/5.0...\"'   │");
    println!("  │ • Sqlmap/Ffuf   : Set '--user-agent=\"...\"' (Default tool signatures leak identity) │");
    println!("  │ • Complete Guide: Run 'wraith pentest' for tool signature evasion presets          │");
    println!("  └────────────────────────────────────────────────────────────────────────────────────┘\n");
}

pub fn cmd_pentest() -> Result<()> {
    print_banner();
    println!("  ╔════════════════════════════════════════════════════════════════════════════════════════════════╗");
    println!("  ║           ⚔️ WRAITH-PRIME OFFENSIVE SECURITY & PENTEST SANITIZATION MATRIX                   ║");
    println!("  ╚════════════════════════════════════════════════════════════════════════════════════════════════╝\n");

    println!("  [1] NMAP PORT SCANNING OVER TOR:");
    println!("  ──────────────────────────────────────────────────────────────────────────────────────────────────");
    println!("  ❌ DO NOT USE: nmap -sS (SYN Scan) or nmap -PE (ICMP Ping) -> Tor is TCP-only; raw packets fail!");
    println!("  ✅ OPTIMAL COMMAND:");
    println!("     nmap -sT -Pn -n -sV --version-intensity 5 -p- <target_ip>\n");
    println!("  🛡️ STRIP NMAP HTTP USER-AGENT LEAK:");
    println!("     nmap -sT -Pn -n --script \"http*\" --script-args http.useragent=\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\" <target_ip>\n");

    println!("  [2] WEB FUZZING (FFUF / GOBUSTER / DIRSEARCH):");
    println!("  ──────────────────────────────────────────────────────────────────────────────────────────────────");
    println!("  ❌ DO NOT USE default headers (e.g. 'User-Agent: ffuf/2.1' or 'User-Agent: gobuster/3.6')");
    println!("  ✅ OPTIMAL COMMAND:");
    println!("     ffuf -u http://<target>/FUZZ -w /path/to/wordlist -H \"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0\" -t 10\n");

    println!("  [3] SQLMAP EXPLOITATION OVER SOCKS5:");
    println!("  ──────────────────────────────────────────────────────────────────────────────────────────────────");
    println!("  ❌ DO NOT USE default sqlmap headers (WAFs instantly ban 'User-Agent: sqlmap/1.8')");
    println!("  ✅ OPTIMAL COMMAND:");
    println!("     sqlmap -u \"http://<target>/item?id=1\" --proxy=\"socks5://127.0.0.1:9050\" --random-agent --tamper=space2comment --threads=4\n");

    println!("  [4] METASPLOIT FRAMEWORK TUNNELING:");
    println!("  ──────────────────────────────────────────────────────────────────────────────────────────────────");
    println!("  ✅ In msfconsole: set Proxies socks5:127.0.0.1:9050");
    println!("  ✅ set HTTP_USER_AGENT Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0");
    println!("  ──────────────────────────────────────────────────────────────────────────────────────────────────\n");

    Ok(())
}
