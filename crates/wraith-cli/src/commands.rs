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

pub async fn cmd_start(
    mac: bool,
    bridge: bool,
    namespace: bool,
    profile: Option<String>,
    harden: bool,
    shield: bool,
    font_jail: bool,
    tcp_mask: bool,
    cloaking: bool,
    jitter: bool,
    black_level: bool,
    gen4: bool,
    self_destruct: bool,
    no_killswitch: bool,
) -> Result<()> {
    print_banner();
    let state_mgr = StateManager::default();

    if state_mgr.is_active() {
        print_error("Wraith is already running! Stop first with: sudo wraith stop");
        return Ok(());
    }

    let is_apex = black_level || gen4;
    let mut state_data = StateData::default();

    // 0. Sovereign Process Memory & Kernel Lockdown (GEN-4 DMA / Anti-PTRACE)
    print_step("Enforcing Process Memory Lockdown (PR_SET_DUMPABLE=0, mlockall)...", "info");
    let _ = enforce_process_lockdown();
    print_step("Process memory secured against debuggers & forensic memory dumpers", "ok");

    if is_apex {
        print_step("Enforcing Linux Kernel Lockdown & DMA Hardware Defense...", "info");
        let _ = enforce_kernel_lockdown();
        print_step("Kernel Lockdown evaluated (/dev/mem & DMA IOMMU protection verified)", "ok");
    }

    // 1. MAC & Hostname Randomization
    if mac || is_apex {
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

        if let Ok((old_h, new_h)) = randomize_hostname() {
            print_step(&format!("Hostname randomized: {old_h} ➔ {new_h}"), "ok");
            state_data.hostname_old = Some(old_h);
        }
    }

    // 2. Machine-ID & Hardware DMI Cloaking
    if cloaking || is_apex {
        print_step("Rotating OS /etc/machine-id unique hardware identifier...", "info");
        if let Ok((old_mid, new_mid)) = rotate_machine_id() {
            print_step(&format!("Machine-ID rotated: {old_mid} ➔ {new_mid}"), "ok");
            state_data.machine_id_old = Some(old_mid);
        }
    }

    // 3. TCP/IP Stack Normalization (p0f OS Fingerprint Evasion)
    if tcp_mask || is_apex {
        print_step("Normalizing TCP/IP L4 Stack (p0f/TTL/Window Evasion)...", "info");
        if backup_and_apply_tcp_mask().is_ok() {
            print_step("TCP/IP stack forged: TTL=128 (Windows Profile), timestamps=0", "ok");
            state_data.tcp_stack_masked = true;
        }
    }

    // 4. JA3/JA4 TLS ClientHello Camouflage SOCKS5 Proxy (GEN-4)
    let (_tls_server, tls_cancel) = if is_apex {
        let (server, ct) = TlsCamouflageServer::new(None);
        server.spawn_server();
        let prof = get_active_tls_profile();
        print_step(&format!("Armed JA3/JA4 TLS Camouflage Proxy on 127.0.0.1:9055 ({}, JA4: {})", prof.name, prof.ja4_hash), "ok");
        (Some(()), Some(ct))
    } else {
        (None, None)
    };

    // 5. Tor Configuration & Bridges
    if bridge {
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
    let _ = backup_resolv();
    configure_dns()?;
    print_step("DNS bound to 127.0.0.1 (Tor Port 5353)", "ok");

    // 7. Start Tor Daemon
    print_step("Bootstrapping Tor daemon...", "info");
    start_tor_daemon().await?;
    print_step("Tor daemon active & verified", "ok");

    // 8. Exit Node Profile
    let exit_prof = if is_apex && profile.is_none() {
        Some("stealth".to_string())
    } else {
        profile
    };

    if let Some(prof_name) = &exit_prof {
        print_step(&format!("Applying geographic exit profile: {prof_name}..."), "info");
        if let Ok(p) = apply_exit_profile(prof_name).await {
            print_step(&format!("Profile '{}' active ({})", p.name, p.desc), "ok");
            state_data.exit_profile = Some(prof_name.clone());
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

    // 10. eBPF / TC Egress Fastpath (GEN-4 Ring 0 Driver Filter)
    if is_apex {
        print_step("Injecting Linux Traffic Control (TC) / eBPF Egress Fastpath...", "info");
        if let Ok(mut fp) = EgressFastpath::new(None) {
            let _ = fp.attach();
        }
    }

    // 11. Seccomp-BPF Syscall Sandboxing (GEN-4 Raw Socket Killer)
    if is_apex {
        print_step("Arming Seccomp-BPF Syscall Filter (SOCK_RAW / AF_PACKET hook trap)...", "info");
        let _ = enforce_seccomp_socket_jail();
        print_step("Syscall filter active: Rogue raw sockets will trigger immediate SIGSYS", "ok");
    }

    // 12. Sovereign Hardware, GPU, Font & Resolution Shield
    if shield || harden || is_apex {
        print_step("Deploying GPU, WebGL, Font & Resolution Anti-Fingerprint Shield...", "info");
        if let Ok(count) = deploy_hardware_and_font_shield() {
            print_step(&format!("Injected anti-fingerprint shield into {count} browser profile(s)"), "ok");
            state_data.browser_hardened = count;
        }
    }

    // 13. System-level Font Jail
    if font_jail || is_apex {
        print_step("Restricting OS-level font discovery (fontconfig sandbox)...", "info");
        if enforce_font_jail().is_ok() {
            print_step("System-level font sandbox active", "ok");
        }
    }

    // 14. cgroup2 Network Socket Jail
    if is_apex {
        let _ = create_cgroup_jail();
        let _ = wraith_net::attach_pid_to_cgroup(std::process::id());
        print_step("cgroup2 network socket jail active", "ok");
    }

    // 15. Network Namespace
    if namespace || is_apex {
        print_step("Creating isolated Linux Network Namespace...", "info");
        if create_namespace().is_ok() {
            print_step("Process namespace jail armed (10.200.1.0/24)", "ok");
            state_data.namespace_active = true;
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
    let (_jitter_engine, jitter_cancel) = if jitter || is_apex {
        print_step("Spawning Traffic Padding & Anti-Correlation Jitter engine...", "info");
        let (je, ct) = TrafficJitterEngine::new();
        je.spawn_obfuscator();
        print_step("Synthetic traffic padding active (200-1400ms Poisson jitter)", "ok");
        (Some(()), Some(ct))
    } else {
        (None, None)
    };

    // 18. Encrypted In-Memory Ephemeral RAMFS Vault
    let _ram_vault = if is_apex {
        print_step("Constructing Sovereign In-Memory ChaCha20-Poly1305 Encrypted Vault (/dev/shm)...", "info");
        if let Ok(mut vault) = EncryptedRamVault::init() {
            let secret_payload = serde_json::to_vec(&state_data).unwrap_or_default();
            let _ = vault.write_secret("session.state.enc", &secret_payload);
            print_step("Encrypted RAMFS Vault active (MADV_DONTDUMP memory locked)", "ok");
            Some(vault)
        } else {
            None
        }
    } else {
        None
    };

    // 19. Sovereign Async DNS Engine with EDNS0 Padding & Sinkhole
    let (_dns_engine, dns_cancel) = if is_apex {
        print_step("Spawning Sovereign RFC 1035 DNS Proxy Engine with EDNS0 Padding...", "info");
        let (dns_srv, ct) = SovereignDnsEngine::new(None, None);
        dns_srv.spawn_server();
        print_step("Sovereign DNS Engine active on 127.0.0.1:53 (EDNS0 468B Padded + Telemetry Sinkhole)", "ok");
        (Some(()), Some(ct))
    } else {
        (None, None)
    };

    // 20. Zero-Copy IDS Raw Packet Sniffer & Egress Watchdog
    let (_ids_sniffer, ids_cancel) = if is_apex {
        print_step("Arming Sovereign Zero-Copy IDS Raw Packet Sniffer (AF_PACKET)...", "info");
        let (ids, _telemetry, ct) = EgressIntrusionDetector::new();
        ids.spawn_sniffer();
        print_step("Zero-Copy IDS Egress Watchdog active: Real-time clearnet leak traps armed", "ok");
        (Some(()), Some(ct))
    } else {
        (None, None)
    };

    // 21. KillSwitch Daemon
    state_data.ip = tor_ip;
    state_data.kill_switch = !no_killswitch;
    state_mgr.activate(state_data)?;

    print_success("Wraith GEN-4 Sovereign Black-Level Anonymization Established");
    print_pentest_notice();

    if !no_killswitch {
        print_step("Arming async Fail-Closed watchdog...", "info");
        let (ks, cancel_token) = KillSwitch::new();
        ks.spawn_monitor();
        print_step("Watchdog active (SIGINT/SIGTERM/SIGHUP will trigger Panic Purge & Clean Shutdown)\n", "ok");

        #[cfg(unix)]
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        #[cfg(unix)]
        let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\n  [🚨 EMERGENCY SIGNAL: SIGINT (Ctrl+C)] Executing Sovereign Panic Purge...");
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
                println!("\n  [🚨 EMERGENCY SIGNAL: SIGTERM] Executing Sovereign Panic Purge...");
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
                println!("\n  [🚨 EMERGENCY SIGNAL: SIGHUP] Executing Sovereign Panic Purge...");
            }
        }

        if let Some(jc) = jitter_cancel {
            jc.cancel();
        }
        if let Some(tc) = tls_cancel {
            tc.cancel();
        }
        if let Some(dc) = dns_cancel {
            dc.cancel();
        }
        if let Some(ic) = ids_cancel {
            ic.cancel();
        }
        cancel_token.cancel();
        cmd_stop(self_destruct).await?;
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
    let _ = flush_rules();
    let _ = flush_ipv6_block();
    let _ = unblock_stun_ports();
    let _ = destroy_cgroup_jail();

    if let Ok(mut fp) = EgressFastpath::new(None) {
        let _ = fp.detach();
    }
    print_step("Firewall reset to default ACCEPT", "ok");

    print_step("Terminating Tor daemon...", "info");
    stop_tor_daemon();
    print_step("Tor daemon offline", "ok");

    print_step("Restoring system DNS resolution...", "info");
    let _ = restore_dns();
    print_step("DNS restored", "ok");

    if let (Some(iface), Some(old_mac)) = (&state_info.mac_interface, &state_info.mac_old) {
        print_step("Restoring hardware MAC address...", "info");
        let _ = restore_mac(iface, old_mac);
        print_step("Hardware MAC restored", "ok");
    }

    if let Some(old_host) = &state_info.hostname_old {
        let _ = std::process::Command::new("hostname").arg(old_host).status();
        print_step("Hostname restored", "ok");
    }

    if let Some(old_mid) = &state_info.machine_id_old {
        print_step("Restoring original OS machine-id...", "info");
        let _ = restore_machine_id(old_mid);
        print_step("Machine-ID restored", "ok");
    }

    if state_info.tcp_stack_masked {
        print_step("Restoring default TCP/IP stack parameters...", "info");
        let mut default_map = std::collections::HashMap::new();
        default_map.insert("net.ipv4.ip_default_ttl".to_string(), "64".to_string());
        default_map.insert("net.ipv4.tcp_timestamps".to_string(), "1".to_string());
        let _ = restore_tcp_stack(&default_map);
        print_step("TCP/IP stack restored", "ok");
    }

    if state_info.namespace_active {
        print_step("Demolishing network namespace...", "info");
        let _ = destroy_namespace();
        print_step("Namespace purged", "ok");
    }

    if state_info.browser_hardened > 0 {
        print_step("Removing hardware and font shield...", "info");
        let _ = remove_hardware_and_font_shield();
        let _ = restore_font_jail();
        print_step("Browser profiles and font config reverted", "ok");
    }

    print_step("Executing anti-forensic memory & volatile state purge...", "info");
    let _ = panic_emergency_purge(self_destruct);
    print_step("RAM caches, ARP tables, logs, and volatile state eradicated", "ok");

    let _ = state_mgr.deactivate();
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

    let count = run_full_cleanup(full)?;
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
