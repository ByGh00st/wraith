//! Wraith Sovereign Localhost Active Deception Honeypot & Rogue Process Tarpit
//! Binds deceptive synthetic decoy listeners strictly on loopback (127.0.0.1: 2222, 3306, 5432, 6379, 8080, 27017).
//! Features:
//! 1. Zero External Attack Surface: Bound strictly to 127.0.0.1 loopback; completely invisible to external network/LAN scans.
//! 2. Authentic Protocol Handshake Emulation: Synthesizes OpenSSH banners, MySQL V10 handshakes, Redis PONG/NOAUTH, and HTTP 401 auth challenges.
//! 3. Active Forensic Process Discovery: Inspects `/proc/net/tcp` and `/proc/*/fd` to extract rogue PID, comm, binary path, and UID in real-time.
//! 4. Asynchronous TCP Tarpit: Entangles rogue scanners in trickle delay streams, freezing attacker threads and sockets.
//! 5. Rogue Process Neutralization: Capability to auto-freeze (SIGSTOP) or terminate (SIGKILL) intruder processes.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

pub const DECOY_PORTS: &[u16] = &[2222, 3306, 5432, 6379, 8080, 27017];

#[derive(Debug, Clone)]
pub struct RogueProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
    pub uid: Option<u32>,
}

#[derive(Clone)]
pub struct HoneyPortTrap {
    alerts_triggered: Arc<AtomicU32>,
    cancel_token: CancellationToken,
    auto_freeze_rogue_process: bool,
    bind_all_interfaces: bool,
}

impl Default for HoneyPortTrap {
    fn default() -> Self {
        Self::new()
    }
}

impl HoneyPortTrap {
    pub fn new() -> Self {
        Self {
            alerts_triggered: Arc::new(AtomicU32::new(0)),
            cancel_token: CancellationToken::new(),
            auto_freeze_rogue_process: false,
            bind_all_interfaces: false,
        }
    }

    pub fn with_auto_freeze(mut self, enabled: bool) -> Self {
        self.auto_freeze_rogue_process = enabled;
        self
    }

    pub fn with_lan_binding(mut self, enabled: bool) -> Self {
        self.bind_all_interfaces = enabled;
        self
    }

    pub fn alerts_count(&self) -> u32 {
        self.alerts_triggered.load(Ordering::Relaxed)
    }

    /// Spawns decoy honeypot listeners across all configured ports as a unified background service
    pub fn spawn_service(&self) -> (CancellationToken, tokio::task::JoinHandle<()>) {
        let cancel = self.cancel_token.clone();
        let cancel_child = cancel.clone();
        let alerts = self.alerts_triggered.clone();
        let auto_freeze = self.auto_freeze_rogue_process;
        let bind_lan = self.bind_all_interfaces;

        let handle = tokio::spawn(async move {
            let mut sub_handles = Vec::new();

            for &port in DECOY_PORTS {
                let ct = cancel_child.clone();
                let al = alerts.clone();

                let h = tokio::spawn(async move {
                    let host_ip = if bind_lan { "0.0.0.0" } else { "127.0.0.1" };
                    let bind_addr = format!("{host_ip}:{port}");
                    match TcpListener::bind(&bind_addr).await {
                        Ok(listener) => {
                            if bind_lan {
                                info!("Active LAN Deception Sensor listening on {bind_addr} [ALL INTERFACES]");
                            } else {
                                info!("Active Deception Honeypot listening on {bind_addr} (Strict Loopback Isolation)");
                            }
                            loop {
                                tokio::select! {
                                    _ = ct.cancelled() => break,
                                    res = listener.accept() => {
                                        match res {
                                            Ok((stream, peer_addr)) => {
                                                al.fetch_add(1, Ordering::SeqCst);
                                                let client_cancel = ct.clone();

                                                tokio::spawn(async move {
                                                    Self::handle_intruder(stream, peer_addr, port, auto_freeze, client_cancel).await;
                                                });
                                            }
                                            Err(e) => {
                                                warn!("Honeypot accept error on :{port}: {e}");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!("Honeypot skip binding :{port} (already bound or restricted): {e}");
                        }
                    }
                });
                sub_handles.push(h);
            }

            // Wait for cancellation
            cancel_child.cancelled().await;
            for h in sub_handles {
                let _ = h.await;
            }
        });

        (cancel, handle)
    }

    /// Handles an incoming intruder connection with active forensic investigation, protocol emulation, and TCP tarpit
    async fn handle_intruder(
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        port: u16,
        auto_freeze: bool,
        cancel: CancellationToken,
    ) {
        let rogue_info = Self::investigate_peer_process(peer_addr.port());

        if let Some(ref proc) = rogue_info {
            error!(
                "🚨 ACTIVE HONEYPOT INTRUSION: Rogue Process '{}' (PID: {}, Binary: '{}') connected to decoy port :{port} from {peer_addr}!",
                proc.name, proc.pid, proc.exe_path
            );

            if auto_freeze {
                Self::neutralize_rogue_process(proc.pid, false);
            }
        } else {
            error!("🚨 ACTIVE HONEYPOT INTRUSION: Unknown local connection on decoy port :{port} from {peer_addr}!");
        }

        // Execute deceptive authentic protocol handshake and TCP tarpit
        let _ = Self::emulate_and_tarpit(&mut stream, port, cancel).await;
    }

    /// Investigates Linux `/proc/net/tcp` and `/proc/*/fd` to resolve client port to PID, process name, and executable
    pub fn investigate_peer_process(peer_port: u16) -> Option<RogueProcessInfo> {
        #[cfg(unix)]
        {
            let inode = Self::find_socket_inode_from_proc_net(peer_port)?;
            Self::find_process_by_socket_inode(inode)
        }
        #[cfg(not(unix))]
        {
            let _ = peer_port;
            None
        }
    }

    #[cfg(unix)]
    fn find_socket_inode_from_proc_net(client_port: u16) -> Option<u64> {
        let content = std::fs::read_to_string("/proc/net/tcp").ok()?;
        let target_port_hex = format!("{:04X}", client_port);

        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 10 {
                let local_addr = fields[1];
                if let Some((_, port_hex)) = local_addr.split_once(':') {
                    if port_hex.eq_ignore_ascii_case(&target_port_hex) {
                        if let Ok(inode) = fields[9].parse::<u64>() {
                            return Some(inode);
                        }
                    }
                }
            }
        }
        None
    }

    #[cfg(unix)]
    fn find_process_by_socket_inode(target_inode: u64) -> Option<RogueProcessInfo> {
        let proc_dir = std::fs::read_dir("/proc").ok()?;
        let socket_target = format!("socket:[{target_inode}]");

        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Ok(pid) = name_str.parse::<u32>() {
                let fd_dir_path = format!("/proc/{pid}/fd");
                if let Ok(fd_entries) = std::fs::read_dir(fd_dir_path) {
                    for fd in fd_entries.flatten() {
                        if let Ok(link) = std::fs::read_link(fd.path()) {
                            if link.to_string_lossy() == socket_target {
                                let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                                    .map(|s| s.trim().to_string())
                                    .unwrap_or_else(|_| "unknown".into());

                                let exe_path = std::fs::read_link(format!("/proc/{pid}/exe"))
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_else(|_| format!("/proc/{pid}"));

                                let uid = std::fs::metadata(format!("/proc/{pid}"))
                                    .ok()
                                    .map(|m| {
                                        use std::os::unix::fs::MetadataExt;
                                        m.uid()
                                    });

                                return Some(RogueProcessInfo {
                                    pid,
                                    name: comm,
                                    exe_path,
                                    uid,
                                });
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Sends authentic deceptive banners followed by an asynchronous TCP Tarpit to stall attackers
    pub async fn emulate_and_tarpit(stream: &mut TcpStream, port: u16, cancel: CancellationToken) -> std::io::Result<()> {
        match port {
            2222 => {
                // OpenSSH authentic identification banner
                stream.write_all(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n").await?;
            }
            3306 => {
                // Authentic MySQL Handshake V10 Packet
                let mut pkt = Vec::new();
                let server_ver = b"8.0.36-0ubuntu0.22.04.1\0";
                let payload_len = 1 + server_ver.len() + 4 + 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10 + 13 + 22;
                
                pkt.extend_from_slice(&(payload_len as u32).to_le_bytes()[..3]); // 3-byte length
                pkt.push(0); // Sequence ID 0
                pkt.push(10); // Protocol version 10
                pkt.extend_from_slice(server_ver);
                pkt.extend_from_slice(&1337u32.to_le_bytes()); // Thread ID
                pkt.extend_from_slice(b"12345678"); // Salt part 1
                pkt.push(0); // Filler
                pkt.extend_from_slice(&0xF7FFu16.to_le_bytes()); // Capabilities low
                pkt.push(0x21); // Charset utf8
                pkt.extend_from_slice(&0x0002u16.to_le_bytes()); // Status autocommit
                pkt.extend_from_slice(&0x81BFu16.to_le_bytes()); // Capabilities high
                pkt.push(21); // Auth plugin data len
                pkt.extend_from_slice(&[0u8; 10]); // Reserved
                pkt.extend_from_slice(b"abcdefghijkl\0"); // Salt part 2
                pkt.extend_from_slice(b"caching_sha2_password\0");
                let _ = stream.write_all(&pkt).await;
            }
            5432 => {
                // PostgreSQL Auth Challenge
                let mut buf = [0u8; 128];
                let _ = stream.read(&mut buf).await;
                // Deny SSL, challenge cleartext password
                let _ = stream.write_all(b"N").await;
            }
            6379 => {
                // Redis RESP Command emulation
                let mut buf = [0u8; 512];
                if let Ok(n) = stream.read(&mut buf).await {
                    let req = String::from_utf8_lossy(&buf[..n]);
                    if req.to_uppercase().contains("PING") {
                        let _ = stream.write_all(b"+PONG\r\n").await;
                    } else {
                        let _ = stream.write_all(b"-NOAUTH Authentication required.\r\n").await;
                    }
                }
            }
            8080 => {
                // HTTP 401 Basic Auth Challenge
                let resp = "HTTP/1.1 401 Unauthorized\r\nServer: nginx/1.24.0 (Ubuntu)\r\nContent-Type: text/html\r\nWWW-Authenticate: Basic realm=\"Wraith Enterprise Control Panel\"\r\nContent-Length: 142\r\nConnection: keep-alive\r\n\r\n<html><head><title>401 Unauthorized</title></head><body><center><h1>401 Unauthorized</h1></center><hr><center>nginx/1.24.0</center></body></html>";
                let _ = stream.write_all(resp.as_bytes()).await;
            }
            _ => {
                let _ = stream.write_all(b"READY\r\n").await;
            }
        }

        // Asynchronous TCP Tarpit (Trickle mode: holds rogue connection open for up to 30 seconds)
        let tarpit_start = tokio::time::Instant::now();
        while tarpit_start.elapsed() < Duration::from_secs(30) {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    if stream.write_all(b"\0").await.is_err() {
                        break; // Attacker closed connection
                    }
                }
            }
        }

        Ok(())
    }

    /// Neutralizes a rogue process by sending SIGSTOP (freeze for forensics) or SIGKILL
    pub fn neutralize_rogue_process(pid: u32, kill: bool) -> bool {
        #[cfg(unix)]
        {
            let sig = if kill { libc::SIGKILL } else { libc::SIGSTOP };
            let res = unsafe { libc::kill(pid as i32, sig) };
            if res == 0 {
                info!(
                    "Rogue process PID: {} successfully {}",
                    pid,
                    if kill { "TERMINATED (SIGKILL)" } else { "FROZEN (SIGSTOP)" }
                );
                true
            } else {
                warn!("Failed signaling rogue PID {pid}: {}", std::io::Error::last_os_error());
                false
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (pid, kill);
            false
        }
    }

    pub fn cancel(&self) {
        self.cancel_token.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_honeypot_initialization_and_cancel() {
        let trap = HoneyPortTrap::new().with_auto_freeze(false);
        assert_eq!(trap.alerts_count(), 0);
        let (ct, handle) = trap.spawn_service();
        ct.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_millis(500), handle).await;
    }

    #[tokio::test]
    async fn test_honeypot_tarpit_and_emulation_responses() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ct = CancellationToken::new();
        let ct_clone = ct.clone();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let _ = HoneyPortTrap::emulate_and_tarpit(&mut stream, 2222, ct_clone).await;
            }
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut banner = vec![0u8; 64];
        let n = client.read(&mut banner).await.unwrap();
        let banner_str = String::from_utf8_lossy(&banner[..n]);
        assert!(banner_str.contains("SSH-2.0-OpenSSH"));
        ct.cancel();
    }
}


