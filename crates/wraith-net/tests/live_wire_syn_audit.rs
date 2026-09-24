//! Opt-in native wire audit. The parent launches an isolated mount+network
//! sandbox; no Tor, public destination, host interface or host firewall is used.

#[test]
#[ignore = "requires Linux root, unshare/mount, iproute2, iptables and AF_PACKET"]
fn live_wire_syn_audit() {
    #[cfg(target_os = "linux")]
    linux::run();
    #[cfg(not(target_os = "linux"))]
    panic!("The live SYN audit requires a Linux kernel");
}

#[cfg(target_os = "linux")]
mod linux {
    use etherparse::{NetSlice, SlicedPacket, TcpOptionElement, TransportSlice};
    use socket2::{Domain, Protocol, Socket, Type};
    use std::{
        fs,
        io::Read,
        net::{Ipv4Addr, SocketAddrV4},
        os::unix::fs::MetadataExt,
        path::Path,
        process::{Child, Command},
        time::{Duration, Instant},
    };
    use wraith_core::TcpFingerprintProfile;
    use wraith_net::namespace::{NAMESPACE_NAME, VETH_HOST, VETH_NS};

    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn wait(child: &mut ChildGuard) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.0.try_wait().expect("wait for audit child") {
                assert!(status.success(), "audit child failed: {status}");
                return;
            }
            assert!(Instant::now() < deadline, "audit child timed out");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    fn command(program: &str, args: &[&str]) {
        let output = Command::new(program)
            .args(args)
            .output()
            .expect("spawn audit command");
        assert!(
            output.status.success(),
            "{program} {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fn identity(path: &str) -> String {
        let metadata = fs::metadata(path).expect("namespace identity");
        format!("{}:{}", metadata.dev(), metadata.ino())
    }
    fn test_command() -> Command {
        let mut cmd = Command::new(std::env::current_exe().expect("test binary"));
        cmd.args([
            "--exact",
            "live_wire_syn_audit",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ]);
        cmd
    }

    pub fn run() {
        assert!(
            nix::unistd::Uid::effective().is_root(),
            "run the ignored audit with sudo -E"
        );
        match std::env::var("WRAITH_WIRE_STAGE").as_deref() {
            Ok("sandbox") => sandbox(),
            Ok("trigger") => trigger(),
            Ok(other) => panic!("unknown internal audit stage: {other}"),
            Err(_) => {
                let directory = tempfile::Builder::new()
                    .prefix("wraith-wire-audit-")
                    .tempdir()
                    .unwrap();
                let mut cmd = Command::new("unshare");
                cmd.args(["--mount", "--net", "--fork", "--kill-child", "--"])
                    .arg(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "live_wire_syn_audit",
                        "--ignored",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env("WRAITH_WIRE_STAGE", "sandbox")
                    .env("WRAITH_WIRE_ROOT", directory.path())
                    .env("WRAITH_WIRE_PARENT_NET", identity("/proc/self/ns/net"))
                    .env("WRAITH_WIRE_PARENT_MNT", identity("/proc/self/ns/mnt"));
                wait(&mut ChildGuard(cmd.spawn().expect("unshare is required")));
            }
        }
    }

    fn sandbox() {
        // Refuse direct stage invocation before any mount or network mutation.
        assert_ne!(
            identity("/proc/self/ns/net"),
            std::env::var("WRAITH_WIRE_PARENT_NET").unwrap()
        );
        assert_ne!(
            identity("/proc/self/ns/mnt"),
            std::env::var("WRAITH_WIRE_PARENT_MNT").unwrap()
        );
        let root_string = std::env::var("WRAITH_WIRE_ROOT").unwrap();
        let root = Path::new(&root_string);
        command("mount", &["--make-rprivate", "/"]);
        // Preserve canonical tool targets before hiding /etc/alternatives.
        let bin = root.join("bin");
        fs::create_dir(&bin).unwrap();
        for tool in ["iptables", "ip6tables", "iptables-save", "ip6tables-save"] {
            let path = std::env::split_paths(&std::env::var_os("PATH").unwrap())
                .map(|directory| directory.join(tool))
                .find(|path| path.is_file())
                .expect("Netfilter tools required");
            std::os::unix::fs::symlink(fs::canonicalize(path).unwrap(), bin.join(tool)).unwrap();
        }
        let mut paths = vec![bin];
        paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
        std::env::set_var("PATH", std::env::join_paths(paths).unwrap());
        for (name, target) in [("etc", "/etc"), ("run", "/run"), ("var-lib", "/var/lib")] {
            let directory = root.join(name);
            fs::create_dir(&directory).unwrap();
            command("mount", &["--bind", directory.to_str().unwrap(), target]);
        }
        fs::write("/etc/resolv.conf", "").unwrap();
        command("ip", &["link", "set", "lo", "up"]);
        let profile = TcpFingerprintProfile::windows11(); // --morph-l4 windows uses this same profile.
        let snapshot = wraith_net::namespace::create_namespace_with_l4_profile(&profile)
            .expect("production namespace/profile setup");
        assert!(
            wraith_net::inspect_tcp_stack(&snapshot)
                .unwrap()
                .matches_profile
        );
        assert_eq!(
            wraith_net::inspect_tcp_stack(&snapshot)
                .unwrap()
                .route
                .unwrap()
                .init_rwnd,
            44
        );
        let (expected_mac, actual_mac, matches) =
            wraith_net::recovery::inspect_namespace_mac().unwrap();
        assert!(matches);
        assert_eq!(expected_mac, actual_mac);

        let mut capture = Socket::new(
            Domain::PACKET,
            Type::RAW,
            Some(Protocol::from(i32::from((libc::ETH_P_ALL as u16).to_be()))),
        )
        .expect("AF_PACKET capture");
        capture.bind_device(Some(VETH_HOST.as_bytes())).unwrap();
        capture
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut command = Command::new("ip");
        command
            .args(["netns", "exec", NAMESPACE_NAME])
            .arg(std::env::current_exe().unwrap())
            .args(test_command().get_args())
            .env("WRAITH_WIRE_STAGE", "trigger");
        let mut child = ChildGuard(command.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut frame = [0u8; 65536];
        let mut audited = false;
        while Instant::now() < deadline {
            let count = match capture.read(&mut frame) {
                Ok(count) => count,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    continue
                }
                Err(e) => panic!("capture failed: {e}"),
            };
            let Ok(packet) = SlicedPacket::from_ethernet(&frame[..count]) else {
                continue;
            };
            let (Some(NetSlice::Ipv4(ip)), Some(TransportSlice::Tcp(tcp))) =
                (packet.net, packet.transport)
            else {
                continue;
            };
            if ip.header().source_addr() != Ipv4Addr::new(10, 200, 1, 2)
                || ip.header().destination_addr() != Ipv4Addr::new(198, 18, 0, 1)
                || tcp.destination_port() != 443
                || !tcp.syn()
                || tcp.ack()
            {
                continue;
            }
            assert_eq!(ip.header().ttl(), 128);
            assert!(tcp.syn() && !tcp.ack());
            let options: Vec<_> = tcp
                .options_iterator()
                .map(|value| value.expect("valid TCP options"))
                .collect();
            assert!(options.contains(&TcpOptionElement::MaximumSegmentSize(1460)));
            assert!(!options
                .iter()
                .any(|option| matches!(option, TcpOptionElement::Timestamp(_, _))));
            // Controlled fixture: MTU 1500, MSS 1460, sufficient receive buffer,
            // and default-route initrwnd 44. This is not a universal OS window.
            assert_eq!(
                tcp.window_size(),
                64240,
                "kernel window differs from the controlled initrwnd=44 fixture"
            );
            let source_mac = frame[6..12]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":");
            assert_eq!(source_mac, expected_mac);
            assert_eq!(frame[6] & 3, 2);
            println!(
                "Captured SYN: TTL=128 MSS=1460 TS=absent WIN={} MAC={source_mac}",
                tcp.window_size()
            );
            audited = true;
            break;
        }
        assert!(audited, "no matching wire SYN captured before deadline");
        wait(&mut child);
        drop(capture);
        wraith_net::namespace::destroy_namespace().expect("owned audit cleanup");
        // Exercise the idempotent orphan preflight in the same isolated sandbox.
        wraith_net::recovery::recover_orphaned_state().unwrap();
        wraith_net::recovery::recover_orphaned_state().unwrap();
    }

    fn trigger() {
        command("ip", &["link", "show", "dev", VETH_NS]);
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        socket.set_recv_buffer_size(256 * 1024).unwrap();
        socket.set_nonblocking(true).unwrap();
        let destination = SocketAddrV4::new(Ipv4Addr::new(198, 18, 0, 1), 443);
        let result = socket.connect(&destination.into());
        assert!(
            result.is_ok()
                || result
                    .as_ref()
                    .err()
                    .is_some_and(|e| e.raw_os_error() == Some(libc::EINPROGRESS))
        );
        // Let ARP resolve and send the queued SYN; finish before a retransmit.
        std::thread::sleep(Duration::from_millis(300));
    }
}
