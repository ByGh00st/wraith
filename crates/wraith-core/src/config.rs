//! Wraith Global Configuration & Constants
//! Production-grade parameters with zero runtime allocation overhead.

pub const TORRC_PATH: &str = "/etc/tor/wraithrc";
pub const RESOLV_PATH: &str = "/etc/resolv.conf";
pub const RESOLV_BACKUP: &str = "/etc/resolv.conf.wraith.bak";
pub const STATE_FILE: &str = "/var/run/wraith.state";
pub const LOG_DIR: &str = "/var/log/wraith";
pub const CONFIG_DIR: &str = "/etc/wraith";
pub const CONFIG_FILE: &str = "/etc/wraith/config.json";

// Tor Network Configuration
pub const TOR_TRANS_PORT: u16 = 9040;
pub const TOR_DNS_PORT: u16 = 5353;
pub const TOR_CONTROL_PORT: u16 = 9051;
pub const TOR_SOCKS_PORT: u16 = 9050;
pub const TOR_USER: &str = "debian-tor";

// Local Subnets for Exemption
pub const LOCAL_NETWORKS: &[&str] = &[
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
];

pub const LOOPBACK_NETWORKS: &[&str] = &["127.0.0.0/8"];

// Public IP & Tor Check Endpoints
pub const IP_CHECK_APIS: &[&str] = &[
    "https://api.ipify.org/?format=json",
    "https://httpbin.org/ip",
    "https://api.myip.com",
];

pub const TOR_CHECK_API: &str = "https://check.torproject.org/api/ip";

pub const DNS_LEAK_TEST_DOMAINS: &[&str] = &[
    "whoami.akamai.net",
    "o-o.myaddr.l.google.com",
];

pub const REQUEST_TIMEOUT_SECS: u64 = 15;
pub const REQUEST_RETRIES: u32 = 3;

// Minimalist High-Performance Torrc Template
pub const TORRC_TEMPLATE: &str = "\
DataDirectory /var/lib/tor
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort 127.0.0.1:{trans_port}
DNSPort 127.0.0.1:{dns_port}
SocksPort 127.0.0.1:9050
ControlPort 127.0.0.1:{control_port}
RunAsDaemon 1
CookieAuthentication 1
CookieAuthFile /run/tor/control.authcookie
CookieAuthFileGroupReadable 1
AvoidDiskWrites 1
";

pub const RESOLV_CONTENT: &str = "nameserver 127.0.0.1\n";
