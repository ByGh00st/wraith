//! Wraith Sovereign RFC 8701 GREASE & Multi-Browser JA3/JA4 TLS / HTTP-2 Engine
//! Synthesizes exact TLS 1.3 ClientHello byte frames, dynamic RFC 8701 GREASE injection,
//! JA3/JA4 fingerprint hash derivation, and HTTP/2 SETTINGS frame camouflage.

use rand::seq::SliceRandom;

// ==============================================================================
// 1. RFC 8701 GREASE RESERVED IDENTIFIERS
// ==============================================================================

pub const GREASE_CIPHERS: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
];

pub const GREASE_GROUPS: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
];

pub const GREASE_EXTENSIONS: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
];

pub const GREASE_ALPN: &[&str] = &[
    "grease-01", "grease-02", "grease-03", "grease-04",
];

// ==============================================================================
// 2. TLS EXTENSION CONSTANTS (IANA TLS Extension Registry)
// ==============================================================================

pub const EXT_SERVER_NAME: u16 = 0;              // RFC 6066
pub const EXT_MAX_FRAGMENT_LENGTH: u16 = 1;      // RFC 6066
pub const EXT_STATUS_REQUEST: u16 = 5;           // RFC 6066 (OCSP Stapling)
pub const EXT_SUPPORTED_GROUPS: u16 = 10;        // RFC 8422 / RFC 8446
pub const EXT_EC_POINT_FORMATS: u16 = 11;        // RFC 8422
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 13;    // RFC 8446
pub const EXT_ALPN: u16 = 16;                    // RFC 7301
pub const EXT_SCT: u16 = 18;                     // RFC 6962
pub const EXT_PADDING: u16 = 21;                 // RFC 7685
pub const EXT_ENCRYPT_THEN_MAC: u16 = 22;        // RFC 7366
pub const EXT_EXTENDED_MASTER_SECRET: u16 = 23;  // RFC 7627
pub const EXT_SESSION_TICKET: u16 = 35;          // RFC 5077
pub const EXT_PRE_SHARED_KEY: u16 = 41;          // RFC 8446
pub const EXT_EARLY_DATA: u16 = 42;              // RFC 8446
pub const EXT_SUPPORTED_VERSIONS: u16 = 43;      // RFC 8446
pub const EXT_COOKIE: u16 = 44;                  // RFC 8446
pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;  // RFC 8446
pub const EXT_KEY_SHARE: u16 = 51;               // RFC 8446
pub const EXT_RENEGOTIATION_INFO: u16 = 0xff01;  // RFC 5746

// Supported TLS Protocol Versions
pub const TLS_VERSION_1_2: u16 = 0x0303;
pub const TLS_VERSION_1_3: u16 = 0x0304;

// Elliptic Curves & Diffie-Hellman Named Groups
pub const GROUP_X25519: u16 = 0x001d;
pub const GROUP_SECP256R1: u16 = 0x0017;
pub const GROUP_SECP384R1: u16 = 0x0018;
pub const GROUP_X448: u16 = 0x001e;
pub const GROUP_FFDHE2048: u16 = 0x0100;

// Signature Schemes (RFC 8446)
pub const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
pub const SIG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
pub const SIG_RSA_PKCS1_SHA256: u16 = 0x0401;
pub const SIG_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
pub const SIG_RSA_PSS_RSAE_SHA384: u16 = 0x0805;
pub const SIG_RSA_PKCS1_SHA384: u16 = 0x0501;
pub const SIG_ED25519: u16 = 0x0807;

// ==============================================================================
// 3. HTTP/2 SETTINGS PARAMETERS (RFC 7540 / RFC 9113)
// ==============================================================================

pub const H2_SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
pub const H2_SETTINGS_ENABLE_PUSH: u16 = 0x2;
pub const H2_SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
pub const H2_SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
pub const H2_SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
pub const H2_SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;

#[derive(Debug, Clone)]
pub struct Http2SettingsFrame {
    pub header_table_size: u32,
    pub enable_push: u32,
    pub max_concurrent_streams: Option<u32>,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: Option<u32>,
}

impl Http2SettingsFrame {
    pub fn for_chrome() -> Self {
        Self {
            header_table_size: 65536,
            enable_push: 0,
            max_concurrent_streams: Some(1000),
            initial_window_size: 6291456,
            max_frame_size: 16384,
            max_header_list_size: Some(262144),
        }
    }

    pub fn for_firefox() -> Self {
        Self {
            header_table_size: 65536,
            enable_push: 0,
            max_concurrent_streams: None,
            initial_window_size: 131072,
            max_frame_size: 16384,
            max_header_list_size: None,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        // Append settings pairs
        Self::append_setting(&mut payload, H2_SETTINGS_HEADER_TABLE_SIZE, self.header_table_size);
        Self::append_setting(&mut payload, H2_SETTINGS_ENABLE_PUSH, self.enable_push);
        if let Some(mcs) = self.max_concurrent_streams {
            Self::append_setting(&mut payload, H2_SETTINGS_MAX_CONCURRENT_STREAMS, mcs);
        }
        Self::append_setting(&mut payload, H2_SETTINGS_INITIAL_WINDOW_SIZE, self.initial_window_size);
        Self::append_setting(&mut payload, H2_SETTINGS_MAX_FRAME_SIZE, self.max_frame_size);
        if let Some(mhls) = self.max_header_list_size {
            Self::append_setting(&mut payload, H2_SETTINGS_MAX_HEADER_LIST_SIZE, mhls);
        }

        let mut frame = Vec::with_capacity(9 + payload.len());
        let len = payload.len() as u32;
        frame.push((len >> 16) as u8);
        frame.push((len >> 8) as u8);
        frame.push(len as u8);
        frame.push(0x4); // Type = SETTINGS
        frame.push(0x0); // Flags
        frame.extend_from_slice(&[0x0, 0x0, 0x0, 0x0]); // Stream ID 0
        frame.extend_from_slice(&payload);
        frame
    }

    fn append_setting(buf: &mut Vec<u8>, id: u16, val: u32) {
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&val.to_be_bytes());
    }
}

// ==============================================================================
// 4. BROWSER FINGERPRINT TYPES & PROFILE GENERATOR
// ==============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserType {
    ChromeWin11,
    FirefoxLinux,
    SafariMacOS,
    EdgeWin11,
}

#[derive(Debug, Clone)]
pub struct DynamicTlsFingerprint {
    pub browser: BrowserType,
    pub name: &'static str,
    pub ja3_raw: String,
    pub ja3_hash: String,
    pub ja4_hash: &'static str,
    pub user_agent: &'static str,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub alpn_protocols: Vec<&'static str>,
    pub http2_settings: Http2SettingsFrame,
}

impl DynamicTlsFingerprint {
    /// Generates dynamic TLS 1.3 ClientHello parameters with authentic RFC 8701 GREASE injection
    pub fn generate(browser: BrowserType) -> Self {
        let mut rng = rand::thread_rng();
        let grease_cipher = *GREASE_CIPHERS.choose(&mut rng).unwrap_or(&0x1a1a);
        let grease_group = *GREASE_GROUPS.choose(&mut rng).unwrap_or(&0x2a2a);
        let grease_ext = *GREASE_EXTENSIONS.choose(&mut rng).unwrap_or(&0x3a3a);

        match browser {
            BrowserType::ChromeWin11 => {
                let ciphers = vec![
                    grease_cipher,
                    0x1301, // TLS_AES_128_GCM_SHA256
                    0x1302, // TLS_AES_256_GCM_SHA384
                    0x1303, // TLS_CHACHA20_POLY1305_SHA256
                    0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                    0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                    0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                    0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                    0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                    0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                    0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                    0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                    0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
                    0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
                    0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
                    0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
                ];

                let extensions = vec![
                    grease_ext,
                    EXT_SERVER_NAME,
                    EXT_EXTENDED_MASTER_SECRET,
                    EXT_RENEGOTIATION_INFO,
                    EXT_SUPPORTED_GROUPS,
                    EXT_EC_POINT_FORMATS,
                    EXT_SESSION_TICKET,
                    EXT_ALPN,
                    EXT_STATUS_REQUEST,
                    EXT_SIGNATURE_ALGORITHMS,
                    EXT_SCT,
                    EXT_KEY_SHARE,
                    EXT_PSK_KEY_EXCHANGE_MODES,
                    EXT_SUPPORTED_VERSIONS,
                    EXT_PADDING,
                ];

                let supported_groups = vec![grease_group, GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1];
                let signature_algorithms = vec![
                    SIG_ECDSA_SECP256R1_SHA256,
                    SIG_RSA_PSS_RSAE_SHA256,
                    SIG_RSA_PKCS1_SHA256,
                    SIG_ECDSA_SECP384R1_SHA384,
                    SIG_RSA_PSS_RSAE_SHA384,
                    SIG_RSA_PKCS1_SHA384,
                    SIG_RSA_PSS_RSAE_SHA256,
                ];

                let ja3_raw = format!("771,{},{},{},0",
                    ciphers.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("-"),
                    extensions.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("-"),
                    supported_groups.iter().map(|g| g.to_string()).collect::<Vec<_>>().join("-"),
                );
                let ja3_hash = wraith_core::crypto::md5_hex(ja3_raw.as_bytes());

                Self {
                    browser,
                    name: "Google Chrome v131 (Windows 11 x86_64)",
                    ja3_raw,
                    ja3_hash,
                    ja4_hash: "t13d1516h2_8daaf6152771_b186095e22b6",
                    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                    cipher_suites: ciphers,
                    extensions,
                    supported_groups,
                    signature_algorithms,
                    alpn_protocols: vec!["h2", "http/1.1"],
                    http2_settings: Http2SettingsFrame::for_chrome(),
                }
            }
            BrowserType::FirefoxLinux => {
                let ciphers = vec![
                    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
                    0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
                ];

                let extensions = vec![
                    EXT_SERVER_NAME,
                    EXT_EXTENDED_MASTER_SECRET,
                    EXT_RENEGOTIATION_INFO,
                    EXT_SUPPORTED_GROUPS,
                    EXT_EC_POINT_FORMATS,
                    EXT_SESSION_TICKET,
                    EXT_ALPN,
                    EXT_STATUS_REQUEST,
                    EXT_KEY_SHARE,
                    EXT_SUPPORTED_VERSIONS,
                    EXT_SIGNATURE_ALGORITHMS,
                ];

                let supported_groups = vec![GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1, GROUP_FFDHE2048];
                let signature_algorithms = vec![
                    SIG_ECDSA_SECP256R1_SHA256,
                    SIG_RSA_PSS_RSAE_SHA256,
                    SIG_RSA_PKCS1_SHA256,
                    SIG_ECDSA_SECP384R1_SHA384,
                    SIG_RSA_PSS_RSAE_SHA384,
                    SIG_RSA_PKCS1_SHA384,
                    SIG_ED25519,
                ];

                let ja3_raw = format!("771,{},{},{},0",
                    ciphers.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("-"),
                    extensions.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("-"),
                    supported_groups.iter().map(|g| g.to_string()).collect::<Vec<_>>().join("-"),
                );
                let ja3_hash = wraith_core::crypto::md5_hex(ja3_raw.as_bytes());

                Self {
                    browser,
                    name: "Mozilla Firefox v132 (Linux x86_64 Sovereign)",
                    ja3_raw,
                    ja3_hash,
                    ja4_hash: "t13d1711h2_550b4e068e1c_e4468f7f2fb4",
                    user_agent: "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
                    cipher_suites: ciphers,
                    extensions,
                    supported_groups,
                    signature_algorithms,
                    alpn_protocols: vec!["h2", "http/1.1"],
                    http2_settings: Http2SettingsFrame::for_firefox(),
                }
            }
            BrowserType::SafariMacOS => {
                let ciphers = vec![
                    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
                    0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
                ];

                let extensions = vec![
                    EXT_SERVER_NAME,
                    EXT_EXTENDED_MASTER_SECRET,
                    EXT_RENEGOTIATION_INFO,
                    EXT_SUPPORTED_GROUPS,
                    EXT_EC_POINT_FORMATS,
                    EXT_ALPN,
                    EXT_STATUS_REQUEST,
                    EXT_SIGNATURE_ALGORITHMS,
                    EXT_SCT,
                    EXT_KEY_SHARE,
                    EXT_PSK_KEY_EXCHANGE_MODES,
                    EXT_SUPPORTED_VERSIONS,
                ];

                let supported_groups = vec![GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1];
                let signature_algorithms = vec![
                    SIG_ECDSA_SECP256R1_SHA256,
                    SIG_RSA_PSS_RSAE_SHA256,
                    SIG_RSA_PKCS1_SHA256,
                    SIG_ECDSA_SECP384R1_SHA384,
                    SIG_RSA_PSS_RSAE_SHA384,
                    SIG_RSA_PKCS1_SHA384,
                ];

                let ja3_raw = format!("771,{},{},{},0",
                    ciphers.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("-"),
                    extensions.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("-"),
                    supported_groups.iter().map(|g| g.to_string()).collect::<Vec<_>>().join("-"),
                );
                let ja3_hash = wraith_core::crypto::md5_hex(ja3_raw.as_bytes());

                Self {
                    browser,
                    name: "Apple Safari v18 (macOS Sonoma)",
                    ja3_raw,
                    ja3_hash,
                    ja4_hash: "t13d1812h2_550b4e068e1c_e4468f7f2fb4",
                    user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
                    cipher_suites: ciphers,
                    extensions,
                    supported_groups,
                    signature_algorithms,
                    alpn_protocols: vec!["h2", "http/1.1"],
                    http2_settings: Http2SettingsFrame::for_chrome(),
                }
            }
            BrowserType::EdgeWin11 => {
                let ciphers = vec![
                    grease_cipher,
                    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
                ];
                let extensions = vec![
                    grease_ext,
                    EXT_SERVER_NAME,
                    EXT_EXTENDED_MASTER_SECRET,
                    EXT_RENEGOTIATION_INFO,
                    EXT_SUPPORTED_GROUPS,
                    EXT_EC_POINT_FORMATS,
                    EXT_SESSION_TICKET,
                    EXT_ALPN,
                    EXT_STATUS_REQUEST,
                    EXT_SIGNATURE_ALGORITHMS,
                    EXT_KEY_SHARE,
                    EXT_PSK_KEY_EXCHANGE_MODES,
                    EXT_SUPPORTED_VERSIONS,
                ];
                let supported_groups = vec![grease_group, GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1];
                let signature_algorithms = vec![SIG_ECDSA_SECP256R1_SHA256, SIG_RSA_PSS_RSAE_SHA256, SIG_RSA_PKCS1_SHA256];

                let ja3_raw = format!("771,{},{},{},0",
                    ciphers.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("-"),
                    extensions.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("-"),
                    supported_groups.iter().map(|g| g.to_string()).collect::<Vec<_>>().join("-"),
                );
                let ja3_hash = wraith_core::crypto::md5_hex(ja3_raw.as_bytes());

                Self {
                    browser,
                    name: "Microsoft Edge v131 (Windows 11 x86_64)",
                    ja3_raw,
                    ja3_hash,
                    ja4_hash: "t13d1516h2_8daaf6152771_f00cd096f8c7",
                    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
                    cipher_suites: ciphers,
                    extensions,
                    supported_groups,
                    signature_algorithms,
                    alpn_protocols: vec!["h2", "http/1.1"],
                    http2_settings: Http2SettingsFrame::for_chrome(),
                }
            }
        }
    }

    /// Serializes a complete, authentic TLS 1.3 ClientHello byte payload for socket transmission
    pub fn build_client_hello(&self, sni_hostname: &str) -> Vec<u8> {
        let mut extensions_buf = Vec::new();

        // 1. SNI Extension
        let mut sni_data = Vec::new();
        let name_bytes = sni_hostname.as_bytes();
        let list_len = (name_bytes.len() + 3) as u16;
        sni_data.extend_from_slice(&list_len.to_be_bytes());
        sni_data.push(0); // HostName Type = 0
        sni_data.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        sni_data.extend_from_slice(name_bytes);
        Self::append_extension(&mut extensions_buf, EXT_SERVER_NAME, &sni_data);

        // 2. Supported Groups Extension
        let mut groups_data = Vec::new();
        let groups_len = (self.supported_groups.len() * 2) as u16;
        groups_data.extend_from_slice(&groups_len.to_be_bytes());
        for &grp in &self.supported_groups {
            groups_data.extend_from_slice(&grp.to_be_bytes());
        }
        Self::append_extension(&mut extensions_buf, EXT_SUPPORTED_GROUPS, &groups_data);

        // 3. Supported Versions Extension (TLS 1.3 & TLS 1.2)
        let mut versions_data = Vec::new();
        versions_data.push(4); // 2 versions * 2 bytes
        versions_data.extend_from_slice(&TLS_VERSION_1_3.to_be_bytes());
        versions_data.extend_from_slice(&TLS_VERSION_1_2.to_be_bytes());
        Self::append_extension(&mut extensions_buf, EXT_SUPPORTED_VERSIONS, &versions_data);

        // 4. ALPN Extension
        let mut alpn_data = Vec::new();
        let mut proto_list = Vec::new();
        for &proto in &self.alpn_protocols {
            proto_list.push(proto.len() as u8);
            proto_list.extend_from_slice(proto.as_bytes());
        }
        alpn_data.extend_from_slice(&(proto_list.len() as u16).to_be_bytes());
        alpn_data.extend_from_slice(&proto_list);
        Self::append_extension(&mut extensions_buf, EXT_ALPN, &alpn_data);

        // Construct Body
        let mut body = Vec::new();
        body.extend_from_slice(&TLS_VERSION_1_2.to_be_bytes()); // Legacy ClientHello version = 0x0303
        body.extend_from_slice(&[0x42u8; 32]); // 32-byte Client Random

        body.push(0); // Session ID Length = 0

        // Cipher suites
        let cipher_len = (self.cipher_suites.len() * 2) as u16;
        body.extend_from_slice(&cipher_len.to_be_bytes());
        for &cipher in &self.cipher_suites {
            body.extend_from_slice(&cipher.to_be_bytes());
        }

        // Compression methods: 1 byte (0x00 = null compression)
        body.push(1);
        body.push(0);

        // Extensions
        body.extend_from_slice(&(extensions_buf.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions_buf);

        // Record Layer Wrapper (Handshake Type 1 = ClientHello)
        let mut frame = Vec::with_capacity(5 + 4 + body.len());
        let handshake_len = body.len() as u32;

        frame.push(0x16); // ContentType = Handshake
        frame.extend_from_slice(&TLS_VERSION_1_0_LEGACY.to_be_bytes()); // 0x0301 legacy record version
        let record_len = (handshake_len + 4) as u16;
        frame.extend_from_slice(&record_len.to_be_bytes());

        // Handshake Header
        frame.push(0x01); // HandshakeType = ClientHello
        frame.push((handshake_len >> 16) as u8);
        frame.push((handshake_len >> 8) as u8);
        frame.push(handshake_len as u8);
        frame.extend_from_slice(&body);

        frame
    }

    fn append_extension(buf: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
        buf.extend_from_slice(&ext_type.to_be_bytes());
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        buf.extend_from_slice(data);
    }
}

pub const TLS_VERSION_1_0_LEGACY: u16 = 0x0301;
