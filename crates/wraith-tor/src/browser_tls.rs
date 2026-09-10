//! Real browser-profile TLS/HTTP2 connections over Tor, with certificate checks.
//! This client owns the TLS handshake; it does not modify another client's TLS.
use futures_util::StreamExt;
use std::{str::FromStr, time::Duration};
use wraith_core::error::{Result, WraithError};
use wreq_util::Emulation;

#[derive(Debug, Clone, Copy)]
pub enum BrowserProfile {
    Chrome,
    Firefox,
    Safari,
}
impl FromStr for BrowserProfile {
    type Err = WraithError;
    fn from_str(value: &str) -> Result<Self> {
        match value {
            "chrome" => Ok(Self::Chrome),
            "firefox" => Ok(Self::Firefox),
            "safari" => Ok(Self::Safari),
            _ => Err(WraithError::Configuration(
                "TLS profile must be chrome, firefox or safari".into(),
            )),
        }
    }
}

#[derive(Clone)]
pub struct BrowserTlsClient {
    client: wreq::Client,
}
pub struct BrowserResponse {
    pub status: u16,
    pub protocol: String,
    pub body: Vec<u8>,
}

fn network(error: wreq::Error) -> WraithError {
    WraithError::Network(error.without_uri().to_string())
}

pub fn validate_https_url(value: &str) -> Result<url::Url> {
    let url = url::Url::parse(value)
        .map_err(|_| WraithError::Configuration("Invalid HTTPS URL".into()))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port() == Some(0)
    {
        return Err(WraithError::Configuration(
            "Expected HTTPS URL without credentials or fragment".into(),
        ));
    }
    Ok(url)
}

impl BrowserTlsClient {
    pub fn new(profile: BrowserProfile) -> Result<Self> {
        Ok(Self {
            client: Self::builder(profile, wraith_core::config::TOR_SOCKS_PORT)?
                .build()
                .map_err(network)?,
        })
    }

    fn builder(profile: BrowserProfile, socks_port: u16) -> Result<wreq::ClientBuilder> {
        let profile = match profile {
            BrowserProfile::Chrome => Emulation::Chrome131,
            BrowserProfile::Firefox => Emulation::Firefox133,
            BrowserProfile::Safari => Emulation::Safari18,
        };
        Ok(wreq::Client::builder()
            .emulation(profile)
            .no_proxy()
            .proxy(wreq::Proxy::all(format!("socks5h://127.0.0.1:{socks_port}")).map_err(network)?)
            .https_only(true)
            .tls_cert_verification(true)
            .tls_verify_hostname(true)
            .tls_min_version(wreq::tls::TlsVersion::TLS_1_2)
            .redirect(wreq::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(25)))
    }

    pub async fn get(&self, url: &str, maximum: usize) -> Result<BrowserResponse> {
        let url = validate_https_url(url)?;
        self.receive(self.client.get(url.as_str()), maximum).await
    }

    pub async fn post_dns(&self, url: &str, query: &[u8]) -> Result<Vec<u8>> {
        let url = validate_https_url(url)?;
        if !(12..=65535).contains(&query.len()) {
            return Err(WraithError::Network("Invalid DNS query length".into()));
        }
        let response = self
            .receive(
                self.client
                    .post(url.as_str())
                    .header("Accept", "application/dns-message")
                    .header("Content-Type", "application/dns-message")
                    .body(query.to_vec()),
                65535,
            )
            .await?;
        if response.status != 200 || response.body.is_empty() {
            return Err(WraithError::Network(
                "DoH server did not return a DNS answer".into(),
            ));
        }
        Ok(response.body)
    }

    async fn receive(
        &self,
        request: wreq::RequestBuilder,
        maximum: usize,
    ) -> Result<BrowserResponse> {
        if maximum == 0 || maximum > 8 * 1024 * 1024 {
            return Err(WraithError::Configuration(
                "Response limit must be 1 byte to 8 MiB".into(),
            ));
        }
        let response = request.send().await.map_err(network)?;
        let status = response.status().as_u16();
        if response
            .content_length()
            .is_some_and(|length| length > maximum as u64)
        {
            return Err(WraithError::Network(
                "HTTPS response exceeds configured size limit".into(),
            ));
        }
        let protocol = format!("{:?}", response.version());
        let stream = response.bytes_stream();
        futures_util::pin_mut!(stream);
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(network)?;
            if chunk.len() > maximum - body.len() {
                return Err(WraithError::Network(
                    "HTTPS response exceeds configured size limit".into(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(BrowserResponse {
            status,
            protocol,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // A local SOCKS endpoint terminates TLS with a generated certificate. No Tor,
    // Internet access, system trust changes or privileged networking is involved.
    async fn exchange(
        profile: BrowserProfile,
        trust: bool,
        hostname: &str,
        maximum: usize,
    ) -> (bool, Vec<u8>) {
        use tokio_rustls::rustls::{self, pki_types::PrivatePkcs8KeyDer};
        let cert = rcgen::generate_simple_self_signed(vec!["example.test".into()]).unwrap();
        let der = cert.cert.der().clone();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![der.clone()],
                PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
            )
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut builder =
            BrowserTlsClient::builder(profile, listener.local_addr().unwrap().port()).unwrap();
        if trust {
            builder = builder.tls_cert_store(
                wreq::tls::trust::CertStore::builder()
                    .add_der_cert(der.as_ref())
                    .build()
                    .unwrap(),
            );
        }
        let client = BrowserTlsClient {
            client: builder.build().unwrap(),
        };
        let expected_host = hostname.to_owned();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            assert_eq!(socket.read_u8().await.unwrap(), 5);
            let count = socket.read_u8().await.unwrap();
            let mut methods = vec![0; count as usize];
            socket.read_exact(&mut methods).await.unwrap();
            assert!(methods.contains(&0));
            socket.write_all(&[5, 0]).await.unwrap();
            let mut command = [0; 5];
            socket.read_exact(&mut command).await.unwrap();
            assert_eq!(&command[..4], &[5, 1, 0, 3]);
            let mut host = vec![0; command[4] as usize];
            socket.read_exact(&mut host).await.unwrap();
            assert_eq!(host, expected_host.as_bytes()); // Remote DNS, never OS DNS.
            assert_eq!(socket.read_u16().await.unwrap(), 443);
            socket
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            let mut hello = vec![0; 18432];
            loop {
                let n = socket.peek(&mut hello).await.unwrap();
                assert!(n > 0);
                if n >= 5 {
                    let length = 5 + u16::from_be_bytes([hello[3], hello[4]]) as usize;
                    assert!(length <= hello.len());
                    if n >= length {
                        hello.truncate(length);
                        break;
                    }
                }
                tokio::task::yield_now().await;
            }
            let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
            if let Ok(mut tls) = acceptor.accept(socket).await {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") && request.len() < 16384 {
                    match tls.read_u8().await {
                        Ok(byte) => request.push(byte),
                        Err(_) => return hello,
                    }
                }
                assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                    )
                    .await;
                let _ = tls.shutdown().await;
            }
            hello
        });
        let response = client.get(&format!("https://{hostname}/"), maximum).await;
        if let Ok(response) = &response {
            assert_eq!(response.body, b"OK");
            assert_eq!(response.status, 200);
        }
        (response.is_ok(), server.await.unwrap())
    }

    #[tokio::test]
    async fn real_tls_profiles_preserve_trust_hostname_remote_dns_and_response_limits() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut cipher_lists = Vec::new();
            for profile in [
                BrowserProfile::Chrome,
                BrowserProfile::Firefox,
                BrowserProfile::Safari,
            ] {
                let (ok, hello) = exchange(profile, true, "example.test", 1024).await;
                assert!(ok, "trusted profile failed: {profile:?}");
                assert_eq!(hello[0], 22); // TLS handshake record.
                assert_eq!(hello[5], 1); // Actual ClientHello.
                assert!(hello.windows(2).any(|bytes| bytes == b"h2"));
                let cipher_offset = 44 + hello[43] as usize;
                let len =
                    u16::from_be_bytes([hello[cipher_offset], hello[cipher_offset + 1]]) as usize;
                cipher_lists.push(hello[cipher_offset + 2..cipher_offset + 2 + len].to_vec());
            }
            assert_ne!(cipher_lists[0], cipher_lists[1]);
            assert!(
                !exchange(BrowserProfile::Chrome, false, "example.test", 1024)
                    .await
                    .0
            );
            assert!(
                !exchange(BrowserProfile::Chrome, true, "wrong.test", 1024)
                    .await
                    .0
            );
            assert!(
                !exchange(BrowserProfile::Chrome, true, "example.test", 1)
                    .await
                    .0
            );
        })
        .await
        .expect("local TLS exchange stalled");
    }
    #[test]
    fn refuses_plaintext_credentials_fragments_and_invalid_profiles() {
        for url in [
            "http://example.org",
            "https://user:password@example.org",
            "https://example.org/#secret",
            "https://example.org:0/",
        ] {
            assert!(validate_https_url(url).is_err());
        }
        assert!(validate_https_url("https://example.org/dns-query").is_ok());
        assert!("unknown".parse::<BrowserProfile>().is_err());
    }
}
