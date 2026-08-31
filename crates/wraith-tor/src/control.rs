//! Wraith Async Tor Control Protocol Client
//! Native line-based TCP client for Tor ControlPort with zero external Python/Stem dependency.

use std::fs;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info};
use wraith_core::config::TOR_CONTROL_PORT;
use wraith_core::error::{Result, WraithError};
use zeroize::Zeroize;

pub struct TorControlClient {
    stream: Option<BufReader<TcpStream>>,
    port: u16,
}

impl Default for TorControlClient {
    fn default() -> Self {
        Self::new(TOR_CONTROL_PORT)
    }
}

impl TorControlClient {
    pub fn new(port: u16) -> Self {
        Self { stream: None, port }
    }

    pub async fn connect(&mut self) -> Result<()> {
        let addr = format!("127.0.0.1:{}", self.port);
        let stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| WraithError::Tor(format!("Failed connecting to Tor ControlPort on {addr}: {e}")))?;

        self.stream = Some(BufReader::new(stream));
        self.authenticate().await?;
        Ok(())
    }

    async fn send_command(&mut self, cmd: &str) -> Result<Vec<String>> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| WraithError::Tor("ControlPort stream not connected".into()))?;

        stream
            .write_all(format!("{cmd}\r\n").as_bytes())
            .await
            .map_err(|e| WraithError::Tor(format!("Write error on ControlPort: {e}")))?;

        stream.flush().await?;

        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            let n = stream.read_line(&mut line).await?;
            if n == 0 {
                return Err(WraithError::Tor("EOF received from Tor ControlPort".into()));
            }

            let trimmed = line.trim_end_matches(|c| c == '\r' || c == '\n').to_string();
            let is_end = trimmed.starts_with("250 ") || trimmed.starts_with("250 OK");
            let is_err = trimmed.starts_with("5") || trimmed.starts_with("4");

            lines.push(trimmed.clone());

            if is_err {
                return Err(WraithError::Tor(format!("Tor command '{cmd}' error: {trimmed}")));
            }

            if is_end {
                break;
            }
        }

        Ok(lines)
    }

    pub async fn authenticate(&mut self) -> Result<()> {
        // Attempt cookie authentication first
        let cookie_paths = [
            "/var/run/tor/control.authcookie",
            "/run/tor/control.authcookie",
            "/var/lib/tor/control.authcookie",
        ];

        let mut authenticated = false;

        for path in cookie_paths {
            if Path::new(path).exists() {
                if let Ok(mut cookie_bytes) = fs::read(path) {
                    let hex_cookie = cookie_bytes
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<String>();
                    cookie_bytes.zeroize();

                    if self.send_command(&format!("AUTHENTICATE {hex_cookie}")).await.is_ok() {
                        debug!("Authenticated to Tor via cookie at {path}");
                        authenticated = true;
                        break;
                    }
                }
            }
        }

        if !authenticated {
            // Fallback: blank authentication
            if self.send_command("AUTHENTICATE \"\"").await.is_ok() {
                debug!("Authenticated to Tor with blank credentials");
                authenticated = true;
            }
        }

        if !authenticated {
            return Err(WraithError::Tor("Authentication to Tor ControlPort failed".into()));
        }

        Ok(())
    }

    pub async fn is_alive(&mut self) -> bool {
        self.send_command("GETINFO version").await.is_ok()
    }

    pub async fn signal_newnym(&mut self) -> Result<()> {
        info!("Sending SIGNAL NEWNYM to Tor ControlPort (requesting fresh circuit)");
        self.send_command("SIGNAL NEWNYM").await?;
        Ok(())
    }

    pub async fn signal_hup(&mut self) -> Result<()> {
        info!("Sending SIGNAL HUP to Tor ControlPort (reloading torrc)");
        self.send_command("SIGNAL HUP").await?;
        Ok(())
    }

    pub async fn get_info(&mut self, key: &str) -> Result<String> {
        let lines = self.send_command(&format!("GETINFO {key}")).await?;
        for line in lines {
            if let Some(pos) = line.find('=') {
                return Ok(line[pos + 1..].to_string());
            }
        }
        Ok(String::new())
    }
}
