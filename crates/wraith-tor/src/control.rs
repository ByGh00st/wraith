//! Wraith Async Tor Control Protocol Client
//! Native line-based TCP client for Tor ControlPort with zero external Python/Stem dependency.

use std::fs;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info};
use wraith_core::config::TOR_CONTROL_PORT;
use wraith_core::error::{Result, WraithError};
use zeroize::Zeroizing;

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
        if let Err(error) = self.authenticate().await {
            self.stream = None;
            return Err(error);
        }
        Ok(())
    }

    async fn send_command(&mut self, cmd: &str) -> Result<Vec<String>> {
        if cmd.contains(['\r', '\n']) {
            return Err(WraithError::Tor("Control command contains a line break".into()));
        }
        let result = tokio::time::timeout(std::time::Duration::from_secs(3), self.send_command_inner(cmd)).await;
        match result {
            Ok(result) => {
                if result.is_err() { self.stream = None; }
                result
            },
            Err(_) => {
                self.stream = None;
                Err(WraithError::Tor("Control command timed out".into()))
            }
        }
    }

    async fn send_command_inner(&mut self, cmd: &str) -> Result<Vec<String>> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| WraithError::Tor("ControlPort stream not connected".into()))?;

        stream
            .write_all(format!("{cmd}\r\n").as_bytes())
            .await
            .map_err(|e| WraithError::Tor(format!("Write error on ControlPort: {e}")))?;

        stream.flush().await?;

        read_reply(stream).await
    }

    pub async fn authenticate(&mut self) -> Result<()> {
        let cookie = Zeroizing::new(fs::read("/run/wraith-tor/control.authcookie")?);
        if cookie.len() != 32 {
            self.stream = None;
            return Err(WraithError::Tor("Invalid managed Tor authentication cookie".into()));
        }
        let hex = Zeroizing::new(cookie.iter().map(|b| format!("{b:02x}")).collect::<String>());
        let command = Zeroizing::new(format!("AUTHENTICATE {}", hex.as_str()));
        self.send_command(&command).await?;
        debug!("Authenticated with managed Tor cookie");
        Ok(())
    }

    pub async fn is_alive(&mut self) -> bool {
        self.send_command("GETINFO version").await.is_ok()
    }

    pub async fn is_ready(&mut self) -> bool {
        self.get_info("status/circuit-established").await
            .map(|value| value == "1").unwrap_or(false)
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
        if lines.is_empty() {
            return Ok(String::new());
        }

        // Check for multiline response: 250+key= \n lines... \n . \n 250 OK
        if let Some(first_line) = lines.first() {
            if first_line.starts_with(&format!("250+{key}=")) || first_line.starts_with("250+") {
                let mut data_lines = Vec::new();
                for line in &lines[1..] {
                    if line == "." {
                        break;
                    }
                    data_lines.push(if line.starts_with("..") { &line[1..] } else { line.as_str() });
                }
                return Ok(data_lines.join("\n"));
            }
        }

        // Single line response 250-key=val or 250 key=val
        for line in lines {
            if let Some(pos) = line.find('=') {
                let val = line[pos + 1..].trim();
                if !val.is_empty() {
                    return Ok(val.to_string());
                }
            }
        }
        Ok(String::new())
    }
}

// Bound both individual lines and the aggregate response before allocation grows.
async fn read_reply<R: tokio::io::AsyncBufRead + Unpin>(stream: &mut R) -> Result<Vec<String>> {
    const MAX_LINE: u64 = 64 * 1024;
    const MAX_REPLY: usize = 1024 * 1024;
    let mut lines = Vec::new();
    let mut total = 0;
    let mut in_data = false;
    loop {
        let mut bytes = Vec::new();
        let n = (&mut *stream).take(MAX_LINE + 1).read_until(b'\n', &mut bytes).await?;
        total += n;
        if n == 0 || n > MAX_LINE as usize || total > MAX_REPLY || lines.len() >= 4096 || !bytes.ends_with(b"\r\n") {
            return Err(WraithError::Tor("Incomplete or oversized control reply".into()));
        }
        let line = String::from_utf8(bytes[..bytes.len()-2].to_vec())
            .map_err(|_| WraithError::Tor("Invalid control reply encoding".into()))?;
        if in_data {
            if line == "." { in_data = false; }
            lines.push(line);
            continue;
        }
        let code = line.get(..3).unwrap_or("");
        let separator = line.as_bytes().get(3).copied();
        if !code.bytes().all(|b| b.is_ascii_digit()) || code.len() != 3 || !matches!(separator, Some(b' ' | b'-' | b'+')) {
            return Err(WraithError::Tor("Malformed control reply status".into()));
        }
        if code != "250" {
            return Err(WraithError::Tor(format!("Tor control command rejected: {code}")));
        }
        in_data = separator == Some(b'+');
        lines.push(line);
        if separator == Some(b' ') { return Ok(lines); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn multiline_data_is_not_a_status_and_dot_stuffing_is_preserved() {
        let mut input = &b"250+key=\r\n500 this is data\r\n..dot\r\n.\r\n250 OK\r\n"[..];
        let lines = read_reply(&mut input).await.unwrap();
        assert_eq!(&lines[1..3], &["500 this is data", "..dot"]);
    }
    #[tokio::test]
    async fn oversized_and_incomplete_replies_fail() {
        let bytes = vec![b'a'; 65538];
        assert!(read_reply(&mut bytes.as_slice()).await.is_err());
        assert!(read_reply(&mut &b"250+key=\r\nunfinished"[..]).await.is_err());
        assert!(read_reply(&mut &b"250 OK\n"[..]).await.is_err());
        assert!(read_reply(&mut &b"515 Bad authentication\r\n"[..]).await.is_err());
    }
}
