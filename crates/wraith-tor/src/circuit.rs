//! Wraith Tor Circuit & Telemetry Engine

use serde::{Deserialize, Serialize};
use wraith_core::error::Result;

use crate::control::TorControlClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitInfo {
    pub id: String,
    pub path: Vec<String>,
    pub purpose: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TorTelemetry {
    pub version: String,
    pub circuits: Vec<CircuitInfo>,
    pub bytes_read: u64,
    pub bytes_written: u64,
}

pub async fn get_circuit_telemetry() -> Result<TorTelemetry> {
    let mut client = TorControlClient::default();
    client.connect().await?;

    let version = client.get_info("version").await.unwrap_or_else(|_| "Unknown".into());
    let bytes_read = client
        .get_info("traffic/read")
        .await
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let bytes_written = client
        .get_info("traffic/written")
        .await
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    let raw_circuits = client.get_info("circuit-status").await.unwrap_or_default();
    let mut circuits = Vec::new();

    for line in raw_circuits.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[1] == "BUILT" {
            let id = parts[0].to_string();
            let path_entries = parts[2].split(',').map(|s| s.to_string()).collect();
            let purpose = if parts.len() > 3 {
                parts[3].replace("PURPOSE=", "")
            } else {
                "GENERAL".to_string()
            };

            circuits.push(CircuitInfo {
                id,
                path: path_entries,
                purpose,
            });
        }
    }

    Ok(TorTelemetry {
        version,
        circuits,
        bytes_read,
        bytes_written,
    })
}
