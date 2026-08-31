//! Wraith Cryptographic & Kernel Subsystem Benchmark Suite
//! Measures real-time throughput (MB/s) and latency of ChaCha20-Poly1305, SHA256, HMAC, and Netlink encoders.

#![allow(dead_code)]

use std::time::Instant;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};
use owo_colors::OwoColorize;
use wraith_core::crypto::{HmacSha256, Sha256};
use wraith_core::vault::chacha20_poly1305_encrypt;
use wraith_guard::dns_engine::DnsPacket;
use wraith_net::netlink::{NetlinkSocket, IFLA_ADDRESS};

#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub engine: &'static str,
    pub iterations: usize,
    pub total_bytes: usize,
    pub elapsed_millis: f64,
    pub throughput_mbs: f64,
    pub ops_per_sec: f64,
}

pub struct BenchmarkSuite;

impl BenchmarkSuite {
    pub fn run_all() -> Vec<BenchmarkResult> {
        let mut results = Vec::new();

        println!("\n  {} {}", "🚀".bright_cyan(), "RUNNING HIGH-PERFORMANCE CRYPTOGRAPHIC & KERNEL BENCHMARKS...".bright_cyan().bold());

        results.push(Self::bench_chacha20_poly1305());
        results.push(Self::bench_sha256());
        results.push(Self::bench_hmac_sha256());
        results.push(Self::bench_dns_parser());
        results.push(Self::bench_netlink_serializer());

        results
    }

    fn bench_chacha20_poly1305() -> BenchmarkResult {
        let key = [0x5au8; 32];
        let nonce = [0xa5u8; 12];
        let aad = b"auth_header";
        let block_size = 64 * 1024; // 64 KB
        let iterations = 2_000;     // 128 MB total
        let data = vec![0x33u8; block_size];

        let start = Instant::now();
        for _ in 0..iterations {
            let _ = chacha20_poly1305_encrypt(&key, &nonce, aad, &data);
        }
        let elapsed = start.elapsed();
        let total_bytes = block_size * iterations;
        let elapsed_secs = elapsed.as_secs_f64();
        let mbs = (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed_secs;
        let ops = iterations as f64 / elapsed_secs;

        BenchmarkResult {
            engine: "ChaCha20-Poly1305 AEAD",
            iterations,
            total_bytes,
            elapsed_millis: elapsed_secs * 1000.0,
            throughput_mbs: mbs,
            ops_per_sec: ops,
        }
    }

    fn bench_sha256() -> BenchmarkResult {
        let block_size = 32 * 1024; // 32 KB
        let iterations = 2_000;     // 64 MB total
        let data = vec![0x55u8; block_size];

        let start = Instant::now();
        for _ in 0..iterations {
            let _ = Sha256::digest(&data);
        }
        let elapsed = start.elapsed();
        let total_bytes = block_size * iterations;
        let elapsed_secs = elapsed.as_secs_f64();
        let mbs = (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed_secs;
        let ops = iterations as f64 / elapsed_secs;

        BenchmarkResult {
            engine: "SHA-256 FIPS Digest",
            iterations,
            total_bytes,
            elapsed_millis: elapsed_secs * 1000.0,
            throughput_mbs: mbs,
            ops_per_sec: ops,
        }
    }

    fn bench_hmac_sha256() -> BenchmarkResult {
        let key = [0x99u8; 32];
        let payload = [0x77u8; 256];
        let iterations = 50_000;

        let start = Instant::now();
        for _ in 0..iterations {
            let _ = HmacSha256::mac(&key, &payload);
        }
        let elapsed = start.elapsed();
        let total_bytes = 256 * iterations;
        let elapsed_secs = elapsed.as_secs_f64();
        let mbs = (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed_secs;
        let ops = iterations as f64 / elapsed_secs;

        BenchmarkResult {
            engine: "HMAC-SHA256 Authenticator",
            iterations,
            total_bytes,
            elapsed_millis: elapsed_secs * 1000.0,
            throughput_mbs: mbs,
            ops_per_sec: ops,
        }
    }

    fn bench_dns_parser() -> BenchmarkResult {
        let mut query = Vec::new();
        query.extend_from_slice(&[0x13, 0x37, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        query.push(5);
        query.extend_from_slice(b"check");
        query.push(10);
        query.extend_from_slice(b"torproject");
        query.push(3);
        query.extend_from_slice(b"org");
        query.push(0);
        query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        let iterations = 100_000;
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = DnsPacket::parse(&query);
        }
        let elapsed = start.elapsed();
        let total_bytes = query.len() * iterations;
        let elapsed_secs = elapsed.as_secs_f64();
        let mbs = (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed_secs;
        let ops = iterations as f64 / elapsed_secs;

        BenchmarkResult {
            engine: "DNS RFC 1035 Zero-Copy Parser",
            iterations,
            total_bytes,
            elapsed_millis: elapsed_secs * 1000.0,
            throughput_mbs: mbs,
            ops_per_sec: ops,
        }
    }

    fn bench_netlink_serializer() -> BenchmarkResult {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let iterations = 100_000;

        let start = Instant::now();
        for _ in 0..iterations {
            let mut buf = Vec::with_capacity(32);
            NetlinkSocket::append_attr(&mut buf, IFLA_ADDRESS, &mac);
        }
        let elapsed = start.elapsed();
        let total_bytes = 12 * iterations;
        let elapsed_secs = elapsed.as_secs_f64();
        let mbs = (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed_secs;
        let ops = iterations as f64 / elapsed_secs;

        BenchmarkResult {
            engine: "Netlink Binary Buffer Encoder",
            iterations,
            total_bytes,
            elapsed_millis: elapsed_secs * 1000.0,
            throughput_mbs: mbs,
            ops_per_sec: ops,
        }
    }

    pub fn print_report(results: &[BenchmarkResult]) {
        let mut table = Table::new();
        table.set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header(vec![
            Cell::new("CRITICAL ENGINE").add_attribute(Attribute::Bold).fg(Color::Cyan),
            Cell::new("ITERATIONS").add_attribute(Attribute::Bold).fg(Color::Cyan),
            Cell::new("LATENCY (TOTAL)").add_attribute(Attribute::Bold).fg(Color::Cyan),
            Cell::new("THROUGHPUT").add_attribute(Attribute::Bold).fg(Color::Green),
            Cell::new("OPS / SECOND").add_attribute(Attribute::Bold).fg(Color::Yellow),
        ]);

        for res in results {
            table.add_row(vec![
                Cell::new(res.engine).add_attribute(Attribute::Bold),
                Cell::new(format!("{}", res.iterations)),
                Cell::new(format!("{:.2} ms", res.elapsed_millis)),
                Cell::new(format!("{:.2} MB/s", res.throughput_mbs)).fg(Color::Green).add_attribute(Attribute::Bold),
                Cell::new(format!("{:.0} ops/s", res.ops_per_sec)).fg(Color::Yellow).add_attribute(Attribute::Bold),
            ]);
        }

        println!("\n{}", table);
    }
}
