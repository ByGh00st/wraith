#!/usr/bin/env python3
"""Numeric-IP TCP/UDP echo fixture; never uses DNS or proxy environment settings."""
import argparse
import pathlib
import socket
import socketserver
import threading

PAYLOAD = b"wraith-egress-probe"


class TcpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        data = bytearray()
        while len(data) < len(PAYLOAD):
            chunk = self.request.recv(len(PAYLOAD) - len(data))
            if not chunk:
                return
            data.extend(chunk)
        self.request.sendall(data)


class UdpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


def serve(address, port, ready):
    with socketserver.ThreadingTCPServer((address, port), TcpEcho) as tcp:
        with socketserver.ThreadingUDPServer((address, port), UdpEcho) as udp:
            threading.Thread(target=tcp.serve_forever, daemon=True).start()
            pathlib.Path(ready).touch()
            udp.serve_forever()


def reachable(address, port, protocol):
    kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    try:
        with socket.socket(socket.AF_INET, kind) as sock:
            sock.settimeout(2)
            sock.connect((address, port))
            sock.sendall(PAYLOAD)
            data = bytearray()
            while len(data) < len(PAYLOAD):
                chunk = sock.recv(len(PAYLOAD) - len(data))
                if not chunk:
                    return False
                data.extend(chunk)
            return data == PAYLOAD
    except OSError:
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("serve", "reachable", "blocked"))
    parser.add_argument("--address", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--ready")
    args = parser.parse_args()
    socket.inet_pton(socket.AF_INET, args.address)
    if args.mode == "serve":
        if not args.ready:
            parser.error("serve requires --ready")
        serve(args.address, args.port, args.ready)
        return
    for protocol in ("tcp", "udp"):
        observed = reachable(args.address, args.port, protocol)
        if observed != (args.mode == "reachable"):
            raise SystemExit(f"FAIL: {protocol} expected {args.mode}, reachable={observed}")
        print(f"PASS: {protocol} {args.mode} at {args.address}:{args.port}")


if __name__ == "__main__":
    main()
