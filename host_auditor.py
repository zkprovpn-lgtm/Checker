#!/usr/bin/env python3
"""
Authorized Host Auditor
For educational use on systems you own or are explicitly allowed to test.

Checks:
- DNS resolution
- TCP ports
- HTTP/HTTPS response
- TLS certificate info
- Optional WebSocket upgrade test

Usage:
    python host_auditor.py --targets example.com,1.2.3.4 --ports 80,443,22
    python host_auditor.py --file targets.txt --ports 80,443 --ws-path /ws
"""

import argparse
import json
import socket
import ssl
import sys
import time
from datetime import datetime
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("Missing dependency: requests")
    print("Install with: pip install requests")
    sys.exit(1)


DEFAULT_TIMEOUT = 5


def normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        return target

    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target

    if "/" in target:
        return target.split("/")[0]

    return target


def resolve_dns(host: str):
    result = {
        "host": host,
        "resolved": False,
        "addresses": [],
        "error": None,
    }
    try:
        infos = socket.getaddrinfo(host, None)
        addrs = sorted(set(info[4][0] for info in infos))
        result["resolved"] = True
        result["addresses"] = addrs
    except Exception as e:
        result["error"] = str(e)
    return result


def check_port(host: str, port: int, timeout: int = DEFAULT_TIMEOUT):
    result = {
        "port": port,
        "open": False,
        "latency_ms": None,
        "error": None,
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    start = time.time()
    try:
        sock.connect((host, port))
        end = time.time()
        result["open"] = True
        result["latency_ms"] = round((end - start) * 1000, 2)
    except Exception as e:
        result["error"] = str(e)
    finally:
        sock.close()

    return result


def get_http_status(host: str, use_https: bool = False, timeout: int = DEFAULT_TIMEOUT):
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}/"
    result = {
        "url": url,
        "ok": False,
        "status_code": None,
        "server": None,
        "content_type": None,
        "error": None,
    }
    try:
        r = requests.get(url, timeout=timeout, verify=use_https, allow_redirects=True)
        result["ok"] = True
        result["status_code"] = r.status_code
        result["server"] = r.headers.get("Server")
        result["content_type"] = r.headers.get("Content-Type")
    except Exception as e:
        result["error"] = str(e)
    return result


def get_tls_info(host: str, port: int = 443, timeout: int = DEFAULT_TIMEOUT):
    result = {
        "host": host,
        "port": port,
        "success": False,
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "error": None,
    }

    context = ssl.create_default_context()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        result["success"] = True
        result["subject"] = dict(x[0] for x in cert.get("subject", []))
        result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
        result["not_before"] = cert.get("notBefore")
        result["not_after"] = cert.get("notAfter")

        if result["not_after"]:
            expiry = datetime.strptime(result["not_after"], "%b %d %H:%M:%S %Y %Z")
            result["days_remaining"] = (expiry - datetime.utcnow()).days

    except Exception as e:
        result["error"] = str(e)

    return result


def websocket_upgrade_test(host: str, port: int = 80, path: str = "/", use_tls: bool = False, timeout: int = DEFAULT_TIMEOUT):
    result = {
        "host": host,
        "port": port,
        "path": path,
        "use_tls": use_tls,
        "success": False,
        "status_line": None,
        "headers": [],
        "error": None,
    }

    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode()

    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)

        if use_tls:
            context = ssl.create_default_context()
            sock = context.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        with sock:
            sock.settimeout(timeout)
            sock.sendall(request)
            response = sock.recv(4096).decode(errors="replace")

        lines = response.split("\r\n")
        if lines:
            result["status_line"] = lines[0]
            result["headers"] = [line for line in lines[1:] if line.strip()]
            if "101" in lines[0]:
                result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


def audit_target(host: str, ports, ws_path=None):
    report = {
        "target": host,
        "dns": resolve_dns(host),
        "ports": [],
        "http": None,
        "https": None,
        "tls": None,
        "websocket": None,
    }

    for port in ports:
        report["ports"].append(check_port(host, port))

    if 80 in ports:
        report["http"] = get_http_status(host, use_https=False)

    if 443 in ports:
        report["https"] = get_http_status(host, use_https=True)
        report["tls"] = get_tls_info(host, 443)

    if ws_path:
        if 443 in ports:
            report["websocket"] = websocket_upgrade_test(host, port=443, path=ws_path, use_tls=True)
        elif 80 in ports:
            report["websocket"] = websocket_upgrade_test(host, port=80, path=ws_path, use_tls=False)

    return report


def print_summary(report):
    print("=" * 70)
    print(f"Target: {report['target']}")

    dns = report["dns"]
    if dns["resolved"]:
        print(f"DNS: OK -> {', '.join(dns['addresses'])}")
    else:
        print(f"DNS: FAILED -> {dns['error']}")

    print("Ports:")
    for port_info in report["ports"]:
        status = "OPEN" if port_info["open"] else "CLOSED"
        extra = f"{port_info['latency_ms']} ms" if port_info["latency_ms"] is not None else port_info["error"]
        print(f"  - {port_info['port']}: {status} ({extra})")

    if report["http"]:
        h = report["http"]
        print(f"HTTP:  {'OK' if h['ok'] else 'FAILED'} -> {h['status_code'] or h['error']}")

    if report["https"]:
        h = report["https"]
        print(f"HTTPS: {'OK' if h['ok'] else 'FAILED'} -> {h['status_code'] or h['error']}")

    if report["tls"]:
        t = report["tls"]
        if t["success"]:
            print(f"TLS: OK -> expires in {t['days_remaining']} day(s)")
        else:
            print(f"TLS: FAILED -> {t['error']}")

    if report["websocket"]:
        w = report["websocket"]
        print(f"WebSocket: {'OK' if w['success'] else 'FAILED'} -> {w['status_line'] or w['error']}")


def parse_targets(args):
    targets = []

    if args.targets:
        targets.extend([normalize_target(x) for x in args.targets.split(",") if x.strip()])

    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(normalize_target(line))
        except Exception as e:
            print(f"Failed to read file: {e}")
            sys.exit(1)

    targets = [t for t in targets if t]
    if not targets:
        print("No targets provided.")
        sys.exit(1)

    return sorted(set(targets))


def main():
    parser = argparse.ArgumentParser(description="Authorized Host Auditor")
    parser.add_argument("--targets", help="Comma-separated targets, e.g. example.com,1.2.3.4")
    parser.add_argument("--file", help="File containing one target per line")
    parser.add_argument("--ports", default="80,443", help="Comma-separated ports, default: 80,443")
    parser.add_argument("--ws-path", help="Optional WebSocket path, e.g. /ws")
    parser.add_argument("--json-out", help="Write full JSON report to a file")
    args = parser.parse_args()

    try:
        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    except ValueError:
        print("Invalid ports format.")
        sys.exit(1)

    targets = parse_targets(args)
    reports = []

    for host in targets:
        report = audit_target(host, ports, ws_path=args.ws_path)
        reports.append(report)
        print_summary(report)

    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump(reports, f, indent=2, default=str)
            print(f"\nSaved JSON report to: {args.json_out}")
        except Exception as e:
            print(f"Failed to save JSON report: {e}")


if __name__ == "__main__":
    main()
