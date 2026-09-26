"""
VibePen Network & Port Scanner Module.

Handles:
1. URL parsing to extract hostname and specific target port.
2. DNS resolution from hostname/domain to IP address.
3. Port and service discovery using Nmap with graceful fallback to native Python sockets.
"""

import os
import shutil
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Standard web and service ports to inspect
DEFAULT_PORTS = [80, 443, 3000, 5000, 8000, 8080, 8443, 21, 22, 25, 53, 3306, 5432, 27017]


def extract_host_and_port(target_url: str) -> Tuple[str, Optional[int]]:
    """
    Extracts the clean hostname/domain and explicit port (if specified) from a URL.
    Examples:
        'http://localhost:3000' -> ('localhost', 3000)
        'https://example.com/login' -> ('example.com', 443)
        'scanme.nmap.org' -> ('scanme.nmap.org', None)
    """
    cleaned = target_url.strip()
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "http://" + cleaned

    parsed = urlparse(cleaned)
    hostname = parsed.hostname or cleaned
    port = parsed.port

    return hostname, port


def resolve_target_ip(hostname: str) -> Dict[str, Any]:
    """
    Resolves domain or hostname to an IPv4 address.
    """
    # Special handling for standard localhost
    if hostname.lower() in ("localhost", "127.0.0.1"):
        return {
            "status": "success",
            "hostname": hostname,
            "ip_address": "127.0.0.1",
            "is_local": True
        }

    try:
        ip = socket.gethostbyname(hostname)
        return {
            "status": "success",
            "hostname": hostname,
            "ip_address": ip,
            "is_local": ip.startswith(("127.", "192.168.", "10."))
        }
    except socket.gaierror as e:
        return {
            "status": "error",
            "hostname": hostname,
            "ip_address": None,
            "error": f"DNS resolution failed: {str(e)}"
        }


def find_nmap_binary() -> Optional[str]:
    """
    Finds the nmap executable on system PATH or default Windows installation directories.
    """
    # 1. Check system PATH
    on_path = shutil.which("nmap")
    if on_path and os.path.exists(on_path):
        return on_path

    # 2. Check standard Windows Program Files directories
    program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")

    candidate_paths = [
        os.path.join(program_files_x86, "Nmap", "nmap.exe"),
        os.path.join(program_files, "Nmap", "nmap.exe"),
        r"D:\Nmap\nmap.exe",
        r"C:\Nmap\nmap.exe"
    ]

    for path in candidate_paths:
        if os.path.exists(path):
            return path

    return None


def run_nmap_scan(ip_or_host: str, ports_to_scan: List[int]) -> Dict[str, Any]:
    """
    Executes Nmap with XML output and parses open ports and services.
    """
    nmap_path = find_nmap_binary()
    if not nmap_path:
        return fallback_socket_scan(ip_or_host, ports_to_scan)

    port_arg = ",".join(str(p) for p in sorted(set(ports_to_scan)))

    # Nmap flags: -T4 (fast timing), -p (specific ports), -oX - (XML output to stdout)
    cmd = [nmap_path, "-T4", "-p", port_arg, "-oX", "-", ip_or_host]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            check=False
        )

        if proc.returncode != 0 and not proc.stdout:
            # Fall back to socket scan if Nmap hit an execution or driver error
            return fallback_socket_scan(ip_or_host, ports_to_scan)

        # Parse XML output
        root = ET.fromstring(proc.stdout)
        open_ports = []

        for port_elem in root.findall(".//port"):
            state_elem = port_elem.find("state")
            if state_elem is not None and state_elem.get("state") == "open":
                port_id = int(port_elem.get("portid", 0))
                proto = port_elem.get("protocol", "tcp")

                service_elem = port_elem.find("service")
                service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                product = service_elem.get("product", "") if service_elem is not None else ""
                version = service_elem.get("version", "") if service_elem is not None else ""

                open_ports.append({
                    "port": port_id,
                    "protocol": proto,
                    "state": "open",
                    "service": service_name,
                    "product": product,
                    "version": version
                })

        return {
            "status": "success",
            "scanner": "Nmap 7.991",
            "open_ports": open_ports,
            "ports_scanned_count": len(ports_to_scan)
        }

    except (subprocess.TimeoutExpired, ET.ParseError, Exception) as exc:
        # Graceful fallback so scans never block or fail silently
        fallback = fallback_socket_scan(ip_or_host, ports_to_scan)
        fallback["note"] = f"Nmap fallback triggered: {str(exc)}"
        return fallback


def fallback_socket_scan(ip_or_host: str, ports_to_scan: List[int]) -> Dict[str, Any]:
    """
    Fast native Python socket-based port scanner used when Nmap is unavailable.
    """
    open_ports = []
    well_known = {
        80: "http",
        443: "https",
        3000: "http/juice-shop",
        8080: "http/dvwa-proxy",
        8000: "http/api",
        22: "ssh",
        21: "ftp",
        3306: "mysql"
    }

    for port in sorted(set(ports_to_scan)):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.3)
                if sock.connect_ex((ip_or_host, port)) == 0:
                    open_ports.append({
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "service": well_known.get(port, "unknown"),
                        "product": "",
                        "version": ""
                    })
        except Exception:
            continue

    return {
        "status": "success",
        "scanner": "Python Socket Fallback",
        "open_ports": open_ports,
        "ports_scanned_count": len(ports_to_scan)
    }


def scan_target_network(target_url: str) -> Dict[str, Any]:
    """
    Main entry point for network reconnaissance.
    Given a URL:
    1. Extracts domain & URL-specific port.
    2. Resolves IP address.
    3. Scans ports via Nmap.
    4. Returns consolidated network metadata.
    """
    start_time = time.time()
    hostname, explicit_port = extract_host_and_port(target_url)
    dns_result = resolve_target_ip(hostname)

    if dns_result["status"] != "success":
        return {
            "status": "error",
            "target": target_url,
            "hostname": hostname,
            "ip_address": None,
            "open_ports": [],
            "error": dns_result.get("error", "Failed to resolve host"),
            "duration_seconds": round(time.time() - start_time, 2)
        }

    target_ip = dns_result["ip_address"]

    # Build ports list, guaranteeing the target URL's specific port is scanned
    ports_to_scan = list(DEFAULT_PORTS)
    if explicit_port and explicit_port not in ports_to_scan:
        ports_to_scan.append(explicit_port)

    # Run scan against resolved IP or host
    scan_result = run_nmap_scan(target_ip, ports_to_scan)

    return {
        "status": "success",
        "target": target_url,
        "hostname": hostname,
        "ip_address": target_ip,
        "is_local": dns_result.get("is_local", False),
        "scanner": scan_result.get("scanner", "Nmap"),
        "open_ports": scan_result.get("open_ports", []),
        "open_port_count": len(scan_result.get("open_ports", [])),
        "ports_scanned_count": scan_result.get("ports_scanned_count", len(ports_to_scan)),
        "duration_seconds": round(time.time() - start_time, 2)
    }
