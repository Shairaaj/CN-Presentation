import ipaddress
import json
import logging
import os
import platform
import re
import shlex
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone

from flask import Flask, jsonify, request
from flask_cors import CORS


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
app = Flask(__name__)
CORS(app)
MAX_MESSAGE = 4096
HOST = "127.0.0.1"

# ============================================================
# Networking Automation and Configuration using Python
# ============================================================

def now():
    """Return a consistent UTC timestamp for API responses and event logs."""
    return datetime.now(timezone.utc).isoformat()


def error(message, status=400):
    """Build the standard JSON error response used by every API endpoint."""
    return jsonify({"ok": False, "error": message}), status


def powershell(script):
    """Run one fixed, read-only PowerShell diagnostic with a time limit."""
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)
    if result.returncode:
        return None, result.stderr.strip() or "PowerShell command failed"
    return result.stdout.strip(), None # Return output and None for no error


def audit_windows():
    """Collect Windows interface, IPv4, gateway, and DNS data with PowerShell."""
    #Get-NetIPConfiguration: obtains interface configuration and gateway information.
    #Get-NetIPAddress: retrieves IPv4 addresses and their prefix lengths.
    #Get-DnsClientServerAddress: retrieves configured DNS servers.
    
    script = r"""
    Get-NetIPConfiguration -All | ForEach-Object {
      $c = $_
      $addresses = @(Get-NetIPAddress -InterfaceIndex $c.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" })
      $gateways = @($c.IPv4DefaultGateway | Where-Object NextHop | ForEach-Object NextHop)
      $dns = @((Get-DnsClientServerAddress -InterfaceIndex $c.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
      [PSCustomObject]@{ name=$c.InterfaceAlias; index=$c.InterfaceIndex; addresses=$addresses; gateways=$gateways; dns=$dns }
    } | ConvertTo-Json -Depth 4
    """
    output, problem = powershell(script)
    if problem:
        return [], problem
    try:
        raw = json.loads(output) if output else []
        return raw if isinstance(raw, list) else [raw], None
    except json.JSONDecodeError:
        return [], "The host returned unreadable network data"


def audit():
    """Normalize Windows network data into the frontend audit format."""
    raw, problem = audit_windows()
    source = "Windows host"
    items = []
    for item in raw:
        addresses = item.get("addresses", []) or []
        addresses = [addresses] if isinstance(addresses, str) else addresses
        parsed = []
        for value in addresses:
            try:
                interface = ipaddress.ip_interface(value)
                parsed.append({
                    "cidr": str(interface), "ip": str(interface.ip),
                    "prefix": interface.network.prefixlen, "network": str(interface.network),
                    "broadcast": str(interface.network.broadcast_address),
                    "link_local": interface.ip.is_link_local,
                })
            except ValueError:
                parsed.append({"cidr": str(value), "error": "Invalid IPv4 address"})
        items.append({
            "name": item.get("name") or item.get("Interface") or "Unknown",
            "index": item.get("index") if item.get("index") is not None else item.get("Index"),
            "status": "Available",
            "addresses": parsed,
            "gateways": item.get("gateways") or item.get("Gateway") or [],
            "dns": item.get("dns") or item.get("DNS") or [],
        })
    return {"source": source, "timestamp": now(), "interfaces": items, "limitation": problem}


def validate_config(entries):
    """Validate supplied sample interfaces, including duplicates and warnings."""
    if not isinstance(entries, list) or not entries:
        return {"result": "INVALID", "findings": [{"severity": "error", "message": "Provide at least one interface entry."}]}
    findings = []
    seen = {}
    for index, entry in enumerate(entries):
        label = entry.get("name") if isinstance(entry, dict) else None
        label = label or f"Entry {index + 1}"
        if not isinstance(entry, dict) or not entry.get("address"):
            findings.append({"severity": "error", "entry": label, "message": "Missing IPv4 address/CIDR."})
            continue
        try:
            interface = ipaddress.ip_interface(entry["address"])
            if interface.version != 4:
                raise ValueError
        except (ValueError, TypeError):
            findings.append({"severity": "error", "entry": label, "message": "Invalid IPv4 address or CIDR prefix."})
            continue
        ip = str(interface.ip)
        if ip in seen:
            findings.append({"severity": "error", "entry": label, "message": f"Duplicate IPv4 address also used by {seen[ip]}."})
        else:
            seen[ip] = label
        if interface.ip.is_link_local:
            findings.append({"severity": "warning", "entry": label, "message": "Link-local address detected; this may indicate missing DHCP."})
        gateway = entry.get("gateway")
        if gateway:
            try:
                gateway_ip = ipaddress.ip_address(gateway)
                if gateway_ip.version != 4:
                    raise ValueError
                if gateway_ip not in interface.network:
                    findings.append({"severity": "warning", "entry": label, "message": "Gateway is outside the configured subnet."})
            except ValueError:
                findings.append({"severity": "error", "entry": label, "message": "Gateway is not a valid IPv4 address."})
        elif entry.get("require_gateway", False):
            findings.append({"severity": "warning", "entry": label, "message": "Gateway is missing."})
        dns = entry.get("dns", [])
        if isinstance(dns, str):
            dns = [dns] if dns else []
        for server in dns:
            try:
                if ipaddress.ip_address(server).version != 4:
                    raise ValueError
            except ValueError:
                findings.append({"severity": "error", "entry": label, "message": f"Malformed DNS server: {server}."})
        if entry.get("require_dns", False) and not dns:
            findings.append({"severity": "warning", "entry": label, "message": "DNS server is missing."})
    result = "INVALID" if any(x["severity"] == "error" for x in findings) else ("VALID WITH WARNINGS" if findings else "VALID")
    return {"result": result, "findings": findings, "checked_entries": len(entries)}


def check_gateway(gateway):
    """Ping one configured gateway and distinguish failure from unavailable ICMP."""
    command = ["ping", "-n", "1", "-w", "1500", gateway]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=4)
        return {"status": "pass" if result.returncode == 0 else "warning", "message": "Gateway responded to ICMP." if result.returncode == 0 else "No ICMP response; firewalls may block ping."}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "warning", "message": f"ICMP test unavailable: {exc}"}


def diagnostics():
    """Run the bounded gateway, DNS, and TCP checks used by the lab checklist."""
    checks = []
    audited = audit()
    gateways = [gateway for item in audited["interfaces"] for gateway in item["gateways"] if gateway]
    if gateways:
        gateway_result = check_gateway(str(gateways[0]))
        checks.append({"name": "Gateway reachability", **gateway_result})
    else:
        checks.append({"name": "Gateway reachability", "status": "warning", "message": "No configured IPv4 gateway was found."})
    try:
        addresses = socket.getaddrinfo("example.com", 443, type=socket.SOCK_STREAM)
        resolved = sorted({item[4][0] for item in addresses})
        checks.append({"name": "DNS resolution", "status": "pass", "message": "example.com resolved successfully.", "addresses": resolved})
    except socket.gaierror as exc:
        checks.append({"name": "DNS resolution", "status": "fail", "message": str(exc)})
    try:
        started = time.perf_counter()
        with socket.create_connection(("example.com", 443), timeout=4):
            pass
        checks.append({"name": "TCP connectivity", "status": "pass", "message": "TCP connection to example.com:443 succeeded.", "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)})
    except OSError as exc:
        checks.append({"name": "TCP connectivity", "status": "fail", "message": str(exc)})
    status = "HEALTHY" if all(check["status"] == "pass" for check in checks) else "WARNING"
    return {"timestamp": now(), "status": status, "checks": checks, "host": audited["source"]}


COMMANDS = {
    "ping": {
        "label": "Ping localhost",
        "description": "Checks whether the local Windows TCP/IP stack responds.",
        "args": ["ping", "-n", "4", "127.0.0.1"],
    },
    "ipconfig": {
        "label": "IP configuration",
        "description": "Shows the host's Windows network adapter configuration.",
        "args": ["ipconfig"],
    },
    "tracert": {
        "label": "Trace route",
        "description": "Shows the route to the local host with a bounded hop count.",
        "args": ["tracert", "-h", "5", "127.0.0.1"],
    },
    "nslookup": {
        "label": "DNS lookup",
        "description": "Looks up the fixed teaching domain example.com.",
        "args": ["nslookup", "example.com"],
    },
    "arp": {
        "label": "ARP cache",
        "description": "Displays the local Address Resolution Protocol cache.",
        "args": ["arp", "-a"],
    },
    "route": {
        "label": "Routing table",
        "description": "Displays the Windows IPv4 routing table.",
        "args": ["route", "print", "-4"],
    },
    "netstat": {
        "label": "Network connections",
        "description": "Shows active connections and listening ports.",
        "args": ["netstat", "-ano"],
    },
}


def run_command(command_id, args=None):
    """Run one validated, read-only Windows networking command."""
    command = COMMANDS[command_id] if command_id in COMMANDS else None
    command_args = command["args"] if args is None else args
    try:
        result = subprocess.run(
            command_args,
            capture_output=True,
            text=True,
            encoding="oem",
            errors="replace",
            timeout=15,
            shell=False,
        )
        output = (result.stdout + result.stderr).strip()
        return {
            "id": command_id,
            "command": " ".join(command_args),
            "output": output or "(Command returned no output.)",
            "exit_code": result.returncode,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        output = ((exc.stdout or "") + (exc.stderr or "")).strip()
        return {
            "id": command_id,
            "command": " ".join(command_args),
            "output": output + ("\n" if output else "") + "Command timed out after 15 seconds.",
            "exit_code": None,
            "timed_out": True,
        }
    except OSError as exc:
        return {
            "id": command_id,
            "command": " ".join(command_args),
            "output": f"Unable to execute command: {exc}",
            "exit_code": None,
            "timed_out": False,
        }


def parse_custom_command(command_line):
    """Parse a terminal request and allow only bounded networking commands."""
    if not isinstance(command_line, str) or not command_line.strip():
        raise ValueError("Enter a networking command.")
    if len(command_line) > 256:
        raise ValueError("Command must be at most 256 characters.")
    if any(character in command_line for character in "&|<>;$`\n\r"):
        raise ValueError("Shell operators and multiline commands are not allowed.")
    try:
        args = shlex.split(command_line, posix=True)
    except ValueError as exc:
        raise ValueError("Command has unmatched quotes.") from exc
    if not args:
        raise ValueError("Enter a networking command.")

    executable = args[0].lower()
    if executable not in {"ping", "ipconfig", "tracert", "nslookup", "arp", "route", "netstat"}:
        raise ValueError("Only the listed read-only networking commands are allowed.")
    if "/" in args[0] or "\\" in args[0]:
        raise ValueError("Command paths are not allowed.")

    integer = r"(?:[1-9]\d{0,3})"
    target = r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}"
    if executable == "ipconfig":
        if args[1:] not in ([], ["/all"]):
            raise ValueError("ipconfig accepts no arguments or /all.")
    elif executable == "arp":
        if args[1:] != ["-a"]:
            raise ValueError("arp only accepts -a.")
    elif executable == "route":
        if args[1:] != ["print", "-4"]:
            raise ValueError("route only accepts print -4.")
    elif executable == "netstat":
        if args[1:] != ["-ano"]:
            raise ValueError("netstat only accepts -ano.")
    elif executable == "nslookup":
        if len(args) != 2 or not re.fullmatch(target, args[1]):
            raise ValueError("nslookup requires one valid hostname.")
    elif executable in {"ping", "tracert"}:
        remaining = args[1:]
        options = {"-n": integer, "-w": integer} if executable == "ping" else {"-h": integer}
        target_value = None
        index = 0
        while index < len(remaining):
            value = remaining[index]
            if value in options:
                if index + 1 >= len(remaining) or not re.fullmatch(options[value], remaining[index + 1]):
                    raise ValueError(f"{value} requires a numeric value.")
                index += 2
            elif value.startswith("-"):
                raise ValueError(f"Unsupported {executable} option.")
            elif target_value is None and re.fullmatch(target, value):
                target_value = value
                index += 1
            else:
                raise ValueError(f"{executable} requires one valid target.")
        if target_value is None:
            raise ValueError(f"{executable} requires one valid target.")
    return args


# ============================================================
# Socket Programming with Python
# ============================================================

class EchoServer:
    """Manage one loopback-only TCP or UDP echo server in a background thread."""
    def __init__(self, protocol):
        """Initialize server state for the selected transport protocol."""
        self.protocol = protocol
        self.socket = None
        self.thread = None
        self.port = None
        self.lock = threading.Lock()
        self.logs = []

    def log(self, message):
        """Append a timestamped event while retaining a bounded history."""
        self.logs.append({"timestamp": now(), "message": message})
        self.logs = self.logs[-50:]

    def start(self):
        """Bind a dynamic loopback port and start the non-blocking listener."""
        with self.lock:
            if self.thread and self.thread.is_alive():
                return
            kind = socket.SOCK_STREAM if self.protocol == "tcp" else socket.SOCK_DGRAM
            self.socket = socket.socket(socket.AF_INET, kind)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((HOST, 0))
            if self.protocol == "tcp":
                self.socket.listen(1)
            self.port = self.socket.getsockname()[1]
            self.socket.settimeout(0.5)
            self.thread = threading.Thread(target=self._run, daemon=True)
            self.thread.start()
            self.log(f"{self.protocol.upper()} server listening on {HOST}:{self.port}")

    def _run(self):
        """Accept TCP clients or UDP datagrams until the server is stopped."""
        while self.socket:
            try:
                if self.protocol == "tcp":
                    connection, _ = self.socket.accept()
                    with connection:
                        connection.settimeout(3)
                        data = connection.recv(MAX_MESSAGE)
                        if data:
                            connection.sendall(data)
                            self.log(f"Echoed {len(data)} bytes")
                else:
                    data, address = self.socket.recvfrom(MAX_MESSAGE)
                    if data:
                        self.socket.sendto(data, address)
                        self.log(f"Echoed {len(data)} byte datagram")
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception:
                logging.exception("Socket listener error")
                break

    def send(self, message):
        """Send one bounded local message and return the echoed response details."""
        if not self.thread or not self.thread.is_alive() or not self.port:
            raise RuntimeError("Start the server first.")
        if not isinstance(message, str) or not message.strip():
            raise ValueError("Message must not be empty.")
        data = message.encode("utf-8")
        if len(data) > MAX_MESSAGE:
            raise ValueError(f"Message must be at most {MAX_MESSAGE} bytes.")
        started = time.perf_counter()
        kind = socket.SOCK_STREAM if self.protocol == "tcp" else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, kind) as client:
            client.settimeout(4)
            client.connect((HOST, self.port)) if self.protocol == "tcp" else None
            if self.protocol == "tcp":
                client.sendall(data)
                response = client.recv(MAX_MESSAGE)
            else:
                client.sendto(data, (HOST, self.port))
                response, _ = client.recvfrom(MAX_MESSAGE)
        result = {"message": response.decode("utf-8", errors="replace"), "bytes": len(response), "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)}
        self.log(f"Client exchanged {len(data)} bytes")
        return result

    def stop(self):
        """Close the listener so its background thread can exit cleanly."""
        with self.lock:
            if self.socket:
                try:
                    self.socket.close()
                except OSError:
                    pass
            self.socket = None
            self.port = None
            self.log(f"{self.protocol.upper()} server stopped")

    def status(self):
        """Report running state, dynamic port, and recent socket activity."""
        return {"running": bool(self.thread and self.thread.is_alive() and self.socket), "port": self.port, "logs": self.logs}


servers = {"tcp": EchoServer("tcp"), "udp": EchoServer("udp")}


# ============================================================
# Shared application and Networking Automation API endpoints
# ============================================================

@app.get("/api/health")
def health():
    """Report that the Flask service is available."""
    return jsonify({"ok": True, "service": "NetLab backend", "timestamp": now()})


@app.get("/api/host-info")
def host_info():
    """Return non-sensitive runtime information for the lab header."""
    return jsonify({"ok": True, "hostname": socket.gethostname(), "platform": platform.platform(), "python": platform.python_version()})


@app.get("/api/network/audit")
def network_audit():
    """Expose the read-only audit of the backend host."""
    return jsonify({"ok": True, "audit": audit()})


@app.post("/api/network/validate")
def network_validate():
    """Validate the interface configuration submitted by the UI."""
    payload = request.get_json(silent=True) or {}
    return jsonify({"ok": True, "validation": validate_config(payload.get("interfaces"))})


@app.post("/api/network/diagnostics")
def network_diagnostics():
    """Run the bounded real-host diagnostics requested by the UI."""
    return jsonify({"ok": True, "diagnostics": diagnostics()})


@app.get("/api/commands")
def command_catalog():
    """Return the safe, fixed Windows networking command catalog."""
    commands = [
        {"id": command_id, "label": command["label"], "description": command["description"], "command": " ".join(command["args"])}
        for command_id, command in COMMANDS.items()
    ]
    return jsonify({"ok": True, "commands": commands})


@app.post("/api/commands/run")
def command_run():
    """Execute one catalog command and return terminal-style output."""
    payload = request.get_json(silent=True) or {}
    command_id = payload.get("id")
    if command_id not in COMMANDS:
        return error("Unknown command", 404)
    return jsonify({"ok": True, "result": run_command(command_id)})


@app.post("/api/commands/execute")
def command_execute():
    """Execute a user-entered command after applying the networking allowlist."""
    payload = request.get_json(silent=True) or {}
    try:
        args = parse_custom_command(payload.get("command"))
    except ValueError as exc:
        return error(str(exc), 400)
    return jsonify({"ok": True, "result": run_command("custom", args)})


# ============================================================
# Socket Programming with Python API endpoints
# ============================================================

@app.get("/api/socket/status")
def socket_status():
    """Return the current state and logs for both local echo servers."""
    return jsonify({"ok": True, "tcp": servers["tcp"].status(), "udp": servers["udp"].status()})


def socket_action(protocol, action):
    """Dispatch a validated start, stop, or send action to one echo server."""
    server = servers[protocol]
    try:
        if action == "start":
            server.start()
            return jsonify({"ok": True, "status": server.status()})
        if action == "stop":
            server.stop()
            return jsonify({"ok": True, "status": server.status()})
        payload = request.get_json(silent=True) or {}
        return jsonify({"ok": True, "result": server.send(payload.get("message")), "status": server.status()})
    except (RuntimeError, ValueError, OSError, socket.timeout) as exc:
        return error(str(exc), 409 if isinstance(exc, RuntimeError) else 400)


@app.post("/api/socket/tcp/<action>")
def tcp_action(action):
    """Handle TCP echo server actions without exposing a public listener."""
    return socket_action("tcp", action) if action in {"start", "stop", "send"} else error("Unknown TCP action", 404)


@app.post("/api/socket/udp/<action>")
def udp_action(action):
    """Handle UDP echo server actions without exposing a public listener."""
    return socket_action("udp", action) if action in {"start", "stop", "send"} else error("Unknown UDP action", 404)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=False)
