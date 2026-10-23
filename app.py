# ============================================================
# Imports and application configuration
# ============================================================
# These modules provide IP-address validation, JSON handling,
# operating-system information, sockets, subprocess execution,
# threading, timing, and UTC timestamps.
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


# Create the Flask application, enable cross-origin requests,
# limit network messages, and keep the lab service on localhost.
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

    """
    Collects the computer's real network configuration,
    such as IP addresses, subnet information, default gateways, and DNS servers,
    for every network interface
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
    # Block 1: retrieve raw interface data from the Windows host.
    raw, problem = audit_windows()
    source = "Windows host"
    items = []
    # Block 2: for every interface and calculate IPv4 network details.
    for item in raw:
        addresses = item.get("addresses", []) or []
        addresses = [addresses] if isinstance(addresses, str) else addresses
        parsed = []
        for value in addresses: #192.168.10.25/24
            try:
                # Convert CIDR text into structured IP, subnet, and broadcast values.
                interface = ipaddress.ip_interface(value)    #Calculates the following
                parsed.append({
                    "cidr": str(interface), "ip": str(interface.ip),
                    "prefix": interface.network.prefixlen, "network": str(interface.network),
                    "broadcast": str(interface.network.broadcast_address),
                    "link_local": interface.ip.is_link_local,
                })
            except ValueError:
                parsed.append({"cidr": str(value), "error": "Invalid IPv4 address"})
        items.append({ #Each interface is represented as a dictionary with its name, index, status, addresses, gateways, and DNS servers.
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
    # Block 1: reject an empty or incorrectly shaped configuration.
    if not isinstance(entries, list) or not entries:
        return {"result": "INVALID", "findings": [{"severity": "error", "message": "Provide at least one interface entry."}]}
    findings = []
    seen = {}
    # Block 2: validate for each 0...n entries and its interfaces and collect errors or warnings.
    for index, entry in enumerate(entries):
        label = entry.get("name") if isinstance(entry, dict) else None
        label = label or f"Entry {index + 1}"
        if not isinstance(entry, dict) or not entry.get("address"):
            findings.append({"severity": "error", "entry": label, "message": "Missing IPv4 address/CIDR."})
            continue
        #Starts here: Validate the IPv4 address and CIDR prefix using the ipaddress module. If the address is invalid or not IPv4, an error is recorded. Duplicate addresses are also checked, and warnings are issued for link-local addresses and gateway issues.
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
    # Checks Gateway reachability
    # DNS resolution
    # TCP connectivity to example.com:443
    """Run the bounded gateway, DNS, and TCP checks used by the lab checklist."""
    checks = []
    # Block 1: find the first configured gateway and test ICMP reachability.
    audited = audit()
    gateways = [gateway for item in audited["interfaces"] for gateway in item["gateways"] if gateway]
    if gateways:
        #1. First Check: Gateway reachability. It pings the first configured gateway and records the result.
        gateway_result = check_gateway(str(gateways[0]))
        checks.append({"name": "Gateway reachability", **gateway_result})
    else:
        checks.append({"name": "Gateway reachability", "status": "warning", "message": "No configured IPv4 gateway was found."})
    # Block 2: resolve a public hostname through the configured DNS path.
    try:
        #2. Second Check: DNS resolution. It attempts to resolve "example.com" to verify that DNS is functioning correctly.
        addresses = socket.getaddrinfo("example.com", 443, type=socket.SOCK_STREAM)
        resolved = sorted({item[4][0] for item in addresses})
        checks.append({"name": "DNS resolution", "status": "pass", "message": "example.com resolved successfully.", "addresses": resolved})
    except socket.gaierror as exc:
        checks.append({"name": "DNS resolution", "status": "fail", "message": str(exc)})
    # Block 3: open a short-lived TCP connection to verify transport access.
    try:
        started = time.perf_counter()
        #3. Third Check: TCP connectivity. It attempts to create a TCP connection to "example.com" on port 443 to ensure that the transport layer is accessible.
        with socket.create_connection(("example.com", 443), timeout=4):
            pass
        checks.append({"name": "TCP connectivity", "status": "pass", "message": "TCP connection to example.com:443 succeeded.", "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)})
    except OSError as exc:
        checks.append({"name": "TCP connectivity", "status": "fail", "message": str(exc)})
    status = "HEALTHY" if all(check["status"] == "pass" for check in checks) else "WARNING"
    return {"timestamp": now(), "status": status, "checks": checks, "host": audited["source"]}


COMMANDS = {
    # A fixed allowlist keeps the command console limited
    # to safe, read-only Windows networking commands.
    "ping": {
        "label": "Ping localhost",
        "description": """to test the reachability of a host (like a website, server, or router) across an Internet Protocol (IP) network and to measure
        the round-trip time (RTT) it takes for data to travel""",
        "args": ["ping", "-n", "4", "127.0.0.1"],
    },
    "ipconfig": {
        "label": "IP configuration",
        "description": "Displays IP addresses, subnet masks, and gateways for network adapters.",
        "args": ["ipconfig"],
    },
    "tracert": {
        "label": "Trace route",
        "description": "Traces the number of hops to reach the specified IP address, here it is limited to 5 hops.",
        "args": ["tracert", "-h", "5", "127.0.0.1"],
    },
    "nslookup": {
        "label": "DNS lookup",
        "description": "Queries DNS servers to resolve specified domain name to an IP address.",
        "args": ["nslookup", "example.com"],
    },
    "arp": {
        "label": "ARP cache",
        "description": "Lists cached IP-to-MAC address mappings on the local network.",
        "args": ["arp", "-a"],
    },
    "netstat": {
        "label": "Network connections",
        "description": "Lists active connections, listening ports, and associated process IDs.",
        "args": ["netstat", "-ano"],
    },
}


def run_command(command_id, command_args=None):
    """Run one fixed, read-only Windows networking command."""
    command = {"args": command_args} if command_args is not None else COMMANDS[command_id]
    try:
        result = subprocess.run(
            command["args"],
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
            "command": " ".join(command["args"]),
            "output": output or "(Command returned no output.)",
            "exit_code": result.returncode,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        output = ((exc.stdout or "") + (exc.stderr or "")).strip()
        return {
            "id": command_id,
            "command": " ".join(command["args"]),
            "output": output + ("\n" if output else "") + "Command timed out after 15 seconds.",
            "exit_code": None,
            "timed_out": True,
        }
    except OSError as exc:
        return {
            "id": command_id,
            "command": " ".join(command["args"]),
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

def validate_message(message):
    """Validate that the user message is non-empty and within the size limit."""
    if not isinstance(message, str) or not message.strip():
        raise ValueError("Message must not be empty.")
    data = message.encode("utf-8")
    if len(data) > MAX_MESSAGE:
        raise ValueError(f"Message must be at most {MAX_MESSAGE} bytes.")
    return data


# ============================================================
# PROGRAM 1: TCP Server (Presentation Slide 12)
# Workflow: socket() -> bind() -> listen() -> accept() -> recv() -> sendall() -> close()
# ============================================================
def tcp_server(server):
    """
    TCP Echo Server routine (Presentation Slide 12).
    Workflow: socket() -> bind() -> listen() -> accept() -> recv() -> sendall() -> close()
    """
    # Block 1: create an IPv4 TCP stream socket.
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Block 2: bind to localhost on a dynamic port.
    # Port 0 lets the operating system choose an available port.
    srv.bind((HOST, 0))

    # Block 3: listen for incoming TCP client connections.
    srv.listen(1)

    # Finite timeout (0.5s) allows server to check server.running periodically
    srv.settimeout(0.5)

    server.socket = srv
    server.port = srv.getsockname()[1]
    server.running = True
    server.log(f"TCP server listening on {HOST}:{server.port}")

    while server.running:
        try:
            # Block 4: accept a client connection.
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        # Block 5: receive the message and echo it back to the client.
        with conn:
            conn.settimeout(3.0)
            try:
                data = conn.recv(MAX_MESSAGE)
                if data:
                    conn.sendall(data)
                    server.log(f"Echoed {len(data)} bytes")
            except (socket.timeout, OSError) as exc:
                server.log(f"TCP client error: {exc}")
        # Block 6: close the client connection automatically with the context manager.


# ============================================================
# PROGRAM 2: TCP Client (Presentation Slides 9 & 11)
# Workflow: socket() -> connect() -> sendall() -> recv() -> close()
# ============================================================
def tcp_client(port, message):
    """
    TCP Client routine (Presentation Slides 9 & 11).
    Workflow: socket() -> connect() -> sendall() -> recv() -> close()
    """
    data = validate_message(message)
    started = time.perf_counter()

    # Block 1: create a TCP socket and guarantee cleanup with a context manager.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(4.0)

        # Block 2: connect to the server using the TCP three-way handshake.
        client.connect((HOST, port))

        # Block 3: send the message and receive the echoed response.
        client.sendall(data)
        response = client.recv(MAX_MESSAGE)
    # Block 4: close the socket automatically after the exchange.

    if not response:
        raise OSError("No response received from TCP server.")

    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    return {
        "message": response.decode("utf-8", errors="replace"),
        "bytes": len(response),
        "elapsed_ms": elapsed_ms,
    }


# ============================================================
# PROGRAM 3: UDP Server (Presentation Slide 13)
# Workflow: socket(AF_INET, SOCK_DGRAM) -> bind() -> recvfrom() -> sendto() -> close()
# ============================================================
def udp_server(server):
    """
    UDP Echo Server routine (Presentation Slide 13).
    Workflow: socket(AF_INET, SOCK_DGRAM) -> bind() -> recvfrom() -> sendto() -> close()
    """
    # Block 1: create an IPv4 UDP datagram socket.
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Block 2: bind to localhost on a dynamic port.
    srv.bind((HOST, 0))

    # Finite timeout (0.5s) allows server to check server.running periodically
    srv.settimeout(0.5)

    server.socket = srv
    server.port = srv.getsockname()[1]
    server.running = True
    server.log(f"UDP server listening on {HOST}:{server.port}")

    while server.running:
        try:
            # Block 3: receive a datagram and the sender address.
            data, addr = srv.recvfrom(MAX_MESSAGE)
            if data:
                # Block 4: echo the datagram directly to its sender.
                srv.sendto(data, addr)
                server.log(f"Echoed {len(data)} byte datagram")
        except socket.timeout:
            continue
        except OSError:
            break
    # Block 5: the manager closes the socket when the server is stopped.


# ============================================================
# PROGRAM 4: UDP Client (Presentation Slides 9, 11 & 13)
# Workflow: socket(AF_INET, SOCK_DGRAM) -> sendto() -> recvfrom() -> close()
# ============================================================
def udp_client(port, message):
    """
    UDP Client routine (Presentation Slides 9, 11 & 13).
    Workflow: socket(AF_INET, SOCK_DGRAM) -> sendto() -> recvfrom() -> close()
    """
    data = validate_message(message)
    started = time.perf_counter()

    # Block 1: create a UDP socket and guarantee cleanup with a context manager.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(4.0)

        # Block 2: send a datagram without establishing a connection.
        client.sendto(data, (HOST, port))

        # Block 3: receive the echoed datagram and sender address.
        response, _ = client.recvfrom(MAX_MESSAGE)
    # Block 4: close the socket automatically after the exchange.

    if not response:
        raise OSError("No response received from UDP server.")

    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    return {
        "message": response.decode("utf-8", errors="replace"),
        "bytes": len(response),
        "elapsed_ms": elapsed_ms,
    }


# ============================================================
# Server Manager (Web API Integration)
# Keeps the server listening across separate Flask HTTP requests
# ============================================================
class EchoServer:
    """Manage background execution, lifecycle, and logs for TCP and UDP servers."""

    def __init__(self, protocol):
        # Store the selected protocol and the state shared by the worker thread
        # and Flask requests.
        self.protocol = protocol.lower()
        self.socket = None
        self.thread = None
        self.port = None
        self.running = False
        self.logs = []
        self.lock = threading.Lock()

    def log(self, message):
        """Append a timestamped event while retaining a bounded history (last 50)."""
        self.logs.append({"timestamp": now(), "message": message})
        self.logs = self.logs[-50:]

    def start(self):
        """
        Start the background server routine (tcp_server or udp_server).
        Flask HTTP requests are short-lived. A background thread keeps the server
        socket alive and listening across multiple separate web requests.
        """
        # Block 1: prevent duplicate server threads.
        with self.lock:
            if self.running and self.thread and self.thread.is_alive():
                return

            # Block 2: choose the protocol routine and run it in the background.
            target = tcp_server if self.protocol == "tcp" else udp_server
            self.thread = threading.Thread(target=target, args=(self,), daemon=True)
            self.thread.start()

            # Wait briefly for server socket to bind and port to be populated
            for _ in range(50):
                if self.port:
                    break
                time.sleep(0.01)

    def send(self, message):
        """Execute the client routine (tcp_client or udp_client) and return results."""
        # Use the matching client to send a message through the running server.
        if not self.running or not self.port:
            raise RuntimeError("Start the server first.")

        if self.protocol == "tcp":
            result = tcp_client(self.port, message)
        else:
            result = udp_client(self.port, message)

        self.log(f"Client exchanged {result['bytes']} bytes")
        return result

    def stop(self):
        """Signal the background server loop to stop, close socket, and join thread."""
        # Signal the loop, close its socket, and wait briefly for the thread to exit.
        with self.lock:
            was_running = self.running or (self.socket is not None)
            self.running = False
            if self.socket:
                try:
                    self.socket.close()
                except OSError:
                    pass
                self.socket = None
            if self.thread and self.thread.is_alive():
                self.thread.join(timeout=1.0)
            self.thread = None
            self.port = None
            if was_running:
                self.log(f"{self.protocol.upper()} server stopped")

    def status(self):
        """Report running state, dynamic port, and recent activity logs."""
        return {
            "running": bool(self.running and self.socket and self.port),
            "port": self.port,
            "logs": self.logs,
        }


servers = {"tcp": EchoServer("tcp"), "udp": EchoServer("udp")}


# ============================================================
# Shared application and Networking Automation API endpoints
# ============================================================

@app.get("/api/health")
def health():
    # Basic service check used by the frontend to confirm the backend is online.
    """Report that the Flask service is available."""
    return jsonify({"ok": True, "service": "NetLab backend", "timestamp": now()})


@app.get("/api/host-info")
def host_info():
    # Return display-safe host details for the lab header.
    """Return non-sensitive runtime information for the lab header."""
    return jsonify({"ok": True, "hostname": socket.gethostname(), "platform": platform.platform(), "python": platform.python_version()})


@app.get("/api/network/audit")
def network_audit():
    # Collect and return the backend machine's current network configuration.
    """Expose the read-only audit of the backend host."""
    return jsonify({"ok": True, "audit": audit()})



@app.post("/api/network/validate")
def network_validate():
    # Read submitted interface data and return validation findings.
    """Validate the interface configuration submitted by the UI."""
    payload = request.get_json(silent=True) or {}
    return jsonify({"ok": True, "validation": validate_config(payload.get("interfaces"))})


@app.post("/api/network/diagnostics")
def network_diagnostics():
    # Run live gateway, DNS, and TCP checks and return their statuses.
    """Run the bounded real-host diagnostics requested by the UI."""
    return jsonify({"ok": True, "diagnostics": diagnostics()})


@app.get("/api/commands")
def command_catalog():
    # Present the fixed command allowlist so the UI can build its command menu.
    """Return the safe, fixed Windows networking command catalog."""
    commands = [
        {"id": command_id, "label": command["label"], "description": command["description"], "command": " ".join(command["args"])}
        for command_id, command in COMMANDS.items()
    ]
    return jsonify({"ok": True, "commands": commands})


@app.post("/api/commands/run")
def command_run():
    # Execute a command selected from the predefined catalog.
    """Execute one catalog command and return terminal-style output."""
    payload = request.get_json(silent=True) or {}
    command_id = payload.get("id")
    if command_id not in COMMANDS:
        return error("Unknown command", 404)
    return jsonify({"ok": True, "result": run_command(command_id)})


@app.post("/api/commands/execute")
def command_execute():
    # Validate a custom command before passing it to the bounded runner.
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
    # Return the current state of both background echo servers.
    """Return the current state and logs for both local echo servers."""
    return jsonify({"ok": True, "tcp": servers["tcp"].status(), "udp": servers["udp"].status()})


def socket_action(protocol, action):
    """Dispatch a validated start, stop, or send action to one echo server."""
    # Route start, stop, and send requests to the selected protocol manager.
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
    # Accept only the three supported TCP actions.
    """Handle TCP echo server actions without exposing a public listener."""
    return socket_action("tcp", action) if action in {"start", "stop", "send"} else error("Unknown TCP action", 404)


@app.post("/api/socket/udp/<action>")
def udp_action(action):
    # Accept only the three supported UDP actions.
    """Handle UDP echo server actions without exposing a public listener."""
    return socket_action("udp", action) if action in {"start", "stop", "send"} else error("Unknown UDP action", 404)


if __name__ == "__main__":
    # Start the Flask development server when this file is run directly.
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=False)

"""
/api/health -	GET	Checks whether the backend service is available.
/api/host-info -	GET	Returns hostname, operating system, and Python version.
/api/network/audit -	GET	Collects and returns network audit information.
/api/network/validate - 	POST	Validates submitted interface settings.
/api/network/diagnostics - 	POST	Runs the network diagnostic checks.
/api/commands - 	GET	Returns the available networking commands.
/api/commands/run - 	POST	Executes a selected command and returns its output.
/api/config-demo - 	GET	Returns the sample configuration profile.
/api/config-demo/apply - 	POST	Validates and saves a proposed demo configuration.
/api/config-demo/revert - 	POST	Restores the original demo configuration.

"""