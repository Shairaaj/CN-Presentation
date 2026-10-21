# NetLab — Python Networking Lab

NetLab is a focused presentation application for two subjects: **Networking Automation and Configuration using Python** and **Socket Programming using Python**. It uses a React/Vite interface and a Flask backend.

## Features

- Read-only audit of the Windows machine hosting the backend using PowerShell.
- IPv4/CIDR validation, duplicate detection, gateway/subnet checks, DNS validation, and link-local warnings.
- Bounded DNS, TCP, and gateway diagnostics with honest unavailable/inconclusive states.
- Reversible application-owned demo profile; it never changes an operating-system adapter.
- Real loopback-only TCP and UDP echo servers with dynamic ports, byte counts, and logs.
- Windows networking command demonstrations with backend terminal output.
- Definitions for common networking protocols: TCP, UDP, HTTP, DNS, DHCP, and ARP.

## Project structure

- `app.py` — Flask backend, grouped into the two subject areas with explanatory function comments.
- `frontend/src/main.jsx` — React views for Overview, Networking Automation, Socket Programming, Commands, and Protocols.
- `frontend/src/styles.css` — light application shell and dark console styling.
- `tests/test_app.py` — backend API and socket round-trip tests.
- `demo_profile.json` — application-owned state for the reversible configuration demonstration.

## Run on this workspace

From `C:\Users\shair\Desktop\Python-Networking-CN`:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

In a second PowerShell window:

```powershell
cd C:\Users\shair\Desktop\Python-Networking-CN\frontend
npm install
npm run dev
```

Open http://127.0.0.1:5173. The Vite development proxy sends `/api` requests to Flask at http://127.0.0.1:5000. For a production frontend build, run `npm run build` in `frontend`.

## Presentation flow

1. Overview: explain the real-host versus isolated-demo boundary.
2. Networking Automation: refresh the audit, load the sample validator, and show the deliberate duplicate result.
3. Run diagnostics and explain that ICMP can be blocked without proving the network is broken.
4. Change the demo profile and restore it; confirm the OS adapter is untouched.
5. Open Commands to run a safe, fixed Windows networking command and explain its terminal output.
6. Open Protocols to review concise definitions of common networking protocols.

No API accepts arbitrary hosts, ports, or shell commands. Command demonstrations use a fixed read-only allowlist and have finite timeouts. Host details reflect the backend machine, not necessarily a student's computer.

## Tests

```powershell
python -m unittest discover -s tests -v
```
