import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { Activity, CheckCircle2, CircleAlert, Network, Play, RotateCcw, Send, Square, Terminal } from "lucide-react";
import "./styles.css";

// Shared API helper: keeps JSON handling and error messages consistent.
const api = async (path, options) => {
  const response = await fetch(path, { headers: { "Content-Type": "application/json" }, ...options });
  const contentType = response.headers.get("content-type") || "";
  const rawBody = await response.text();
  let body;
  try {
    body = contentType.includes("application/json") ? JSON.parse(rawBody) : null;
  } catch {
    throw new Error(`Backend returned invalid JSON for ${path}.`);
  }
  if (!body) {
    if (rawBody.trimStart().startsWith("<!doctype") || rawBody.trimStart().startsWith("<html")) {
      throw new Error(`Backend API is unavailable for ${path}. Start Flask with "python app.py" and open the Vite URL.`);
    }
    throw new Error(`Backend returned an unexpected response for ${path} (HTTP ${response.status}).`);
  }
  if (!response.ok) throw new Error(body.error || "Request failed");
  return body;
};

const sample = [{ name: "Office LAN", address: "192.168.10.25/24", gateway: "192.168.10.1", dns: ["1.1.1.1"], require_gateway: true, require_dns: true }, { name: "Duplicate sample", address: "192.168.10.25/24", gateway: "192.168.10.1", dns: ["8.8.8.8"] }];
const protocols = [
  { name: "TCP", definition: "Transmission Control Protocol provides reliable, ordered, connection-oriented delivery of a byte stream between applications." },
  { name: "UDP", definition: "User Datagram Protocol sends independent datagrams with low overhead, but it does not guarantee delivery, order, or duplicate protection." },
  { name: "HTTP", definition: "Hypertext Transfer Protocol is an application-layer protocol used by web clients and servers to request and transfer resources." },
  { name: "DNS", definition: "Domain Name System translates human-readable domain names such as example.com into IP addresses and other records." },
  { name: "DHCP", definition: "Dynamic Host Configuration Protocol automatically provides clients with network settings such as an IP address, subnet mask, gateway, and DNS server." },
  { name: "ARP", definition: "Address Resolution Protocol maps an IPv4 address to the hardware address of a device on the local network." },
];

// Small presentation components shared by both lab modules.
function Badge({ children, tone = "info" }) { return <span className={`badge ${tone}`}>{children}</span>; }
function Console({ children }) { return <pre className="console">{children}</pre>; }

// Overview introduces the two in-scope subjects and their safety boundaries.
function Overview({ go }) {
  return <main className="hero">
    <div className="eyebrow">INTERACTIVE LEARNING ENVIRONMENT</div>
    <h1>Computer Networks <span>Interactive Lab</span></h1>
    <p className="lead">Explore real network configuration checks and hands-on TCP/UDP socket programming using Python.</p>
    <div className="cards">
      <section className="card module-card"><Badge tone="blue">MODULE 2</Badge><h2>Networking Automation and Configuration</h2><p>Inspect the backend host, validate IP/CIDR configuration, detect duplicate addresses, run bounded diagnostics, and practise a reversible demo-profile change.</p><button onClick={() => go("automation")}>Open Networking Lab <Play size={16}/></button></section>
      <section className="card module-card"><Badge tone="purple">SOCKET PROGRAMMING</Badge><h2>Socket Programming with Python</h2><p>Run real loopback-only TCP and UDP echo servers, exchange messages, inspect byte counts, and read timestamped activity logs.</p><button onClick={() => go("sockets")}>Open Socket Lab <Play size={16}/></button></section>
    </div>
    <section className="card how"><h2>How this lab works</h2><p><strong>Real host checks:</strong> the audit and diagnostics describe the machine running the Python backend, which may be a container or lab server rather than your personal computer.</p><p><strong>Safe demonstrations:</strong> configuration changes are written only to an application-owned JSON profile, while socket servers bind to <code>127.0.0.1</code> and never expose public ports.</p></section>
  </main>;
}

// Networking Automation and Configuration page combines audit, validation,
// diagnostics, and the isolated configuration-change demonstration.
function Automation() {
  const [audit, setAudit] = useState(null); const [validation, setValidation] = useState(null); const [text, setText] = useState(JSON.stringify(sample, null, 2)); const [diagnostic, setDiagnostic] = useState(null); const [profile, setProfile] = useState(null); const [busy, setBusy] = useState(false); const [message, setMessage] = useState("");
  const run = async (action) => { setBusy(true); setMessage(""); try { await action(); } catch (error) { setMessage(error instanceof Error ? error.message : "Request failed"); } finally { setBusy(false); } };
  useEffect(() => { run(async () => { const [a, p] = await Promise.all([api("/api/network/audit"), api("/api/config-demo")]); setAudit(a.audit); setProfile(p.profile); }); }, []);
  const validate = () => run(async () => { let interfaces; try { interfaces = JSON.parse(text); } catch { throw new Error("Configuration must be valid JSON."); } setValidation((await api("/api/network/validate", { method: "POST", body: JSON.stringify({ interfaces }) })).validation); });
  return <main className="content"><div className="section-title"><div><div className="eyebrow">MODULE 2</div><h1>Networking Automation</h1><p>Read-only host inspection, configuration validation, bounded diagnostics, and a safe profile demonstration.</p></div><button className="secondary" disabled={busy} onClick={() => run(async () => setAudit((await api("/api/network/audit")).audit))}><RotateCcw size={16}/> Refresh Audit</button></div>
    {message && <div className="notice error">{message}</div>}
    <div className="grid-two"><section className="card"><h2>Interface & IP audit</h2><p className="muted">{audit ? `Source: ${audit.source} · ${new Date(audit.timestamp).toLocaleString()}` : "Loading real host data..."}</p>{audit?.limitation && <div className="notice warning">{audit.limitation}</div>}<div className="audit-list">{audit?.interfaces?.map(item => <article className="audit-item" key={`${item.name}-${item.index}`}><div className="row"><strong><Network size={16}/> {item.name}</strong><Badge tone="success">{item.status}</Badge></div><div className="facts"><span>Index: {item.index ?? "Unavailable"}</span><span>Gateway: {item.gateways.join(", ") || "Unavailable"}</span><span>DNS: {item.dns.join(", ") || "Unavailable"}</span></div>{item.addresses.map(address => <div className="address" key={address.cidr}>{address.error ? address.error : `${address.cidr} · network ${address.network} · broadcast ${address.broadcast}`}{address.link_local && <Badge tone="warning">link-local</Badge>}</div>)}</article>)}</div></section>
    <section className="card"><div className="row"><div><h2>Configuration validator</h2><p className="muted">Sample data includes a deliberate duplicate IP for presentation.</p></div><button className="secondary" onClick={() => setText(JSON.stringify(sample, null, 2))}>Load Example</button></div><textarea aria-label="Configuration JSON" value={text} onChange={event => setText(event.target.value)}/><button onClick={validate} disabled={busy}>Validate configuration <CheckCircle2 size={16}/></button>{validation && <div className={`result ${validation.result === "INVALID" ? "bad" : validation.result.includes("WARNING") ? "warn" : "good"}`}><strong>{validation.result}</strong>{validation.findings.map((item, index) => <div className="finding" key={index}><CircleAlert size={15}/> {item.entry && `${item.entry}: `}{item.message}</div>)}</div>}</section></div>
    <section className="card diagnostics"><div className="row"><div><h2>Automatic problem detection</h2><p className="muted">DNS and TCP target example.com; gateway testing uses the configured host gateway when available.</p></div><button disabled={busy} onClick={() => run(async () => setDiagnostic((await api("/api/network/diagnostics", { method: "POST" })).diagnostics))}><Activity size={16}/> Run diagnostics</button></div>{diagnostic && <><Badge tone={diagnostic.status === "HEALTHY" ? "success" : "warning"}>{diagnostic.status}</Badge><div className="check-grid">{diagnostic.checks.map(check => <div className="check" key={check.name}><strong>{check.status === "pass" ? "✓" : "!"} {check.name}</strong><span>{check.message}</span></div>)}</div></>}</section>
    <ConfigDemo profile={profile} setProfile={setProfile} run={run}/>
  </main>;
}

// This panel edits and persists only the application-owned demo profile.
function ConfigDemo({ profile, setProfile, run }) { if (!profile) return null; const current = profile.current; return <section className="card"><h2>Safe configuration-change demonstration</h2><div className="notice info">Demo profile only — this does not change the operating system's network adapter.</div><div className="profile"><label>Demo IPv4/CIDR<input value={current.address} onChange={e => setProfile({...profile, current: {...current, address: e.target.value}})}/></label><label>Demo gateway<input value={current.gateway} onChange={e => setProfile({...profile, current: {...current, gateway: e.target.value}})}/></label></div><div className="actions"><button onClick={() => run(async () => setProfile((await api("/api/config-demo/apply", {method:"POST", body: JSON.stringify({profile: current})})).profile))}>Apply to demo profile</button><button className="secondary" onClick={() => run(async () => setProfile((await api("/api/config-demo/revert", {method:"POST"})).profile))}>Restore original</button></div><Console>{profile.changes.length ? profile.changes.map(change => `${change.timestamp}  ${change.action}`).join("\n") : "No changes yet."}</Console></section>; }

// Socket Programming with Python page switches between the TCP and UDP demos.
function Sockets() { const [protocol, setProtocol] = useState("tcp"); return <main className="content"><div className="eyebrow">SOCKET PROGRAMMING</div><h1>Local Socket Lab</h1><p className="lead">Actual Python echo servers, bound to loopback with finite timeouts and dynamic ports.</p><div className="tabs"><button className={protocol === "tcp" ? "active" : ""} onClick={() => setProtocol("tcp")}>TCP Socket Demo</button><button className={protocol === "udp" ? "active" : ""} onClick={() => setProtocol("udp")}>UDP Socket Demo</button></div><SocketDemo protocol={protocol}/></main>; }
// SocketDemo controls one backend-managed echo server and displays its logs.
function SocketDemo({ protocol }) { const [status, setStatus] = useState({}); const [message, setMessage] = useState("Hello from NetLab"); const [result, setResult] = useState(null); const [busy, setBusy] = useState(false); const [error, setError] = useState(""); const refresh = async () => setStatus((await api("/api/socket/status"))[protocol]); useEffect(() => { refresh().catch(() => undefined); }, [protocol]); const act = async (action) => { setBusy(true); setError(""); try { const body = action === "send" ? {method:"POST", body: JSON.stringify({message})} : {method:"POST"}; const response = await api(`/api/socket/${protocol}/${action}`, body); if (action === "send") setResult(response.result); setStatus(response.status); } catch (e) { setError(e instanceof Error ? e.message : "Socket action failed"); } finally { setBusy(false); } }; return <section className="card socket-card"><div className="row"><div><h2>{protocol.toUpperCase()} echo server</h2><p className="muted">{protocol === "tcp" ? "TCP establishes a connection and provides ordered, reliable bytes." : "UDP sends independent datagrams without a TCP-style connection or delivery guarantee."}</p></div><Badge tone={status.running ? "success" : "muted"}>{status.running ? `Running on ${status.port}` : "Stopped"}</Badge></div><div className="actions"><button onClick={() => act("start")} disabled={busy || status.running}><Play size={16}/> Start server</button><button className="secondary" onClick={() => act("stop")} disabled={busy || !status.running}><Square size={16}/> Stop server</button></div><div className="send-row"><input aria-label="Socket message" value={message} onChange={e => setMessage(e.target.value)} disabled={!status.running}/><button onClick={() => act("send")} disabled={busy || !status.running}><Send size={16}/> Send</button></div>{error && <div className="notice error">{error}</div>}{result && <div className="result good"><strong>Echo received: {result.message}</strong><span>{result.bytes} bytes · {result.elapsed_ms} ms</span></div>}<Console>{status.logs?.length ? status.logs.map(log => `${new Date(log.timestamp).toLocaleTimeString()}  ${log.message}`).join("\n") : "Activity log is empty."}</Console><button className="link-button" onClick={() => setStatus({...status, logs: []})}>Clear log</button></section>; }

function Commands() {
  const [commands, setCommands] = useState([]);
  const [selected, setSelected] = useState(null);
  const [commandInput, setCommandInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => { api("/api/commands").then(response => setCommands(response.commands)).catch(error => setError(error instanceof Error ? error.message : "Could not load commands")); }, []);
  const run = async (id) => {
    setBusy(true); setError("");
    try { setSelected((await api("/api/commands/run", { method: "POST", body: JSON.stringify({ id }) })).result); }
    catch (error) { setError(error instanceof Error ? error.message : "Command failed"); }
    finally { setBusy(false); }
  };
  const execute = async (event) => {
    event.preventDefault();
    setBusy(true); setError("");
    try {
      setSelected((await api("/api/commands/execute", { method: "POST", body: JSON.stringify({ command: commandInput }) })).result);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Command failed");
    } finally { setBusy(false); }
  };
  return <main className="content"><div className="eyebrow">MODULE 02 · COMMANDS</div><h1>Network commands</h1><p className="lead">Write a read-only networking command, request execution from the Python backend, and inspect its real terminal output.</p>{error && <div className="notice error">{error}</div>}<div className="command-layout"><div className="command-left"><section className="card command-terminal"><div className="row"><div><h2>Backend terminal</h2><p className="muted">Allowlisted commands only · shell execution is disabled</p></div><Terminal size={19}/></div><form className="terminal-form" onSubmit={execute}><input aria-label="Network command" value={commandInput} onChange={event => setCommandInput(event.target.value)} placeholder="Example: ping 127.0.0.1" spellCheck="false"/><button type="submit" disabled={busy || !commandInput.trim()}><Send size={15}/> Execute</button></form><p className="terminal-help">Try <code>ipconfig /all</code>, <code>ping 127.0.0.1</code>, or <code>nslookup example.com</code>.</p></section><section className="card command-list">{commands.map(command => <article className="command-row" key={command.id}><div><code>{command.command}</code><strong>{command.label}</strong><span>{command.description}</span></div><button onClick={() => { setCommandInput(command.command); run(command.id); }} disabled={busy}>Run in console <Play size={14}/></button></article>)}</section></div><section className="card live-console"><div className="row"><div><h2>Live console</h2><p className="muted">Runs on the backend host</p></div><Badge tone={busy ? "warning" : "success"}>{busy ? "Running" : "Ready"}</Badge></div><Console>{selected ? `PS C:\\NetLab> ${selected.command}\n\n${selected.output}\n\n[exit code: ${selected.exit_code ?? "timeout"}]` : "Enter a command or select a preset to run it in the backend terminal."}</Console></section></div></main>;
}

function Protocols() {
  return <main className="content"><div className="eyebrow">MODULE 02 · COMMUNICATION RULES</div><h1>Network protocols</h1><p className="lead">Protocols define the format and order of messages exchanged between networked systems.</p><div className="protocol-grid">{protocols.map(protocol => <article className="card protocol-card" key={protocol.name}><Badge tone="blue">{protocol.name}</Badge><p>{protocol.definition}</p></article>)}</div></main>;
}

// App owns the navigation views for the lab modules.
function App() { const [view, setView] = useState("overview"); return <><header><div className="brand"><div className="logo"><Network/></div><div><strong>NetLab</strong><span>Python Networking Lab</span></div></div><nav>{["overview", "automation", "sockets", "commands", "protocols"].map(item => <button key={item} className={view === item ? "active" : ""} onClick={() => setView(item)}>{item === "overview" ? "Overview" : item === "automation" ? "Networking Automation" : item === "sockets" ? "Socket Programming" : item === "commands" ? "Commands" : "Protocols"}</button>)}</nav><div className="backend"><i/> Python backend</div></header>{view === "overview" ? <Overview go={setView}/> : view === "automation" ? <Automation/> : view === "sockets" ? <Sockets/> : view === "commands" ? <Commands/> : <Protocols/>}</>; }
createRoot(document.getElementById("root")).render(<StrictMode><App/></StrictMode>);
