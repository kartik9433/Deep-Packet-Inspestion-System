import { useEffect, useState } from "react";
import {
  getRules,
  blockIp, unblockIp,
  blockDomain, unblockDomain,
  blockPort, unblockPort,
  blockApp, unblockApp,
} from "../api/ruleApi";
import { Trash2, Plus } from "lucide-react";

const TABS = ["IP", "Domain", "Port", "App"];

const APP_TYPES = [
  "HTTP","HTTPS","DNS","FTP","SMTP","SSH","BITTORRENT","TLS","QUIC","UNKNOWN"
];

export default function Rules() {
  const [rules, setRules] = useState({});
  const [tab, setTab] = useState("IP");
  const [input, setInput] = useState("");
  const [error, setError] = useState("");

  const load = async () => {
    try {
      const res = await getRules();
      setRules(res.data);
    } catch {
      setError("Could not load rules. Is backend running?");
    }
  };

  useEffect(() => { load(); }, []);

  const add = async () => {
    if (!input.trim()) return;
    setError("");
    try {
      if (tab === "IP")     await blockIp(input.trim());
      if (tab === "Domain") await blockDomain(input.trim());
      if (tab === "Port")   await blockPort(parseInt(input.trim()));
      if (tab === "App")    await blockApp(input.trim().toUpperCase());
      setInput("");
      load();
    } catch (e) {
      setError(e.response?.data?.error ?? "Failed to add rule.");
    }
  };

  const remove = async (value) => {
    try {
      if (tab === "IP")     await unblockIp(value);
      if (tab === "Domain") await unblockDomain(value);
      if (tab === "Port")   await unblockPort(value);
      if (tab === "App")    await unblockApp(value);
      load();
    } catch {
      
    }
  };

  const listKey = {
    IP: "blockedIps",
    Domain: "blockedDomains",
    Port: "blockedPorts",
    App: "blockedApps",
  }[tab];

  const items = rules[listKey] ?? [];

  return (
    <div className="page">
      <div className="rule-tabs">
        {TABS.map((t) => (
          <button
            key={t}
            className={`filter-tab ${tab === t ? "active" : ""}`}
            onClick={() => { setTab(t); setInput(""); setError(""); }}
          >
            {t}
          </button>
        ))}
      </div>

      <div className="add-rule-bar">
        {tab === "App" ? (
          <select
            className="rule-select"
            value={input}
            onChange={(e) => setInput(e.target.value)}
          >
            <option value="">Select app type…</option>
            {APP_TYPES.map((a) => (
              <option key={a} value={a}>{a}</option>
            ))}
          </select>
        ) : (
          <input
            className="rule-input"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={
              tab === "IP"     ? "e.g. 192.168.1.1" :
              tab === "Domain" ? "e.g. example.com" :
                                 "e.g. 8080"
            }
            onKeyDown={(e) => e.key === "Enter" && add()}
          />
        )}
        <button className="btn-danger" onClick={add} disabled={!input}>
          <Plus size={14} /> Block
        </button>
      </div>

      {error && <p className="error-msg">{error}</p>}

      <div className="rule-list">
        {items.length === 0 ? (
          <p className="empty-msg">No blocked {tab.toLowerCase()}s</p>
        ) : (
          items.map((item, i) => (
            <div key={i} className="rule-item">
              <span className="rule-value mono">{item}</span>
              <button className="icon-btn danger" onClick={() => remove(item)} title="Remove">
                <Trash2 size={14} />
              </button>
            </div>
          ))
        )}
      </div>

      <div className="rule-stats">
        <span>{rules.stats?.totalRules ?? 0} total rules</span>
        <span>{rules.stats?.activeRules ?? 0} active</span>
      </div>
    </div>
  );
}