import { useEffect, useState, useCallback } from "react";
import { getPacketStatus } from "../api/packetApi";
import { getConnectionStats } from "../api/connectionApi";
import StatsCard from "../components/StatsCard";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from "recharts";
import { Layers, ArrowDownCircle, ArrowUpCircle, Wifi } from "lucide-react";

const PIE_COLORS = ["#22d3ee", "#f59e0b", "#f87171", "#a78bfa", "#34d399", "#fb923c"];

function useLiveStats(interval = 3000) {
  const [stats, setStats] = useState(null);
  const [connStats, setConnStats] = useState(null);
  const [history, setHistory] = useState([]);

  const fetch = useCallback(async () => {
    try {
      const [s, c] = await Promise.all([getPacketStatus(), getConnectionStats()]);
      setStats(s.data);
      setConnStats(c.data);
      setHistory((h) => {
        const entry = {
          t: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
          forwarded: s.data.forwardedPackets ?? 0,
          dropped: s.data.droppedPackets ?? 0,
        };
        const next = [...h, entry];
        return next.length > 20 ? next.slice(-20) : next;
      });
    } catch {
        
    }
  }, []);

  useEffect(() => {
    fetch();
    const id = setInterval(fetch, interval);
    return () => clearInterval(id);
  }, [fetch, interval]);

  return { stats, connStats, history, refresh: fetch };
}

export default function Dashboard() {
  const { stats, connStats, history } = useLiveStats();

  const appDist = connStats?.appDistribution
    ? Object.entries(connStats.appDistribution).map(([name, value]) => ({ name, value }))
    : [];

  return (
    <div className="page">
      {/* Stats Row */}
      <div className="stats-grid">
        <StatsCard title="Total Packets"    value={stats?.totalPackets?.toLocaleString()}    icon={Layers}           accent="cyan" />
        <StatsCard title="Forwarded"        value={stats?.forwardedPackets?.toLocaleString()} icon={ArrowUpCircle}   accent="green" />
        <StatsCard title="Dropped"          value={stats?.droppedPackets?.toLocaleString()}   icon={ArrowDownCircle} accent="red" />
        <StatsCard title="Active Connections" value={stats?.activeConnections?.toLocaleString()} icon={Wifi}         accent="purple" />
      </div>

      {/* Charts Row */}
      <div className="charts-grid">
        <div className="chart-card">
          <h3 className="chart-title">Packet Traffic — live</h3>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={history} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="gFwd" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#22d3ee" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gDrp" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#f87171" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#f87171" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="t" tick={{ fontSize: 10, fill: "#64748b" }} interval="preserveStartEnd" />
              <YAxis tick={{ fontSize: 10, fill: "#64748b" }} />
              <Tooltip
                contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 6 }}
                labelStyle={{ color: "#94a3b8" }}
                itemStyle={{ color: "#e2e8f0" }}
              />
              <Area type="monotone" dataKey="forwarded" stroke="#22d3ee" fill="url(#gFwd)" strokeWidth={2} dot={false} name="Forwarded" />
              <Area type="monotone" dataKey="dropped"   stroke="#f87171" fill="url(#gDrp)" strokeWidth={2} dot={false} name="Dropped" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card">
          <h3 className="chart-title">App Distribution</h3>
          {appDist.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie
                  data={appDist}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {appDist.map((_, i) => (
                    <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 6 }}
                  itemStyle={{ color: "#e2e8f0" }}
                />
                <Legend
                  iconSize={8}
                  formatter={(v) => <span style={{ color: "#94a3b8", fontSize: 11 }}>{v}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-chart">No connection data yet</div>
          )}
        </div>
      </div>

      {/* Protocol breakdown */}
      {stats && (
        <div className="chart-card">
          <h3 className="chart-title">Protocol Breakdown</h3>
          <div className="protocol-bars">
            {[
              { label: "TCP",   value: stats.tcpPackets,   color: "#22d3ee" },
              { label: "UDP",   value: stats.udpPackets,   color: "#a78bfa" },
              { label: "Other", value: stats.otherPackets, color: "#64748b" },
            ].map(({ label, value, color }) => {
              const total = (stats.tcpPackets || 0) + (stats.udpPackets || 0) + (stats.otherPackets || 0);
              const pct = total > 0 ? Math.round((value / total) * 100) : 0;
              return (
                <div key={label} className="proto-row">
                  <span className="proto-label">{label}</span>
                  <div className="proto-track">
                    <div className="proto-fill" style={{ width: `${pct}%`, background: color }} />
                  </div>
                  <span className="proto-pct">{pct}%</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}