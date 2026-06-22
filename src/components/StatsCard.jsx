export default function StatsCard({ title, value, icon: Icon, accent, delta }) {
  return (
    <div className={`stats-card ${accent ? `accent-${accent}` : ""}`}>
      <div className="stats-card-header">
        <span className="stats-label">{title}</span>
        {Icon && (
          <span className="stats-icon">
            <Icon size={14} />
          </span>
        )}
      </div>
      <div className="stats-value">{value ?? "—"}</div>
      {delta != null && (
        <div className={`stats-delta ${delta >= 0 ? "up" : "down"}`}>
          {delta >= 0 ? "▲" : "▼"} {Math.abs(delta)}
        </div>
      )}
    </div>
  );
}