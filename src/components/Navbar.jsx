import { useLocation } from "react-router-dom";
import { RefreshCw } from "lucide-react";

const titles = {
  "/": "Dashboard",
  "/packets": "Packet Analysis",
  "/connections": "Connections",
  "/rules": "Rule Management",
};

export default function Navbar({ onRefresh }) {
  const { pathname } = useLocation();
  const title = titles[pathname] ?? "DPI System";

  return (
    <header className="topbar">
      <h1 className="topbar-title">{title}</h1>
      <div className="topbar-right">
        <span className="status-dot" />
        <span className="status-label">Live</span>
        {onRefresh && (
          <button className="icon-btn" onClick={onRefresh} title="Refresh">
            <RefreshCw size={15} />
          </button>
        )}
      </div>
    </header>
  );
}