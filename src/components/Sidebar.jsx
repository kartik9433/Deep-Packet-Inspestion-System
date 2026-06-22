import { NavLink, useNavigate } from "react-router-dom";
import {
  LayoutDashboard,
  PackageSearch,
  Network,
  ShieldAlert,
  LogOut,
  Activity,
} from "lucide-react";

const navItems = [
  { to: "/", label: "Dashboard",        icon: LayoutDashboard },
  { to: "/packets", label: "Packet Analysis", icon: PackageSearch },
  { to: "/connections", label: "Connections",   icon: Network },
  { to: "/rules",   label: "Rules",          icon: ShieldAlert },
];

export default function Sidebar() {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem("token");
    navigate("/login");
  };

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <Activity size={20} className="brand-icon" />
        <span>DPI<span className="brand-accent">Sys</span></span>
      </div>

      <nav className="sidebar-nav">
        {navItems.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) =>
              `sidebar-link ${isActive ? "active" : ""}`
            }
          >
            <Icon size={16} />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      <button className="sidebar-logout" onClick={handleLogout}>
        <LogOut size={15} />
        <span>Logout</span>
      </button>
    </aside>
  );
}