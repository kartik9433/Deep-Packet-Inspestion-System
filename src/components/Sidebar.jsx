import { Link } from "react-router-dom";

function Sidebar() {
  return (
    <div className="bg-dark text-white vh-100 p-3">
      <h4>DPI Dashboard</h4>

      <ul className="nav flex-column mt-4">
        <li className="nav-item">
          <Link className="nav-link text-white" to="/">
            Dashboard
          </Link>
        </li>

        <li className="nav-item">
          <Link className="nav-link text-white" to="/packets">
            Packet Analysis
          </Link>
        </li>

        <li className="nav-item">
          <Link className="nav-link text-white" to="/connections">
            Connections
          </Link>
        </li>

        <li className="nav-item">
          <Link className="nav-link text-white" to="/rules">
            Rules
          </Link>
        </li>
      </ul>
    </div>
  );
}

export default Sidebar;