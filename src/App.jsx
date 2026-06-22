import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Navbar from "./components/Navbar";
import ProtectedRoute from "./components/ProtectedRoute";
import Login from "./pages/Login";
import Signup from "./pages/Signup";
import Dashboard from "./pages/Dashboard";
import PacketAnalysis from "./pages/PacketAnalysis";
import Connections from "./pages/Connections";
import Rules from "./pages/Rules";

function Layout() {
  return (
    <div className="app-shell">
      <Sidebar />
      <div className="main-area">
        <Navbar />
        <Routes>
          <Route path="/"            element={<Dashboard />} />
          <Route path="/packets"     element={<PacketAnalysis />} />
          <Route path="/connections" element={<Connections />} />
          <Route path="/rules"       element={<Rules />} />
          <Route path="*"            element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login"  element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        <Route
          path="/*"
          element={
            <ProtectedRoute>
              <Layout />
            </ProtectedRoute>
          }
        />
      </Routes>
    </BrowserRouter>
  );
}