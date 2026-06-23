import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { login } from "../api/authapi";
import { Activity, Eye, EyeOff } from "lucide-react";

export default function Login() {
  const [form, setForm] = useState({ username: "", password: "" });
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handle = (e) =>
    setForm((f) => ({ ...f, [e.target.name]: e.target.value }));

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await login(form.username, form.password);
      localStorage.setItem("token", res.data.jwt);  
      navigate("/");
    } catch {
      setError("Invalid credentials. Check username and password.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-brand">
          <Activity size={28} />
          <span>DPI<span className="brand-accent">Sys</span></span>
        </div>
        <p className="auth-subtitle">Deep Packet Inspection Console</p>

        <form onSubmit={submit} className="auth-form">
          <div className="field">
            <label>Username</label>
            <input
              name="username"
              value={form.username}
              onChange={handle}
              autoComplete="username"
              required
            />
          </div>

          <div className="field">
            <label>Password</label>
            <div className="input-wrap">
              <input
                name="password"
                type={showPw ? "text" : "password"}
                value={form.password}
                onChange={handle}
                autoComplete="current-password"
                required
              />
              <button
                type="button"
                className="pw-toggle"
                onClick={() => setShowPw((v) => !v)}
              >
                {showPw ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
          </div>

          {error && <p className="auth-error">{error}</p>}

          <button className="btn-primary" disabled={loading}>
            {loading ? "Signing in…" : "Sign in"}
          </button>
        </form>

        <p className="auth-footer">
          No account?{" "}
          <Link to="/signup">Create one</Link>
        </p>
      </div>
    </div>
  );
}