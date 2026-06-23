import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { signup } from "../api/authapi";
import { Activity } from "lucide-react";

export default function Signup() {
  const [form, setForm] = useState({ username: "", password: "", confirm: "" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handle = (e) =>
    setForm((f) => ({ ...f, [e.target.name]: e.target.value }));

  const submit = async (e) => {
    e.preventDefault();
    if (form.password !== form.confirm) {
      setError("Passwords do not match.");
      return;
    }
    setError("");
    setLoading(true);
    try {
      await signup(form.username, form.password);
      navigate("/login");
    } catch {
      setError("Signup failed. Username may already be taken.");
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
        <p className="auth-subtitle">Create your account</p>

        <form onSubmit={submit} className="auth-form">
          <div className="field">
            <label>Username</label>
            <input name="username" value={form.username} onChange={handle} required />
          </div>
          <div className="field">
            <label>Password</label>
            <input name="password" type="password" value={form.password} onChange={handle} required />
          </div>
          <div className="field">
            <label>Confirm Password</label>
            <input name="confirm" type="password" value={form.confirm} onChange={handle} required />
          </div>

          {error && <p className="auth-error">{error}</p>}

          <button className="btn-primary" disabled={loading}>
            {loading ? "Creating…" : "Create account"}
          </button>
        </form>

        <p className="auth-footer">
          Have an account? <Link to="/login">Sign in</Link>
        </p>
      </div>
    </div>
  );
}