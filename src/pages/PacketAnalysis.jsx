import { useState, useRef } from "react";
import { uploadPcap, getReport } from "../api/packetApi";
import { Upload, FileText, CheckCircle, XCircle } from "lucide-react";

export default function PacketAnalysis() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [report, setReport] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const inputRef = useRef();

  const analyze = async () => {
    if (!file) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const fd = new FormData();
      fd.append("file", file);
      const res = await uploadPcap(fd);
      setResult(res.data);
    } catch (e) {
      setError(e.response?.data?.error ?? "Analysis failed. Is the backend running?");
    } finally {
      setLoading(false);
    }
  };

  const fetchReport = async () => {
    try {
      const res = await getReport();
      setReport(res.data);
    } catch {
      setReport("Could not load report.");
    }
  };

  return (
    <div className="page">
      {/* Upload zone */}
      <div
        className={`upload-zone ${file ? "has-file" : ""}`}
        onClick={() => inputRef.current?.click()}
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => {
          e.preventDefault();
          const f = e.dataTransfer.files[0];
          if (f) setFile(f);
        }}
      >
        <Upload size={28} className="upload-icon" />
        {file ? (
          <>
            <p className="upload-filename">{file.name}</p>
            <p className="upload-meta">{(file.size / 1024).toFixed(1)} KB</p>
          </>
        ) : (
          <>
            <p className="upload-hint">Drop a <code>.pcap</code> file here, or click to browse</p>
          </>
        )}
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng"
          style={{ display: "none" }}
          onChange={(e) => setFile(e.target.files[0])}
        />
      </div>

      <div className="row-actions">
        <button className="btn-primary" onClick={analyze} disabled={!file || loading}>
          {loading ? "Analyzing…" : "Run Analysis"}
        </button>
        <button className="btn-ghost" onClick={fetchReport}>
          <FileText size={14} /> View Report
        </button>
      </div>

      {error && <p className="error-msg">{error}</p>}

      {result && (
        <div className="result-card">
          <div className="result-header">
            {result.success
              ? <CheckCircle size={18} className="icon-green" />
              : <XCircle size={18} className="icon-red" />}
            <span>{result.message}</span>
          </div>
          <div className="result-grid">
            <div className="result-item">
              <span className="result-label">Total Packets</span>
              <span className="result-value">{result.totalPackets?.toLocaleString()}</span>
            </div>
            <div className="result-item accent-green">
              <span className="result-label">Forwarded</span>
              <span className="result-value">{result.forwardedPackets?.toLocaleString()}</span>
            </div>
            <div className="result-item accent-red">
              <span className="result-label">Dropped</span>
              <span className="result-value">{result.droppedPackets?.toLocaleString()}</span>
            </div>
          </div>
        </div>
      )}

      {report && (
        <div className="report-box">
          <h3 className="chart-title">Engine Report</h3>
          <pre>{report}</pre>
        </div>
      )}
    </div>
  );
}