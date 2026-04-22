import React, { useEffect, useState } from "react";
import axios from "axios";
import { Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  registerables,
} from "chart.js";
import VulnerabilityChart from "./components/VulnerabilityChart";
import {
  Shield,
  Layout,
  AlertTriangle,
  Activity,
  Terminal,
  Globe,
  ChevronDown,
} from "lucide-react";
import "./App.css";

ChartJS.register(...registerables);

function App() {
  const [projects, setProjects] = useState([]);
  const [selectedId, setSelectedId] = useState("");
  const [data, setData] = useState(null);

  useEffect(() => {
    axios.get("http://127.0.0.1:8000/projects").then((res) => {
      setProjects(res.data);
      if (res.data.length > 0) setSelectedId(res.data[0].id);
    });
  }, []);

  useEffect(() => {
    if (selectedId) {
      axios
        .get(`http://127.0.0.1:8000/dashboard-summary/${selectedId}`)
        .then((res) => setData(res.data))
        .catch((err) => console.error("Error loading dashboard", err));
    }
  }, [selectedId]);

  if (!data)
    return <div className="loading">Initializing Secure Environment...</div>;

  const lineData = {
    labels: data.trend.map((t) => t.month),
    datasets: [
      {
        label: "Threats Detected",
        data: data.trend.map((t) => t.count),
        borderColor: "#60a5fa",
        tension: 0.4,
      },
    ],
  };

  return (
    <div className="container">
      <nav className="sidebar">
        <div className="logo">
          <Shield color="#60a5fa" size={28} />
          <span>AutoShield</span>
        </div>

        <div className="nav-item active">
          <Layout size={20} /> Dashboard
        </div>
        <div className="nav-item">
          <Terminal size={20} /> Dev Agent
        </div>
        <div className="nav-item">
          <Globe size={20} /> Runtime
        </div>
      </nav>

      <main className="main-content">
        <header className="top-bar">
          <div className="project-selector">
            <Layout size={18} />
            <select
              value={selectedId}
              onChange={(e) => setSelectedId(e.target.value)}
            >
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
            <ChevronDown size={16} />
          </div>
          <div className="user-profile">SM</div>
        </header>

        <section className="stats-grid">
          <div className="glass-card risk-meter">
            <h3>Unified Risk Score</h3>
            <div
              className="score-value"
              style={{
                color: data.risk_score > 70 ? "#4ade80" : "#f87171",
              }}
            >
              {data.risk_score}
              <span>/100</span>
            </div>
            <p>
              {data.risk_score > 70
                ? "System Secure"
                : "Immediate Action Required"}
            </p>
            <p>Based on {data.total_scans} active scans</p>
          </div>

          <div className="glass-card chart-container">
            <h3>Severity Distribution</h3>
            <div className="chart-wrapper">
              <VulnerabilityChart stats={data.stats} />
            </div>
          </div>

          <div className="glass-card chart-container">
            <h3>Detection Trend</h3>
            <div className="chart-wrapper">
              <Line
                data={lineData}
                options={{
                  responsive: true,
                  maintainAspectRatio: false,
                  scales: {
                    y: {
                      grid: { color: "#334155" },
                      ticks: { color: "#94a3b8" },
                    },
                    x: {
                      grid: { display: false },
                      ticks: { color: "#94a3b8" },
                    },
                  },
                }}
              />
            </div>
          </div>
        </section>

        <section className="glass-card">
          <h3>Threat Breakdown</h3>
          <ul className="threat-list">
            <li>
              <AlertTriangle color="#ef4444" /> High: {data.stats.high}
            </li>
            <li>
              <AlertTriangle color="#f59e0b" /> Medium: {data.stats.medium}
            </li>
            <li>
              <Activity color="#10b981" /> Low: {data.stats.low}
            </li>
          </ul>
        </section>

        <section className="vuln-table glass-card">
          <h3>Recent Findings</h3>
          <table>
            <thead>
              <tr>
                <th>Tool</th>
                <th>Vulnerability</th>
                <th>Severity</th>
                <th>Path</th>
              </tr>
            </thead>
            <tbody>
              {data.recent_vulns.map((v, i) => (
                <tr key={i}>
                  <td>
                    <span className={`badge ${v.tool}`}>{v.tool}</span>
                  </td>
                  <td>{v.message}</td>
                  <td>
                    <span className={`sev ${v.severity}`}>
                      {v.severity}
                    </span>
                  </td>
                  <td>
                    <code>
                      {v.file_path}:{v.line}
                    </code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      </main>
    </div>
  );
}

export default App;