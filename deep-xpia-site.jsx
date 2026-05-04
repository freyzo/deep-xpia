import { useState, useEffect, useRef } from "react";

const AGENTS = [
  { id: "email", label: "Email Agent", x: 80, y: 200 },
  { id: "calendar", label: "Calendar Agent", x: 320, y: 200 },
  { id: "action", label: "Action Agent", x: 560, y: 200 },
];

const HOPS = [
  { from: 0, to: 1 },
  { from: 1, to: 2 },
];

const DDA_DATA = [
  { depth: 2, accuracy: 0.72 },
  { depth: 3, accuracy: 0.58 },
  { depth: 4, accuracy: 0.31 },
  { depth: 5, accuracy: 0.12 },
];

const TAXONOMY = [
  { id: "DXPIA-001", name: "Session smuggling", mech: "instruction piggyback", depth: 2 },
  { id: "DXPIA-002", name: "Memory poisoning", mech: "temporal persistence", depth: 2 },
  { id: "DXPIA-003", name: "Tool chain cascade", mech: "data flow cascade", depth: 3 },
  { id: "DXPIA-004", name: "Chain re-routing", mech: "control plane injection", depth: 2 },
  { id: "DXPIA-005", name: "Scope escalation", mech: "privilege differential", depth: 2 },
  { id: "DXPIA-006", name: "Intent laundering", mech: "adversarial refinement", depth: 3 },
  { id: "DXPIA-007", name: "Delayed trigger", mech: "conditional activation", depth: 2 },
];

const RESULTS = [
  { defense: "None", asr: 0.87, tpr: 0.05, fpr: 0.05 },
  { defense: "Intent verify", asr: 0.52, tpr: 0.57, fpr: 0.15 },
  { defense: "Taint tracking", asr: 0.64, tpr: 0.53, fpr: 0.08 },
  { defense: "Scope tokens", asr: 0.66, tpr: 0.38, fpr: 0.05 },
  { defense: "DLP", asr: 0.71, tpr: 0.33, fpr: 0.10 },
  { defense: "All combined", asr: 0.36, tpr: 0.76, fpr: 0.18 },
];

function CascadeViz() {
  const [step, setStep] = useState(0);
  const [defended, setDefended] = useState(false);
  const intervalRef = useRef(null);

  useEffect(() => {
    intervalRef.current = setInterval(() => {
      setStep((s) => {
        if (s >= 4) return 0;
        return s + 1;
      });
    }, 1400);
    return () => clearInterval(intervalRef.current);
  }, [defended]);

  const getAgentColor = (i) => {
    if (step === 0) return "#22c55e";
    if (i === 0 && step >= 1) return "#ef4444";
    if (i === 1 && step >= 2) {
      if (defended) return "#f59e0b";
      return "#ef4444";
    }
    if (i === 2 && step >= 3 && !defended) return "#ef4444";
    return "#22c55e";
  };

  const getHopColor = (i) => {
    if (step === 0) return "#334155";
    if (i === 0 && step >= 2) return "#ef4444";
    if (i === 1 && step >= 3) {
      if (defended) return "#f59e0b";
      return "#ef4444";
    }
    return "#334155";
  };

  const getNarration = () => {
    if (step === 0) return "Pipeline idle. 3 agents connected.";
    if (step === 1) return "HOP 1: Malicious email ingested. Email Agent compromised.";
    if (step === 2 && !defended) return "HOP 2: Poisoned data flows to Calendar Agent. Trust boundary breached.";
    if (step === 2 && defended) return "HOP 2: Intent verification caught drift. Score: 0.73. Blocked.";
    if (step === 3 && !defended) return "HOP 3: Action Agent sends credentials to attacker. Exfiltration complete.";
    if (step === 3 && defended) return "Attack stopped at depth 2. Pipeline safe.";
    if (step === 4) return defended ? "Defense held. Restarting..." : "3 hops. 0 alerts. Full compromise. Restarting...";
    return "";
  };

  return (
    <div style={{ position: "relative" }}>
      <div style={{
        display: "flex", justifyContent: "center", gap: 12, marginBottom: 24
      }}>
        <button
          onClick={() => { setDefended(false); setStep(0); }}
          style={{
            padding: "8px 20px",
            background: !defended ? "#ef4444" : "transparent",
            color: !defended ? "#fff" : "#94a3b8",
            border: `1px solid ${!defended ? "#ef4444" : "#334155"}`,
            borderRadius: 6,
            cursor: "pointer",
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 13,
            transition: "all 0.2s",
          }}
        >undefended</button>
        <button
          onClick={() => { setDefended(true); setStep(0); }}
          style={{
            padding: "8px 20px",
            background: defended ? "#22c55e" : "transparent",
            color: defended ? "#fff" : "#94a3b8",
            border: `1px solid ${defended ? "#22c55e" : "#334155"}`,
            borderRadius: 6,
            cursor: "pointer",
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 13,
            transition: "all 0.2s",
          }}
        >defended</button>
      </div>

      <svg viewBox="0 0 640 300" style={{ width: "100%", maxWidth: 640, display: "block", margin: "0 auto" }}>
        {HOPS.map((h, i) => (
          <g key={i}>
            <line
              x1={AGENTS[h.from].x + 40} y1={AGENTS[h.from].y}
              x2={AGENTS[h.to].x - 40} y2={AGENTS[h.to].y}
              stroke={getHopColor(i)}
              strokeWidth={3}
              style={{ transition: "stroke 0.4s" }}
            />
            <text
              x={(AGENTS[h.from].x + AGENTS[h.to].x) / 2}
              y={AGENTS[h.from].y - 30}
              fill={getHopColor(i)}
              textAnchor="middle"
              fontFamily="'JetBrains Mono', monospace"
              fontSize={11}
              style={{ transition: "fill 0.4s" }}
            >HOP {i + 1}</text>
            {defended && i === 1 && step >= 2 && (
              <g>
                <rect
                  x={(AGENTS[h.from].x + AGENTS[h.to].x) / 2 - 8}
                  y={AGENTS[h.from].y - 8}
                  width={16} height={16} rx={3}
                  fill="#f59e0b" opacity={0.9}
                />
                <text
                  x={(AGENTS[h.from].x + AGENTS[h.to].x) / 2}
                  y={AGENTS[h.from].y + 5}
                  fill="#000" textAnchor="middle"
                  fontFamily="'JetBrains Mono', monospace"
                  fontSize={12} fontWeight="bold"
                >x</text>
              </g>
            )}
          </g>
        ))}

        {AGENTS.map((a, i) => (
          <g key={a.id}>
            <circle
              cx={a.x} cy={a.y} r={36}
              fill="transparent"
              stroke={getAgentColor(i)}
              strokeWidth={2.5}
              style={{ transition: "stroke 0.4s" }}
            />
            {getAgentColor(i) === "#ef4444" && (
              <circle
                cx={a.x} cy={a.y} r={36}
                fill="transparent"
                stroke="#ef4444"
                strokeWidth={1}
                opacity={0.4}
              >
                <animate attributeName="r" from="36" to="52" dur="1s" repeatCount="indefinite" />
                <animate attributeName="opacity" from="0.4" to="0" dur="1s" repeatCount="indefinite" />
              </circle>
            )}
            <text
              x={a.x} y={a.y + 4}
              fill={getAgentColor(i)}
              textAnchor="middle"
              fontFamily="'JetBrains Mono', monospace"
              fontSize={10}
              style={{ transition: "fill 0.4s" }}
            >{a.label}</text>
          </g>
        ))}
      </svg>

      <div style={{
        textAlign: "center",
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: 13,
        color: step >= 1 && !defended ? "#ef4444" : step >= 2 && defended ? "#22c55e" : "#94a3b8",
        minHeight: 40,
        marginTop: 16,
        transition: "color 0.3s",
      }}>
        {getNarration()}
      </div>
    </div>
  );
}

function Bar({ value, max = 1, color = "#ef4444", label }) {
  const pct = (value / max) * 100;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
      <span style={{
        width: 50, textAlign: "right", fontFamily: "'JetBrains Mono', monospace",
        fontSize: 12, color: "#94a3b8"
      }}>{label}</span>
      <div style={{
        flex: 1, height: 14, background: "#1e293b", borderRadius: 3, overflow: "hidden"
      }}>
        <div style={{
          width: `${pct}%`, height: "100%", background: color,
          borderRadius: 3, transition: "width 0.6s ease"
        }} />
      </div>
      <span style={{
        width: 40, fontFamily: "'JetBrains Mono', monospace",
        fontSize: 12, color
      }}>{(value * 100).toFixed(0)}%</span>
    </div>
  );
}

export default function DeepXPIA() {
  const [activeTab, setActiveTab] = useState("taxonomy");

  return (
    <div style={{
      minHeight: "100vh",
      background: "#0a0f1a",
      color: "#e2e8f0",
      fontFamily: "'IBM Plex Sans', -apple-system, sans-serif",
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;500;700&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        a { color: #60a5fa; text-decoration: none; }
        a:hover { text-decoration: underline; }
        ::selection { background: #ef4444; color: #fff; }
      `}</style>

      {/* nav */}
      <nav style={{
        display: "flex", justifyContent: "space-between", alignItems: "center",
        padding: "20px 32px", borderBottom: "1px solid #1e293b",
        maxWidth: 1100, margin: "0 auto",
      }}>
        <div style={{
          fontFamily: "'JetBrains Mono', monospace", fontWeight: 700,
          fontSize: 18, color: "#ef4444", letterSpacing: -0.5,
        }}>deep-xpia</div>
        <div style={{ display: "flex", gap: 24, fontSize: 14 }}>
          <a href="#demo">Demo</a>
          <a href="#results">Results</a>
          <a href="#taxonomy-section">Taxonomy</a>
          <a href="https://github.com/freyzo/deep-xpia" target="_blank" rel="noopener">GitHub</a>
        </div>
      </nav>

      {/* hero */}
      <section style={{
        maxWidth: 800, margin: "0 auto", padding: "80px 32px 40px",
        textAlign: "center",
      }}>
        <div style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11, color: "#ef4444", letterSpacing: 2,
          textTransform: "uppercase", marginBottom: 20,
        }}>multi-hop cross-prompt injection benchmark</div>

        <h1 style={{
          fontFamily: "'IBM Plex Sans', sans-serif",
          fontSize: 44, fontWeight: 600, lineHeight: 1.15,
          color: "#f8fafc", marginBottom: 24,
          letterSpacing: -1,
        }}>
          One injection.<br/>Three agents.<br/>
          <span style={{ color: "#ef4444" }}>Zero alerts.</span>
        </h1>

        <p style={{
          fontSize: 17, color: "#94a3b8", lineHeight: 1.7,
          maxWidth: 560, margin: "0 auto 40px",
        }}>
          Your agent pipeline has 3 agents. An attacker injects one document.
          By hop 3, your credentials are exfiltrated - and no single agent
          did anything wrong. <strong style={{ color: "#e2e8f0" }}>deep-xpia</strong> benchmarks
          how detection degrades with depth.
        </p>

        <div style={{ display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap" }}>
          <a href="https://github.com/freyzo/deep-xpia" target="_blank" rel="noopener"
            style={{
              display: "inline-block", padding: "12px 28px",
              background: "#ef4444", color: "#fff", borderRadius: 6,
              fontFamily: "'JetBrains Mono', monospace", fontSize: 14,
              fontWeight: 500, textDecoration: "none",
              transition: "background 0.2s",
            }}
            onMouseEnter={e => e.target.style.background = "#dc2626"}
            onMouseLeave={e => e.target.style.background = "#ef4444"}
          >View on GitHub</a>
          <a href="#demo"
            style={{
              display: "inline-block", padding: "12px 28px",
              background: "transparent", color: "#94a3b8",
              border: "1px solid #334155", borderRadius: 6,
              fontFamily: "'JetBrains Mono', monospace", fontSize: 14,
              fontWeight: 500, textDecoration: "none",
              transition: "border-color 0.2s",
            }}
            onMouseEnter={e => e.target.style.borderColor = "#64748b"}
            onMouseLeave={e => e.target.style.borderColor = "#334155"}
          >Watch the cascade</a>
        </div>
      </section>

      {/* stats bar */}
      <section style={{
        maxWidth: 700, margin: "40px auto",
        display: "flex", justifyContent: "center", gap: 48, flexWrap: "wrap",
        padding: "0 32px",
      }}>
        {[
          { num: "250", label: "attack cases" },
          { num: "7", label: "DXPIA patterns" },
          { num: "4", label: "defenses evaluated" },
          { num: "60pt", label: "detection drop (depth 2-5)" },
        ].map(s => (
          <div key={s.label} style={{ textAlign: "center" }}>
            <div style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 28, fontWeight: 700, color: "#ef4444",
            }}>{s.num}</div>
            <div style={{ fontSize: 12, color: "#64748b", marginTop: 4 }}>{s.label}</div>
          </div>
        ))}
      </section>

      {/* cascade demo */}
      <section id="demo" style={{
        maxWidth: 700, margin: "60px auto", padding: "0 32px",
      }}>
        <h2 style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 14, color: "#64748b", letterSpacing: 1,
          textTransform: "uppercase", marginBottom: 24,
        }}>Live cascade</h2>

        <div style={{
          background: "#0f172a", border: "1px solid #1e293b",
          borderRadius: 8, padding: 32,
        }}>
          <CascadeViz />
        </div>

        <p style={{
          fontSize: 13, color: "#475569", marginTop: 12, textAlign: "center",
          fontFamily: "'JetBrains Mono', monospace",
        }}>
          Toggle between undefended and defended to see the difference.
        </p>
      </section>

      {/* DDA chart */}
      <section id="results" style={{
        maxWidth: 700, margin: "60px auto", padding: "0 32px",
      }}>
        <h2 style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 14, color: "#64748b", letterSpacing: 1,
          textTransform: "uppercase", marginBottom: 24,
        }}>Depth-dependent accuracy (DDA)</h2>

        <div style={{
          background: "#0f172a", border: "1px solid #1e293b",
          borderRadius: 8, padding: 32,
        }}>
          <p style={{ fontSize: 14, color: "#94a3b8", marginBottom: 20, lineHeight: 1.6 }}>
            Detection accuracy for intent verification, measured at each hop depth.
            The deeper the injection propagates, the harder it is to catch.
          </p>
          {DDA_DATA.map(d => (
            <Bar
              key={d.depth}
              value={d.accuracy}
              label={`d=${d.depth}`}
              color={d.accuracy > 0.5 ? "#22c55e" : d.accuracy > 0.25 ? "#f59e0b" : "#ef4444"}
            />
          ))}
        </div>
      </section>

      {/* results table */}
      <section style={{
        maxWidth: 700, margin: "60px auto", padding: "0 32px",
      }}>
        <h2 style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 14, color: "#64748b", letterSpacing: 1,
          textTransform: "uppercase", marginBottom: 24,
        }}>Defense evaluation</h2>

        <div style={{
          background: "#0f172a", border: "1px solid #1e293b",
          borderRadius: 8, overflow: "hidden",
        }}>
          <table style={{
            width: "100%", borderCollapse: "collapse",
            fontFamily: "'JetBrains Mono', monospace", fontSize: 13,
          }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #1e293b" }}>
                {["Defense", "ASR", "TPR", "FPR"].map(h => (
                  <th key={h} style={{
                    padding: "12px 16px", textAlign: "left",
                    color: "#64748b", fontWeight: 500, fontSize: 11,
                    textTransform: "uppercase", letterSpacing: 1,
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {RESULTS.map((r, i) => (
                <tr key={r.defense} style={{
                  borderBottom: i < RESULTS.length - 1 ? "1px solid #1e293b" : "none",
                  background: r.defense === "All combined" ? "#1e293b" : "transparent",
                }}>
                  <td style={{ padding: "10px 16px", color: "#e2e8f0" }}>{r.defense}</td>
                  <td style={{
                    padding: "10px 16px",
                    color: r.asr < 0.5 ? "#22c55e" : r.asr < 0.7 ? "#f59e0b" : "#ef4444"
                  }}>{r.asr.toFixed(2)}</td>
                  <td style={{
                    padding: "10px 16px",
                    color: r.tpr > 0.5 ? "#22c55e" : r.tpr > 0.3 ? "#f59e0b" : "#ef4444"
                  }}>{r.tpr.toFixed(2)}</td>
                  <td style={{ padding: "10px 16px", color: "#94a3b8" }}>{r.fpr.toFixed(2)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* taxonomy */}
      <section id="taxonomy-section" style={{
        maxWidth: 700, margin: "60px auto", padding: "0 32px",
      }}>
        <h2 style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 14, color: "#64748b", letterSpacing: 1,
          textTransform: "uppercase", marginBottom: 24,
        }}>Attack taxonomy</h2>

        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {TAXONOMY.map(t => (
            <div key={t.id} style={{
              background: "#0f172a", border: "1px solid #1e293b",
              borderRadius: 6, padding: "14px 20px",
              display: "flex", alignItems: "center", gap: 16,
              flexWrap: "wrap",
            }}>
              <span style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 12, color: "#ef4444", fontWeight: 600,
                minWidth: 90,
              }}>{t.id}</span>
              <span style={{ color: "#e2e8f0", fontSize: 14, flex: 1, minWidth: 140 }}>{t.name}</span>
              <span style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 11, color: "#64748b",
                background: "#1e293b", padding: "3px 8px", borderRadius: 4,
              }}>{t.mech}</span>
              <span style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 11, color: "#475569",
              }}>depth {t.depth}+</span>
            </div>
          ))}
        </div>
      </section>

      {/* quickstart */}
      <section style={{
        maxWidth: 700, margin: "60px auto", padding: "0 32px",
      }}>
        <h2 style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 14, color: "#64748b", letterSpacing: 1,
          textTransform: "uppercase", marginBottom: 24,
        }}>Quickstart</h2>

        <div style={{
          background: "#0f172a", border: "1px solid #1e293b",
          borderRadius: 8, padding: 24,
          fontFamily: "'JetBrains Mono', monospace", fontSize: 13,
          color: "#94a3b8", lineHeight: 2,
          overflowX: "auto",
        }}>
          <div><span style={{ color: "#475569" }}># full stack with visualizer</span></div>
          <div><span style={{ color: "#22c55e" }}>$</span> docker compose up</div>
          <div style={{ marginTop: 12 }}><span style={{ color: "#475569" }}># or pip</span></div>
          <div><span style={{ color: "#22c55e" }}>$</span> pip install deep-xpia</div>
          <div><span style={{ color: "#22c55e" }}>$</span> deepxpia demo</div>
          <div style={{ marginTop: 12 }}><span style={{ color: "#475569" }}># run the benchmark</span></div>
          <div><span style={{ color: "#22c55e" }}>$</span> deepxpia bench run --defense all</div>
        </div>
      </section>

      {/* footer */}
      <footer style={{
        maxWidth: 700, margin: "80px auto 0", padding: "32px",
        borderTop: "1px solid #1e293b",
        display: "flex", justifyContent: "space-between", alignItems: "center",
        flexWrap: "wrap", gap: 16,
      }}>
        <div>
          <span style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 14, color: "#ef4444", fontWeight: 700,
          }}>deep-xpia</span>
          <span style={{ color: "#334155", marginLeft: 12, fontSize: 13 }}>
            MIT License. Built by <a href="https://github.com/freyzo">Freya Zou</a>.
          </span>
        </div>
        <div style={{ display: "flex", gap: 20, fontSize: 13 }}>
          <a href="https://github.com/freyzo/deep-xpia">GitHub</a>
          <a href="https://arxiv.org/abs/2604.07775">ACIArena</a>
          <a href="https://arxiv.org/abs/2604.02767">SentinelAgent</a>
        </div>
      </footer>

      <div style={{ height: 40 }} />
    </div>
  );
}
