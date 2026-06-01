"""
reporter/template_builder.py

Build prompt untuk AI reasoning dan render HTML report
dari findings JSON.

Flow:
    findings (dict) → build_prompt() → AI → parse_ai_response()
                                           → render_html()
                                           → report_{ts}.html
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from typing import Optional

from .ai_client import get_client

# ── Risk level mapping ────────────────────────────────────────────────────────

RISK_ORDER = ["critical", "high", "medium", "low", "info"]

RISK_COLOR = {
    "critical": "#ff4757",
    "high":     "#ff6b35",
    "medium":   "#ffb347",
    "low":      "#00d4ff",
    "info":     "#6b7a99",
}

RISK_SAFE_THRESHOLD = {"critical", "high", "medium"}  # ini yang trigger notif


# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a senior application security engineer specializing in web application vulnerabilities, particularly for PHP-based academic publishing systems like Open Journal Systems (OJS).

Your task is to analyze security findings from automated scans (SAST via Semgrep and DAST via custom scanner) and produce structured, actionable security reports.

For each finding, provide:
1. A clear, non-technical explanation of what the vulnerability is and why it's dangerous
2. Specific mitigation steps for BOTH administrators and developers
3. A CVSS-based risk score (0-10) with justification
4. Priority level: critical / high / medium / low / info

Always respond in valid JSON format exactly as specified. No markdown, no preamble."""


# ── Prompt builder ────────────────────────────────────────────────────────────

def build_prompt(findings: list[dict], target: str = "") -> str:
    """Build prompt untuk AI dari list findings."""

    findings_json = json.dumps(findings, indent=2, ensure_ascii=False)

    return f"""Analyze these security findings from an OJS (Open Journal Systems) security scan of target: {target or 'OJS instance'}

FINDINGS:
{findings_json}

Respond with a JSON object in this exact structure:
{{
  "executive_summary": {{
    "overview": "2-3 sentence non-technical summary of the overall security posture",
    "critical_count": <number>,
    "high_count": <number>,
    "medium_count": <number>,
    "low_count": <number>,
    "top_risk": "The single most critical issue in one sentence",
    "immediate_action": "The one thing that must be done immediately"
  }},
  "findings": [
    {{
      "id": "<original finding id or index>",
      "rule_id": "<rule id from scan>",
      "title": "Short descriptive title",
      "severity": "critical|high|medium|low|info",
      "cvss_score": <0.0-10.0>,
      "cvss_justification": "Why this score",
      "source": "sast|dast",
      "url_or_file": "<affected URL or file path>",
      "explanation": "Clear non-technical explanation of the vulnerability and its impact",
      "technical_detail": "Technical explanation for developers",
      "mitigation_admin": [
        "Step 1 for admin",
        "Step 2 for admin"
      ],
      "mitigation_developer": [
        "Step 1 for developer",
        "Step 2 for developer"
      ],
      "priority": <1-10, 1=most urgent>,
      "cwe": "<CWE-ID if applicable>",
      "owasp": "<OWASP category if applicable>"
    }}
  ],
  "recommendations": {{
    "immediate": ["Action 1", "Action 2"],
    "short_term": ["Action 1", "Action 2"],
    "long_term": ["Action 1", "Action 2"]
  }}
}}

Sort findings by priority (1=most urgent first).
Be specific and actionable. Reference OJS-specific paths and configurations where relevant."""


# ── AI response parser ────────────────────────────────────────────────────────

def parse_ai_response(raw: str) -> Optional[dict]:
    """Parse JSON response dari AI — handle kalau ada markdown wrapper."""
    if not raw:
        return None

    # Strip markdown code blocks kalau ada
    clean = re.sub(r"```(?:json)?\s*", "", raw).strip()
    clean = re.sub(r"```\s*$", "", clean).strip()

    try:
        return json.loads(clean)
    except json.JSONDecodeError as e:
        # Coba extract JSON dari dalam text
        match = re.search(r"\{.*\}", clean, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except Exception:
                pass

        import logging
        logging.getLogger("template_builder").error(f"Failed to parse AI response: {e}")
        return None


# ── HTML renderer ─────────────────────────────────────────────────────────────

def render_html(ai_result: dict, raw_findings: list[dict], meta: dict) -> str:
    """Render HTML report dari AI result."""

    ts          = meta.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    target      = meta.get("target", "OJS Instance")
    scan_types  = meta.get("scan_types", [])

    summary     = ai_result.get("executive_summary", {})
    findings    = ai_result.get("findings", [])
    recs        = ai_result.get("recommendations", {})

    total       = len(findings)
    critical    = summary.get("critical_count", 0)
    high        = summary.get("high_count", 0)
    medium      = summary.get("medium_count", 0)
    low         = summary.get("low_count", 0)

    # Overall risk level
    if critical > 0:
        overall_risk = "CRITICAL"
        overall_color = RISK_COLOR["critical"]
    elif high > 0:
        overall_risk = "HIGH"
        overall_color = RISK_COLOR["high"]
    elif medium > 0:
        overall_risk = "MEDIUM"
        overall_color = RISK_COLOR["medium"]
    elif low > 0:
        overall_risk = "LOW"
        overall_color = RISK_COLOR["low"]
    else:
        overall_risk = "SAFE"
        overall_color = "#00e5a0"

    # Build findings HTML
    findings_html = ""
    for i, f in enumerate(findings):
        sev         = f.get("severity", "info").lower()
        color       = RISK_COLOR.get(sev, RISK_COLOR["info"])
        cvss        = f.get("cvss_score", 0)
        admin_steps = "".join(f"<li>{s}</li>" for s in f.get("mitigation_admin", []))
        dev_steps   = "".join(f"<li>{s}</li>" for s in f.get("mitigation_developer", []))

        findings_html += f"""
        <div class="finding-card" data-severity="{sev}" style="--sev-color:{color}">
          <div class="finding-header">
            <div class="finding-meta">
              <span class="finding-num">#{i+1:02d}</span>
              <span class="sev-badge" style="background:{color}20;color:{color};border-color:{color}40">{sev.upper()}</span>
              <span class="source-badge">{f.get('source','').upper()}</span>
            </div>
            <div class="cvss-ring" title="CVSS {cvss}">
              <svg viewBox="0 0 36 36">
                <circle cx="18" cy="18" r="15.9" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="3"/>
                <circle cx="18" cy="18" r="15.9" fill="none" stroke="{color}" stroke-width="3"
                  stroke-dasharray="{cvss * 10} 100" stroke-linecap="round"
                  transform="rotate(-90 18 18)"/>
              </svg>
              <span>{cvss:.1f}</span>
            </div>
          </div>

          <h3 class="finding-title">{f.get('title', 'Unknown Finding')}</h3>
          <p class="finding-location"><code>{f.get('url_or_file', '')}</code></p>

          <div class="finding-tabs">
            <button class="ftab active" onclick="switchTab(this,'explain-{i}')">Explanation</button>
            <button class="ftab" onclick="switchTab(this,'admin-{i}')">For Admin</button>
            <button class="ftab" onclick="switchTab(this,'dev-{i}')">For Developer</button>
          </div>

          <div class="finding-panels">
            <div id="explain-{i}" class="fpanel active">
              <p class="explanation">{f.get('explanation','')}</p>
              <p class="tech-detail">{f.get('technical_detail','')}</p>
              <div class="tags-row">
                {'<span class="tag">'+f.get('cwe','')+'</span>' if f.get('cwe') else ''}
                {'<span class="tag tag-owasp">'+f.get('owasp','')+'</span>' if f.get('owasp') else ''}
              </div>
            </div>
            <div id="admin-{i}" class="fpanel">
              <ol class="step-list">{admin_steps}</ol>
            </div>
            <div id="dev-{i}" class="fpanel">
              <ol class="step-list">{dev_steps}</ol>
            </div>
          </div>
        </div>
        """

    # Build recommendations HTML
    def rec_list(items):
        return "".join(f"<li>{item}</li>" for item in items)

    recs_html = f"""
    <div class="recs-grid">
      <div class="rec-card rec-immediate">
        <h4>⚡ Immediate</h4>
        <ul>{rec_list(recs.get('immediate', []))}</ul>
      </div>
      <div class="rec-card rec-short">
        <h4>📅 Short Term</h4>
        <ul>{rec_list(recs.get('short_term', []))}</ul>
      </div>
      <div class="rec-card rec-long">
        <h4>🔭 Long Term</h4>
        <ul>{rec_list(recs.get('long_term', []))}</ul>
      </div>
    </div>
    """

    scan_badges = " ".join(
        f'<span class="scan-badge">{s.upper()}</span>' for s in scan_types
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>Security Report — {target} — {ts}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link href="https://fonts.googleapis.com/css2?family=Syne:wght@600;700;800&family=DM+Sans:wght@300;400;500;600&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet"/>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    :root{{
      --bg:#07090f;--bg2:#0c1220;--card:rgba(255,255,255,.035);--border:rgba(255,255,255,.07);
      --text:#e8edf5;--muted:#6b7a99;--cyan:#00d4ff;--green:#00e5a0;
      --radius:16px;--radius-sm:10px;
    }}
    html{{scroll-behavior:smooth}}
    body{{font-family:'DM Sans',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden}}
    body::before{{content:'';position:fixed;inset:0;
      background-image:radial-gradient(circle at 1px 1px,rgba(0,212,255,.06) 1px,transparent 0);
      background-size:36px 36px;pointer-events:none;z-index:0}}
    .wrap{{max-width:1100px;margin:0 auto;padding:0 1.5rem 4rem;position:relative;z-index:1}}

    /* ── HEADER ── */
    .rpt-header{{padding:2.5rem 0 2rem;border-bottom:1px solid var(--border);margin-bottom:2.5rem}}
    .rpt-header h1{{font-family:'Syne',sans-serif;font-size:clamp(1.4rem,3vw,2rem);font-weight:800;letter-spacing:-.02em}}
    .header-row{{display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;flex-wrap:wrap}}
    .header-meta{{display:flex;flex-direction:column;gap:.4rem}}
    .meta-line{{font-size:.78rem;color:var(--muted)}}
    .meta-line strong{{color:var(--text)}}
    .scan-badge{{display:inline-block;font-size:.68rem;font-weight:600;letter-spacing:.08em;
      padding:2px 8px;border-radius:4px;background:rgba(0,212,255,.1);border:1px solid rgba(0,212,255,.2);color:var(--cyan);margin-right:4px}}

    /* ── OVERALL RISK BADGE ── */
    .risk-hero{{display:flex;flex-direction:column;align-items:center;gap:.4rem;
      background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:var(--radius);
      padding:1.25rem 2rem;text-align:center;min-width:160px}}
    .risk-label{{font-size:.68rem;font-weight:600;letter-spacing:.12em;color:var(--muted);text-transform:uppercase}}
    .risk-value{{font-family:'Syne',sans-serif;font-size:1.6rem;font-weight:800;color:{overall_color}}}

    /* ── STATS ── */
    .stats-row{{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:2.5rem}}
    .stat{{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:1.25rem;
      position:relative;overflow:hidden;transition:border-color .2s}}
    .stat::after{{content:'';position:absolute;bottom:0;left:0;right:0;height:2px;background:var(--sev-color)}}
    .stat-num{{font-family:'Syne',sans-serif;font-size:2rem;font-weight:800;color:var(--sev-color)}}
    .stat-label{{font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-top:.25rem}}

    /* ── SECTION ── */
    .section-label{{font-size:.68rem;font-weight:600;color:var(--muted);text-transform:uppercase;
      letter-spacing:.12em;margin-bottom:1rem;display:flex;align-items:center;gap:8px}}
    .section-label::after{{content:'';flex:1;height:1px;background:var(--border)}}

    /* ── EXECUTIVE SUMMARY ── */
    .summary-card{{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);
      padding:1.5rem;margin-bottom:2.5rem}}
    .summary-card p{{color:var(--text);line-height:1.7;margin-bottom:.75rem}}
    .summary-card p:last-child{{margin-bottom:0}}
    .highlight-box{{background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.2);
      border-radius:var(--radius-sm);padding:1rem 1.25rem;margin-top:1rem}}
    .highlight-box .hl-label{{font-size:.7rem;font-weight:600;letter-spacing:.1em;color:#ff4757;margin-bottom:.4rem}}
    .highlight-box p{{color:var(--text);font-size:.9rem;margin:0}}

    /* ── FINDINGS ── */
    .findings-list{{display:flex;flex-direction:column;gap:1rem;margin-bottom:2.5rem}}
    .finding-card{{background:var(--card);border:1px solid rgba(255,255,255,.07);
      border-left:3px solid var(--sev-color);border-radius:var(--radius);padding:1.5rem;
      transition:border-color .2s}}
    .finding-header{{display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem}}
    .finding-meta{{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap}}
    .finding-num{{font-family:'DM Mono',monospace;font-size:.75rem;color:var(--muted)}}
    .sev-badge{{font-size:.68rem;font-weight:600;letter-spacing:.08em;padding:3px 10px;
      border-radius:4px;border:1px solid}}
    .source-badge{{font-size:.65rem;font-weight:600;letter-spacing:.1em;padding:2px 8px;
      border-radius:4px;background:rgba(255,255,255,.06);color:var(--muted)}}
    .cvss-ring{{position:relative;width:48px;height:48px;flex-shrink:0}}
    .cvss-ring svg{{width:100%;height:100%}}
    .cvss-ring span{{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
      font-family:'Syne',sans-serif;font-size:.75rem;font-weight:700;color:var(--sev-color)}}
    .finding-title{{font-family:'Syne',sans-serif;font-size:1rem;font-weight:700;margin-bottom:.4rem}}
    .finding-location{{font-size:.78rem;color:var(--muted);margin-bottom:1rem}}
    .finding-location code{{font-family:'DM Mono',monospace;color:var(--cyan);font-size:.76rem}}

    /* ── TABS ── */
    .finding-tabs{{display:flex;gap:.5rem;margin-bottom:1rem;border-bottom:1px solid var(--border);padding-bottom:.75rem}}
    .ftab{{font-family:'DM Sans',sans-serif;font-size:.78rem;font-weight:500;
      padding:.4rem 1rem;border-radius:6px;border:1px solid transparent;
      background:transparent;color:var(--muted);cursor:pointer;transition:all .15s}}
    .ftab.active{{background:rgba(0,212,255,.1);border-color:rgba(0,212,255,.2);color:var(--cyan)}}
    .ftab:hover:not(.active){{background:rgba(255,255,255,.04);color:var(--text)}}
    .fpanel{{display:none}}
    .fpanel.active{{display:block}}
    .explanation{{color:var(--text);line-height:1.7;margin-bottom:.75rem}}
    .tech-detail{{font-size:.85rem;color:var(--muted);line-height:1.6;margin-bottom:.75rem}}
    .tags-row{{display:flex;gap:.5rem;flex-wrap:wrap}}
    .tag{{font-size:.68rem;font-weight:600;padding:2px 8px;border-radius:4px;
      background:rgba(0,212,255,.08);border:1px solid rgba(0,212,255,.15);color:var(--cyan)}}
    .tag-owasp{{background:rgba(245,200,66,.08);border-color:rgba(245,200,66,.15);color:#f5c842}}
    .step-list{{padding-left:1.25rem;color:var(--text);line-height:1.8;font-size:.9rem}}
    .step-list li{{margin-bottom:.4rem}}

    /* ── RECOMMENDATIONS ── */
    .recs-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:2.5rem}}
    .rec-card{{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:1.25rem}}
    .rec-card h4{{font-family:'Syne',sans-serif;font-size:.9rem;font-weight:700;margin-bottom:.75rem}}
    .rec-immediate h4{{color:#ff4757}}
    .rec-short h4{{color:#ffb347}}
    .rec-long h4{{color:var(--cyan)}}
    .rec-card ul{{padding-left:1.1rem;font-size:.85rem;color:var(--text);line-height:1.7}}
    .rec-card li{{margin-bottom:.35rem}}

    /* ── FOOTER ── */
    .rpt-footer{{border-top:1px solid var(--border);padding-top:1.5rem;
      display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.75rem}}
    .footer-meta{{font-size:.75rem;color:var(--muted)}}

    @media(max-width:700px){{
      .stats-row{{grid-template-columns:repeat(2,1fr)}}
      .recs-grid{{grid-template-columns:1fr}}
      .header-row{{flex-direction:column}}
    }}
  </style>
</head>
<body>
<div class="wrap">

  <!-- HEADER -->
  <header class="rpt-header">
    <div class="header-row">
      <div class="header-meta">
        <h1>Security Assessment Report</h1>
        <p class="meta-line"><strong>Target:</strong> {target}</p>
        <p class="meta-line"><strong>Generated:</strong> {ts}</p>
        <p class="meta-line"><strong>Scan types:</strong> {scan_badges}</p>
        <p class="meta-line"><strong>Total findings:</strong> {total}</p>
      </div>
      <div class="risk-hero">
        <span class="risk-label">Overall Risk</span>
        <span class="risk-value">{overall_risk}</span>
      </div>
    </div>
  </header>

  <!-- STATS -->
  <div class="stats-row">
    <div class="stat" style="--sev-color:{RISK_COLOR['critical']}">
      <div class="stat-num">{critical}</div>
      <div class="stat-label">Critical</div>
    </div>
    <div class="stat" style="--sev-color:{RISK_COLOR['high']}">
      <div class="stat-num">{high}</div>
      <div class="stat-label">High</div>
    </div>
    <div class="stat" style="--sev-color:{RISK_COLOR['medium']}">
      <div class="stat-num">{medium}</div>
      <div class="stat-label">Medium</div>
    </div>
    <div class="stat" style="--sev-color:{RISK_COLOR['low']}">
      <div class="stat-num">{low}</div>
      <div class="stat-label">Low</div>
    </div>
  </div>

  <!-- EXECUTIVE SUMMARY -->
  <p class="section-label">Executive Summary</p>
  <div class="summary-card">
    <p>{summary.get('overview','')}</p>
    <div class="highlight-box">
      <div class="hl-label">⚠ Top Risk</div>
      <p>{summary.get('top_risk','')}</p>
    </div>
    <div class="highlight-box" style="background:rgba(0,212,255,.06);border-color:rgba(0,212,255,.2);margin-top:.75rem">
      <div class="hl-label" style="color:var(--cyan)">⚡ Immediate Action Required</div>
      <p>{summary.get('immediate_action','')}</p>
    </div>
  </div>

  <!-- FINDINGS -->
  <p class="section-label">Findings ({total})</p>
  <div class="findings-list">
    {findings_html}
  </div>

  <!-- RECOMMENDATIONS -->
  <p class="section-label">Recommendations</p>
  {recs_html}

  <!-- FOOTER -->
  <footer class="rpt-footer">
    <div class="footer-meta">
      OJS Security Assessment Platform &nbsp;·&nbsp; Report generated {ts}
    </div>
    <div class="footer-meta">
      AI-assisted analysis &nbsp;·&nbsp; Not a substitute for manual review
    </div>
  </footer>

</div>
<script>
function switchTab(btn, panelId) {{
  const card = btn.closest('.finding-card');
  card.querySelectorAll('.ftab').forEach(t => t.classList.remove('active'));
  card.querySelectorAll('.fpanel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById(panelId).classList.add('active');
}}
</script>
</body>
</html>"""


# ── Main entry point ──────────────────────────────────────────────────────────

def generate_report(
    findings: list[dict],
    target: str = "",
    scan_types: list[str] | None = None,
    output_dir: str = "../results/reports",
) -> Optional[str]:
    """
    Generate HTML report dari findings.
    Return: path ke file HTML yang dihasilkan, atau None kalau gagal.
    """
    if not findings:
        return None

    os.makedirs(output_dir, exist_ok=True)

    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    ts_disp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build prompt dan kirim ke AI
    prompt = build_prompt(findings, target)
    client = get_client()

    print(f"[Reporter] Sending {len(findings)} findings to AI...")
    raw = client.complete(prompt, SYSTEM_PROMPT)

    if not raw:
        print("[Reporter] AI gagal merespons")
        return None

    ai_result = parse_ai_response(raw)
    if not ai_result:
        print("[Reporter] Gagal parse AI response")
        return None

    print(f"[Reporter] AI response OK — rendering HTML...")

    meta = {
        "timestamp":  ts_disp,
        "target":     target,
        "scan_types": scan_types or [],
    }

    html    = render_html(ai_result, findings, meta)
    outpath = os.path.join(output_dir, f"report_{ts}.html")

    with open(outpath, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[Reporter] Report saved: {outpath}")
    return outpath
