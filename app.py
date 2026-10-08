import streamlit as st
from aws_adapter import AWSCloudAdapter
from auditor_engine import CloudSecurityAuditor
from aws_remediator import AWSRemediator
import io
import csv
from datetime import datetime

# ─── Page Config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AWS CSPM & Auto-Remediation Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Global CSS Design System ─────────────────────────────────────────────────
st.markdown("""
<style>
/* ── Base & Reset ─────────────────────────────────────────────────── */
html, body, [data-testid="stAppViewContainer"] {
    background-color: #0d1117 !important;
    color: #e6edf3 !important;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif !important;
}
[data-testid="stMain"] {
    background-color: #0d1117 !important;
}

/* ── Sidebar ──────────────────────────────────────────────────────── */
[data-testid="stSidebar"] {
    background-color: #0d1117 !important;
    border-right: 1px solid #21262d !important;
}
[data-testid="stSidebar"] > div:first-child {
    padding-top: 0 !important;
}
.sidebar-brand {
    background: linear-gradient(135deg, #1f2937 0%, #111827 100%);
    border-bottom: 1px solid #21262d;
    padding: 20px 16px 16px 16px;
    margin-bottom: 8px;
}
.sidebar-brand-title {
    font-size: 18px;
    font-weight: 700;
    color: #58a6ff;
    letter-spacing: -0.3px;
    display: flex;
    align-items: center;
    gap: 8px;
}
.sidebar-brand-sub {
    font-size: 11px;
    color: #8b949e;
    margin-top: 4px;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}
.sidebar-section-label {
    font-size: 11px;
    font-weight: 600;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    padding: 16px 16px 6px 0;
    margin-bottom: 4px;
}
.sidebar-footer {
    position: fixed;
    bottom: 0;
    padding: 12px 16px;
    border-top: 1px solid #21262d;
    background: #0d1117;
    width: 280px;
}
.sidebar-footer-text {
    font-size: 11px;
    color: #484f58;
}

/* ── Streamlit widget overrides ───────────────────────────────────── */
[data-testid="stSelectbox"] label,
[data-testid="stTextInput"] label {
    color: #8b949e !important;
    font-size: 12px !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.6px !important;
}
[data-testid="stSelectbox"] > div > div {
    background-color: #161b22 !important;
    border: 1px solid #30363d !important;
    border-radius: 8px !important;
    color: #e6edf3 !important;
}
[data-testid="stSelectbox"] > div > div:hover {
    border-color: #58a6ff !important;
}

/* ── Buttons ──────────────────────────────────────────────────────── */
[data-testid="stButton"] > button {
    border-radius: 8px !important;
    font-weight: 600 !important;
    font-size: 14px !important;
    transition: all 0.2s ease !important;
    border: none !important;
    width: 100% !important;
    padding: 10px 16px !important;
}
/* Primary CTA – Run Audit */
[data-testid="stButton"]:nth-of-type(2) > button,
[data-testid="stButton"] > button[kind="primary"] {
    background: linear-gradient(135deg, #1f6feb 0%, #0d4fa8 100%) !important;
    color: #ffffff !important;
    box-shadow: 0 2px 8px rgba(31, 111, 235, 0.3) !important;
}
[data-testid="stButton"] > button:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 4px 16px rgba(31, 111, 235, 0.4) !important;
    opacity: 0.92 !important;
}
[data-testid="stButton"] > button:active {
    transform: translateY(0px) !important;
}

/* ── Cards ────────────────────────────────────────────────────────── */
.cspm-card {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 16px;
    transition: border-color 0.2s ease;
}
.cspm-card:hover {
    border-color: #30363d;
}
.cspm-card-header {
    font-size: 13px;
    font-weight: 600;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-bottom: 12px;
    display: flex;
    align-items: center;
    gap: 8px;
}

/* ── Score Card ───────────────────────────────────────────────────── */
.score-card {
    background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
    border: 1px solid #21262d;
    border-radius: 16px;
    padding: 28px;
    text-align: center;
    position: relative;
    overflow: hidden;
    margin-bottom: 16px;
}
.score-card::before {
    content: "";
    position: absolute;
    top: -60px; left: 50%; transform: translateX(-50%);
    width: 200px; height: 200px;
    border-radius: 50%;
    opacity: 0.05;
}
.score-card.score-critical::before { background: #f85149; }
.score-card.score-warning::before  { background: #d29922; }
.score-card.score-good::before     { background: #3fb950; }
.score-label-small {
    font-size: 12px;
    font-weight: 600;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 8px;
}
.score-value {
    font-size: 64px;
    font-weight: 800;
    line-height: 1;
    margin-bottom: 8px;
    letter-spacing: -2px;
}
.score-value.score-critical { color: #f85149; }
.score-value.score-warning  { color: #d29922; }
.score-value.score-good     { color: #3fb950; }
.score-badge {
    display: inline-block;
    padding: 4px 14px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
}
.score-badge.score-critical { background: rgba(248,81,73,0.15); color: #f85149; border: 1px solid rgba(248,81,73,0.3); }
.score-badge.score-warning  { background: rgba(210,153,34,0.15); color: #d29922; border: 1px solid rgba(210,153,34,0.3); }
.score-badge.score-good     { background: rgba(63,185,80,0.15);  color: #3fb950; border: 1px solid rgba(63,185,80,0.3); }

/* ── Severity Badges ──────────────────────────────────────────────── */
.sev-badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.6px;
    text-transform: uppercase;
    white-space: nowrap;
}
.sev-CRITICAL { background: rgba(248,81,73,0.15);  color: #f85149; border: 1px solid rgba(248,81,73,0.25); }
.sev-HIGH     { background: rgba(219,109,40,0.15);  color: #db6d28; border: 1px solid rgba(219,109,40,0.25); }
.sev-MEDIUM   { background: rgba(210,153,34,0.15);  color: #d29922; border: 1px solid rgba(210,153,34,0.25); }
.sev-LOW      { background: rgba(88,166,255,0.12);  color: #58a6ff; border: 1px solid rgba(88,166,255,0.2); }

/* ── Category Icons ───────────────────────────────────────────────── */
.cat-badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 600;
    background: #21262d;
    color: #8b949e;
    border: 1px solid #30363d;
    white-space: nowrap;
}

/* ── Violations Table ─────────────────────────────────────────────── */
.violations-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13.5px;
}
.violations-table thead tr {
    border-bottom: 1px solid #21262d;
}
.violations-table thead th {
    padding: 10px 14px;
    text-align: left;
    font-size: 11px;
    font-weight: 600;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.7px;
    white-space: nowrap;
}
.violations-table tbody tr {
    border-bottom: 1px solid #161b22;
    transition: background-color 0.15s ease;
}
.violations-table tbody tr:hover {
    background-color: #1c2128;
}
.violations-table tbody td {
    padding: 12px 14px;
    color: #e6edf3;
    vertical-align: top;
}
.violations-table tbody td.resource-col {
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    font-size: 12.5px;
    color: #79c0ff;
}
.violations-table tbody td.issue-col {
    color: #c9d1d9;
    font-size: 13px;
    line-height: 1.5;
}
.section-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 14px;
}
.section-title {
    font-size: 16px;
    font-weight: 700;
    color: #e6edf3;
    display: flex;
    align-items: center;
    gap: 8px;
}
.count-badge {
    background: #21262d;
    border: 1px solid #30363d;
    color: #8b949e;
    font-size: 11px;
    font-weight: 600;
    padding: 2px 10px;
    border-radius: 20px;
}
.count-badge.has-issues {
    background: rgba(248,81,73,0.1);
    border-color: rgba(248,81,73,0.25);
    color: #f85149;
}

/* ── Alert / Info Boxes ───────────────────────────────────────────── */
.alert-box {
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 14px;
    display: flex;
    align-items: flex-start;
    gap: 12px;
    font-size: 13.5px;
    line-height: 1.5;
}
.alert-info    { background: rgba(88,166,255,0.08);  border: 1px solid rgba(88,166,255,0.2);  color: #79c0ff; }
.alert-success { background: rgba(63,185,80,0.08);   border: 1px solid rgba(63,185,80,0.2);   color: #3fb950; }
.alert-warning { background: rgba(210,153,34,0.08);  border: 1px solid rgba(210,153,34,0.2);  color: #d29922; }
.alert-danger  { background: rgba(248,81,73,0.08);   border: 1px solid rgba(248,81,73,0.2);   color: #f85149; }
.alert-icon { font-size: 18px; flex-shrink: 0; margin-top: 1px; }
.alert-body { flex: 1; }
.alert-body strong { display: block; font-weight: 700; margin-bottom: 3px; }

/* ── Dry Run Result Items ─────────────────────────────────────────── */
.dryrun-item {
    background: #161b22;
    border: 1px solid #21262d;
    border-left: 3px solid #58a6ff;
    border-radius: 8px;
    padding: 12px 16px;
    margin-bottom: 10px;
    font-size: 13px;
    color: #c9d1d9;
    line-height: 1.5;
}
.dryrun-item code {
    background: #21262d;
    border-radius: 4px;
    padding: 1px 6px;
    font-size: 12px;
    color: #79c0ff;
    font-family: "SFMono-Regular", Consolas, monospace;
}
.iam-dryrun-item {
    border-left-color: #d29922;
}

/* ── Welcome Screen ───────────────────────────────────────────────── */
.welcome-card {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 16px;
    padding: 40px;
    text-align: center;
    margin-top: 20px;
}
.welcome-title {
    font-size: 26px;
    font-weight: 800;
    color: #e6edf3;
    margin-bottom: 10px;
}
.welcome-subtitle {
    font-size: 15px;
    color: #8b949e;
    margin-bottom: 28px;
    line-height: 1.6;
}
.feature-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 14px;
    margin: 24px 0;
    text-align: left;
}
.feature-item {
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 10px;
    padding: 16px;
}
.feature-icon { font-size: 20px; margin-bottom: 6px; }
.feature-label {
    font-size: 13px;
    font-weight: 700;
    color: #e6edf3;
    margin-bottom: 4px;
}
.feature-desc {
    font-size: 12px;
    color: #8b949e;
    line-height: 1.4;
}

/* ── Page Header ──────────────────────────────────────────────────── */
.page-header {
    padding: 8px 0 20px 0;
    border-bottom: 1px solid #21262d;
    margin-bottom: 24px;
}
.page-title {
    font-size: 28px;
    font-weight: 800;
    color: #e6edf3;
    letter-spacing: -0.5px;
    margin: 0;
}
.page-tagline {
    font-size: 14px;
    color: #8b949e;
    margin-top: 4px;
}

/* ── Metric Overrides ─────────────────────────────────────────────── */
[data-testid="stMetric"] {
    background: #161b22 !important;
    border: 1px solid #21262d !important;
    border-radius: 10px !important;
    padding: 16px !important;
}
[data-testid="stMetricLabel"] {
    font-size: 11px !important;
    font-weight: 600 !important;
    color: #8b949e !important;
    text-transform: uppercase !important;
    letter-spacing: 0.7px !important;
}
[data-testid="stMetricValue"] {
    color: #e6edf3 !important;
    font-size: 26px !important;
    font-weight: 800 !important;
}

/* ── Spinner / Status ─────────────────────────────────────────────── */
[data-testid="stSpinner"] > div {
    color: #58a6ff !important;
}

/* ── Divider ──────────────────────────────────────────────────────── */
hr {
    border: none !important;
    border-top: 1px solid #21262d !important;
    margin: 20px 0 !important;
}

/* ── Remediation section ──────────────────────────────────────────── */
.remediation-card {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 12px;
    padding: 22px 24px;
    margin-top: 20px;
}
.remediation-title {
    font-size: 15px;
    font-weight: 700;
    color: #e6edf3;
    margin-bottom: 6px;
    display: flex;
    align-items: center;
    gap: 8px;
}
.remediation-desc {
    font-size: 13px;
    color: #8b949e;
    margin-bottom: 16px;
    line-height: 1.5;
}
.success-banner {
    background: rgba(63,185,80,0.08);
    border: 1px solid rgba(63,185,80,0.25);
    border-radius: 10px;
    padding: 18px 22px;
    display: flex;
    align-items: center;
    gap: 14px;
}
.success-banner-icon { font-size: 28px; }
.success-banner-title { font-size: 16px; font-weight: 700; color: #3fb950; margin-bottom: 2px; }
.success-banner-sub { font-size: 13px; color: #8b949e; }

/* ── Scrollbar ────────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0d1117; }
::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #484f58; }
</style>
""", unsafe_allow_html=True)


# ─── Helper: score class ──────────────────────────────────────────────────────
def score_class(score):
    if score >= 80:
        return "good"
    elif score >= 50:
        return "warning"
    return "critical"

def score_label(score):
    if score >= 80:
        return "Secure"
    elif score >= 50:
        return "At Risk"
    return "Critical"

def sev_icon(sev):
    icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}
    return icons.get(sev, "⚪")

def cat_icon(cat):
    icons = {"IAM": "👤", "Storage": "🗄️", "Network": "🌐"}
    return icons.get(cat, "📋")


# ─── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div class="sidebar-brand">
        <div class="sidebar-brand-title">🛡️ ShieldScan</div>
        <div class="sidebar-brand-sub">Cloud Security Posture Management</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="sidebar-section-label">⚙️ Configuration</div>', unsafe_allow_html=True)

    # ── PRESERVED: region selectbox ──
    region = st.selectbox("AWS Region", ["us-east-1", "us-west-2", "eu-west-1"])

    st.markdown('<div class="sidebar-section-label">🔧 Controls</div>', unsafe_allow_html=True)

    # ── PRESERVED: reset button ──
    if st.button("🔄 Reset Dashboard"):
        st.session_state.clear()
        st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    # ── PRESERVED: run audit button ──
    run_audit = st.button("🔍 Run Live Audit", key="run_audit_btn")

    st.markdown("""
    <div style="margin-top: 24px; padding: 12px; background: #0d1117; border: 1px solid #21262d; border-radius: 8px;">
        <div style="font-size: 11px; color: #484f58; line-height: 1.6;">
            <div>🔒 Read-only audit mode</div>
            <div>⚡ Real-time AWS scanning</div>
            <div>📋 Auto-remediation engine</div>
        </div>
    </div>
    """, unsafe_allow_html=True)


# ─── Initialize AWS clients (PRESERVED exactly) ───────────────────────────────
adapter = AWSCloudAdapter(region_name=region)
remediator = AWSRemediator(region_name=region)


# ─── Page Header ──────────────────────────────────────────────────────────────
st.markdown(f"""
<div class="page-header">
    <div class="page-title">🛡️ Cloud Security Posture Management</div>
    <div class="page-tagline">Automated Cloud Security Auditor &amp; Auto-Remediation Engine &nbsp;·&nbsp; Region: <code style="background:#161b22;color:#79c0ff;padding:2px 7px;border-radius:5px;font-size:12px;">{region}</code></div>
</div>
""", unsafe_allow_html=True)


# ─── Run Audit (PRESERVED exactly) ───────────────────────────────────────────
if run_audit:
    with st.spinner("🔎 Connecting to AWS and fetching live infrastructure metadata…"):
        config = adapter.get_standardized_config()
        auditor = CloudSecurityAuditor(config)
        score, issues = auditor.generate_report()

        st.session_state["score"] = score
        st.session_state["issues"] = issues


# ─── Dashboard Content ────────────────────────────────────────────────────────
if "score" in st.session_state:
    score  = st.session_state["score"]
    issues = st.session_state["issues"]
    sc     = score_class(score)

    # ── Security Score + Metrics ──────────────────────────────────────────────
    col_score, col_metrics = st.columns([1, 2], gap="medium")

    with col_score:
        st.markdown(f"""
        <div class="score-card score-{sc}">
            <div class="score-label-small">Overall Security Score</div>
            <div class="score-value score-{sc}">{score:.0f}<span style="font-size:28px;opacity:0.6;">%</span></div>
            <div class="score-badge score-{sc}">{score_label(score)}</div>
        </div>
        """, unsafe_allow_html=True)

    with col_metrics:
        total_violations = len(issues)
        critical_count   = sum(1 for i in issues if i.get("severity") == "CRITICAL")
        high_count       = sum(1 for i in issues if i.get("severity") == "HIGH")
        medium_count     = sum(1 for i in issues if i.get("severity") == "MEDIUM")

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("🚨 Total Findings", total_violations)
        m2.metric("🔴 Critical", critical_count)
        m3.metric("🟠 High", high_count)
        m4.metric("🟡 Medium", medium_count)

        # Region + scan info strip
        st.markdown(f"""
        <div style="background:#161b22;border:1px solid #21262d;border-radius:10px;padding:14px 18px;margin-top:12px;display:flex;gap:24px;flex-wrap:wrap;">
            <div>
                <div style="font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:0.6px;font-weight:600;">Region</div>
                <div style="font-size:14px;color:#79c0ff;font-weight:600;margin-top:3px;">{region}</div>
            </div>
            <div>
                <div style="font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:0.6px;font-weight:600;">Compliance</div>
                <div style="font-size:14px;color:{'#3fb950' if score>=80 else '#d29922' if score>=50 else '#f85149'};font-weight:600;margin-top:3px;">{'Compliant' if score>=80 else 'Partial' if score>=50 else 'Non-Compliant'}</div>
            </div>
            <div>
                <div style="font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:0.6px;font-weight:600;">Engine</div>
                <div style="font-size:14px;color:#e6edf3;font-weight:600;margin-top:3px;">IAM · S3 · Network</div>
            </div>
            <div>
                <div style="font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:0.6px;font-weight:600;">Status</div>
                <div style="font-size:14px;font-weight:600;margin-top:3px;color:#3fb950;">✅ Scan Complete</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Active Violations ─────────────────────────────────────────────────────
    if issues:
        count_class = "has-issues" if issues else ""
        st.markdown(f"""
        <div class="section-header">
            <div class="section-title">⚠️ Active Violations</div>
            <span class="count-badge {count_class}">{len(issues)} Finding{"s" if len(issues)!=1 else ""}</span>
        </div>
        """, unsafe_allow_html=True)

        # Build HTML table
        rows_html = ""
        for issue in issues:
            sev      = issue.get("severity", "LOW")
            cat      = issue.get("category", "Unknown")
            resource = issue.get("resource", "—")
            text     = issue.get("issue", "—")
            rows_html += f"""
            <tr>
                <td><span class="sev-badge sev-{sev}">{sev_icon(sev)} {sev}</span></td>
                <td><span class="cat-badge">{cat_icon(cat)} {cat}</span></td>
                <td class="resource-col">{resource}</td>
                <td class="issue-col">{text}</td>
            </tr>"""

        st.markdown(f"""
        <div class="cspm-card" style="padding:0;overflow:hidden;">
            <table class="violations-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Category</th>
                        <th>Resource</th>
                        <th>Issue Description</th>
                    </tr>
                </thead>
                <tbody>{rows_html}</tbody>
            </table>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # ── Auto-Remediation Panel ────────────────────────────────────────────
        st.markdown("""
        <div class="remediation-title">🔧 Auto-Remediation Controls</div>
        <div class="remediation-desc">
            Choose an action to remediate the detected violations. <strong>Dry-Run</strong> previews changes without modifying AWS resources. <strong>Live Remediation</strong> applies security patches immediately.
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="alert-box alert-warning">
            <div class="alert-icon">⚠️</div>
            <div class="alert-body">
                <strong>Before proceeding</strong>
                Live Auto-Remediation will mutate your live AWS infrastructure configurations. Ensure you have appropriate permissions and have reviewed the violations above.
            </div>
        </div>
        """, unsafe_allow_html=True)

        col1, col2 = st.columns(2)

        # ── PRESERVED: Dry-Run button + logic ──
        with col1:
            if st.button("🧪 Run Dry-Run Simulation"):
                st.markdown("""
                <div class="alert-box alert-info">
                    <div class="alert-icon">🧪</div>
                    <div class="alert-body">
                        <strong>Dry-Run Mode Active</strong>
                        Simulating remediation actions — no changes applied to AWS infrastructure.
                    </div>
                </div>
                """, unsafe_allow_html=True)

                for issue in st.session_state["issues"]:
                    if issue["category"] == "Storage":
                        st.markdown(f"""
                        <div class="dryrun-item">
                            🧪 <strong>[DRY-RUN]</strong> Would enforce Public Access Block on: <code>{issue['resource']}</code>
                        </div>
                        <div class="dryrun-item">
                            🧪 <strong>[DRY-RUN]</strong> Would enforce SSE-S3 Encryption on: <code>{issue['resource']}</code>
                        </div>
                        """, unsafe_allow_html=True)
                    elif issue["category"] == "IAM":
                        st.markdown(f"""
                        <div class="dryrun-item iam-dryrun-item">
                            ⚠️ <strong>[DRY-RUN]</strong> IAM MFA required on user <code>{issue['resource']}</code> — requires hardware token setup.
                        </div>
                        """, unsafe_allow_html=True)

                st.markdown("""
                <div class="alert-box alert-success">
                    <div class="alert-icon">✅</div>
                    <div class="alert-body">
                        <strong>Dry-run simulation complete</strong>
                        Zero changes applied to live infrastructure.
                    </div>
                </div>
                """, unsafe_allow_html=True)

        # ── PRESERVED: Live Remediation button + logic ──
        with col2:
            if st.button("⚡ Execute Live Auto-Remediation"):
                with st.spinner("Applying live security patches to AWS infrastructure…"):
                    for issue in st.session_state["issues"]:
                        if issue["category"] == "Storage":
                            remediator.fix_s3_public_access(issue["resource"], dry_run=False)
                            remediator.fix_s3_encryption(issue["resource"], dry_run=False)

                    remaining_issues = [
                        issue for issue in st.session_state["issues"]
                        if issue["category"] != "Storage"
                    ]

                    st.session_state["issues"] = remaining_issues
                    st.session_state["score"]  = 80.0

                    st.rerun()

        # ══════════════════════════════════════════════════════════════════════
        # FEATURE 1 — Security Analytics Charts
        # ══════════════════════════════════════════════════════════════════════
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("""
        <div class="section-header">
            <div class="section-title">📊 Security Analytics</div>
        </div>
        """, unsafe_allow_html=True)

        chart_col1, chart_col2 = st.columns(2, gap="medium")

        with chart_col1:
            st.markdown('<div class="cspm-card-header">Findings by Severity</div>', unsafe_allow_html=True)
            severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            sev_counts = {s: 0 for s in severity_order}
            for iss in issues:
                sev = iss.get("severity", "LOW")
                if sev in sev_counts:
                    sev_counts[sev] += 1
            import pandas as pd
            sev_df = pd.DataFrame({"Count": list(sev_counts.values())}, index=list(sev_counts.keys()))
            st.bar_chart(sev_df, color="#f85149", height=220)

        with chart_col2:
            st.markdown('<div class="cspm-card-header">Findings by Category</div>', unsafe_allow_html=True)
            cat_counts = {}
            for iss in issues:
                cat = iss.get("category", "Unknown")
                cat_counts[cat] = cat_counts.get(cat, 0) + 1
            cat_df = pd.DataFrame({"Count": list(cat_counts.values())}, index=list(cat_counts.keys()))
            st.bar_chart(cat_df, color="#58a6ff", height=220)

        # ══════════════════════════════════════════════════════════════════════
        # FEATURE 2 — One-Click CSV Audit Report Export
        # ══════════════════════════════════════════════════════════════════════
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("""
        <div class="section-header">
            <div class="section-title">📥 Export Audit Report</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="cspm-card">
            <div class="cspm-card-header">📄 Download full audit findings as a CSV report</div>
            <p style="font-size:13px;color:#8b949e;margin:6px 0 0 0;">
                Export a timestamped, portable CSV report of all current findings — share with your
                security team, attach to a ticket, or archive for compliance records.
            </p>
        </div>
        """, unsafe_allow_html=True)

        csv_buffer = io.StringIO()
        writer = csv.writer(csv_buffer)
        writer.writerow(["Timestamp", "Region", "Security Score (%)", "Severity", "Category", "Resource", "Issue"])
        scan_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for iss in issues:
            writer.writerow([
                scan_ts, region, f"{score:.2f}",
                iss.get("severity", ""), iss.get("category", ""),
                iss.get("resource", ""), iss.get("issue", ""),
            ])
        csv_content = csv_buffer.getvalue()
        filename = f"cspm_audit_{region}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        st.download_button(
            label="⬇️ Download Audit Report (CSV)",
            data=csv_content,
            file_name=filename,
            mime="text/csv",
        )

        # ══════════════════════════════════════════════════════════════════════
        # FEATURE 3 — CIS AWS Benchmark Compliance Mapper
        # ══════════════════════════════════════════════════════════════════════
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("""
        <div class="section-header">
            <div class="section-title">🏛️ CIS AWS Benchmark Compliance</div>
            <span class="count-badge">CIS AWS Foundations v1.4</span>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div style="font-size:13px;color:#8b949e;margin-bottom:16px;line-height:1.6;">
            Your findings are mapped against the <strong style="color:#e6edf3;">CIS AWS Foundations Benchmark v1.4</strong>
            — the industry-standard security baseline used by enterprise CSPM platforms like Prisma Cloud and Wiz.
        </div>
        """, unsafe_allow_html=True)

        CIS_CONTROLS = {
            ("IAM",     "MFA is disabled"):                      ("1.10", "Section 1 — Identity & Access", "Ensure MFA is enabled for all IAM users with console access"),
            ("IAM",     "wildcard policy"):                      ("1.16", "Section 1 — Identity & Access", "Ensure IAM policies that allow full admin are not directly attached"),
            ("IAM",     "access key age"):                       ("1.14", "Section 1 — Identity & Access", "Ensure access keys are rotated every 90 days or less"),
            ("Storage", "Public Access Block is disabled"):      ("2.1.2", "Section 2 — Storage",           "Ensure S3 Block Public Access setting is enabled"),
            ("Storage", "Server-Side Encryption"):               ("2.1.1", "Section 2 — Storage",           "Ensure all S3 buckets employ encryption-at-rest"),
            ("Network", "port 22"):                              ("5.2",   "Section 5 — Networking",         "Ensure no security groups allow unrestricted ingress to port 22"),
            ("Network", "port 3389"):                            ("5.3",   "Section 5 — Networking",         "Ensure no security groups allow unrestricted ingress to port 3389"),
        }

        def match_cis(issue_cat, issue_text):
            for (cat, keyword), ctrl in CIS_CONTROLS.items():
                if cat == issue_cat and keyword.lower() in issue_text.lower():
                    return ctrl
            return None

        sections = {}
        for (cat, keyword), (ctrl_id, section, description) in CIS_CONTROLS.items():
            if section not in sections:
                sections[section] = {"passed": 0, "failed": 0, "controls": {}}
            if ctrl_id not in sections[section]["controls"]:
                sections[section]["controls"][ctrl_id] = {
                    "id": ctrl_id, "desc": description,
                    "resources": [], "status": "PASS", "severity": ""
                }

        for iss in issues:
            ctrl = match_cis(iss.get("category", ""), iss.get("issue", ""))
            if ctrl:
                ctrl_id, section, _ = ctrl
                c = sections[section]["controls"][ctrl_id]
                if c["status"] == "PASS":
                    sections[section]["failed"]  += 1
                    sections[section]["passed"]  = max(0, sections[section]["passed"] - 0)
                c["status"]   = "FAIL"
                c["severity"] = iss.get("severity", "")
                c["resources"].append(iss.get("resource", ""))

        for section, data in sections.items():
            data["passed"] = sum(1 for c in data["controls"].values() if c["status"] == "PASS")
            data["failed"] = sum(1 for c in data["controls"].values() if c["status"] == "FAIL")

        total_pass = sum(v["passed"] for v in sections.values())
        total_fail = sum(v["failed"] for v in sections.values())
        total_ctrl = total_pass + total_fail
        cis_score  = (total_pass / total_ctrl * 100) if total_ctrl > 0 else 100.0
        cis_color  = "#3fb950" if cis_score >= 80 else "#d29922" if cis_score >= 50 else "#f85149"

        st.markdown(f"""
        <div class="cspm-card" style="margin-bottom:16px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                <div>
                    <div style="font-size:13px;font-weight:700;color:#e6edf3;">Overall CIS Compliance Score</div>
                    <div style="font-size:12px;color:#8b949e;margin-top:2px;">{total_pass} of {total_ctrl} controls passing</div>
                </div>
                <div style="font-size:36px;font-weight:800;color:{cis_color};">{cis_score:.0f}%</div>
            </div>
            <div style="background:#21262d;border-radius:6px;height:8px;overflow:hidden;">
                <div style="width:{cis_score:.1f}%;height:100%;background:{cis_color};border-radius:6px;"></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        section_order = ["Section 1 — Identity & Access", "Section 2 — Storage", "Section 5 — Networking"]
        for section_name in section_order:
            if section_name not in sections:
                continue
            data      = sections[section_name]
            n_pass    = data["passed"]
            n_fail    = data["failed"]
            n_total   = n_pass + n_fail
            sec_score = (n_pass / n_total * 100) if n_total > 0 else 100.0
            sec_icon  = "✅" if sec_score == 100 else ("⚠️" if sec_score >= 50 else "❌")
            with st.expander(f"{sec_icon}  {section_name}  —  {n_pass}/{n_total} passing  ({sec_score:.0f}%)", expanded=(n_fail > 0)):
                rows = ""
                for ctrl in sorted(data["controls"].values(), key=lambda x: (x["status"] == "PASS")):
                    status_html = (
                        '<span style="color:#f85149;font-weight:700;">✗ FAIL</span>'
                        if ctrl["status"] == "FAIL"
                        else '<span style="color:#3fb950;font-weight:700;">✓ PASS</span>'
                    )
                    sev_html  = f'<span class="sev-badge sev-{ctrl["severity"]}">{ctrl["severity"]}</span>' if ctrl["severity"] else "—"
                    res_html  = ", ".join(f'<code style="color:#79c0ff;font-size:12px;">{r}</code>' for r in ctrl["resources"]) or "—"
                    rows += f"""<tr style="border-bottom:1px solid #21262d;">
                        <td style="padding:10px 12px;font-size:12px;color:#8b949e;white-space:nowrap;font-weight:600;">CIS {ctrl['id']}</td>
                        <td style="padding:10px 12px;font-size:13px;color:#c9d1d9;line-height:1.4;">{ctrl['desc']}</td>
                        <td style="padding:10px 12px;">{res_html}</td>
                        <td style="padding:10px 12px;">{sev_html}</td>
                        <td style="padding:10px 12px;">{status_html}</td>
                    </tr>"""
                st.markdown(f"""
                <table style="width:100%;border-collapse:collapse;">
                    <thead><tr style="border-bottom:1px solid #30363d;">
                        <th style="padding:8px 12px;font-size:11px;color:#8b949e;text-align:left;text-transform:uppercase;letter-spacing:0.6px;white-space:nowrap;">Control</th>
                        <th style="padding:8px 12px;font-size:11px;color:#8b949e;text-align:left;text-transform:uppercase;letter-spacing:0.6px;">Description</th>
                        <th style="padding:8px 12px;font-size:11px;color:#8b949e;text-align:left;text-transform:uppercase;letter-spacing:0.6px;">Resource</th>
                        <th style="padding:8px 12px;font-size:11px;color:#8b949e;text-align:left;text-transform:uppercase;letter-spacing:0.6px;">Severity</th>
                        <th style="padding:8px 12px;font-size:11px;color:#8b949e;text-align:left;text-transform:uppercase;letter-spacing:0.6px;">Status</th>
                    </tr></thead>
                    <tbody>{rows}</tbody>
                </table>
                """, unsafe_allow_html=True)

    else:
        # ── Zero Violations Success State ─────────────────────────────────────
        st.markdown("""
        <div class="success-banner">
            <div class="success-banner-icon">🎉</div>
            <div>
                <div class="success-banner-title">Zero Active Violations</div>
                <div class="success-banner-sub">Your AWS environment is fully compliant. All security checks passed.</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

else:
    # ── Welcome / Empty State ─────────────────────────────────────────────────
    st.markdown("""
    <div class="welcome-card">
        <div class="welcome-title">Welcome to ShieldScan CSPM</div>
        <div class="welcome-subtitle">
            Connect to your live AWS environment and instantly surface security misconfigurations,
            compliance violations, and risky resource configurations — with one click.
        </div>
        <div class="feature-grid">
            <div class="feature-item">
                <div class="feature-icon">👤</div>
                <div class="feature-label">IAM Audit</div>
                <div class="feature-desc">MFA enforcement, access key rotation, overly-permissive policies</div>
            </div>
            <div class="feature-item">
                <div class="feature-icon">🗄️</div>
                <div class="feature-label">S3 Security</div>
                <div class="feature-desc">Public access blocks, encryption at rest (SSE-KMS / SSE-S3)</div>
            </div>
            <div class="feature-item">
                <div class="feature-icon">🌐</div>
                <div class="feature-label">Network Security</div>
                <div class="feature-desc">Security group rules, open ports (SSH/RDP) exposed to internet</div>
            </div>
        </div>
        <div class="alert-box alert-info" style="text-align:left;max-width:480px;margin:0 auto;">
            <div class="alert-icon">👈</div>
            <div class="alert-body">
                <strong>Get Started</strong>
                Select an AWS region in the sidebar, then click <strong>🔍 Run Live Audit</strong> to begin scanning.
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)