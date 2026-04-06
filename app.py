import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import time
import warnings
warnings.filterwarnings('ignore')

from generate_logs import generate_logs
from detector import load_and_preprocess, train_model, evaluate

st.set_page_config(
    page_title="CyberSentinel | Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── CUSTOM CSS ──────────────────────────────────────────────────────────────
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

  html, body, [class*="css"] {
    font-family: 'Rajdhani', sans-serif;
    background-color: #050d1a;
    color: #c9d8f0;
  }

  .main { background: #050d1a; }

  h1, h2, h3 { font-family: 'Share Tech Mono', monospace; }

  .stMetric {
    background: linear-gradient(135deg, #0a1628 0%, #0d1f3c 100%);
    border: 1px solid #1a3a6b;
    border-radius: 8px;
    padding: 16px !important;
  }
  .stMetric label { color: #4a90d9 !important; font-family: 'Share Tech Mono', monospace; font-size: 0.75rem !important; letter-spacing: 2px; }
  .stMetric [data-testid="metric-container"] > div:nth-child(2) { color: #ffffff !important; font-size: 2rem !important; font-weight: 700; }

  .threat-card {
    background: linear-gradient(135deg, #0f0f23 0%, #1a0a2e 100%);
    border-left: 3px solid #ff3a3a;
    border-radius: 6px;
    padding: 12px 16px;
    margin: 8px 0;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.8rem;
  }

  .normal-card {
    background: #0a1628;
    border-left: 3px solid #00ff88;
    border-radius: 6px;
    padding: 12px 16px;
    margin: 8px 0;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.8rem;
  }

  .section-header {
    font-family: 'Share Tech Mono', monospace;
    color: #4a90d9;
    font-size: 0.7rem;
    letter-spacing: 4px;
    text-transform: uppercase;
    border-bottom: 1px solid #1a3a6b;
    padding-bottom: 8px;
    margin-bottom: 16px;
  }

  .stDataFrame { font-family: 'Share Tech Mono', monospace; font-size: 0.75rem; }
  .stSidebar { background: #030b17 !important; }
  .stButton button {
    background: linear-gradient(90deg, #0066cc, #004499);
    color: white;
    border: 1px solid #1a5fa8;
    font-family: 'Share Tech Mono', monospace;
    letter-spacing: 2px;
    font-size: 0.75rem;
  }
  .stButton button:hover { background: linear-gradient(90deg, #0077ee, #0055bb); }

  div[data-testid="stSelectbox"] label,
  div[data-testid="stSlider"] label,
  div[data-testid="stMultiSelect"] label { color: #4a90d9; font-size: 0.75rem; letter-spacing: 2px; }

  .metric-label { color: #4a90d9; font-family: 'Share Tech Mono', monospace; font-size: 0.65rem; letter-spacing: 2px; margin-bottom: 2px; }
  .metric-value { color: #ffffff; font-family: 'Rajdhani', sans-serif; font-size: 1.8rem; font-weight: 700; line-height: 1.1; }
  .metric-delta { font-family: 'Share Tech Mono', monospace; font-size: 0.65rem; margin-top: 2px; }
  .metric-delta.danger { color: #ff3a3a; }
  .metric-delta.success { color: #00ff88; }
  .metric-delta.info { color: #4a90d9; }

  .metric-card {
    background: linear-gradient(135deg, #0a1628 0%, #0d1f3c 100%);
    border: 1px solid #1a3a6b;
    border-radius: 8px;
    padding: 16px 20px;
    text-align: center;
  }
</style>
""", unsafe_allow_html=True)

# ── HEADER ──────────────────────────────────────────────────────────────────
col_logo, col_title, col_status = st.columns([1, 4, 1])
with col_logo:
    st.markdown("## 🛡️")
with col_title:
    st.markdown("# CYBERSENTINEL")
    st.markdown('<p class="section-header">Threat Detection & Network Analysis System</p>', unsafe_allow_html=True)
with col_status:
    st.markdown(
        '<p style="color:#00ff88; font-family: Share Tech Mono; font-size:0.75rem; margin-top:20px;">'
        '● SYSTEM ONLINE</p>',
        unsafe_allow_html=True
    )

st.markdown("---")

# ── SIDEBAR ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<p class="section-header">⚙ Control Panel</p>', unsafe_allow_html=True)

    n_logs = st.slider("Log Volume", 500, 5000, 1000, step=100)

    if st.button("🔄 GENERATE NEW LOGS & ANALYZE", use_container_width=True):
        st.session_state["run_seed"] = int(time.time())
        st.cache_data.clear()

    st.markdown("---")
    st.markdown('<p class="section-header">🔍 Filters</p>', unsafe_allow_html=True)

    severity_filter = st.multiselect(
        "SEVERITY LEVEL",
        ["Critical", "High", "Medium", "Low", "None"],
        default=["Critical", "High", "Medium", "Low", "None"]
    )

    threat_filter = st.multiselect(
        "THREAT TYPE",
        ["Brute Force", "Data Exfiltration", "Unusual Location",
         "Off-Hours Activity", "Port Scan", "Suspicious Activity", "Normal"],
        default=["Brute Force", "Data Exfiltration", "Unusual Location",
                 "Off-Hours Activity", "Port Scan", "Suspicious Activity", "Normal"]
    )

    st.markdown("---")
    st.markdown(
        '<p style="font-family: Share Tech Mono; font-size: 0.65rem; color: #2a5a8b;">'
        'CYBERSENTINEL v2.5.0<br>Isolation Forest ML Engine<br>© 2026 RDG Security Labs</p>',
        unsafe_allow_html=True
    )

# ── DATA LOADING ──────────────────────────────────────────────────────────────
@st.cache_data(show_spinner=False)
def get_analyzed_data(n, seed):
    np.random.seed(seed)
    import random; random.seed(seed)
    df_raw = generate_logs(n)
    df, features = load_and_preprocess(df_raw)
    df, model, scaler, features = train_model(df, features)
    report = evaluate(df)
    return df, report

current_seed = st.session_state.get("run_seed", 42)

with st.spinner("🔍 Analyzing network traffic..."):
    df, model_report = get_analyzed_data(n_logs, current_seed)

# Apply filters — use AND so both severity and threat type must match
filtered = df[
    (df["severity"].isin(severity_filter)) &
    (df["threat_type"].isin(threat_filter))
]
threats_df = filtered[filtered["predicted_anomaly"] == 1]

# ── METRICS ROW ──────────────────────────────────────────────────────────────
m1, m2, m3, m4, m5 = st.columns(5)

total_events = len(filtered)
threat_count = int(filtered["predicted_anomaly"].sum())
critical = int(len(filtered[filtered["severity"] == "Critical"]))
suspicious_ips = filtered[filtered["is_suspicious_ip"] == 1]["source_ip"].nunique()
unique_users = filtered[filtered["predicted_anomaly"] == 1]["user"].nunique()
threat_pct = (threat_count / total_events * 100) if total_events > 0 else 0

with m1:
    st.markdown(f"""<div class="metric-card">
        <div class="metric-label">TOTAL EVENTS</div>
        <div class="metric-value">{total_events:,}</div>
        <div class="metric-delta info">filtered view</div>
    </div>""", unsafe_allow_html=True)
with m2:
    st.markdown(f"""<div class="metric-card">
        <div class="metric-label">THREATS DETECTED</div>
        <div class="metric-value">{threat_count:,}</div>
        <div class="metric-delta danger">{threat_pct:.1f}% of traffic</div>
    </div>""", unsafe_allow_html=True)
with m3:
    alert_msg = "⚠ Immediate action required" if critical > 0 else "✓ All clear"
    alert_cls = "danger" if critical > 0 else "success"
    st.markdown(f"""<div class="metric-card">
        <div class="metric-label">CRITICAL ALERTS</div>
        <div class="metric-value">{critical}</div>
        <div class="metric-delta {alert_cls}">{alert_msg}</div>
    </div>""", unsafe_allow_html=True)
with m4:
    st.markdown(f"""<div class="metric-card">
        <div class="metric-label">FLAGGED IPs</div>
        <div class="metric-value">{suspicious_ips}</div>
        <div class="metric-delta info">unique addresses</div>
    </div>""", unsafe_allow_html=True)
with m5:
    st.markdown(f"""<div class="metric-card">
        <div class="metric-label">AFFECTED USERS</div>
        <div class="metric-value">{unique_users}</div>
        <div class="metric-delta info">compromised accounts</div>
    </div>""", unsafe_allow_html=True)

st.markdown("---")

# ── MAIN CHARTS ROW ──────────────────────────────────────────────────────────
c1, c2, c3 = st.columns([2, 1.5, 1.5])

with c1:
    st.markdown('<p class="section-header">📊 Threat Timeline (24hr)</p>', unsafe_allow_html=True)
    timeline_df = filtered.copy()
    timeline_df["hour_bin"] = timeline_df["timestamp"].dt.floor("h")
    timeline = timeline_df.groupby(["hour_bin", "predicted_anomaly"]).size().reset_index(name="count")
    timeline["type"] = timeline["predicted_anomaly"].map({0: "Normal", 1: "Threat"})

    fig_timeline = px.bar(
        timeline, x="hour_bin", y="count", color="type",
        color_discrete_map={"Normal": "#1a4a8a", "Threat": "#ff3a3a"},
        template="plotly_dark",
        labels={"hour_bin": "Time", "count": "Events"}
    )
    fig_timeline.update_layout(
        paper_bgcolor="#050d1a", plot_bgcolor="#050d1a",
        margin=dict(l=0, r=0, t=10, b=0),
        legend=dict(font=dict(color="#c9d8f0", size=10), bgcolor="rgba(0,0,0,0)"),
        xaxis=dict(gridcolor="#0d2040", tickfont=dict(color="#4a90d9", size=9)),
        yaxis=dict(gridcolor="#0d2040", tickfont=dict(color="#4a90d9", size=9)),
        bargap=0.1, height=250
    )
    st.plotly_chart(fig_timeline, use_container_width=True)

with c2:
    st.markdown('<p class="section-header">🎯 Threat Categories</p>', unsafe_allow_html=True)
    threat_counts = threats_df["threat_type"].value_counts()
    colors = ["#ff3a3a", "#ff6b35", "#ffa500", "#ffcc00", "#4a90d9", "#8b5cf6"]

    if len(threat_counts) > 0:
        fig_pie = go.Figure(data=[go.Pie(
            labels=threat_counts.index,
            values=threat_counts.values,
            hole=0.6,
            marker_colors=colors[:len(threat_counts)],
            textfont=dict(family="Share Tech Mono", size=9, color="white"),
            hovertemplate="<b>%{label}</b><br>Count: %{value}<br>%{percent}<extra></extra>"
        )])
        fig_pie.update_layout(
            paper_bgcolor="#050d1a", margin=dict(l=0, r=0, t=10, b=0),
            legend=dict(font=dict(color="#c9d8f0", size=9), bgcolor="rgba(0,0,0,0)"),
            height=250
        )
        st.plotly_chart(fig_pie, use_container_width=True)
    else:
        st.info("No threats match current filters.")

with c3:
    st.markdown('<p class="section-header">⚡ Severity Distribution</p>', unsafe_allow_html=True)
    sev_order = ["Critical", "High", "Medium", "Low"]
    sev_colors = {"Critical": "#ff1a1a", "High": "#ff6600", "Medium": "#ffaa00", "Low": "#3399ff"}
    sev_counts = threats_df["severity"].value_counts()

    fig_sev = go.Figure(go.Bar(
        x=[sev_counts.get(s, 0) for s in sev_order],
        y=sev_order,
        orientation="h",
        marker_color=[sev_colors[s] for s in sev_order],
        text=[sev_counts.get(s, 0) for s in sev_order],
        textposition="outside",
        textfont=dict(family="Share Tech Mono", color="white", size=10)
    ))
    fig_sev.update_layout(
        paper_bgcolor="#050d1a", plot_bgcolor="#050d1a",
        margin=dict(l=0, r=30, t=10, b=0),
        xaxis=dict(gridcolor="#0d2040", tickfont=dict(color="#4a90d9", size=9)),
        yaxis=dict(tickfont=dict(family="Share Tech Mono", color="#c9d8f0", size=10)),
        height=250
    )
    st.plotly_chart(fig_sev, use_container_width=True)

# ── ANOMALY SCATTER ──────────────────────────────────────────────────────────
st.markdown('<p class="section-header">🔬 Anomaly Score Map — Login Attempts vs Bytes Transferred</p>', unsafe_allow_html=True)

scatter_df = filtered.sample(min(800, len(filtered)), random_state=42).copy()
# Ensure minimum marker size for visibility
scatter_df["marker_size"] = scatter_df["anomaly_score"].clip(lower=0.01)

fig_scatter = px.scatter(
    scatter_df,
    x="login_attempts", y="bytes_transferred",
    color="threat_type",
    size="marker_size",
    size_max=20,
    hover_data=["user", "source_ip", "location", "severity", "anomaly_score"],
    color_discrete_map={
        "Normal": "#1a4a8a",
        "Brute Force": "#ff1a1a",
        "Data Exfiltration": "#ff6600",
        "Unusual Location": "#ffaa00",
        "Off-Hours Activity": "#cc00ff",
        "Port Scan": "#00ffaa",
        "Suspicious Activity": "#ff3399"
    },
    labels={"login_attempts": "Login Attempts", "bytes_transferred": "Bytes Transferred",
            "marker_size": "Score", "threat_type": "Threat Type"},
    template="plotly_dark",
    log_y=True
)
fig_scatter.update_layout(
    paper_bgcolor="#050d1a", plot_bgcolor="#050d1a",
    xaxis=dict(gridcolor="#0d2040", tickfont=dict(color="#4a90d9")),
    yaxis=dict(gridcolor="#0d2040", tickfont=dict(color="#4a90d9")),
    legend=dict(font=dict(color="#c9d8f0", size=10), bgcolor="rgba(0,0,0,0)"),
    height=350, margin=dict(l=0, r=0, t=10, b=0)
)
st.plotly_chart(fig_scatter, use_container_width=True)

# ── THREAT LOG TABLE ──────────────────────────────────────────────────────────
st.markdown('<p class="section-header">🚨 Active Threat Log</p>', unsafe_allow_html=True)

if len(threats_df) > 0:
    display_df = threats_df[[
        "timestamp", "user", "source_ip", "location",
        "threat_type", "severity", "login_attempts",
        "bytes_transferred", "anomaly_score"
    ]].copy()
    display_df["timestamp"] = display_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M")
    display_df["anomaly_score"] = display_df["anomaly_score"].round(4)
    display_df["bytes_transferred"] = display_df["bytes_transferred"].apply(lambda x: f"{x:,}")
    display_df = display_df.sort_values("anomaly_score", ascending=False)
    display_df.columns = ["TIMESTAMP", "USER", "SOURCE IP", "LOCATION",
                           "THREAT TYPE", "SEVERITY", "LOGIN ATTEMPTS",
                           "BYTES", "THREAT SCORE"]

    def color_severity(val):
        colors = {
            "Critical": "color: #ff1a1a; font-weight: bold",
            "High": "color: #ff6600; font-weight: bold",
            "Medium": "color: #ffaa00",
            "Low": "color: #3399ff",
        }
        return colors.get(val, "")

    styled = display_df.style.map(color_severity, subset=["SEVERITY"])
    st.dataframe(styled, use_container_width=True, height=350)

    # Export button
    csv_data = display_df.to_csv(index=False)
    st.download_button(
        label="📥 EXPORT THREAT LOG (CSV)",
        data=csv_data,
        file_name="cybersentinel_threats.csv",
        mime="text/csv",
        use_container_width=True
    )
else:
    st.info("No threats match the current filter criteria. Adjust filters in the sidebar.")

# ── BOTTOM CHARTS ────────────────────────────────────────────────────────────
c4, c5 = st.columns(2)
with c4:
    st.markdown('<p class="section-header">🌍 Attack Origin Locations</p>', unsafe_allow_html=True)
    loc_counts = threats_df["location"].value_counts().reset_index()
    loc_counts.columns = ["location", "count"]
    if len(loc_counts) > 0:
        fig_bar = px.bar(
            loc_counts, x="count", y="location", orientation="h",
            color="count", color_continuous_scale=["#0a1628", "#ff3a3a"],
            template="plotly_dark",
            labels={"count": "Incidents", "location": "Location"}
        )
        fig_bar.update_layout(
            paper_bgcolor="#050d1a", plot_bgcolor="#050d1a",
            xaxis=dict(gridcolor="#0d2040", tickfont=dict(color="#4a90d9", size=9)),
            yaxis=dict(tickfont=dict(family="Share Tech Mono", color="#c9d8f0", size=10)),
            coloraxis_showscale=False, height=300,
            margin=dict(l=0, r=0, t=10, b=0)
        )
        st.plotly_chart(fig_bar, use_container_width=True)
    else:
        st.info("No location data for current filters.")

with c5:
    st.markdown('<p class="section-header">🖥 Top Targeted Users</p>', unsafe_allow_html=True)
    user_threats = threats_df["user"].value_counts().head(10).reset_index()
    user_threats.columns = ["user", "incidents"]
    if len(user_threats) > 0:
        fig_users = px.bar(
            user_threats, x="incidents", y="user", orientation="h",
            color="incidents", color_continuous_scale=["#0a3a8a", "#cc00ff"],
            template="plotly_dark",
            labels={"incidents": "Incidents", "user": "User"}
        )
        fig_users.update_layout(
            paper_bgcolor="#050d1a", plot_bgcolor="#050d1a",
            xaxis=dict(gridcolor="#0d2040", tickfont=dict(color="#4a90d9", size=9)),
            yaxis=dict(tickfont=dict(family="Share Tech Mono", color="#c9d8f0", size=10)),
            coloraxis_showscale=False, height=300,
            margin=dict(l=0, r=0, t=10, b=0)
        )
        st.plotly_chart(fig_users, use_container_width=True)
    else:
        st.info("No user data for current filters.")

# ── MODEL PERFORMANCE ────────────────────────────────────────────────────────
with st.expander("📈 Model Performance Metrics"):
    perf1, perf2, perf3, perf4 = st.columns(4)
    precision = model_report.get("Anomaly", {}).get("precision", 0)
    recall = model_report.get("Anomaly", {}).get("recall", 0)
    f1 = model_report.get("Anomaly", {}).get("f1-score", 0)
    accuracy = model_report.get("accuracy", 0)

    with perf1:
        st.metric("Precision", f"{precision:.1%}")
    with perf2:
        st.metric("Recall", f"{recall:.1%}")
    with perf3:
        st.metric("F1-Score", f"{f1:.1%}")
    with perf4:
        st.metric("Accuracy", f"{accuracy:.1%}")

# ── FOOTER ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    '<p style="font-family: Share Tech Mono; font-size: 0.65rem; color: #2a5a8b; text-align: center;">'
    'CYBERSENTINEL v2.5.0 — Isolation Forest ML Engine | Python + Scikit-learn + Streamlit | Built by Kimora Taylor'
    '</p>', unsafe_allow_html=True
)
