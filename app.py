import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import joblib
import warnings
warnings.filterwarnings('ignore')

from generate_logs import generate_logs
from detector import load_and_preprocess, train_model

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
  div[data-testid="stSlider"] label { color: #4a90d9; font-size: 0.75rem; letter-spacing: 2px; }
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
    st.markdown('<p style="color:#00ff88; font-family: Share Tech Mono; font-size:0.75rem; margin-top:20px;">● SYSTEM ONLINE</p>', unsafe_allow_html=True)

st.markdown("---")

# ── SIDEBAR ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<p class="section-header">⚙ Control Panel</p>', unsafe_allow_html=True)
    
    n_logs = st.slider("Log Volume", 500, 5000, 1000, step=100)
    
    if st.button("🔄 GENERATE NEW LOGS & ANALYZE", use_container_width=True):
        st.session_state["refresh"] = True
    
    st.markdown("---")
    st.markdown('<p class="section-header">🔍 Filters</p>', unsafe_allow_html=True)
    
    severity_filter = st.multiselect(
        "SEVERITY LEVEL",
        ["Critical", "High", "Medium", "Low", "None"],
        default=["Critical", "High", "Medium", "Low"]
    )
    
    threat_filter = st.multiselect(
        "THREAT TYPE",
        ["Brute Force", "Data Exfiltration", "Unusual Location", 
         "Off-Hours Activity", "Port Scan", "Suspicious Activity", "Normal"],
        default=["Brute Force", "Data Exfiltration", "Unusual Location", 
                 "Off-Hours Activity", "Port Scan", "Suspicious Activity"]
    )
    
    st.markdown("---")
    st.markdown('<p style="font-family: Share Tech Mono; font-size: 0.65rem; color: #2a5a8b;">CYBERSENTINEL v2.4.1<br>Isolation Forest ML Engine<br>© 2026 RDG Security Labs</p>', unsafe_allow_html=True)

# ── DATA LOADING ──────────────────────────────────────────────────────────────
@st.cache_data(show_spinner=False)
def get_analyzed_data(n, seed=42):
    np.random.seed(seed)
    import random; random.seed(seed)
    df_raw = generate_logs(n)
    df_raw.to_csv("/tmp/logs_temp.csv", index=False)
    df, features = load_and_preprocess("/tmp/logs_temp.csv")
    df, model, scaler, features = train_model(df, features)
    return df

if "refresh" in st.session_state and st.session_state["refresh"]:
    get_analyzed_data.clear()
    st.session_state["refresh"] = False

with st.spinner("🔍 Analyzing network traffic..."):
    df = get_analyzed_data(n_logs)

# Apply filters
filtered = df[
    (df["severity"].isin(severity_filter)) |
    (df["threat_type"].isin(threat_filter))
]
threats_df = df[df["predicted_anomaly"] == 1]

# ── METRICS ROW ──────────────────────────────────────────────────────────────
m1, m2, m3, m4, m5 = st.columns(5)

with m1:
    st.metric("TOTAL EVENTS", f"{len(df):,}")
with m2:
    threat_count = df["predicted_anomaly"].sum()
    st.metric("THREATS DETECTED", f"{threat_count}", delta=f"{threat_count/len(df)*100:.1f}% of traffic", delta_color="inverse")
with m3:
    critical = len(df[df["severity"] == "Critical"])
    st.metric("CRITICAL ALERTS", f"{critical}", delta="Immediate action required" if critical > 0 else "All clear", delta_color="inverse")
with m4:
    suspicious_ips = df[df["is_suspicious_ip"] == 1]["source_ip"].nunique()
    st.metric("FLAGGED IPs", f"{suspicious_ips}")
with m5:
    unique_users = df[df["predicted_anomaly"] == 1]["user"].nunique()
    st.metric("AFFECTED USERS", f"{unique_users}")

st.markdown("---")

# ── MAIN CHARTS ROW ──────────────────────────────────────────────────────────
c1, c2, c3 = st.columns([2, 1.5, 1.5])

with c1:
    st.markdown('<p class="section-header">📊 Threat Timeline (24hr)</p>', unsafe_allow_html=True)
    df["hour_bin"] = df["timestamp"].dt.floor("h")
    timeline = df.groupby(["hour_bin", "predicted_anomaly"]).size().reset_index(name="count")
    timeline["type"] = timeline["predicted_anomaly"].map({0: "Normal", 1: "Threat"})
    
    fig_timeline = px.bar(
        timeline, x="hour_bin", y="count", color="type",
        color_discrete_map={"Normal": "#1a4a8a", "Threat": "#ff3a3a"},
        template="plotly_dark"
    )
    fig_timeline.update_layout(
        paper_bgcolor="#050d1a", plot_bgcolor="#050d1a",
        margin=dict(l=0, r=0, t=10, b=0),
        legend=dict(font=dict(color="#c9d8f0", size=10), bgcolor="rgba(0,0,0,0)"),
        xaxis=dict(gridcolor="#0d2040", tickfont=dict(color="#4a90d9", size=9)),
        yaxis=dict(gridcolor="#0d2040", tickfont=dict(color="#4a90d9", size=9)),
        bargap=0.1, height=220
    )
    st.plotly_chart(fig_timeline, use_container_width=True)

with c2:
    st.markdown('<p class="section-header">🎯 Threat Categories</p>', unsafe_allow_html=True)
    threat_counts = threats_df["threat_type"].value_counts()
    colors = ["#ff3a3a", "#ff6b35", "#ffa500", "#ffcc00", "#4a90d9", "#8b5cf6"]
    
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
        height=220
    )
    st.plotly_chart(fig_pie, use_container_width=True)

with c3:
    st.markdown('<p class="section-header">⚡ Severity Distribution</p>', unsafe_allow_html=True)
    sev_order = ["Critical", "High", "Medium", "Low"]
    sev_colors = {"Critical": "#ff1a1a", "High": "#ff6600", "Medium": "#ffaa00", "Low": "#3399ff"}
    sev_counts = df[df["predicted_anomaly"]==1]["severity"].value_counts()
    
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
        margin=dict(l=0, r=20, t=10, b=0),
        xaxis=dict(gridcolor="#0d2040", tickfont=dict(color="#4a90d9", size=9)),
        yaxis=dict(tickfont=dict(family="Share Tech Mono", color="#c9d8f0", size=10)),
        height=220
    )
    st.plotly_chart(fig_sev, use_container_width=True)

# ── ANOMALY SCATTER ──────────────────────────────────────────────────────────
st.markdown('<p class="section-header">🔬 Anomaly Score Map — Login Attempts vs Bytes Transferred</p>', unsafe_allow_html=True)

fig_scatter = px.scatter(
    df.sample(min(500, len(df))),
    x="login_attempts", y="bytes_transferred",
    color="threat_type",
    size="anomaly_score",
    size_max=20,
    hover_data=["user", "source_ip", "location", "severity", "timestamp"],
    color_discrete_map={
        "Normal": "#1a4a8a",
        "Brute Force": "#ff1a1a",
        "Data Exfiltration": "#ff6600",
        "Unusual Location": "#ffaa00",
        "Off-Hours Activity": "#cc00ff",
        "Port Scan": "#00ffaa",
        "Suspicious Activity": "#ff3399"
    },
    template="plotly_dark",
    log_y=True
)
fig_scatter.update_layout(
    paper_bgcolor="#050d1a", plot_bgcolor="#050d1a",
    xaxis=dict(gridcolor="#0d2040", tickfont=dict(color="#4a90d9")),
    yaxis=dict(gridcolor="#0d2040", tickfont=dict(color="#4a90d9")),
    legend=dict(font=dict(color="#c9d8f0", size=10), bgcolor="rgba(0,0,0,0)"),
    height=320, margin=dict(l=0, r=0, t=10, b=0)
)
st.plotly_chart(fig_scatter, use_container_width=True)

# ── THREAT LOG TABLE ──────────────────────────────────────────────────────────
st.markdown('<p class="section-header">🚨 Active Threat Log</p>', unsafe_allow_html=True)

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

styled = display_df.style.applymap(color_severity, subset=["SEVERITY"])
st.dataframe(styled, use_container_width=True, height=300)

# ── GEOLOCATION HEATMAP ──────────────────────────────────────────────────────
c4, c5 = st.columns(2)
with c4:
    st.markdown('<p class="section-header">🌍 Attack Origin Locations</p>', unsafe_allow_html=True)
    loc_counts = df[df["predicted_anomaly"]==1]["location"].value_counts().reset_index()
    loc_counts.columns = ["location", "count"]
    fig_bar = px.bar(
        loc_counts, x="count", y="location", orientation="h",
        color="count", color_continuous_scale=["#0a1628", "#ff3a3a"],
        template="plotly_dark"
    )
    fig_bar.update_layout(
        paper_bgcolor="#050d1a", plot_bgcolor="#050d1a",
        xaxis=dict(gridcolor="#0d2040", tickfont=dict(color="#4a90d9", size=9)),
        yaxis=dict(tickfont=dict(family="Share Tech Mono", color="#c9d8f0", size=10)),
        coloraxis_showscale=False, height=280,
        margin=dict(l=0, r=0, t=10, b=0)
    )
    st.plotly_chart(fig_bar, use_container_width=True)

with c5:
    st.markdown('<p class="section-header">🖥 Top Targeted Users</p>', unsafe_allow_html=True)
    user_threats = df[df["predicted_anomaly"]==1]["user"].value_counts().head(10).reset_index()
    user_threats.columns = ["user", "incidents"]
    fig_users = px.bar(
        user_threats, x="incidents", y="user", orientation="h",
        color="incidents", color_continuous_scale=["#0a3a8a", "#cc00ff"],
        template="plotly_dark"
    )
    fig_users.update_layout(
        paper_bgcolor="#050d1a", plot_bgcolor="#050d1a",
        xaxis=dict(gridcolor="#0d2040", tickfont=dict(color="#4a90d9", size=9)),
        yaxis=dict(tickfont=dict(family="Share Tech Mono", color="#c9d8f0", size=10)),
        coloraxis_showscale=False, height=280,
        margin=dict(l=0, r=0, t=10, b=0)
    )
    st.plotly_chart(fig_users, use_container_width=True)

# ── FOOTER ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    '<p style="font-family: Share Tech Mono; font-size: 0.65rem; color: #2a5a8b; text-align: center;">'
    'CYBERSENTINEL — Isolation Forest ML Engine | Python + Scikit-learn + Streamlit | Built by Reed Digital Group'
    '</p>', unsafe_allow_html=True
)
