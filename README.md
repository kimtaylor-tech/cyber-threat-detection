# cyber-threat-detection
Python-based cyber threat detection system using Isolation Forest ML to analyze network logs and flag anomalous behavior - brute force, data exfiltration, port scans &amp; more. Built with Streamlit + Plotly
# CyberSentinel - Cyber Threat Detection System

Ever wonder how security teams catch hackers in real time? This project is my take on that.

CyberSentinel analyzes network and login logs, learns what "normal" traffic looks like, and flags anything suspicious - all visualized in a live dashboard.
## About
Built by **Kimora Taylor** 

## 🔴 Live Demo
[Check it out →](https://cyber-threat-detection-himsmjgwrriwoeq6xba85k.streamlit.app/)

## What It Does
I trained an Isolation Forest model on simulated network logs to detect 5 types of threats:

- **Brute Force** — way too many login attempts from one IP
- **Data Exfiltration** — massive file transfers going somewhere sketchy
- **Unusual Location** — logins coming from flagged regions
- **Off-Hours Activity** — someone poking around at 3AM
- **Port Scan** — probing the network looking for open doors

Each threat gets a severity level (Critical → Low) and an anomaly score so you know what to prioritize.

## The Dashboard
- Real-time metrics — total events, threats detected, critical alerts, flagged IPs
- 24-hour threat timeline
- Anomaly scatter plot showing normal vs. malicious traffic
- Full sortable threat log with color-coded severity
- You can generate up to 5,000 log events on the fly and watch it re-analyze

## Tech Stack
- **Python** — core logic
- **Pandas + NumPy** — data processing
- **Scikit-learn** — Isolation Forest ML model
- **Streamlit + Plotly** — dashboard and visualizations

## Run It Yourself
```bash
git clone https://github.com/YOUR-USERNAME/cyber-threat-detection
cd cyber-threat-detection
pip install -r requirements.txt
streamlit run app.py
```

## How the Code Is Organized
- `generate_logs.py` — creates realistic fake network logs to train and test on
- `detector.py` — handles feature engineering, model training, and threat classification
- `app.py` — the full Streamlit dashboard
