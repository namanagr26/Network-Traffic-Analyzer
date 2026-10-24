"""
dashboard.py - MODULE 4: Dashboard & Visualization (Streamlit)

Run:   streamlit run dashboard.py
Open:  http://localhost:8501
Reads the SQLite database that capture.py / detector.py fill.
"""
import time

import pandas as pd
import plotly.express as px
import streamlit as st

import analysis
import config
import db
import detector
import report

st.set_page_config(page_title="Network Traffic Analyzer", page_icon="🛰️", layout="wide")

SEV_COLORS = {"high": "#d62728", "medium": "#ff7f0e", "low": "#1f77b4"}
RANGES = {"Last 5 minutes": 300, "Last 15 minutes": 900, "Last 1 hour": 3600,
          "Last 6 hours": 21600, "Last 24 hours": 86400, "All data": None}


# ---- small helpers that work on old and new Streamlit versions
def show_chart(fig):
    fig.update_layout(margin=dict(l=10, r=10, t=40, b=10), height=340)
    try:
        st.plotly_chart(fig, width="stretch")
    except TypeError:
        st.plotly_chart(fig, use_container_width=True)


def show_table(df, **kw):
    try:
        st.dataframe(df, width="stretch", hide_index=True, **kw)
    except TypeError:
        st.dataframe(df, use_container_width=True, hide_index=True, **kw)


def sev_style(df):
    def color(v):
        return "color: white; background-color: %s" % SEV_COLORS.get(v, "gray")
    try:
        return df.style.map(color, subset=["severity"])
    except AttributeError:
        return df.style.applymap(color, subset=["severity"])


# ------------------------------------------------------------------ sidebar
conn = db.get_conn()
st.sidebar.title("🛰️ Traffic Analyzer")
range_label = st.sidebar.selectbox("Time range", list(RANGES), index=2)
auto = st.sidebar.checkbox("Auto-refresh", value=True)
interval = st.sidebar.slider("Refresh every (seconds)", 2, 30, config.REFRESH_SECONDS)

if auto:
    try:
        from streamlit_autorefresh import st_autorefresh
        st_autorefresh(interval=interval * 1000, key="auto_refresh")
    except ImportError:
        st.sidebar.warning("pip install streamlit-autorefresh for auto-refresh")

if st.sidebar.button("🔍 Run detection now"):
    new = detector.run_detection(conn, lookback=0, verbose=False)
    st.sidebar.success("%d new alert(s)" % len(new))

if st.sidebar.button("📄 Generate report"):
    secs_sel = RANGES[range_label]
    folder = report.generate_report(conn, since_ts=(time.time() - secs_sel) if secs_sel else None)
    st.sidebar.success("Report saved in:\n%s" % folder)

st.sidebar.caption("Database: %s" % config.DB_PATH)

# ------------------------------------------------------------------ data
secs = RANGES[range_label]
since = (time.time() - secs) if secs else None
df = analysis.load_packets(conn, since)
alerts = analysis.load_alerts(conn, since)

last = conn.execute("SELECT MAX(ts) FROM packets").fetchone()[0]
live = last is not None and (time.time() - last) < 10
st.title("Network Traffic Analyzer")
st.caption(("🟢 Capture is live" if live else "⚪ No packets in the last 10 s (capture stopped, or showing stored data)")
           + "  |  Range: %s" % range_label)

if df.empty:
    st.info("No packets in this time range yet.\n\n"
            "Start capture in a terminal:  `sudo ./venv/bin/python capture.py`\n\n"
            "or load sample data:  `python demo_data.py`")
    st.stop()

# ------------------------------------------------------------------ KPIs
s = analysis.summary(df)
c = st.columns(6)
c[0].metric("Packets", "{:,}".format(s["packets"]))
c[1].metric("Data", analysis.human_bytes(s["bytes"]))
c[2].metric("Avg rate", "%.1f pkt/s" % s["pps"])
c[3].metric("Avg bandwidth", "%.1f kbps" % s["kbps"])
c[4].metric("Unique IPs", s["unique_ips"])
c[5].metric("Alerts", len(alerts))

tabs = st.tabs(["📈 Overview", "🧩 Protocols", "💻 Devices", "🚨 Alerts",
                "🔌 Live connections", "🗂 Raw packets"])

# ---- Overview
with tabs[0]:
    ts_df = analysis.traffic_over_time(df)
    a, b = st.columns(2)
    with a:
        fig = px.line(ts_df, x="time", y="pps", title="Packets per second")
        # mark alerts on the chart
        for _, r in alerts.iterrows():
            fig.add_vline(x=r["time"], line_dash="dot", line_color=SEV_COLORS.get(r["severity"], "gray"))
        show_chart(fig)
    with b:
        show_chart(px.area(ts_df, x="time", y="kbps", title="Bandwidth (kbps)"))
    a, b = st.columns(2)
    with a:
        d = analysis.direction_counts(df)
        show_chart(px.bar(d, x="direction", y="bytes", color="direction", title="Traffic by direction (bytes)"))
    with b:
        show_chart(px.bar(analysis.top_ports(df), x="dst_port", y="packets",
                          title="Top destination ports").update_xaxes(type="category"))

# ---- Protocols
with tabs[1]:
    a, b = st.columns(2)
    p = analysis.protocol_counts(df)
    with a:
        show_chart(px.pie(p, names="protocol", values="packets", title="Protocol distribution", hole=0.35))
    with b:
        sv = analysis.service_counts(df)
        if sv.empty:
            st.info("No known services seen yet.")
        else:
            show_chart(px.bar(sv, x="service", y="packets", color="service", title="Services (by port)"))
    show_table(p)

# ---- Devices
with tabs[2]:
    dev = analysis.device_activity(df)
    top = dev.head(10)
    show_chart(px.bar(top.melt(id_vars="ip", value_vars=["bytes_sent", "bytes_recv"]),
                      x="ip", y="value", color="variable", barmode="group",
                      title="Top 10 IP addresses by traffic (bytes)"))
    st.subheader("All devices / IP addresses")
    show_table(dev)
    st.subheader("Top conversations")
    show_table(analysis.top_conversations(df))

# ---- Alerts
with tabs[3]:
    if alerts.empty:
        st.success("No suspicious activity detected in this range.")
    else:
        a, b = st.columns(2)
        with a:
            by = alerts.groupby(["alert_type", "severity"]).size().reset_index(name="count")
            show_chart(px.bar(by, x="alert_type", y="count", color="severity",
                              color_discrete_map=SEV_COLORS, title="Alerts by type"))
        with b:
            show_chart(px.scatter(alerts, x="time", y="alert_type", color="severity",
                                  color_discrete_map=SEV_COLORS, title="Alert timeline"))
        view = alerts[["time", "severity", "alert_type", "src_ip", "dst_ip", "details"]]
        st.dataframe(sev_style(view), hide_index=True)

# ---- Live connections (psutil)
with tabs[4]:
    cur = analysis.net_io_snapshot()
    prev = st.session_state.get("prev_io")
    st.session_state["prev_io"] = cur
    if prev:
        up, down = analysis.bandwidth_between(prev, cur)
        m = st.columns(2)
        m[0].metric("Upload now", "%.1f KB/s" % up)
        m[1].metric("Download now", "%.1f KB/s" % down)
    else:
        st.caption("Live bandwidth appears after the next refresh.")
    conns = analysis.live_connections()
    st.caption("Active connections on this machine: %d" % len(conns))
    show_table(conns)

# ---- Raw packets
with tabs[5]:
    cols = ["time", "src_ip", "dst_ip", "protocol", "service", "src_port", "dst_port",
            "size", "tcp_flags", "direction"]
    show_table(df.sort_values("ts", ascending=False)[cols].head(500))
    st.download_button("⬇ Download packets as CSV", df[cols].to_csv(index=False),
                       file_name="packets.csv", mime="text/csv")
