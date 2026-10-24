"""
report.py - MODULE 5: Report Generation

Creates a timestamped folder inside reports/ containing:
  traffic_summary.csv           headline numbers
  protocol_stats.csv            packets/bytes per protocol
  top_talkers.csv               busiest IP addresses
  suspicious_activity_log.csv   every alert
  security_report.html          full report with charts (open in a browser; Ctrl+P -> Save as PDF)

Usage:
    python report.py              # report on ALL stored data
    python report.py --minutes 60 # only the last hour
"""
import argparse
import datetime as dt
import html
import os
import time

import plotly.express as px

import analysis
import config
import db

CSS = """
body{font-family:Segoe UI,Arial,sans-serif;max-width:1000px;margin:30px auto;color:#222;padding:0 16px}
h1{border-bottom:3px solid #5b2be0;padding-bottom:8px} h2{color:#5b2be0;margin-top:34px}
table{border-collapse:collapse;width:100%;font-size:13px;margin:10px 0}
th,td{border:1px solid #ddd;padding:6px 8px;text-align:left} th{background:#f1ecff}
.kpi{display:inline-block;background:#f6f3ff;border-radius:8px;padding:10px 18px;margin:4px 8px 4px 0}
.kpi b{display:block;font-size:20px}
.high{background:#fbd5d5}.medium{background:#ffe8cc}.low{background:#dbeafe}
.note{color:#666;font-size:12px}
"""


def _table(df, max_rows=50):
    if df.empty:
        return "<p><i>No data.</i></p>"
    return df.head(max_rows).to_html(index=False, border=0, escape=True)


PALETTE = ["#5B3FD6", "#22A6C8", "#F2994A", "#27AE60", "#EB5757", "#9B51E0", "#2D9CDB", "#C9A227"]


def _fig_html(fig, first):
    # Colours, template and margins are set explicitly so the charts look the same
    # whatever Plotly version is installed.
    fig.update_layout(template="plotly_white", colorway=PALETTE, height=360,
                      margin=dict(l=80, r=40, t=60, b=80),
                      paper_bgcolor="white", plot_bgcolor="white",
                      font=dict(color="#222222", size=13))
    fig.update_xaxes(automargin=True, title_standoff=12, gridcolor="#E6E6E6")
    fig.update_yaxes(automargin=True, title_standoff=12, gridcolor="#E6E6E6")
    # first chart embeds plotly.js (works offline), the rest reuse it
    return fig.to_html(full_html=False, include_plotlyjs=True if first else False)


def _fmt_time(t):
    return t.strftime("%Y-%m-%d %H:%M:%S") if t is not None and str(t) != "NaT" else "-"


def _cell(v):
    return "" if v is None or (isinstance(v, float) and v != v) else str(v)


def generate_report(conn, since_ts=None, out_dir=None):
    df = analysis.load_packets(conn, since_ts)
    alerts = analysis.load_alerts(conn, since_ts)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    folder = out_dir or os.path.join(config.REPORTS_DIR, "report_" + stamp)
    os.makedirs(folder, exist_ok=True)

    s = analysis.summary(df)
    proto = analysis.protocol_counts(df)
    dev = analysis.device_activity(df)
    ports = analysis.top_ports(df)
    direction = analysis.direction_counts(df)

    # ---- CSV files
    import pandas as pd
    pd.DataFrame([
        ("report_generated", dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        ("total_packets", s["packets"]), ("total_bytes", s["bytes"]),
        ("duration_seconds", round(s["duration"], 1)),
        ("avg_packets_per_second", round(s["pps"], 2)),
        ("avg_bandwidth_kbps", round(s["kbps"], 2)),
        ("unique_ip_addresses", s["unique_ips"]), ("alerts_total", len(alerts)),
    ], columns=["metric", "value"]).to_csv(os.path.join(folder, "traffic_summary.csv"), index=False)
    proto.to_csv(os.path.join(folder, "protocol_stats.csv"), index=False)
    dev.to_csv(os.path.join(folder, "top_talkers.csv"), index=False)
    log = alerts[["time", "severity", "alert_type", "src_ip", "dst_ip", "details"]] if not alerts.empty else alerts
    log.to_csv(os.path.join(folder, "suspicious_activity_log.csv"), index=False)

    # ---- HTML report
    parts = ["<html><head><meta charset='utf-8'><title>Network Traffic Analysis Report</title>"
             "<style>%s</style></head><body>" % CSS,
             "<h1>Network Traffic Analysis Report</h1>",
             "<p class='note'>Generated %s &nbsp;|&nbsp; Data: %s to %s</p>" % (
                 dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 _fmt_time(df["time"].min()) if not df.empty else "-",
                 _fmt_time(df["time"].max()) if not df.empty else "-")]

    parts.append("<h2>1. Traffic Summary</h2>")
    for label, val in [("Packets", "{:,}".format(s["packets"])), ("Data", analysis.human_bytes(s["bytes"])),
                       ("Avg rate", "%.1f pkt/s" % s["pps"]), ("Avg bandwidth", "%.1f kbps" % s["kbps"]),
                       ("Unique IPs", s["unique_ips"]), ("Alerts", len(alerts))]:
        parts.append("<div class='kpi'>%s<b>%s</b></div>" % (label, val))

    if not df.empty:
        ts_df = analysis.traffic_over_time(df)
        parts.append(_fig_html(px.line(ts_df, x="time", y="pps", title="Packets per second",
                                       template="plotly_white", color_discrete_sequence=PALETTE), True))
        parts.append(_fig_html(px.pie(proto, names="protocol", values="packets",
                                      title="Protocol distribution", hole=0.35,
                                      template="plotly_white", color_discrete_sequence=PALETTE), False))
        parts.append("<h2>2. Protocol Statistics</h2>" + _table(proto))
        top = dev.head(10)
        parts.append("<h2>3. Top Talkers (IP addresses)</h2>")
        parts.append(_fig_html(px.bar(top, x="ip", y=["bytes_sent", "bytes_recv"], barmode="group",
                                      title="Top 10 IPs by bytes",
                                      template="plotly_white", color_discrete_sequence=PALETTE), False))
        parts.append(_table(top))
        parts.append("<h2>4. Traffic Direction and Top Ports</h2>" + _table(direction) + _table(ports))

    parts.append("<h2>5. Security Analysis</h2>")
    if alerts.empty:
        parts.append("<p>No suspicious activity was detected in this period.</p>")
    else:
        by = alerts.groupby(["alert_type", "severity"]).size().reset_index(name="count")
        parts.append("<p><b>%d alert(s)</b> were raised by the rule-based detector.</p>" % len(alerts))
        parts.append(_table(by))
        parts.append("<h2>6. Suspicious Activity Log</h2><table><tr><th>Time</th><th>Severity</th>"
                     "<th>Type</th><th>Source IP</th><th>Target IP</th><th>Details</th></tr>")
        for _, r in alerts.sort_values("ts").iterrows():
            parts.append("<tr class='%s'><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                r["severity"], r["time"].strftime("%Y-%m-%d %H:%M:%S"), r["severity"].upper(),
                html.escape(str(r["alert_type"])), html.escape(str(r["src_ip"])),
                html.escape(_cell(r["dst_ip"])), html.escape(str(r["details"]))))
        parts.append("</table>")
        parts.append("<h2>7. Recommendations</h2><ul>"
                     "<li>Investigate each high-severity source IP and block it at the firewall if it is not trusted.</li>"
                     "<li>Restrict access to sensitive services (SSH, RDP, SMB) to known IP addresses only.</li>"
                     "<li>Use key-based SSH login and rate-limiting (e.g. fail2ban) against repeated access attempts.</li>"
                     "<li>Add confirmed-legitimate IP addresses to the baseline (python detector.py --learn).</li></ul>")
    parts.append("<p class='note'>Detection is rule-based and educational; thresholds are set in config.py.</p></body></html>")

    with open(os.path.join(folder, "security_report.html"), "w", encoding="utf-8") as f:
        f.write("\n".join(parts))
    return folder


def main():
    ap = argparse.ArgumentParser(description="Generate traffic & security reports")
    ap.add_argument("--minutes", type=int, default=0, help="only include the last N minutes (0 = all)")
    args = ap.parse_args()
    conn = db.get_conn()
    folder = generate_report(conn, since_ts=(time.time() - args.minutes * 60) if args.minutes else None)
    print("[*] Report created:", folder)
    for f in sorted(os.listdir(folder)):
        print("    -", f)


if __name__ == "__main__":
    main()
