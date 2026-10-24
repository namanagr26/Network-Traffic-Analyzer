"""
detector.py - MODULE 3: Suspicious Activity Detection (rule based, defensive only)

Four simple rules scan the stored packets and write alerts to the `alerts` table:
  1. Traffic spike         - packets/sec far above the normal level
  2. Unknown IP            - inbound connection attempt from an IP not in the baseline
  3. Port-scan-like        - one source probing many different ports on one target
  4. Repeated access       - many SYNs from one source to the same port (e.g. SSH)

Usage:
    python detector.py --learn        # mark all IPs seen so far as "known/normal"
    python detector.py                # scan once
    python detector.py --watch        # scan every 5 seconds (leave running)
    python detector.py --all          # scan ALL stored packets, not just the last hour
    python detector.py --clear-alerts # delete old alerts
"""
import argparse
import time

import numpy as np
import pandas as pd

import config
import db


# ------------------------------------------------------------------ helpers
def _load(conn, since):
    return pd.read_sql_query(
        "SELECT ts, src_ip, dst_ip, protocol, dst_port, size, tcp_flags, direction "
        "FROM packets WHERE ts >= ?", conn, params=(since,))


def _alert(ts, kind, severity, src, dst, details):
    return dict(ts=float(ts), alert_type=kind, severity=severity,
                src_ip=src, dst_ip=dst, details=details)


# ------------------------------------------------------------------ rule 1
def detect_spikes(df):
    """Flag 5-second windows whose packet rate is far above the typical rate.
    Uses median + K*MAD (a robust form of mean + 3*std that a spike cannot distort)."""
    out = []
    if df.empty:
        return out
    secs = df["ts"].astype(int)
    counts = secs.value_counts().sort_index()
    full = counts.reindex(range(counts.index.min(), counts.index.max() + 1), fill_value=0)
    if len(full) < config.SPIKE_MIN_HISTORY_SEC:
        return out

    median = float(np.median(full.values))
    mad = float(np.median(np.abs(full.values - median))) * 1.4826
    threshold = max(median + config.SPIKE_K * max(mad, 1.0),
                    median * config.SPIKE_MIN_FACTOR,
                    config.SPIKE_MIN_PPS)

    w = config.SPIKE_BUCKET_SEC
    n = len(full) // w
    if n == 0:
        return out
    rates = full.values[:n * w].reshape(n, w).mean(axis=1)
    starts = full.index.values[:n * w:w]

    i = 0
    while i < n:
        if rates[i] > threshold:
            j = i
            while j + 1 < n and rates[j + 1] > threshold:
                j += 1
            t0, t1 = float(starts[i]), float(starts[j] + w)
            peak = float(rates[i:j + 1].max())
            win = df[(df["ts"] >= t0) & (df["ts"] < t1)]
            top = win["src_ip"].value_counts()
            top_src = top.index[0] if len(top) else None
            sev = "high" if peak > 10 * max(median, 1.0) else "medium"
            out.append(_alert(
                t0, "Traffic Spike", sev, top_src, None,
                "Peak %.0f pkts/s for %ds (normal ~%.1f pkts/s, threshold %.0f). "
                "Top source: %s" % (peak, t1 - t0, median, threshold, top_src)))
            i = j + 1
        else:
            i += 1
    return out


# ------------------------------------------------------------------ rule 2
def detect_unknown_ips(df, known):
    """Inbound connection attempts (TCP SYN) from IPs that are not in the baseline."""
    out = []
    if df.empty or not known:
        return out
    inc = df[(df["direction"] == "incoming") & (df["protocol"] == "TCP")
             & (df["tcp_flags"] == "S")]
    if inc.empty:
        return out
    for ip, g in inc.groupby("src_ip"):
        if ip in known or ip in config.WHITELIST_IPS:
            continue
        ports = sorted({int(p) for p in g["dst_port"].dropna()})
        sensitive = [p for p in ports if p in config.SENSITIVE_PORTS]
        sev = "medium" if sensitive else "low"
        out.append(_alert(
            g["ts"].min(), "Unknown IP Activity", sev, ip, g["dst_ip"].iloc[0],
            "Unknown IP made %d connection attempt(s) to port(s) %s"
            % (len(g), ", ".join(map(str, ports[:10])))))
    return out


# ------------------------------------------------------------------ rule 3
def detect_port_scans(df):
    out = []
    syn = df[(df["protocol"] == "TCP") & (df["tcp_flags"] == "S")].copy()
    if syn.empty:
        return out
    syn["bin"] = (syn["ts"] // config.PORTSCAN_WINDOW_SEC).astype(int)
    g = syn.groupby(["src_ip", "dst_ip", "bin"]).agg(
        ports=("dst_port", "nunique"), first=("ts", "min"))
    for (src, dst, _), row in g[g["ports"] >= config.PORTSCAN_PORTS].iterrows():
        out.append(_alert(
            row["first"], "Port Scan Behaviour", "high", src, dst,
            "%d different ports probed on %s within %ds"
            % (row["ports"], dst, config.PORTSCAN_WINDOW_SEC)))
    return out


# ------------------------------------------------------------------ rule 4
def detect_repeated_access(df):
    out = []
    syn = df[(df["protocol"] == "TCP") & (df["tcp_flags"] == "S")].copy()
    if syn.empty:
        return out
    syn["bin"] = (syn["ts"] // config.SYN_WINDOW_SEC).astype(int)
    g = syn.groupby(["src_ip", "dst_ip", "dst_port", "bin"]).agg(
        attempts=("ts", "size"), first=("ts", "min"))
    for (src, dst, port, _), row in g.iterrows():
        port = int(port)
        limit = (config.SYN_THRESHOLD_SENSITIVE if port in config.SENSITIVE_PORTS
                 else config.SYN_THRESHOLD_OTHER)
        if row["attempts"] >= limit:
            sev = "high" if row["attempts"] >= 3 * limit else "medium"
            out.append(_alert(
                row["first"], "Repeated Access Attempts", sev, src, dst,
                "%d connection attempts to port %d within %ds"
                % (row["attempts"], port, config.SYN_WINDOW_SEC)))
    return out


# ------------------------------------------------------------------ runner
def run_detection(conn, lookback=None, now=None, verbose=True):
    """Run all rules and store NEW alerts. Returns the list of new alerts."""
    now = now or time.time()
    since = 0 if lookback == 0 else now - (lookback or config.DEFAULT_LOOKBACK_SEC)
    df = _load(conn, since)
    known = db.get_known_ips(conn)
    if not known and verbose:
        print("[i] No baseline yet - unknown-IP rule skipped. Run:  python detector.py --learn")

    candidates = (detect_spikes(df) + detect_unknown_ips(df, known)
                  + detect_port_scans(df) + detect_repeated_access(df))
    candidates.sort(key=lambda a: a["ts"])

    new = []
    for a in candidates:
        if db.alert_exists(conn, a["alert_type"], a["src_ip"], a["ts"], config.ALERT_COOLDOWN_SEC):
            continue
        db.insert_alert(conn, a["ts"], a["alert_type"], a["severity"],
                        a["src_ip"], a["dst_ip"], a["details"])
        if a["alert_type"] == "Unknown IP Activity":
            db.add_known_ips(conn, [a["src_ip"]], source="alerted")   # alert only once
        new.append(a)
        if verbose:
            print("[ALERT][%s] %s  src=%s  %s" %
                  (a["severity"].upper(), a["alert_type"], a["src_ip"], a["details"]))
    if verbose and not new:
        print("[ok] no new suspicious activity (%d packets checked)" % len(df))
    return new


def learn_baseline(conn):
    df = pd.read_sql_query("SELECT DISTINCT src_ip AS ip FROM packets UNION "
                           "SELECT DISTINCT dst_ip FROM packets", conn)
    ips = [i for i in df["ip"].dropna()]
    db.add_known_ips(conn, ips, source="learned")
    print("[*] Baseline learned: %d IP addresses marked as normal." % len(ips))


def main():
    ap = argparse.ArgumentParser(description="Suspicious activity detector")
    ap.add_argument("--watch", action="store_true", help="scan repeatedly every 5 seconds")
    ap.add_argument("--learn", action="store_true", help="mark all IPs seen so far as normal")
    ap.add_argument("--all", action="store_true", help="scan every stored packet")
    ap.add_argument("--lookback", type=int, default=None, help="seconds to look back")
    ap.add_argument("--clear-alerts", action="store_true", help="delete all stored alerts")
    args = ap.parse_args()

    conn = db.get_conn()
    if args.clear_alerts:
        db.reset(conn, tables=("alerts",))
        print("[*] Alerts cleared.")
        return
    if args.learn:
        learn_baseline(conn)
        return

    lookback = 0 if args.all else args.lookback
    if args.watch:
        print("[*] Watching... Ctrl+C to stop.")
        try:
            while True:
                run_detection(conn, lookback=lookback or 600, verbose=True)
                time.sleep(config.REFRESH_SECONDS)
        except KeyboardInterrupt:
            print("\n[*] Stopped.")
    else:
        run_detection(conn, lookback=lookback)


if __name__ == "__main__":
    main()
