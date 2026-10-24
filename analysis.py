"""
analysis.py - MODULE 2: Traffic Monitoring System

Pandas helpers that turn raw packets into numbers and tables for the
dashboard and the reports. Also reads live system info with psutil.
"""
import time

import pandas as pd
import psutil

import config

_TZ_OFFSET = time.localtime().tm_gmtoff or 0


def _to_local_time(ts_series):
    return pd.to_datetime(ts_series, unit="s") + pd.to_timedelta(_TZ_OFFSET, unit="s")


# ---------------------------------------------------------------- loading
def load_packets(conn, since_ts=None):
    """Load packets (newest MAX_ROWS) into a DataFrame with a local-time column."""
    sql = ("SELECT ts, src_ip, dst_ip, protocol, service, src_port, dst_port, "
           "size, tcp_flags, direction FROM packets")
    params = []
    if since_ts:
        sql += " WHERE ts >= ?"
        params.append(since_ts)
    sql += " ORDER BY ts DESC LIMIT %d" % config.MAX_ROWS_LOADED
    df = pd.read_sql_query(sql, conn, params=params)
    df = df.sort_values("ts").reset_index(drop=True)
    df["time"] = _to_local_time(df["ts"])
    return df


def load_alerts(conn, since_ts=None):
    sql = "SELECT id, ts, alert_type, severity, src_ip, dst_ip, details FROM alerts"
    params = []
    if since_ts:
        sql += " WHERE ts >= ?"
        params.append(since_ts)
    sql += " ORDER BY ts DESC"
    df = pd.read_sql_query(sql, conn, params=params)
    df["time"] = _to_local_time(df["ts"])
    return df


# ---------------------------------------------------------------- aggregation
def human_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.1f %s" % (n, unit) if unit != "B" else "%d B" % n
        n /= 1024


def summary(df):
    """Headline numbers."""
    if df.empty:
        return dict(packets=0, bytes=0, duration=0, pps=0.0, kbps=0.0, unique_ips=0)
    duration = max(df["ts"].max() - df["ts"].min(), 1.0)
    ips = set(df["src_ip"].dropna()) | set(df["dst_ip"].dropna())
    total_bytes = int(df["size"].sum())
    return dict(packets=len(df), bytes=total_bytes, duration=duration,
                pps=len(df) / duration, kbps=total_bytes * 8 / duration / 1000.0,
                unique_ips=len(ips))


def pick_frequency(df):
    """Choose a sensible time bucket for the chart."""
    if df.empty:
        return "1s"
    span = df["ts"].max() - df["ts"].min()
    if span <= 600:
        return "1s"
    if span <= 3600:
        return "10s"
    if span <= 6 * 3600:
        return "1min"
    return "5min"


def traffic_over_time(df, freq=None):
    """Packets and bytes per time bucket (rates are per second)."""
    if df.empty:
        return pd.DataFrame(columns=["time", "packets", "bytes", "pps", "kbps"])
    freq = freq or pick_frequency(df)
    secs = pd.Timedelta(freq).total_seconds()
    g = (df.set_index("time")
           .resample(freq)
           .agg(packets=("size", "count"), bytes=("size", "sum"))
           .reset_index())
    g["pps"] = g["packets"] / secs
    g["kbps"] = g["bytes"] * 8 / secs / 1000.0
    return g


def protocol_counts(df):
    if df.empty:
        return pd.DataFrame(columns=["protocol", "packets", "bytes"])
    g = df.groupby("protocol").agg(packets=("size", "count"), bytes=("size", "sum"))
    return g.sort_values("packets", ascending=False).reset_index()


def service_counts(df):
    d = df[df["service"].fillna("") != ""]
    if d.empty:
        return pd.DataFrame(columns=["service", "packets", "bytes"])
    g = d.groupby("service").agg(packets=("size", "count"), bytes=("size", "sum"))
    return g.sort_values("packets", ascending=False).reset_index()


def direction_counts(df):
    if df.empty:
        return pd.DataFrame(columns=["direction", "packets", "bytes"])
    g = df.groupby("direction").agg(packets=("size", "count"), bytes=("size", "sum"))
    return g.sort_values("packets", ascending=False).reset_index()


def device_activity(df, local_ips=None):
    """Per-IP activity: packets/bytes sent and received (every IP is a 'device')."""
    if df.empty:
        return pd.DataFrame(columns=["ip", "packets_sent", "bytes_sent",
                                     "packets_recv", "bytes_recv", "total_bytes"])
    sent = df.groupby("src_ip").agg(packets_sent=("size", "count"), bytes_sent=("size", "sum"))
    recv = df.groupby("dst_ip").agg(packets_recv=("size", "count"), bytes_recv=("size", "sum"))
    out = sent.join(recv, how="outer").fillna(0).astype(int)
    out.index.name = "ip"
    out["total_bytes"] = out["bytes_sent"] + out["bytes_recv"]
    out = out.sort_values("total_bytes", ascending=False).reset_index()
    return out


def top_ips(df, n=10):
    return device_activity(df).head(n)


def top_conversations(df, n=10):
    """Most active src -> dst pairs."""
    if df.empty:
        return pd.DataFrame(columns=["src_ip", "dst_ip", "packets", "bytes"])
    g = df.groupby(["src_ip", "dst_ip"]).agg(packets=("size", "count"), bytes=("size", "sum"))
    return g.sort_values("bytes", ascending=False).head(n).reset_index()


def top_ports(df, n=10):
    d = df.dropna(subset=["dst_port"])
    if d.empty:
        return pd.DataFrame(columns=["dst_port", "packets"])
    g = d.groupby("dst_port").size().sort_values(ascending=False).head(n)
    out = g.reset_index(name="packets")
    out["dst_port"] = out["dst_port"].astype(int)
    return out


# ---------------------------------------------------------------- live system info
def live_connections(limit=200):
    """Active network connections on this machine (psutil)."""
    rows = []
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        return pd.DataFrame(columns=["proto", "local", "remote", "status", "pid"])
    for c in conns[:limit]:
        proto = "TCP" if c.type == 1 else "UDP"
        local = "%s:%s" % (c.laddr.ip, c.laddr.port) if c.laddr else ""
        remote = "%s:%s" % (c.raddr.ip, c.raddr.port) if c.raddr else ""
        rows.append((proto, local, remote, c.status, c.pid))
    return pd.DataFrame(rows, columns=["proto", "local", "remote", "status", "pid"])


def net_io_snapshot():
    io = psutil.net_io_counters()
    return dict(t=time.time(), sent=io.bytes_sent, recv=io.bytes_recv)


def bandwidth_between(prev, cur):
    """(upload KB/s, download KB/s) between two net_io_snapshot() calls."""
    dt = max(cur["t"] - prev["t"], 0.001)
    return ((cur["sent"] - prev["sent"]) / dt / 1024.0,
            (cur["recv"] - prev["recv"]) / dt / 1024.0)
