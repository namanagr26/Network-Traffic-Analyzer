"""
db.py - SQLite helpers shared by every module.

Tables
  packets   : one row per captured packet
  alerts    : one row per suspicious-activity alert
  known_ips : baseline of "normal" IP addresses (used by the unknown-IP rule)
"""
import sqlite3
import time

import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL    NOT NULL,      -- unix time (seconds)
    src_ip     TEXT,
    dst_ip     TEXT,
    protocol   TEXT,                  -- TCP / UDP / ICMP / DNS / ARP / ...
    service    TEXT,                  -- HTTPS / SSH / ... (guessed from port)
    src_port   INTEGER,
    dst_port   INTEGER,
    size       INTEGER,               -- bytes
    tcp_flags  TEXT,                  -- S, SA, A, PA, FA, R ...
    direction  TEXT                   -- incoming / outgoing / local / transit
);
CREATE INDEX IF NOT EXISTS idx_packets_ts  ON packets(ts);
CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip);

CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,         -- when the suspicious activity started
    alert_type TEXT NOT NULL,
    severity   TEXT NOT NULL,         -- low / medium / high
    src_ip     TEXT,
    dst_ip     TEXT,
    details    TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);

CREATE TABLE IF NOT EXISTS known_ips (
    ip         TEXT PRIMARY KEY,
    first_seen REAL,
    source     TEXT
);
"""

PACKET_COLUMNS = ("ts", "src_ip", "dst_ip", "protocol", "service",
                  "src_port", "dst_port", "size", "tcp_flags", "direction")


def get_conn(path=None):
    """Open the database (creating tables if needed). WAL mode lets the dashboard
    read while capture.py is writing."""
    conn = sqlite3.connect(path or config.DB_PATH, timeout=30)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.DatabaseError:
        pass
    conn.executescript(SCHEMA)
    return conn


def insert_packets(conn, rows):
    """rows: list of tuples in PACKET_COLUMNS order."""
    if not rows:
        return 0
    sql = "INSERT INTO packets (%s) VALUES (%s)" % (
        ",".join(PACKET_COLUMNS), ",".join("?" * len(PACKET_COLUMNS)))
    conn.executemany(sql, rows)
    conn.commit()
    return len(rows)


def insert_alert(conn, ts, alert_type, severity, src_ip, dst_ip, details):
    conn.execute(
        "INSERT INTO alerts (ts, alert_type, severity, src_ip, dst_ip, details) "
        "VALUES (?,?,?,?,?,?)",
        (ts, alert_type, severity, src_ip, dst_ip, details))
    conn.commit()


def alert_exists(conn, alert_type, src_ip, ts, cooldown):
    """True if the same alert type from the same source already exists near ts."""
    row = conn.execute(
        "SELECT 1 FROM alerts WHERE alert_type=? AND IFNULL(src_ip,'')=IFNULL(?,'') "
        "AND ABS(ts-?) < ? LIMIT 1",
        (alert_type, src_ip, ts, cooldown)).fetchone()
    return row is not None


def add_known_ips(conn, ips, source="learned"):
    now = time.time()
    conn.executemany(
        "INSERT OR IGNORE INTO known_ips (ip, first_seen, source) VALUES (?,?,?)",
        [(ip, now, source) for ip in ips])
    conn.commit()


def get_known_ips(conn):
    return {r[0] for r in conn.execute("SELECT ip FROM known_ips")}


def count_rows(conn, table):
    return conn.execute("SELECT COUNT(*) FROM %s" % table).fetchone()[0]


def reset(conn, tables=("packets", "alerts", "known_ips")):
    for t in tables:
        conn.execute("DELETE FROM %s" % t)
    conn.commit()


if __name__ == "__main__":
    c = get_conn()
    print("Database ready:", config.DB_PATH)
    print("packets:", count_rows(c, "packets"), "| alerts:", count_rows(c, "alerts"))
