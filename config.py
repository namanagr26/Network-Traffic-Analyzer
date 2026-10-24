"""
config.py - ALL settings live here. Tune thresholds in this file only.
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Database / output locations (override DB with:  export NTA_DB=/path/to/other.db)
DB_PATH = os.environ.get("NTA_DB", os.path.join(BASE_DIR, "traffic.db"))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# ---------------- Capture ----------------
# "any" = sniff every interface (eth0 + lo together). Use "eth0" or "lo" to restrict.
INTERFACE = "any"
FLUSH_INTERVAL = 1.0        # seconds between database writes

# ---------------- Detection ----------------
DEFAULT_LOOKBACK_SEC = 3600     # how far back the detector looks on each run
ALERT_COOLDOWN_SEC = 60         # same alert type + same source within this time = duplicate

# Rule 1: traffic spike (robust version of "mean + 3*std": median + K*MAD)
SPIKE_BUCKET_SEC = 5            # packets/sec is averaged over this many seconds
SPIKE_K = 3.0                   # how many "deviations" above normal counts as a spike
SPIKE_MIN_PPS = 200             # never alert below this packets/sec (avoids noise)
SPIKE_MIN_FACTOR = 3.0          # also must be >= this many times the median rate
SPIKE_MIN_HISTORY_SEC = 30      # need at least this much data to know what "normal" is

# Rule 2: unknown IP (inbound connection attempt from an IP not in baseline/whitelist)
WHITELIST_IPS = {
    # "192.168.1.1",   # example: your router
}

# Rule 3: port-scan-like behaviour (one source, many different ports, same target)
PORTSCAN_WINDOW_SEC = 10
PORTSCAN_PORTS = 15             # distinct destination ports inside the window

# Rule 4: repeated access attempts (many SYNs from one source to the same port)
SYN_WINDOW_SEC = 60
SYN_THRESHOLD_SENSITIVE = 15    # for ports listed below
SYN_THRESHOLD_OTHER = 100       # for every other port
SENSITIVE_PORTS = {21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 5900}

# ---------------- Dashboard ----------------
MAX_ROWS_LOADED = 300_000       # safety limit when loading packets into pandas
REFRESH_SECONDS = 5
