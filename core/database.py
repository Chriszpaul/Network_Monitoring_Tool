import sqlite3
import os
from datetime import datetime

DB_NAME = "alerts.db"
LOG_DIR = "logs"

os.makedirs(LOG_DIR, exist_ok=True)


# =========================
# LOGGING
# =========================
def write_log(message):
    today = datetime.now().strftime("%Y-%m-%d")
    logfile = os.path.join(LOG_DIR, f"alerts_{today}.log")

    with open(logfile, "a", encoding="utf-8") as f:
        timestamp = datetime.now().strftime("%H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")


# =========================
# INIT DATABASE
# =========================
def init_db():

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # ALERT TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            message TEXT,
            severity TEXT,
            score INTEGER,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            port INTEGER,
            packet_count INTEGER
        )
    """)

    # RAW PACKETS TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            port INTEGER,
            packet_size INTEGER
        )
    """)

    conn.commit()
    conn.close()


# =========================
# SAVE RAW PACKET
# =========================
def save_packet(src_ip, dst_ip, protocol, port, packet_size):

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO packets
        (src_ip, dst_ip, protocol, port, packet_size)
        VALUES (?, ?, ?, ?, ?)
    """, (src_ip, dst_ip, protocol, port, packet_size))

    conn.commit()
    conn.close()


# =========================
# SAVE ALERT
# =========================
def save_alert(
    message,
    severity,
    src_ip=None,
    dst_ip=None,
    protocol=None,
    port=None,
    packet_count=None
):

    score_map = {
        "INFO": 10,
        "WARNING": 70,
        "CRITICAL": 95
    }

    score = score_map.get(severity, 0)

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts
        (message, severity, score, src_ip, dst_ip, protocol, port, packet_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        message,
        severity,
        score,
        src_ip,
        dst_ip,
        protocol,
        port,
        packet_count
    ))

    conn.commit()
    conn.close()

    write_log(f"{severity} | {message} | {src_ip} -> {dst_ip}")