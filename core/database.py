import sqlite3

DB_NAME = "alerts.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

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

    conn.commit()
    conn.close()


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