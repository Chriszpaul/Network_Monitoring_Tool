import sqlite3

DB_NAME = "alerts.db"

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
            score INTEGER
        )
    """)

    # PACKET TABLE (expert mode)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            port INTEGER
        )
    """)

    conn.commit()
    conn.close()


# ===============================
# SAVE ALERT
# ===============================
def save_alert(message, severity):

    # threat score mapping
    score_map = {
        "INFO": 10,
        "WARNING": 70,
        "CRITICAL": 95
    }

    score = score_map.get(severity, 0)

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts (message, severity, score)
        VALUES (?, ?, ?)
    """, (message, severity, score))

    conn.commit()
    conn.close()

# ===============================
# SAVE PACKETS
# ===============================

def save_packet(src_ip, dst_ip, protocol, port):

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO packets (src_ip, dst_ip, protocol, port)
        VALUES (?, ?, ?, ?)
    """, (src_ip, dst_ip, protocol, port))

    conn.commit()
    conn.close()