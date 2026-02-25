import sqlite3

DB_NAME = "alerts.db"

def view_alerts():

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT name FROM sqlite_master
        WHERE type='table' AND name='alerts';
    """)

    if cursor.fetchone() is None:
        print("No alerts table found.")
        conn.close()
        return

    cursor.execute("""
        SELECT timestamp, severity, score, message
        FROM alerts
        ORDER BY id DESC
        LIMIT 30;
    """)

    rows = cursor.fetchall()

    print("\n===== ALERT HISTORY (LATEST 30) =====\n")

    if not rows:
        print("No alerts stored yet.")
    else:
        for row in rows:
            timestamp, severity, score, message = row

            if score <= 30:
                level = "LOW"
            elif score <= 70:
                level = "MEDIUM"
            else:
                level = "HIGH"

            print(f"[{severity} | SCORE:{score} | {level}] {timestamp} -> {message}")

    print("\n===== END =====")
    conn.close()


if __name__ == "__main__":
    view_alerts()