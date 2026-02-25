def generate_report(alerts):

    print("\n===== NETWORK SECURITY REPORT =====\n")

    if not alerts:
        print("No suspicious activity detected.")
    else:
        for alert in alerts:
            print("•", alert)

    print("\n===== END OF REPORT =====")