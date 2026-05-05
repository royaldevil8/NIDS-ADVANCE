def log_alert(msg):
    with open("alerts.log", "a") as f:
        f.write(msg + "\n")
