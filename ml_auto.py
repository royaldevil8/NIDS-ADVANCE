import time
import os
import subprocess

DATA_FILE = "/home/royal/NIDS/ml_data.csv"
MIN_LINES = 500   # retrain threshold
CHECK_INTERVAL = 30  # seconds


def get_line_count():
    if not os.path.exists(DATA_FILE):
        return 0
    with open(DATA_FILE) as f:
        return sum(1 for _ in f)


def auto_retrain():
    last_trained = 0

    while True:
        time.sleep(CHECK_INTERVAL)

        lines = get_line_count()

        print(f"[ML] Data lines: {lines}")

        # retrain only if enough new data
        if lines - last_trained >= MIN_LINES:
            print("[ML] Retraining model...")

            try:
                subprocess.run(["python3", "train_model.py"])
                print("[ML] Model updated ✅")

                last_trained = lines

            except Exception as e:
                print("[ML ERROR]", e)
