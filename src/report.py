



"""import json
import os
from datetime import datetime

REPORT_FILE = os.path.join("reports", "report.json")

def save_report(url: str, result: str):
    report_entry = {
        "url": url,
        "result": result,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    os.makedirs("reports", exist_ok=True)

    with open(REPORT_FILE, "a") as f:
        f.write(json.dumps(report_entry) + "\n")"""


import json
import os
from datetime import datetime

REPORT_FILE = os.path.join("reports", "report.json")

def save_report(url: str, result: str, score: float):
    report_entry = {
        "url": url,
        "result": result,
        "score": score,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    os.makedirs("reports", exist_ok=True)

    with open(REPORT_FILE, "a") as f:
        f.write(json.dumps(report_entry) + "\n")

