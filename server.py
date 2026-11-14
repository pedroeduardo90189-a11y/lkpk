from flask import Flask, request, send_from_directory
from flask_cors import CORS
from pathlib import Path
from datetime import datetime
import os

app = Flask(__name__)
CORS(app)
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

@app.route("/collect", methods=["POST"])
def collect():
    token = request.headers.get("Authorization", "")
    expected = os.environ.get("COLLECTOR_TOKEN", "")
    if expected and token != expected:
        return "", 401
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ip_clean = ip.replace(".", "_").replace(":", "_")
    timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = LOG_DIR / f"{ip_clean}.txt"
    data = request.get_data(as_text=True)
    if not data:
        return "", 204
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"\n--- {timestamp} UTC ---\n")
        f.write(data)
    return "", 200

@app.route("/logs", methods=["GET"])
def list_logs():
    token = request.headers.get("Authorization", "")
    expected = os.environ.get("COLLECTOR_TOKEN", "")
    if expected and token != expected:
        return "", 401
    files = sorted(LOG_DIR.iterdir())
    out = [f"{f.name} — {f.stat().st_size} bytes" for f in files]
    return "\n".join(out), 200

@app.route("/logs/<filename>", methods=["GET"])
def read_log(filename):
    token = request.headers.get("Authorization", "")
    expected = os.environ.get("COLLECTOR_TOKEN", "")
    if expected and token != expected:
        return "", 401
    path = LOG_DIR / filename
    if not path.exists() or not path.is_relative_to(LOG_DIR):
        return "not found", 404
    return path.read_text(encoding="utf-8"), 200

@app.route("/", methods=["GET"])
def viewer():
    return send_from_directory(".", "viewer.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
