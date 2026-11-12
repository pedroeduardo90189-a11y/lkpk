import hmac
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, abort, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MiB per request

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
TOKEN = os.environ.get("COLLECTOR_TOKEN", "")


def require_token():
    """Require a configured bearer token; fail closed if it is missing."""
    if not TOKEN:
        abort(503, description="Server authentication is not configured")

    scheme, _, supplied = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not supplied or not hmac.compare_digest(supplied, TOKEN):
        abort(401, description="Unauthorized")


@app.route("/collect", methods=["POST"])
def collect():
    require_token()

    data = request.get_data(as_text=True)
    if not data:
        return "", 204

    # Use the direct peer address. X-Forwarded-For is client-controlled unless
    # a trusted proxy is explicitly configured to sanitize it.
    peer_ip = request.remote_addr or "unknown"
    ip_clean = re.sub(r"[^A-Za-z0-9_-]", "_", peer_ip)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    log_file = LOG_DIR / f"{ip_clean}.txt"

    with log_file.open("a", encoding="utf-8") as f:
        f.write(f"\n--- {timestamp} UTC ---\n")
        f.write(data)
    return "", 200


@app.route("/logs", methods=["GET"])
def list_logs():
    require_token()
    files = sorted(f for f in LOG_DIR.iterdir() if f.is_file() and f.suffix == ".txt")
    out = [f"{f.name} — {f.stat().st_size} bytes" for f in files]
    return "\n".join(out), 200


@app.route("/logs/<filename>", methods=["GET"])
def read_log(filename):
    require_token()

    # Only accept generated log filenames; reject traversal and other paths.
    if not re.fullmatch(r"[A-Za-z0-9_-]+\.txt", filename):
        return "not found", 404

    path = LOG_DIR / filename
    if not path.is_file() or path.is_symlink():
        return "not found", 404
    return path.read_text(encoding="utf-8"), 200


if __name__ == "__main__":
    # For deployment, run behind a production WSGI server such as Gunicorn.
    # Do not expose the development server directly to the public internet.
    app.run(host="127.0.0.1", port=5000)
