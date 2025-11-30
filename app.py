import os
import ipaddress
from flask import Flask, render_template, request, jsonify
import requests

# Optional rate limiting (recommended for public deployments)
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    RATE_LIMITING_AVAILABLE = True
except ImportError:
    RATE_LIMITING_AVAILABLE = False

app = Flask(__name__)

API_KEY = os.getenv("ABUSEIPDB_KEY")


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


@app.before_request
def ensure_api_key():
    # Return 503 to indicate server misconfiguration (missing secret)
    if not API_KEY:
        return jsonify({"error": "Server misconfigured: missing ABUSEIPDB_KEY"}), 503

    # Enforce JSON content-type for the API endpoint
    if request.path == "/check_ip" and request.method == "POST":
        if request.content_type is None or "application/json" not in request.content_type.lower():
            return jsonify({"status": "invalid", "message": "Content-Type must be application/json"}), 400


# Configure rate limiting if the library is installed
if RATE_LIMITING_AVAILABLE:
    limiter = Limiter(get_remote_address, app=app, default_limits=["30 per hour"])


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/check_ip", methods=["POST"])
# Per-endpoint limit (active only if flask-limiter is installed)
def check_ip():
    payload = request.get_json(silent=True) or {}
    ip_address = (payload.get("ip") or "").strip()

    if not is_valid_ip(ip_address):
        return jsonify({"status": "invalid", "message": "Please enter a valid IP address."}), 400

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=8)
        if resp.status_code != 200:
            # Do not echo upstream bodies to clients in production; log server-side if needed
            return jsonify({
                "status": "error",
                "message": f"Upstream API error: {resp.status_code}"
            }), 502

        data = resp.json()
        info = data.get("data", {})
        score = info.get("abuseConfidenceScore", 0)
        reports = info.get("totalReports", 0)

        # Interpret the score
        if score > 50:
            return jsonify({"status": "malicious", "score": score, "reports": reports}), 200
        # If no reports and score 0, consider clean; otherwise unknown
        if reports == 0 and score == 0:
            return jsonify({"status": "unknown", "message": "No data found for this IP."}), 200

        return jsonify({"status": "clean", "score": score, "reports": reports}), 200

    except requests.Timeout:
        return jsonify({"status": "error", "message": "Request timed out."}), 504
    except requests.RequestException as e:
        return jsonify({"status": "error", "message": "Network error."}), 502
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid JSON from upstream API."}), 502
    except Exception:
        return jsonify({"status": "error", "message": "Server error."}), 500


if __name__ == "__main__":
    # Disable debug for production; use a WSGI server like gunicorn/waitress when deploying
    app.run(debug=False)

