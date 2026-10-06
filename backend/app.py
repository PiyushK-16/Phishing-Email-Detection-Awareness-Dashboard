"""Flask REST API + static dashboard. Run from project root: python -m backend.app"""
import collections, os, time
from flask import Flask, jsonify, request
from backend import db
from backend.services.preprocess import parse_sender, sanitize
from backend.services.risk_engine import analyze_email
from backend.services.url_analyzer import analyze_url

try:
    from dotenv import load_dotenv; load_dotenv()
except ImportError:
    pass
FRONTEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend")


def create_app():
    app = Flask(__name__, static_folder=FRONTEND, static_url_path="")
    app.config["MAX_CONTENT_LENGTH"] = 1_000_000  # 1 MB request limit
    db.init_db()
    hits = collections.defaultdict(collections.deque)

    @app.before_request
    def rate_limit():  # simple per-IP limiter on analysis endpoints
        if request.path.startswith("/api/analyze"):
            now, q = time.time(), hits[request.remote_addr]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= int(os.getenv("RATE_LIMIT_PER_MIN", "60")):
                app.logger.warning("rate limit hit from %s", request.remote_addr)
                return jsonify(error="Rate limit exceeded"), 429
            q.append(now)

    @app.after_request
    def headers(r):
        r.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self'; img-src 'self' data:"
        r.headers["X-Content-Type-Options"] = "nosniff"
        return r

    @app.get("/")
    def index():
        return app.send_static_file("index.html")

    @app.post("/api/analyze")
    def analyze():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(error="JSON body required"), 400
        sender, subject, body, att = (data.get(k, "") for k in ("sender", "subject", "body", "attachment_name"))
        if not all(isinstance(v, str) for v in (sender, subject, body, att)):
            return jsonify(error="All fields must be strings"), 400
        if len(sender) > 320 or len(subject) > 300 or len(body) > 50000 or len(att) > 255:
            return jsonify(error="Input too long"), 400
        if not subject.strip() and not body.strip():
            return jsonify(error="Provide at least a subject or a body"), 400
        result = analyze_email(sanitize(sender), sanitize(subject), sanitize(body), sanitize(att), use_ml=bool(data.get("use_ml", True)))
        result["analysis_id"] = db.save_analysis(result, parse_sender(sender)[2] or "invalid", sanitize(subject) or "(no subject)")
        return jsonify(result), 201

    @app.post("/api/analyze/url")
    def analyze_url_route():
        data = request.get_json(silent=True)
        url = data.get("url") if isinstance(data, dict) else None
        if not isinstance(url, str) or not url.strip() or len(url) > 2048:
            return jsonify(error="A 'url' string (max 2048 chars) is required"), 400
        return jsonify(analyze_url(url)), 200

    @app.get("/api/analyses")
    def analyses():
        a = request.args
        return jsonify(db.list_analyses(a.get("q", "")[:100], a.get("classification", ""), a.get("sort", "created_at"), a.get("order", "desc")))

    @app.get("/api/analyses/<int:aid>")
    def analysis(aid):
        row = db.get_analysis(aid)
        return (jsonify(row), 200) if row else (jsonify(error="Not found"), 404)

    @app.delete("/api/analyses/<int:aid>")
    def delete(aid):
        return ("", 204) if db.delete_analysis(aid) else (jsonify(error="Not found"), 404)

    @app.get("/api/dashboard/stats")
    def dash_stats():
        return jsonify(db.stats())

    @app.get("/api/dashboard/indicators")
    def dash_ind():
        return jsonify(db.top_indicators())

    @app.errorhandler(413)
    def too_big(e):
        return jsonify(error="Payload too large"), 413

    @app.errorhandler(404)
    def nf(e):
        return jsonify(error="Not found"), 404

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=os.getenv("FLASK_DEBUG") == "1")
