"""Council driver licensing: admin CRM + public licence checker.

Standard library only (Python 3.9+). Run with:  python3 app.py
  Public checker:  http://localhost:8000/
  Admin dashboard: http://localhost:8000/admin
"""
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DB_PATH = Path(os.environ.get("DB_PATH", BASE_DIR / "drivers.db"))
PORT = int(os.environ.get("PORT", "8000"))
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme")
SESSION_HOURS = 8

STATUSES = ("active", "suspended", "revoked")
LICENCE_TYPES = ("Hackney Carriage", "Private Hire", "Dual")
DRIVER_FIELDS = ("full_name", "licence_number", "licence_type", "expiry_date",
                 "phone", "email", "notes")

_db_lock = threading.Lock()
_sessions = {}  # token -> expiry datetime


# ---------------------------------------------------------------- database

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _db_lock, db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS drivers (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name      TEXT NOT NULL,
                licence_number TEXT NOT NULL,
                licence_key    TEXT NOT NULL UNIQUE,
                licence_type   TEXT NOT NULL,
                expiry_date    TEXT NOT NULL,
                status         TEXT NOT NULL DEFAULT 'active',
                phone          TEXT DEFAULT '',
                email          TEXT DEFAULT '',
                notes          TEXT DEFAULT '',
                created_at     TEXT NOT NULL,
                updated_at     TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                driver_id  INTEGER NOT NULL,
                action     TEXT NOT NULL,
                detail     TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        """)
        if conn.execute("SELECT COUNT(*) FROM drivers").fetchone()[0] == 0:
            seed(conn)


def seed(conn):
    today = dt.date.today()
    sample = [
        ("Amira Khan", "PH-10421", "Private Hire", 400, "active"),
        ("David Okafor", "HC-20877", "Hackney Carriage", 210, "active"),
        ("Sarah Whitfield", "PH-10588", "Private Hire", 18, "active"),
        ("Tomasz Nowak", "DL-30112", "Dual", 540, "active"),
        ("James Patel", "HC-20931", "Hackney Carriage", 95, "suspended"),
        ("Grace Mensah", "PH-10702", "Private Hire", 300, "active"),
        ("Liam O'Connor", "PH-10355", "Private Hire", -12, "active"),
        ("Fatima Rahman", "HC-21004", "Hackney Carriage", 660, "revoked"),
    ]
    now = _now()
    for name, num, ltype, days, status in sample:
        expiry = (today + dt.timedelta(days=days)).isoformat()
        cur = conn.execute(
            "INSERT INTO drivers (full_name, licence_number, licence_key, licence_type,"
            " expiry_date, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
            (name, num, licence_key(num), ltype, expiry, status, now, now))
        conn.execute("INSERT INTO audit_log (driver_id, action, detail, created_at)"
                     " VALUES (?,?,?,?)", (cur.lastrowid, "created", "Sample record", now))


def _now():
    return dt.datetime.now().isoformat(timespec="seconds")


def driver_to_dict(row):
    d = dict(row)
    d["expired"] = d["expiry_date"] < dt.date.today().isoformat()
    return d


def normalise_licence(value):
    """Tidy for display: uppercase, single hyphens instead of spaces."""
    return re.sub(r"[\s-]+", "-", str(value or "").strip()).strip("-").upper()


def licence_key(value):
    """Match key that ignores spacing/punctuation, so 'ph 10421' == 'PH-10421'."""
    return re.sub(r"[^A-Z0-9]", "", str(value or "").upper())


def validate_driver(data, partial=False):
    """Return (clean_dict, error). With partial=True only supplied keys are checked."""
    clean = {}
    for key in DRIVER_FIELDS + ("status",):
        if key in data:
            clean[key] = str(data[key] or "").strip()
    if not partial:
        for key in ("full_name", "licence_number", "licence_type", "expiry_date"):
            if not clean.get(key):
                return None, f"{key.replace('_', ' ').capitalize()} is required"
    if "licence_number" in clean:
        clean["licence_number"] = normalise_licence(clean["licence_number"])
        clean["licence_key"] = licence_key(clean["licence_number"])
    if "licence_type" in clean and clean["licence_type"] not in LICENCE_TYPES:
        return None, "Invalid licence type"
    if "status" in clean and clean["status"] not in STATUSES:
        return None, "Invalid status"
    if "expiry_date" in clean:
        try:
            dt.date.fromisoformat(clean["expiry_date"])
        except ValueError:
            return None, "Expiry date must be YYYY-MM-DD"
    return clean, None


# ---------------------------------------------------------------- sessions

def create_session():
    token = secrets.token_urlsafe(32)
    _sessions[token] = dt.datetime.now() + dt.timedelta(hours=SESSION_HOURS)
    return token


def valid_session(token):
    expiry = _sessions.get(token or "")
    if expiry and expiry > dt.datetime.now():
        return True
    _sessions.pop(token, None)
    return False


def password_ok(candidate):
    a = hashlib.sha256(candidate.encode()).digest()
    b = hashlib.sha256(ADMIN_PASSWORD.encode()).digest()
    return hmac.compare_digest(a, b)


# ---------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "LicensingApp/1.0"

    # -- helpers
    def send_json(self, payload, status=200, extra_headers=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, name, content_type="text/html; charset=utf-8"):
        path = (STATIC_DIR / name).resolve()
        if STATIC_DIR not in path.parents or not path.is_file():
            return self.send_error(404)
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > 100_000:
            return None
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return None

    def session_token(self):
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        return jar["session"].value if "session" in jar else None

    def is_admin(self):
        return valid_session(self.session_token())

    # -- routing
    def do_GET(self):
        url = urlparse(self.path)
        path = url.path

        if path in ("/", "/check"):
            return self.send_file("public.html")
        if path == "/styles.css":
            return self.send_file("styles.css", "text/css; charset=utf-8")
        if path == "/login":
            return self.send_file("login.html")
        if path == "/admin":
            return self.send_file("admin.html") if self.is_admin() else self.redirect("/login")

        if path == "/api/public/check":
            return self.public_check(parse_qs(url.query))

        if path.startswith("/api/admin/"):
            if not self.is_admin():
                return self.send_json({"error": "Not signed in"}, 401)
            if path == "/api/admin/drivers":
                return self.list_drivers()
            if path == "/api/admin/audit":
                return self.list_audit()
        self.send_error(404)

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/login":
            return self.login()
        if path == "/api/logout":
            _sessions.pop(self.session_token(), None)
            return self.send_json({"ok": True}, extra_headers={
                "Set-Cookie": "session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})
        if not self.is_admin():
            return self.send_json({"error": "Not signed in"}, 401)
        if path == "/api/admin/drivers":
            return self.create_driver()
        self.send_error(404)

    def do_PATCH(self):
        m = re.fullmatch(r"/api/admin/drivers/(\d+)", urlparse(self.path).path)
        if not m:
            return self.send_error(404)
        if not self.is_admin():
            return self.send_json({"error": "Not signed in"}, 401)
        self.update_driver(int(m.group(1)))

    # -- public
    def public_check(self, query):
        """Only active, in-date licences are ever returned. Suspended, revoked
        and expired drivers look identical to 'not found' so nothing leaks."""
        number = normalise_licence((query.get("licence") or [""])[0])
        if not licence_key(number):
            return self.send_json({"error": "Enter a licence number"}, 400)
        with db() as conn:
            row = conn.execute(
                "SELECT full_name, licence_number, licence_type, expiry_date FROM drivers"
                " WHERE licence_key = ? AND status = 'active' AND expiry_date >= ?",
                (licence_key(number), dt.date.today().isoformat())).fetchone()
        if row:
            return self.send_json({"licensed": True, "driver": dict(row),
                                   "checked_at": _now()})
        self.send_json({"licensed": False, "licence_number": number, "checked_at": _now()})

    # -- auth
    def login(self):
        data = self.read_json() or {}
        if not password_ok(str(data.get("password", ""))):
            return self.send_json({"error": "Incorrect password"}, 401)
        token = create_session()
        self.send_json({"ok": True}, extra_headers={
            "Set-Cookie": f"session={token}; Path=/; HttpOnly; SameSite=Strict;"
                          f" Max-Age={SESSION_HOURS * 3600}"})

    # -- admin
    def list_drivers(self):
        with db() as conn:
            rows = conn.execute("SELECT * FROM drivers ORDER BY full_name").fetchall()
        self.send_json({"drivers": [driver_to_dict(r) for r in rows],
                        "statuses": STATUSES, "licence_types": LICENCE_TYPES})

    def list_audit(self):
        with db() as conn:
            rows = conn.execute(
                "SELECT a.*, d.full_name, d.licence_number FROM audit_log a"
                " JOIN drivers d ON d.id = a.driver_id"
                " ORDER BY a.id DESC LIMIT 50").fetchall()
        self.send_json({"entries": [dict(r) for r in rows]})

    def create_driver(self):
        clean, error = validate_driver(self.read_json() or {})
        if error:
            return self.send_json({"error": error}, 400)
        clean.setdefault("status", "active")
        now = _now()
        cols = list(clean) + ["created_at", "updated_at"]
        try:
            with _db_lock, db() as conn:
                cur = conn.execute(
                    f"INSERT INTO drivers ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                    [*clean.values(), now, now])
                conn.execute("INSERT INTO audit_log (driver_id, action, detail, created_at)"
                             " VALUES (?,?,?,?)",
                             (cur.lastrowid, "created", f"Added as {clean['status']}", now))
                row = conn.execute("SELECT * FROM drivers WHERE id=?", (cur.lastrowid,)).fetchone()
        except sqlite3.IntegrityError:
            return self.send_json({"error": "That licence number already exists"}, 409)
        self.send_json({"driver": driver_to_dict(row)}, 201)

    def update_driver(self, driver_id):
        clean, error = validate_driver(self.read_json() or {}, partial=True)
        if error:
            return self.send_json({"error": error}, 400)
        if not clean:
            return self.send_json({"error": "Nothing to update"}, 400)
        now = _now()
        try:
            with _db_lock, db() as conn:
                before = conn.execute("SELECT * FROM drivers WHERE id=?", (driver_id,)).fetchone()
                if not before:
                    return self.send_json({"error": "Driver not found"}, 404)
                sets = ", ".join(f"{k}=?" for k in clean)
                conn.execute(f"UPDATE drivers SET {sets}, updated_at=? WHERE id=?",
                             [*clean.values(), now, driver_id])
                for key, value in clean.items():
                    if key != "licence_key" and before[key] != value:
                        action = "status" if key == "status" else "edited"
                        conn.execute(
                            "INSERT INTO audit_log (driver_id, action, detail, created_at)"
                            " VALUES (?,?,?,?)",
                            (driver_id, action,
                             f"{key.replace('_', ' ')}: {before[key] or '—'} → {value or '—'}", now))
                row = conn.execute("SELECT * FROM drivers WHERE id=?", (driver_id,)).fetchone()
        except sqlite3.IntegrityError:
            return self.send_json({"error": "That licence number already exists"}, 409)
        self.send_json({"driver": driver_to_dict(row)})

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {fmt % args}")


if __name__ == "__main__":
    init_db()
    if ADMIN_PASSWORD == "changeme":
        print("⚠  Using default admin password 'changeme' — set ADMIN_PASSWORD before real use.")
    print(f"Public checker:  http://localhost:{PORT}/")
    print(f"Admin dashboard: http://localhost:{PORT}/admin")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
