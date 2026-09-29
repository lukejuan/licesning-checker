"""Council taxi licensing: staff register for drivers and vehicles + public checkers.

Standard library only (Python 3.9+). Run with:  python3 app.py
  Public registers: http://localhost:8000/  (drivers at /drivers, vehicles at /vehicles)
  Staff dashboard:  http://localhost:8000/admin
On first run, /admin takes you to /setup to create the first admin account.
"""
import csv
import datetime as dt
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import importer

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DB_PATH = Path(os.environ.get("DB_PATH", BASE_DIR / "drivers.db"))
PORT = int(os.environ.get("PORT", "8000"))
SESSION_HOURS = 8

STATUSES = ("active", "suspended", "revoked")
ROLES = ("officer", "admin")

MIN_PASSWORD_LENGTH = 10
PBKDF2_ITERATIONS = 600_000
MAX_LOGIN_FAILURES = 5
LOCKOUT_SECONDS = 15 * 60

STATIC_ASSETS = {
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}

_db_lock = threading.Lock()
_login_failures = {}  # email -> [timestamps of recent failures]


# ---------------------------------------------------------------- reference numbers

def normalise_licence(value):
    """Tidy for display: uppercase, single hyphens instead of spaces."""
    return re.sub(r"[\s-]+", "-", str(value or "").strip()).strip("-").upper()


def normalise_registration(value):
    """Vehicle registrations keep their spaces: 'ab12  cde' -> 'AB12 CDE'."""
    return re.sub(r"\s+", " ", str(value or "").strip()).upper()


def match_key(value):
    """Match key that ignores spacing/punctuation, so 'ph 10421' == 'PH-10421'."""
    return re.sub(r"[^A-Z0-9]", "", str(value or "").upper())


# ---------------------------------------------------------------- registers
#
# Drivers and vehicles work the same way: a status dropdown, expiry dates, an
# activity log, and a public checker that only shows active, in-date records.
# Everything that differs between the two lives in this table.

REGISTERS = {
    "drivers": {
        "table": "drivers",
        "fields": ("full_name", "licence_number", "licence_type", "expiry_date",
                   "phone", "email", "notes"),
        "required": ("full_name", "licence_number", "licence_type", "expiry_date"),
        # reference field -> (match-key column, display normaliser)
        "keys": {"licence_number": ("licence_key", normalise_licence)},
        "expiry_fields": ("expiry_date",),
        "licence_types": ("Hackney Carriage", "Private Hire", "Dual"),
        "order_by": "full_name",
        "label_sql": "e.full_name",
        "sub_sql": "e.licence_number",
        "public_fields": ("full_name", "licence_number", "licence_type", "expiry_date"),
        "duplicate_error": "That licence number already exists",
    },
    "vehicles": {
        "table": "vehicles",
        "fields": ("registration", "plate_number", "make", "model", "colour",
                   "proprietor_name", "licence_type", "licence_expiry", "test_expiry", "notes"),
        "required": ("registration", "plate_number", "make", "model", "proprietor_name",
                     "licence_type", "licence_expiry", "test_expiry"),
        "keys": {"plate_number": ("plate_key", normalise_licence),
                 "registration": ("registration_key", normalise_registration)},
        "expiry_fields": ("licence_expiry", "test_expiry"),
        "licence_types": ("Hackney Carriage", "Private Hire"),
        "order_by": "registration",
        "label_sql": "e.registration",
        "sub_sql": "e.make || ' ' || e.model || ' · plate ' || e.plate_number",
        # Proprietor names are deliberately not published.
        "public_fields": ("registration", "plate_number", "make", "model", "colour",
                          "licence_type", "licence_expiry", "test_expiry"),
        "duplicate_error": "That registration or plate number is already on the register",
    },
}

FIELD_LABELS = {
    "expiry_date": "licence expiry",
    "licence_expiry": "licence expiry",
    "test_expiry": "test certificate expiry",
    "proprietor_name": "proprietor",
}


def field_label(key):
    return FIELD_LABELS.get(key, key.replace("_", " "))


# ---------------------------------------------------------------- database

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
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
            CREATE TABLE IF NOT EXISTS vehicles (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                registration     TEXT NOT NULL,
                registration_key TEXT NOT NULL UNIQUE,
                plate_number     TEXT NOT NULL,
                plate_key        TEXT NOT NULL UNIQUE,
                make             TEXT NOT NULL,
                model            TEXT NOT NULL,
                colour           TEXT DEFAULT '',
                proprietor_name  TEXT NOT NULL,
                licence_type     TEXT NOT NULL,
                licence_expiry   TEXT NOT NULL,
                test_expiry      TEXT NOT NULL,
                status           TEXT NOT NULL DEFAULT 'active',
                notes            TEXT DEFAULT '',
                created_at       TEXT NOT NULL,
                updated_at       TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name            TEXT NOT NULL,
                email                TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash        TEXT NOT NULL,
                role                 TEXT NOT NULL DEFAULT 'officer',
                is_active            INTEGER NOT NULL DEFAULT 1,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                created_at           TEXT NOT NULL,
                last_login_at        TEXT
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS staff_log (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id       INTEGER REFERENCES users(id),
                target_user_id INTEGER NOT NULL REFERENCES users(id),
                detail         TEXT NOT NULL,
                created_at     TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS activity_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                register    TEXT NOT NULL,
                record_id   INTEGER NOT NULL,
                user_id     INTEGER REFERENCES users(id),
                action      TEXT NOT NULL,
                detail      TEXT NOT NULL,
                created_at  TEXT NOT NULL
            );
        """)
        migrate_driver_audit_log(conn)
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (_now(),))
        if conn.execute("SELECT COUNT(*) FROM drivers").fetchone()[0] == 0:
            seed_drivers(conn)
        if conn.execute("SELECT COUNT(*) FROM vehicles").fetchone()[0] == 0:
            seed_vehicles(conn)


def migrate_driver_audit_log(conn):
    """Older databases logged driver changes in audit_log; move them to activity_log."""
    if not conn.execute("SELECT 1 FROM sqlite_master WHERE name='audit_log'").fetchone():
        return
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(audit_log)")]
    user_col = "user_id" if "user_id" in cols else "NULL"
    conn.execute(
        "INSERT INTO activity_log (register, record_id, user_id, action, detail, created_at)"
        f" SELECT 'drivers', driver_id, {user_col}, action, detail, created_at"
        " FROM audit_log ORDER BY id")
    conn.execute("DROP TABLE audit_log")


def insert_record(conn, register, values, user_id, detail):
    now = _now()
    cols = list(values) + ["created_at", "updated_at"]
    cur = conn.execute(
        f"INSERT INTO {REGISTERS[register]['table']} ({','.join(cols)})"
        f" VALUES ({','.join('?' * len(cols))})", [*values.values(), now, now])
    log_activity(conn, register, cur.lastrowid, user_id, "created", detail)
    return cur.lastrowid


def log_activity(conn, register, record_id, user_id, action, detail):
    conn.execute("INSERT INTO activity_log (register, record_id, user_id, action, detail,"
                 " created_at) VALUES (?,?,?,?,?,?)",
                 (register, record_id, user_id, action, detail, _now()))


def update_record_values(conn, register, before, clean, user_id, note=""):
    """Apply validated changes to one record and log each field that changed."""
    cfg = REGISTERS[register]
    key_cols = {col for col, _ in cfg["keys"].values()}
    sets = ", ".join(f"{k}=?" for k in clean)
    conn.execute(f"UPDATE {cfg['table']} SET {sets}, updated_at=? WHERE id=?",
                 [*clean.values(), _now(), before["id"]])
    for key, value in clean.items():
        if key not in key_cols and before[key] != value:
            log_activity(conn, register, before["id"], user_id,
                         "status" if key == "status" else "edited",
                         f"{field_label(key)}: {before[key] or '—'} → {value or '—'}{note}")


def plan_import(conn, register, rows, header_row, mapping, options):
    """Work out what importing each spreadsheet row would do, without saving anything.
    Each result has an action: new, update, unchanged, skip (exists but updates are
    turned off) or error."""
    cfg = REGISTERS[register]
    key_fields = cfg["keys"]
    existing = conn.execute(f"SELECT * FROM {cfg['table']}").fetchall()
    by_id = {r["id"]: r for r in existing}
    by_key = {col: {r[col]: r["id"] for r in existing} for col, _ in key_fields.values()}
    seen_in_file = {col: {} for col, _ in key_fields.values()}
    today = dt.date.today().isoformat()
    results = []

    for line, row in enumerate(rows[header_row + 1:], start=header_row + 2):
        if not any(row):
            continue
        values, errors, warnings = importer.build_values(
            register, row, mapping, cfg["licence_types"], options.get("default_licence_type"))
        result = {"row": line, "values": values, "errors": errors, "warnings": warnings,
                  "action": "error"}
        results.append(result)
        if errors:
            continue

        keys = {col: match_key(normalise(values[field]))
                for field, (col, normalise) in key_fields.items() if values.get(field)}
        for field, (col, _) in key_fields.items():
            earlier = seen_in_file[col].get(keys.get(col))
            if earlier:
                errors.append(f"Same {field_label(field)} as row {earlier}")
        for col, key in keys.items():
            seen_in_file[col].setdefault(key, line)
        matches = {by_key[col][key] for col, key in keys.items() if key in by_key[col]}
        if len(matches) > 1:
            errors.append("Registration and plate number belong to different vehicles"
                          " already on the register")
        if errors:
            continue

        if matches:
            before = by_id[matches.pop()]
            clean, error = validate_record(register, values, partial=True)
            if error:
                errors.append(error)
                continue
            changes = {k: v for k, v in clean.items() if before[k] != v}
            result["record_id"] = before["id"]
            result["changes"] = [field_label(k) for k in changes if k in cfg["fields"] + ("status",)]
            result["clean"] = changes
            result["action"] = ("unchanged" if not changes else
                                "update" if options.get("update_existing") else "skip")
        else:
            missing = [field_label(f) for f in cfg["required"] if not values.get(f)]
            if missing:
                errors.append(f"Missing {', '.join(missing)}")
                continue
            clean, error = validate_record(register, values)
            if error:
                errors.append(error)
                continue
            clean.setdefault("status", "active")
            result["clean"] = clean
            result["action"] = "new"

        for field in cfg["expiry_fields"]:
            date = clean.get(field) or (by_id[result["record_id"]][field]
                                        if "record_id" in result else None)
            if date and date < today:
                warnings.append(f"{field_label(field).capitalize()} has passed, so it won't"
                                " show on the public register")
    return results


def seed_drivers(conn):
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
    for name, num, ltype, days, status in sample:
        insert_record(conn, "drivers", {
            "full_name": name, "licence_number": num, "licence_key": match_key(num),
            "licence_type": ltype, "status": status,
            "expiry_date": (today + dt.timedelta(days=days)).isoformat(),
        }, None, "Sample record")


def seed_vehicles(conn):
    today = dt.date.today()
    day = lambda n: (today + dt.timedelta(days=n)).isoformat()
    sample = [
        # reg, plate, make, model, colour, proprietor, type, licence days, test days, status
        ("KX21 LMR", "PHV-0412", "Toyota", "Corolla Hybrid", "Silver", "Amira Khan",
         "Private Hire", 320, 140, "active"),
        ("LT68 HCN", "HCV-0087", "LEVC", "TX", "Black", "Okafor Cabs Ltd",
         "Hackney Carriage", 200, 60, "active"),
        ("YR19 OPW", "PHV-0533", "Skoda", "Octavia", "Grey", "Northside Private Hire Ltd",
         "Private Hire", 25, 90, "active"),
        ("BD70 TZE", "PHV-0601", "Kia", "Niro EV", "White", "Grace Mensah",
         "Private Hire", 410, 12, "active"),
        ("MF17 XKA", "HCV-0102", "Peugeot", "E-7", "Black", "James Patel",
         "Hackney Carriage", 180, 75, "suspended"),
        ("GN66 UYB", "PHV-0288", "Ford", "Galaxy", "Blue", "Northside Private Hire Ltd",
         "Private Hire", 150, -8, "active"),
        ("WP65 RDE", "PHV-0199", "Toyota", "Prius+", "Silver", "Liam O'Connor",
         "Private Hire", -30, 40, "active"),
        ("SK20 FVJ", "HCV-0145", "Mercedes-Benz", "Vito Taxi", "Black", "Fatima Rahman",
         "Hackney Carriage", 260, 100, "revoked"),
    ]
    for reg, plate, make, model, colour, owner, ltype, lic, test, status in sample:
        insert_record(conn, "vehicles", {
            "registration": reg, "registration_key": match_key(reg),
            "plate_number": plate, "plate_key": match_key(plate),
            "make": make, "model": model, "colour": colour, "proprietor_name": owner,
            "licence_type": ltype, "licence_expiry": day(lic), "test_expiry": day(test),
            "status": status,
        }, None, "Sample record")


def _now():
    return dt.datetime.now().isoformat(timespec="seconds")


def record_to_dict(register, row):
    d = dict(row)
    today = dt.date.today().isoformat()
    d["expired"] = any(d[f] < today for f in REGISTERS[register]["expiry_fields"])
    return d


def user_to_dict(row):
    return {k: row[k] for k in ("id", "full_name", "email", "role", "created_at",
                                "last_login_at")} | {
        "is_active": bool(row["is_active"]),
        "must_change_password": bool(row["must_change_password"]),
    }


def validate_record(register, data, partial=False):
    """Return (clean_dict, error). With partial=True only supplied keys are checked."""
    cfg = REGISTERS[register]
    clean = {}
    for key in cfg["fields"] + ("status",):
        if key in data:
            clean[key] = str(data[key] or "").strip()
    if not partial:
        for key in cfg["required"]:
            if not clean.get(key):
                return None, f"{field_label(key).capitalize()} is required"
    for field, (key_col, normalise) in cfg["keys"].items():
        if field in clean:
            clean[field] = normalise(clean[field])
            clean[key_col] = match_key(clean[field])
            if not clean[key_col]:
                return None, f"{field_label(field).capitalize()} is required"
    if "licence_type" in clean and clean["licence_type"] not in cfg["licence_types"]:
        return None, "Invalid licence type"
    if "status" in clean and clean["status"] not in STATUSES:
        return None, "Invalid status"
    for key in cfg["expiry_fields"]:
        if key in clean:
            try:
                dt.date.fromisoformat(clean[key])
            except ValueError:
                return None, f"{field_label(key).capitalize()} must be a valid date"
    return clean, None


def validate_staff(data):
    """Return (full_name, email, role, error) for a new staff member."""
    full_name = str(data.get("full_name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    role = str(data.get("role", "officer"))
    if not full_name:
        return None, None, None, "Full name is required"
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return None, None, None, "Enter a valid email address"
    if role not in ROLES:
        return None, None, None, "Invalid role"
    return full_name, email, role, None


# ---------------------------------------------------------------- passwords

def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password, stored):
    try:
        _, iterations, salt, expected = stored.split("$")
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt),
                                     int(iterations))
    except ValueError:
        return False
    return hmac.compare_digest(digest.hex(), expected)


# Checked against when the email doesn't exist, so response time doesn't reveal it.
_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def password_problem(password):
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
    return None


def temporary_password():
    # Readable: no 0/O/1/l/I confusion when read out or copied.
    alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3))


def login_locked(email):
    cutoff = time.time() - LOCKOUT_SECONDS
    recent = [t for t in _login_failures.get(email, []) if t > cutoff]
    _login_failures[email] = recent
    return len(recent) >= MAX_LOGIN_FAILURES


# ---------------------------------------------------------------- sessions

def _token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(conn, user_id):
    token = secrets.token_urlsafe(32)
    expires = dt.datetime.now() + dt.timedelta(hours=SESSION_HOURS)
    conn.execute("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?,?,?)",
                 (_token_hash(token), user_id, expires.isoformat(timespec="seconds")))
    return token


def session_user(token):
    if not token:
        return None
    with db() as conn:
        return conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id"
            " WHERE s.token_hash = ? AND s.expires_at > ? AND u.is_active = 1",
            (_token_hash(token), _now())).fetchone()


def session_cookie(token, max_age):
    return f"session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}"


# ---------------------------------------------------------------- HTTP

REGISTER_NAMES = "|".join(REGISTERS)


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
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def read_json(self, limit=100_000):
        length = int(self.headers.get("Content-Length") or 0)
        if length > limit:
            return {}
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def session_token(self):
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        return jar["session"].value if "session" in jar else None

    @property
    def user(self):
        if not hasattr(self, "_user"):
            self._user = session_user(self.session_token())
        return self._user

    def require_staff(self, admin=False, allow_password_change=False):
        """Return True if the request may continue; otherwise send the error."""
        if not self.user:
            self.send_json({"error": "Not signed in"}, 401)
            return False
        if self.user["must_change_password"] and not allow_password_change:
            self.send_json({"error": "password_change_required"}, 403)
            return False
        if admin and self.user["role"] != "admin":
            self.send_json({"error": "Only admins can do that"}, 403)
            return False
        return True

    def staff_page(self, name, admin=False):
        if not self.user:
            return self.redirect("/setup" if no_users() else "/login")
        if self.user["must_change_password"]:
            return self.redirect("/account")
        if admin and self.user["role"] != "admin":
            return self.redirect("/admin")
        self.send_file(name)

    # -- routing
    def do_GET(self):
        url = urlparse(self.path)
        path = url.path

        if path in ("/", "/drivers", "/vehicles"):
            return self.send_file("public.html")
        if path in STATIC_ASSETS:
            return self.send_file(*STATIC_ASSETS[path])
        if path == "/login":
            return self.redirect("/setup") if no_users() else self.send_file("login.html")
        if path == "/setup":
            return self.send_file("setup.html") if no_users() else self.redirect("/login")
        if path in ("/admin", "/admin/drivers", "/admin/vehicles"):
            return self.staff_page("admin.html")
        if path == "/admin/staff":
            return self.staff_page("staff.html", admin=True)
        if re.fullmatch(rf"/admin/({REGISTER_NAMES})/import", path):
            return self.staff_page("import.html", admin=True)
        if path == "/account":
            return self.send_file("account.html") if self.user else self.redirect("/login")

        m = re.fullmatch(rf"/api/public/({REGISTER_NAMES})", path)
        if m:
            return self.public_check(m.group(1), parse_qs(url.query))
        if path == "/api/me":
            if self.require_staff(allow_password_change=True):
                self.send_json({"user": user_to_dict(self.user)})
            return
        m = re.fullmatch(rf"/api/admin/({REGISTER_NAMES})", path)
        if m:
            return self.require_staff() and self.list_records(m.group(1))
        m = re.fullmatch(rf"/api/admin/({REGISTER_NAMES})/activity", path)
        if m:
            return self.require_staff() and self.list_activity(m.group(1))
        m = re.fullmatch(rf"/api/admin/({REGISTER_NAMES})/import/template", path)
        if m:
            return self.require_staff(admin=True) and self.import_template(m.group(1))
        if path == "/api/admin/staff":
            return self.require_staff(admin=True) and self.list_staff()
        self.send_error(404)

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/setup":
            return self.first_run_setup()
        if path == "/api/login":
            return self.login()
        if path == "/api/logout":
            return self.logout()
        if path == "/api/account/password":
            return self.require_staff(allow_password_change=True) and self.change_password()
        m = re.fullmatch(rf"/api/admin/({REGISTER_NAMES})", path)
        if m:
            return self.require_staff() and self.create_record(m.group(1))
        m = re.fullmatch(rf"/api/admin/({REGISTER_NAMES})/import/(preview|commit)", path)
        if m:
            return self.require_staff(admin=True) and self.run_import(
                m.group(1), commit=m.group(2) == "commit")
        if path == "/api/admin/staff":
            return self.require_staff(admin=True) and self.create_staff()
        m = re.fullmatch(r"/api/admin/staff/(\d+)/reset-password", path)
        if m:
            return self.require_staff(admin=True) and self.reset_staff_password(int(m.group(1)))
        self.send_error(404)

    def do_PATCH(self):
        path = urlparse(self.path).path
        m = re.fullmatch(rf"/api/admin/({REGISTER_NAMES})/(\d+)", path)
        if m:
            return self.require_staff() and self.update_record(m.group(1), int(m.group(2)))
        m = re.fullmatch(r"/api/admin/staff/(\d+)", path)
        if m:
            return self.require_staff(admin=True) and self.update_staff(int(m.group(1)))
        self.send_error(404)

    # -- public
    def public_check(self, register, query):
        """Only active, in-date records are ever returned. Suspended, revoked and
        expired ones look identical to 'not found' so nothing leaks."""
        cfg = REGISTERS[register]
        entered = str((query.get("q") or [""])[0]).strip()[:40]
        key = match_key(entered)
        if not key:
            return self.send_json({"error": "Enter a number to check"}, 400)
        today = dt.date.today().isoformat()
        lookup = " OR ".join(f"{col} = ?" for col, _ in cfg["keys"].values())
        in_date = " AND ".join(f"{f} >= ?" for f in cfg["expiry_fields"])
        with db() as conn:
            row = conn.execute(
                f"SELECT {', '.join(cfg['public_fields'])} FROM {cfg['table']}"
                f" WHERE ({lookup}) AND status = 'active' AND {in_date}",
                [key] * len(cfg["keys"]) + [today] * len(cfg["expiry_fields"])).fetchone()
        if row:
            return self.send_json({"licensed": True, "record": dict(row), "checked_at": _now()})
        self.send_json({"licensed": False, "entered": entered.upper(), "checked_at": _now()})

    # -- auth
    def first_run_setup(self):
        """Create the first admin. Only possible while there are no staff accounts."""
        data = self.read_json()
        full_name, email, _, error = validate_staff(data)
        password = str(data.get("password", ""))
        error = error or password_problem(password)
        if error:
            return self.send_json({"error": error}, 400)
        with _db_lock, db() as conn:
            if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
                return self.send_json({"error": "Setup has already been completed"}, 409)
            now = _now()
            cur = conn.execute(
                "INSERT INTO users (full_name, email, password_hash, role, created_at,"
                " last_login_at) VALUES (?,?,?,?,?,?)",
                (full_name, email, hash_password(password), "admin", now, now))
            conn.execute("INSERT INTO staff_log (actor_id, target_user_id, detail, created_at)"
                         " VALUES (?,?,?,?)", (cur.lastrowid, cur.lastrowid,
                                               "Created first admin account", now))
            token = create_session(conn, cur.lastrowid)
        self.send_json({"ok": True}, 201,
                       {"Set-Cookie": session_cookie(token, SESSION_HOURS * 3600)})

    def login(self):
        data = self.read_json()
        email = str(data.get("email", "")).strip().lower()
        password = str(data.get("password", ""))
        if login_locked(email):
            return self.send_json({"error": "Too many failed attempts. Try again in 15 minutes."},
                                  429)
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        ok = verify_password(password, user["password_hash"] if user else _DUMMY_HASH)
        if not (user and ok and user["is_active"]):
            _login_failures.setdefault(email, []).append(time.time())
            return self.send_json({"error": "Incorrect email or password"}, 401)
        _login_failures.pop(email, None)
        with _db_lock, db() as conn:
            conn.execute("UPDATE users SET last_login_at=? WHERE id=?", (_now(), user["id"]))
            token = create_session(conn, user["id"])
        self.send_json({"ok": True, "must_change_password": bool(user["must_change_password"])},
                       extra_headers={"Set-Cookie": session_cookie(token, SESSION_HOURS * 3600)})

    def logout(self):
        token = self.session_token()
        if token:
            with _db_lock, db() as conn:
                conn.execute("DELETE FROM sessions WHERE token_hash=?", (_token_hash(token),))
        self.send_json({"ok": True}, extra_headers={"Set-Cookie": session_cookie("", 0)})

    def change_password(self):
        data = self.read_json()
        current = str(data.get("current_password", ""))
        new = str(data.get("new_password", ""))
        if not verify_password(current, self.user["password_hash"]):
            return self.send_json({"error": "Current password is incorrect"}, 400)
        error = password_problem(new)
        if not error and new == current:
            error = "New password must be different from the current one"
        if error:
            return self.send_json({"error": error}, 400)
        with _db_lock, db() as conn:
            conn.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?",
                         (hash_password(new), self.user["id"]))
            # Sign out every other device that was using the old password.
            conn.execute("DELETE FROM sessions WHERE user_id=? AND token_hash<>?",
                         (self.user["id"], _token_hash(self.session_token())))
            conn.execute("INSERT INTO staff_log (actor_id, target_user_id, detail, created_at)"
                         " VALUES (?,?,?,?)",
                         (self.user["id"], self.user["id"], "Changed own password", _now()))
        self.send_json({"ok": True})

    # -- registers (drivers and vehicles)
    def list_records(self, register):
        cfg = REGISTERS[register]
        with db() as conn:
            rows = conn.execute(
                f"SELECT * FROM {cfg['table']} ORDER BY {cfg['order_by']}").fetchall()
        self.send_json({"records": [record_to_dict(register, r) for r in rows],
                        "statuses": STATUSES, "licence_types": cfg["licence_types"]})

    def list_activity(self, register):
        cfg = REGISTERS[register]
        with db() as conn:
            rows = conn.execute(
                f"SELECT a.detail, a.created_at, {cfg['label_sql']} AS label,"
                f" {cfg['sub_sql']} AS sub, u.full_name AS staff_name"
                f" FROM activity_log a JOIN {cfg['table']} e ON e.id = a.record_id"
                " LEFT JOIN users u ON u.id = a.user_id"
                " WHERE a.register = ? ORDER BY a.id DESC LIMIT 50", (register,)).fetchall()
        self.send_json({"entries": [dict(r) for r in rows]})

    def create_record(self, register):
        cfg = REGISTERS[register]
        clean, error = validate_record(register, self.read_json())
        if error:
            return self.send_json({"error": error}, 400)
        clean.setdefault("status", "active")
        try:
            with _db_lock, db() as conn:
                record_id = insert_record(conn, register, clean, self.user["id"],
                                          f"Added as {clean['status']}")
                row = conn.execute(f"SELECT * FROM {cfg['table']} WHERE id=?",
                                   (record_id,)).fetchone()
        except sqlite3.IntegrityError:
            return self.send_json({"error": cfg["duplicate_error"]}, 409)
        self.send_json({"record": record_to_dict(register, row)}, 201)

    def update_record(self, register, record_id):
        cfg = REGISTERS[register]
        clean, error = validate_record(register, self.read_json(), partial=True)
        if error:
            return self.send_json({"error": error}, 400)
        if not clean:
            return self.send_json({"error": "Nothing to update"}, 400)
        try:
            with _db_lock, db() as conn:
                before = conn.execute(f"SELECT * FROM {cfg['table']} WHERE id=?",
                                      (record_id,)).fetchone()
                if not before:
                    return self.send_json({"error": "Record not found"}, 404)
                update_record_values(conn, register, before, clean, self.user["id"])
                row = conn.execute(f"SELECT * FROM {cfg['table']} WHERE id=?",
                                   (record_id,)).fetchone()
        except sqlite3.IntegrityError:
            return self.send_json({"error": cfg["duplicate_error"]}, 409)
        self.send_json({"record": record_to_dict(register, row)})

    # -- spreadsheet import (admin only)
    def import_template(self, register):
        body = importer.template_csv(register).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition",
                         f'attachment; filename="{register}-import-template.csv"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def run_import(self, register, commit):
        if int(self.headers.get("Content-Length") or 0) > importer.MAX_BYTES + 100_000:
            return self.send_json({"error": "That file is too large (5 MB maximum)"}, 413)
        data = self.read_json(limit=importer.MAX_BYTES + 100_000)
        rows = importer.read_rows(str(data.get("csv", "")))
        if sum(1 for r in rows if any(r)) < 2:
            return self.send_json({"error": "The file doesn't have any rows to import"}, 400)
        if len(rows) > importer.MAX_ROWS + 20:
            return self.send_json({"error": f"Import up to {importer.MAX_ROWS} rows at a time."
                                            " Split the file and import each part."}, 400)

        header_row = importer.find_header_row(rows, register)
        headers = rows[header_row]
        fields = {f for f, _, _ in importer.IMPORT_FIELDS[register]}
        if isinstance(data.get("mapping"), dict):
            mapping = {f: int(i) for f, i in data["mapping"].items()
                       if f in fields and isinstance(i, int) and 0 <= i < len(headers)}
        else:
            mapping = importer.auto_map(headers, register)
        options = data.get("options") if isinstance(data.get("options"), dict) else {}

        with _db_lock, db() as conn:
            results = plan_import(conn, register, rows, header_row, mapping, options)
            counts = {a: sum(r["action"] == a for r in results)
                      for a in ("new", "update", "unchanged", "skip", "error")}
            if commit:
                filename = str(data.get("filename") or "spreadsheet")[:80]
                for r in results:
                    if r["action"] == "new":
                        insert_record(conn, register, r["clean"], self.user["id"],
                                      f"Imported from {filename}")
                    elif r["action"] == "update":
                        before = conn.execute(f"SELECT * FROM {REGISTERS[register]['table']}"
                                              " WHERE id=?", (r["record_id"],)).fetchone()
                        update_record_values(conn, register, before, r["clean"],
                                             self.user["id"], " (import)")

        failed = [r for r in results if r["action"] == "error"]
        payload = {
            "counts": counts,
            "header_row": header_row + 1,
            "headers": headers,
            "sample": next((r for r in rows[header_row + 1:] if any(r)), []),
            "mapping": mapping,
            "fields": [[f, label] for f, label, _ in importer.IMPORT_FIELDS[register]],
            "licence_types": REGISTERS[register]["licence_types"],
            "rows": [{k: v for k, v in r.items() if k != "clean"} for r in results],
        }
        if commit:
            payload["failed_csv"] = failed_rows_csv(rows, header_row, failed)
        self.send_json(payload)

    # -- staff (admin only)
    def log_staff(self, conn, target_id, detail):
        conn.execute("INSERT INTO staff_log (actor_id, target_user_id, detail, created_at)"
                     " VALUES (?,?,?,?)", (self.user["id"], target_id, detail, _now()))

    def list_staff(self):
        with db() as conn:
            users = conn.execute("SELECT * FROM users ORDER BY is_active DESC, full_name").fetchall()
            log = conn.execute(
                "SELECT l.detail, l.created_at, a.full_name AS actor_name,"
                " t.full_name AS target_name FROM staff_log l"
                " LEFT JOIN users a ON a.id = l.actor_id JOIN users t ON t.id = l.target_user_id"
                " ORDER BY l.id DESC LIMIT 50").fetchall()
        self.send_json({"users": [user_to_dict(u) for u in users], "roles": ROLES,
                        "log": [dict(r) for r in log], "me": self.user["id"]})

    def create_staff(self):
        full_name, email, role, error = validate_staff(self.read_json())
        if error:
            return self.send_json({"error": error}, 400)
        password = temporary_password()
        try:
            with _db_lock, db() as conn:
                cur = conn.execute(
                    "INSERT INTO users (full_name, email, password_hash, role,"
                    " must_change_password, created_at) VALUES (?,?,?,?,1,?)",
                    (full_name, email, hash_password(password), role, _now()))
                self.log_staff(conn, cur.lastrowid, f"Added as {role}")
                row = conn.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
        except sqlite3.IntegrityError:
            return self.send_json({"error": "A staff member with that email already exists"}, 409)
        self.send_json({"user": user_to_dict(row), "temporary_password": password}, 201)

    def update_staff(self, user_id):
        data = self.read_json()
        changes = {}
        if "role" in data:
            if data["role"] not in ROLES:
                return self.send_json({"error": "Invalid role"}, 400)
            changes["role"] = data["role"]
        if "is_active" in data:
            changes["is_active"] = 1 if data["is_active"] else 0
        if not changes:
            return self.send_json({"error": "Nothing to update"}, 400)
        if user_id == self.user["id"]:
            return self.send_json({"error": "You can't change your own role or access"}, 400)
        with _db_lock, db() as conn:
            before = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            if not before:
                return self.send_json({"error": "Staff member not found"}, 404)
            sets = ", ".join(f"{k}=?" for k in changes)
            conn.execute(f"UPDATE users SET {sets} WHERE id=?", [*changes.values(), user_id])
            if not conn.execute("SELECT 1 FROM users WHERE role='admin' AND is_active=1").fetchone():
                conn.rollback()
                return self.send_json({"error": "There must be at least one active admin"}, 400)
            if changes.get("role", before["role"]) != before["role"]:
                self.log_staff(conn, user_id, f"Role: {before['role']} → {changes['role']}")
            if changes.get("is_active", before["is_active"]) != before["is_active"]:
                self.log_staff(conn, user_id, "Reactivated" if changes["is_active"]
                               else "Deactivated")
                if not changes["is_active"]:
                    conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
            row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        self.send_json({"user": user_to_dict(row)})

    def reset_staff_password(self, user_id):
        if user_id == self.user["id"]:
            return self.send_json({"error": "Use 'Change password' for your own account"}, 400)
        password = temporary_password()
        with _db_lock, db() as conn:
            cur = conn.execute("UPDATE users SET password_hash=?, must_change_password=1"
                               " WHERE id=?", (hash_password(password), user_id))
            if not cur.rowcount:
                return self.send_json({"error": "Staff member not found"}, 404)
            conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
            self.log_staff(conn, user_id, "Password reset")
            email = conn.execute("SELECT email FROM users WHERE id=?", (user_id,)).fetchone()[0]
        _login_failures.pop(email, None)  # a reset also lifts any sign-in lockout
        self.send_json({"temporary_password": password})

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {fmt % args}")


def failed_rows_csv(rows, header_row, failed):
    """The rows that couldn't be imported, with the reason, ready to fix and re-import."""
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(rows[header_row] + ["Import problem"])
    for r in failed:
        writer.writerow(rows[r["row"] - 1] + ["; ".join(r["errors"])])
    return out.getvalue()


def no_users():
    with db() as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


if __name__ == "__main__":
    init_db()
    print(f"Public registers: http://localhost:{PORT}/")
    print(f"Staff dashboard:  http://localhost:{PORT}/admin")
    if no_users():
        print(f"First run: create the first admin account at http://localhost:{PORT}/setup")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
