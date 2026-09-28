"""
SecureNotes (FIXED VERSION)
===========================
Remediated version of vulnerable_app/app.py. Each fix is tagged with the
finding ID from reports/SECURITY_REVIEW.md, e.g. [F3] fixes [V3].
"""
import ipaddress
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
from functools import wraps

from flask import (Flask, abort, redirect, render_template_string, request,
                   send_from_directory, session)
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

# [F1] secret comes from the environment, never from source code
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,      # JavaScript cannot read the session cookie
    SESSION_COOKIE_SAMESITE="Lax",     # basic CSRF protection
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)
DB = "notes.db"
UPLOAD_DIR = os.path.abspath("uploads")
PING_BIN = shutil.which("ping") or "/bin/ping"   # absolute path, avoids PATH hijacking
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def db():
    return sqlite3.connect(DB)


def init_db():
    con = db()
    con.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE,
                                         password TEXT, is_admin INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, owner INTEGER, body TEXT);
    """)
    admin_pw = os.environ.get("ADMIN_PASSWORD")
    if admin_pw:                        # [F2] no default admin password in the code
        con.execute("INSERT OR IGNORE INTO users(username,password,is_admin) VALUES(?,?,1)",
                    ("admin", generate_password_hash(admin_pw)))
    con.commit()
    con.close()
    os.makedirs(UPLOAD_DIR, exist_ok=True)


# ---------- helpers ----------
def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if "uid" not in session:
            return redirect("/")
        return f(*a, **kw)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("admin"):
            abort(403)
        return f(*a, **kw)
    return login_required(wrapper)


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


@app.before_request
def check_csrf():
    if request.method == "POST" and request.endpoint not in ("login", "register"):
        if not secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", "")):
            abort(400, "CSRF token missing or invalid")


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


# ---------- routes ----------
@app.route("/register", methods=["POST"])
def register():
    u, p = request.form.get("username", ""), request.form.get("password", "")
    if not USERNAME_RE.fullmatch(u) or len(p) < 12:          # [F2] input + password policy
        abort(400, "Username must be 3-32 safe characters and password at least 12 characters")
    con = db()
    try:
        # [F2] salted, slow hash    [F3] parameterised query
        con.execute("INSERT INTO users(username,password) VALUES(?,?)",
                    (u, generate_password_hash(p)))
        con.commit()
    except sqlite3.IntegrityError:
        abort(409, "Username taken")
    return "Registered"


@app.route("/login", methods=["POST"])
def login():
    u, p = request.form.get("username", ""), request.form.get("password", "")
    row = db().execute("SELECT id, is_admin, password FROM users WHERE username=?",
                       (u,)).fetchone()                        # [F3]
    if row and check_password_hash(row[2], p):
        session.clear()                                        # prevent session fixation
        session["uid"], session["admin"] = row[0], bool(row[1])
        session["prefs"] = {"theme": "light"}                  # [F4] signed JSON session, no pickle
        return redirect("/notes")
    return "Invalid username or password", 401                 # [F5] no reflected input


NOTES_TMPL = """
<h1>Your notes ({{ theme }})</h1>
{% for nid, body in rows %}<p><a href="/note/{{ nid }}">#{{ nid }}</a> {{ body }}</p>{% endfor %}
<form method="post" action="/notes"><input name="body"><input type="hidden" name="csrf" value="{{ csrf }}">
<button>Add note</button></form>
"""


@app.route("/notes", methods=["GET", "POST"])
@login_required
def notes():
    con = db()
    if request.method == "POST":
        body = request.form.get("body", "")[:5000]
        con.execute("INSERT INTO notes(owner, body) VALUES(?,?)", (session["uid"], body))
        con.commit()
    rows = con.execute("SELECT id, body FROM notes WHERE owner=?", (session["uid"],)).fetchall()
    # [F5] Jinja2 auto-escapes {{ body }}, so stored XSS payloads render as harmless text
    return render_template_string(NOTES_TMPL, rows=rows, csrf=csrf_token(),
                                  theme=session.get("prefs", {}).get("theme", "light"))


@app.route("/note/<int:nid>")
@login_required
def view_note(nid):
    # [F6] enforce ownership in the query itself
    row = db().execute("SELECT body FROM notes WHERE id=? AND owner=?",
                       (nid, session["uid"])).fetchone()
    if not row:
        abort(404)                                  # 404 rather than 403, to avoid revealing that the note exists
    return render_template_string("<p>{{ body }}</p>", body=row[0])


@app.route("/search")
@login_required
def search():
    q = request.args.get("q", "")
    # [F7] user input is passed as data, never concatenated into the template
    return render_template_string("<h2>Results for {{ q }}</h2>", q=q)


@app.route("/admin/ping")
@admin_required
def ping():
    host = request.args.get("host", "127.0.0.1")
    try:
        ip = str(ipaddress.ip_address(host))        # [F8] allow only a valid IP address
    except ValueError:
        abort(400, "Invalid IP address")
    # [F8] argument list with no shell, so metacharacters are never interpreted
    result = subprocess.run(  # nosec B603 - fixed binary, validated IP, no shell
        [PING_BIN, "-c", "1", ip], capture_output=True, text=True, timeout=5)
    return "<pre>" + str(escape(result.stdout)) + "</pre>"


@app.route("/download")
@login_required
def download():
    name = secure_filename(request.args.get("file", ""))   # [F9] strips ../ and slashes
    if not name:
        abort(400)
    return send_from_directory(UPLOAD_DIR, name, as_attachment=True)  # [F9] confined to UPLOAD_DIR


if __name__ == "__main__":
    init_db()
    # [F10] debug off and bound to localhost; use a WSGI server (gunicorn) behind HTTPS in production
    app.run(host="127.0.0.1", debug=False)
