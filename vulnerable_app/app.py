"""
SecureNotes (VULNERABLE VERSION)
================================
A small note-taking web app used as the target of a secure code review.
It contains deliberate security flaws for educational purposes.
DO NOT deploy this code. Run it only locally for testing.
"""
import hashlib
import os
import pickle
import base64
import sqlite3
import subprocess

from flask import Flask, request, session, redirect, render_template_string, send_file

app = Flask(__name__)
app.secret_key = "supersecret123"                     # [V1] hard-coded secret
DB = "notes.db"
UPLOAD_DIR = "uploads"


def db():
    return sqlite3.connect(DB)


def init_db():
    con = db()
    con.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE,
                                         password TEXT, is_admin INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, owner INTEGER, body TEXT);
    """)
    # [V2] weak, unsalted MD5 password hashing
    pw = hashlib.md5(b"admin123").hexdigest()
    con.execute("INSERT OR IGNORE INTO users(username,password,is_admin) VALUES('admin',?,1)", (pw,))
    con.commit()
    con.close()
    os.makedirs(UPLOAD_DIR, exist_ok=True)


@app.route("/register", methods=["POST"])
def register():
    u, p = request.form["username"], request.form["password"]
    pw = hashlib.md5(p.encode()).hexdigest()           # [V2] weak hashing, no password policy
    con = db()
    con.execute(f"INSERT INTO users(username,password) VALUES('{u}','{pw}')")  # [V3] SQLi
    con.commit()
    return "Registered"


@app.route("/login", methods=["POST"])
def login():
    u = request.form["username"]
    pw = hashlib.md5(request.form["password"].encode()).hexdigest()
    query = "SELECT id, is_admin FROM users WHERE username='%s' AND password='%s'" % (u, pw)
    row = db().execute(query).fetchone()               # [V3] SQL injection
    if row:
        session["uid"], session["admin"] = row
        # [V4] insecure deserialisation: preferences stored as a pickled cookie
        resp = redirect("/notes")
        resp.set_cookie("prefs", base64.b64encode(pickle.dumps({"theme": "light"})).decode())
        return resp
    return "Invalid credentials for " + u, 401          # [V5] reflected XSS (text/html)


@app.route("/notes")
def notes():
    prefs = pickle.loads(base64.b64decode(request.cookies.get("prefs", "")))  # [V4]
    rows = db().execute("SELECT id, body FROM notes WHERE owner=?", (session.get("uid"),)).fetchall()
    html = f"<h1>Your notes ({prefs.get('theme')})</h1>"
    for nid, body in rows:
        html += f"<p><a href='/note/{nid}'>#{nid}</a> {body}</p>"   # [V5] stored XSS
    return html


@app.route("/note/<int:nid>")
def view_note(nid):
    # [V6] IDOR: no check that the note belongs to the logged-in user
    row = db().execute("SELECT body FROM notes WHERE id=?", (nid,)).fetchone()
    return row[0] if row else ("Not found", 404)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # [V7] server-side template injection: user input becomes part of the template
    return render_template_string("<h2>Results for " + q + "</h2>")


@app.route("/admin/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # [V8] OS command injection
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    return "<pre>" + out.decode() + "</pre>"


@app.route("/download")
def download():
    name = request.args.get("file")
    # [V9] path traversal: ?file=../../etc/passwd
    return send_file(os.path.join(UPLOAD_DIR, name))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", debug=True)                # [V10] debug mode exposed on all interfaces
