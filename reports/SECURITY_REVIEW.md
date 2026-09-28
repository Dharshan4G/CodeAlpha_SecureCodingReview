# Secure Coding Review — SecureNotes (Python / Flask)

**Auditor:** CodeAlpha Cyber Security Intern
**Target:** `vulnerable_app/app.py`, a small Flask note-taking web application
**Method:** manual code review + automated static analysis with [Bandit](https://bandit.readthedocs.io), then live exploit verification
**Result:** 10 findings (5 High, 4 Medium, 1 Low). All are fixed in `fixed_app/app.py`.

---

## How the review was done

1. **Manual inspection.** Read the code route by route, tracing where untrusted input (`request.form`, `request.args`, `request.cookies`) reaches a dangerous "sink" such as an SQL query, the shell, the filesystem or a template.
2. **Static analysis.** Ran `bandit -r vulnerable_app`, which flags known-dangerous Python patterns automatically.
3. **Dynamic verification.** Started each app and fired real payloads to confirm the flaws are exploitable, not theoretical (see `exploit_test` output below).
4. **Remediation.** Rewrote each flaw the secure way and re-ran the same payloads to prove they are blocked.

### Bandit summary

| Version | High | Medium | Low |
|---|---|---|---|
| `vulnerable_app` | 5 | 4 | 3 |
| `fixed_app` | 0 | 0 | 3 (subprocess-usage notices only, suppressed with justification) |

Bandit output is saved in `reports/bandit_vulnerable.txt` and `reports/bandit_fixed.txt`.

### Live exploit proof (excerpt)

```
[VULNERABLE APP]
 V8 OS command injection  -> PWNED: uid=0(root) gid=0(root) groups=0(root)
 V9 path traversal        -> PWNED: leaked source, secret_key line present
 V7 template injection    -> PWNED: {{7*7}} rendered as 49
 V5 reflected XSS         -> PWNED: <script> reflected unescaped
 V3 SQL injection         -> PWNED: admin'-- returns row (1,1) => admin login, no password

[FIXED APP — identical payloads]
 V8 -> BLOCKED (HTTP 404 / invalid IP)
 V9 -> BLOCKED (HTTP 404)
 V7 -> BLOCKED (rendered literally)
 V5 -> BLOCKED (escaped)
 V3 -> BLOCKED (HTTP 401)
```

---

## Findings

Severity uses an informal CVSS-style High/Medium/Low. CWE is the industry vulnerability catalogue.

### [V1] Hard-coded secret key — Medium (CWE-798)
`app.secret_key = "supersecret123"` is committed to source. Anyone who reads the repo can forge session cookies and impersonate any user.
**Fix [F1]:** load the key from `os.environ["SECRET_KEY"]`; fall back to a random key for local dev only.

### [V2] Weak password storage — High (CWE-916 / CWE-521)
Passwords are hashed with a single round of unsalted **MD5**. MD5 is fast and broken, so a leaked database can be cracked almost instantly with rainbow tables. There is also no password-strength policy.
**Fix [F2]:** use `werkzeug.security.generate_password_hash` (PBKDF2, salted, many rounds) and enforce a minimum length. Argon2 or bcrypt are equally good choices.

### [V3] SQL injection — High (CWE-89)
The login and register queries build SQL by string formatting:
```python
query = "SELECT id, is_admin FROM users WHERE username='%s' AND password='%s'" % (u, pw)
```
The payload `username = admin'--` turns the query into
`... WHERE username='admin'--' AND password='...'`, commenting out the password check and logging the attacker in as admin. Verified: the query returns `(1, 1)`.
**Fix [F3]:** use parameterised queries (`execute(sql, (u,))`). The database driver then treats input as data, never as code.

### [V4] Insecure deserialisation — High (CWE-502)
User preferences are stored in a cookie as a base64-encoded **pickle**. On every `/notes` request the server calls `pickle.loads()` on attacker-controlled bytes. A crafted pickle can execute arbitrary code on the server.
**Fix [F4]:** never unpickle untrusted data. Store preferences in Flask's signed session (JSON, tamper-evident) instead.

### [V5] Cross-site scripting (XSS) — High (CWE-79)
Note bodies are concatenated straight into an HTML string, and login errors reflect the raw username. A note containing `<script>…</script>` runs in every viewer's browser (stored XSS); the search page reflects input unescaped (reflected XSS).
**Fix [F5]:** render through Jinja2 templates, which auto-escape `{{ variable }}`. Add a `Content-Security-Policy` header as defence in depth.

### [V6] Broken access control / IDOR — High (CWE-639)
`/note/<id>` fetches any note by id with no ownership check, so user A can read user B's notes by changing the number in the URL.
**Fix [F6]:** scope the query to the current user: `WHERE id=? AND owner=?`, and return 404 when there is no match.

### [V7] Server-side template injection — High (CWE-1336)
`/search` builds the template with `render_template_string("<h2>Results for " + q + "</h2>")`, so `q={{7*7}}` renders as `49`. This escalates to remote code execution via Jinja2 object traversal.
**Fix [F7]:** keep the template static and pass user input as a variable: `render_template_string("<h2>Results for {{ q }}</h2>", q=q)`.

### [V8] OS command injection — High (CWE-78)
`/admin/ping` runs `subprocess.check_output("ping -c 1 " + host, shell=True)`. The payload `host=127.0.0.1; id` executed `id` and returned `uid=0(root)`, full command execution.
**Fix [F8]:** validate that `host` is a real IP with `ipaddress`, then call `subprocess.run([ping, "-c", "1", ip])` with an argument list and **no shell**, so shell metacharacters can't be interpreted. The route is also now admin-only.

### [V9] Path traversal — Medium (CWE-22)
`/download?file=` joins user input onto the uploads path with no checks, so `?file=../app.py` leaks the application source (including the secret key), and `../../etc/passwd` leaks system files.
**Fix [F9]:** sanitise with `secure_filename()` and serve via `send_from_directory(UPLOAD_DIR, name)`, which refuses to escape the directory.

### [V10] Debug mode + bind to all interfaces — Medium (CWE-489 / CWE-215)
`app.run(host="0.0.0.0", debug=True)` exposes the Werkzeug debugger (an interactive Python console) to the whole network.
**Fix [F10]:** `debug=False`, bind to `127.0.0.1` for local runs, and serve behind a production WSGI server (gunicorn/uWSGI) with HTTPS.

### Additional hardening added in the fixed version
- **CSRF protection** on state-changing POST requests (SameSite cookie + per-session token). *(CWE-352)*
- **Security headers**: `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`.
- **Secure cookie flags**: `HttpOnly`, `SameSite`, and `Secure` in production.
- **`session.clear()` on login** to prevent session fixation.
- **Request size limit** to blunt basic denial-of-service.

---

## Secure coding checklist (takeaways)

- Never build SQL, shell commands or HTML by string concatenation. Use parameterised queries, argument lists and auto-escaping templates.
- Treat every value from the client as hostile: validate type, length and format on the server.
- Store passwords with a slow, salted hash (bcrypt, Argon2, PBKDF2). Never MD5 or SHA-1.
- Never deserialise untrusted data with `pickle`, `yaml.load`, etc.
- Check authorisation on every request, not just authentication.
- Keep secrets in environment variables, never in source control.
- Disable debug mode in anything reachable by others; ship security headers and HTTPS.
- Run a static analyser (Bandit, Semgrep) in CI so regressions are caught automatically.
