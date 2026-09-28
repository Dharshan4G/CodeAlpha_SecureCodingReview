# CodeAlpha — Task 3: Secure Coding Review

A hands-on secure code review of a deliberately vulnerable Python/Flask web app ("SecureNotes"),
using manual inspection, the **Bandit** static analyser, and **live exploit verification**.

## What's inside
```
vulnerable_app/app.py   the target: 10 real vulnerabilities, each tagged [V1]..[V10]
fixed_app/app.py        the remediated version, each fix tagged [F1]..[F10]
reports/SECURITY_REVIEW.md   the full findings report (read this)
reports/bandit_vulnerable.txt / bandit_fixed.txt   raw static-analysis output
```

## Findings at a glance
| ID | Vulnerability | CWE | Severity |
|----|---------------|-----|----------|
| V1 | Hard-coded secret key | 798 | Medium |
| V2 | Weak MD5 password hashing | 916 | High |
| V3 | SQL injection (auth bypass) | 89 | High |
| V4 | Insecure deserialisation (pickle cookie) | 502 | High |
| V5 | Stored + reflected XSS | 79 | High |
| V6 | Broken access control (IDOR) | 639 | High |
| V7 | Server-side template injection | 1336 | High |
| V8 | OS command injection | 78 | High |
| V9 | Path traversal | 22 | Medium |
| V10| Debug mode + bind to 0.0.0.0 | 489 | Medium |

Command injection, SSTI, XSS, path traversal and SQLi auth-bypass were all confirmed with live payloads,
then shown to be blocked in the fixed version. Bandit drops from **5 High / 4 Medium** to **0 / 0**.

## Reproduce it
```bash
pip install -r requirements.txt

# static analysis
bandit -r vulnerable_app          # lots of findings
bandit -r fixed_app               # clean

# run the vulnerable app (LOCAL ONLY, never expose it)
cd vulnerable_app && python3 app.py
# example exploit, in another terminal:
curl "http://127.0.0.1:5000/admin/ping?host=127.0.0.1;%20id"    # returns uid=0(root)

# run the fixed app
cd ../fixed_app
SECRET_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))") ADMIN_PASSWORD='ChangeThisLongPassword!' python3 app.py
```

> The vulnerable app exists only to be studied. Do not deploy it or run it on a public network.
