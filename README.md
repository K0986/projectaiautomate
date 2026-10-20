# Still - Python Login Project

A Flask starter with registration, sign-in, a protected account page, and POST-only sign-out. Uses SQLite, Werkzeug scrypt password hashes, Flask-WTF CSRF protection, parameterized queries, and one-hour cookie sessions.

## Run on Windows

Requires Python 3.10 or newer. From this folder in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Open http://127.0.0.1:5000 and choose **Create an account**. Usernames are case-insensitive, 3-32 letters, numbers, or underscores. Passwords must have 12-128 characters. No default account is provided.

If port 5000 is busy, set `$env:PORT = '5001'` before starting.

## Test

```powershell
.\.venv\Scripts\python.exe -m unittest -v
```

Tests use a temporary database and keep CSRF protection enabled.

## Project Layout

- `app.py`: app factory, forms, database setup, and authentication routes.
- `templates/`: sign-in, registration, account, and error pages.
- `static/style.css`: responsive styles.
- `test_app.py`: authentication and security regression tests.
- `instance/`: automatically generated local database and session-signing secret; excluded from Git.

The optional mountain photograph is loaded from Unsplash and requires an internet connection. Authentication works without it.

## Deployment Boundaries

This is a local development starter, not a complete production identity system. Before exposing it publicly, add shared-store login and registration rate limits, account recovery, monitoring, and HTTPS behind a production WSGI server. Set a strong `SECRET_KEY` environment variable through your deployment's secret manager and `COOKIE_SECURE=1` under HTTPS. Do not enable secure cookies for local HTTP.

Keep the generated instance folder private and back up the database securely. Cookie sessions are signed, not encrypted; this app stores only the user ID and session metadata in them. Logout clears the current browser's cookie but cannot revoke a stolen cookie server-side; production revocation requires server-side session management. No password reset, email verification, or MFA is included.