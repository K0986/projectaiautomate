from html.parser import HTMLParser
from pathlib import Path
import sqlite3
import tempfile
import unittest

from werkzeug.security import check_password_hash

from app import create_app


class TokenParser(HTMLParser):
    token = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "input" and attributes.get("name") == "csrf_token":
            self.token = attributes["value"]


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.database = str(Path(self.directory.name) / "test.sqlite3")
        self.app = create_app({"TESTING": True, "SECRET_KEY": "test-only-secret",
                               "DATABASE": self.database})
        self.client = self.app.test_client()

    def submit(self, path, **data):
        parser = TokenParser()
        parser.feed(self.client.get(path).get_data(as_text=True))
        self.assertIsNotNone(parser.token)
        return self.client.post(path, data={"csrf_token": parser.token, **data},
                                follow_redirects=True)

    def register(self, username="alice"):
        return self.submit("/register", username=username, password="a-long-test-password")

    def test_account_is_protected(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/login"))

    def test_registration_hashes_password(self):
        self.assertIn(b"Account created", self.register().data)
        database = sqlite3.connect(self.database)
        self.addCleanup(database.close)
        stored = database.execute("SELECT password_hash FROM users").fetchone()[0]
        self.assertNotEqual(stored, "a-long-test-password")
        self.assertTrue(check_password_hash(stored, "a-long-test-password"))

    def test_login_and_logout(self):
        self.register()
        response = self.submit("/login", username="ALICE", password="a-long-test-password")
        self.assertIn(b"Welcome home", response.data)
        parser = TokenParser()
        parser.feed(response.get_data(as_text=True))
        response = self.client.post("/logout", data={"csrf_token": parser.token},
                                    follow_redirects=True)
        self.assertIn(b"You have signed out", response.data)
        self.assertEqual(self.client.get("/").status_code, 302)

    def test_wrong_password_and_unknown_user(self):
        self.register()
        for username in ("alice", "unknown", "' OR 1=1 --"):
            response = self.submit("/login", username=username, password="wrong-password")
            self.assertIn(b"Incorrect username or password", response.data)
            self.assertEqual(self.client.get("/").status_code, 302)

    def test_duplicate_username_is_case_insensitive(self):
        self.register()
        self.assertIn(b"already taken", self.register("ALICE").data)

    def test_registration_validation(self):
        response = self.submit("/register", username="<script>", password="short")
        self.assertIn(b"letters, numbers, and underscores", response.data)
        self.assertIn(b"between 12 and 128", response.data)

    def test_csrf_and_logout_method(self):
        for path in ("/register", "/login", "/logout"):
            self.assertEqual(self.client.post(path, data={}).status_code, 400)
            self.assertEqual(self.client.post(path, data={"csrf_token": "invalid"}).status_code, 400)
        self.assertEqual(self.client.get("/logout").status_code, 405)

    def test_deleted_account_session_is_rejected(self):
        with self.client.session_transaction() as session:
            session["user_id"] = 999
        self.assertEqual(self.client.get("/").status_code, 302)

    def test_security_headers(self):
        response = self.client.get("/login")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("HttpOnly", response.headers["Set-Cookie"])
        self.assertIn("SameSite=Lax", response.headers["Set-Cookie"])


if __name__ == "__main__":
    unittest.main()