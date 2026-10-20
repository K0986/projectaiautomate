import os
from pathlib import Path
import secrets
import sqlite3
from datetime import timedelta

from flask import Flask, flash, g, redirect, render_template, session, url_for
from flask_wtf import CSRFProtect, FlaskForm
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import InputRequired, Length, Regexp


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(max=32)])
    password = PasswordField("Password", validators=[InputRequired(), Length(max=128)])
    submit = SubmitField("Sign in")


class RegistrationForm(LoginForm):
    username = StringField("Username", validators=[
        InputRequired(), Length(min=3, max=32),
        Regexp(r"^[A-Za-z0-9_]+$", message="Use letters, numbers, and underscores only."),
    ])
    password = PasswordField("Password", validators=[
        InputRequired(), Length(min=12, max=128,
                                message="Use between 12 and 128 characters."),
    ])
    submit = SubmitField("Create account")


def get_db():
    if "db" not in g:
        from flask import current_app
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        DATABASE=str(Path(app.instance_path) / "users.sqlite3"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    if not app.config["SECRET_KEY"]:
        key_path = Path(app.instance_path) / "secret.key"
        try:
            with key_path.open("x", encoding="ascii") as key_file:
                key_file.write(secrets.token_hex(32))
        except FileExistsError:
            pass
        app.config["SECRET_KEY"] = key_path.read_text(encoding="ascii")

    CSRFProtect(app)
    dummy_hash = generate_password_hash(secrets.token_hex(32))

    @app.teardown_appcontext
    def close_db(error=None):
        database = g.pop("db", None)
        if database is not None:
            database.close()

    with app.app_context():
        get_db().execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        get_db().commit()

    @app.before_request
    def load_user():
        g.user = None
        if session.get("user_id") is not None:
            g.user = get_db().execute(
                "SELECT id, username, created_at FROM users WHERE id = ?",
                (session["user_id"],),
            ).fetchone()
            if g.user is None:
                session.clear()

    @app.after_request
    def security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' https://images.unsplash.com; "
            "style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
        )
        return response

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if g.user is not None:
            return redirect(url_for("dashboard"))
        form = RegistrationForm()
        if form.validate_on_submit():
            try:
                get_db().execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (form.username.data, generate_password_hash(form.password.data)),
                )
                get_db().commit()
            except sqlite3.IntegrityError:
                get_db().rollback()
                form.username.errors.append("That username is already taken.")
            else:
                flash("Account created. You can sign in now.", "success")
                return redirect(url_for("login"))
        return render_template("auth.html", form=form, registering=True)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user is not None:
            return redirect(url_for("dashboard"))
        form = LoginForm()
        if form.validate_on_submit():
            user = get_db().execute(
                "SELECT * FROM users WHERE username = ?", (form.username.data,),
            ).fetchone()
            valid_password = check_password_hash(
                user["password_hash"] if user else dummy_hash, form.password.data,
            )
            if user is not None and valid_password:
                session.clear()
                session["user_id"] = user["id"]
                session.permanent = True
                return redirect(url_for("dashboard"))
            flash("Incorrect username or password.", "error")
        return render_template("auth.html", form=form, registering=False)

    @app.get("/")
    def dashboard():
        if g.user is None:
            return redirect(url_for("login"))
        return render_template("dashboard.html", logout_form=FlaskForm())

    @app.post("/logout")
    def logout():
        session.clear()
        flash("You have signed out.", "success")
        return redirect(url_for("login"))

    @app.errorhandler(400)
    def bad_request(error):
        return render_template("error.html"), 400

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))