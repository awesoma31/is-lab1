"""Защищённое REST API: аутентификация по JWT, посты пользователей."""

import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

import bcrypt
from flask import Flask, current_app, g, jsonify, request
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    current_user,
    get_jwt_identity,
    jwt_required,
)
from markupsafe import escape

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
PASSWORD_MIN_LEN = 8
PASSWORD_MAX_LEN = 72  # bcrypt учитывает только первые 72 байта
TITLE_MAX_LEN = 200
BODY_MAX_LEN = 5000

# Хэш-заглушка: сверяем с ним пароль, если пользователя нет,
# чтобы время ответа не выдавало существование логина.
DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt())

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash BLOB    NOT NULL
);
CREATE TABLE IF NOT EXISTS posts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id  INTEGER NOT NULL REFERENCES users(id),
    title      TEXT    NOT NULL,
    body       TEXT    NOT NULL,
    created_at TEXT    NOT NULL
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))


def check_password(password, password_hash):
    return bcrypt.checkpw(password.encode("utf-8"), password_hash)


def error(message, status):
    return jsonify({"error": message}), status


def read_json(*fields):
    """Возвращает значения полей из JSON-тела или None, если тело некорректно."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None
    values = tuple(data.get(f) for f in fields)
    if not all(isinstance(v, str) for v in values):
        return None
    return values


def validate_credentials(username, password):
    if not USERNAME_RE.fullmatch(username):
        return "username must be 3-32 chars: letters, digits, underscore"
    if not PASSWORD_MIN_LEN <= len(password.encode("utf-8")) <= PASSWORD_MAX_LEN:
        return f"password must be {PASSWORD_MIN_LEN}-{PASSWORD_MAX_LEN} bytes"
    return None


def serialize_post(row):
    # Экранирование пользовательских данных на выходе (защита от XSS).
    return {
        "id": row["id"],
        "author": str(escape(row["author"])),
        "title": str(escape(row["title"])),
        "body": str(escape(row["body"])),
        "created_at": row["created_at"],
    }


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(
        DATABASE=os.environ.get("DATABASE", "app.db"),
        JWT_SECRET_KEY=os.environ.get("JWT_SECRET_KEY") or secrets.token_hex(32),
        JWT_ACCESS_TOKEN_EXPIRES=timedelta(minutes=15),
        JWT_TOKEN_LOCATION=["headers"],
        JWT_ALGORITHM="HS256",
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if config:
        app.config.update(config)

    jwt = JWTManager(app)
    app.teardown_appcontext(close_db)

    with app.app_context():
        get_db().executescript(SCHEMA)

    @jwt.unauthorized_loader
    def missing_token(reason):
        return error("missing or malformed Authorization header", 401)

    @jwt.invalid_token_loader
    def invalid_token(reason):
        return error("invalid token", 401)

    @jwt.expired_token_loader
    def expired_token(_header, _payload):
        return error("token expired", 401)

    @jwt.user_lookup_loader
    def load_user(_header, payload):
        return (
            get_db()
            .execute("SELECT id, username FROM users WHERE id = ?", (int(payload["sub"]),))
            .fetchone()
        )

    @jwt.user_lookup_error_loader
    def unknown_user(_header, _payload):
        return error("invalid token", 401)

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(404)
    def not_found(_e):
        return error("not found", 404)

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return error("method not allowed", 405)

    @app.errorhandler(413)
    def too_large(_e):
        return error("request body too large", 413)

    @app.post("/auth/register")
    def register():
        body = read_json("username", "password")
        if body is None:
            return error("username and password are required", 400)
        username, password = body
        problem = validate_credentials(username, password)
        if problem:
            return error(problem, 400)

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hash_password(password)),
            )
            db.commit()
        except sqlite3.IntegrityError:
            return error("username already taken", 409)
        return jsonify({"message": "user created"}), 201

    @app.post("/auth/login")
    def login():
        body = read_json("username", "password")
        if body is None:
            return error("username and password are required", 400)
        username, password = body

        user = (
            get_db()
            .execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
            .fetchone()
        )
        stored_hash = user["password_hash"] if user else DUMMY_HASH
        password_ok = check_password(password[:PASSWORD_MAX_LEN], stored_hash)
        if not user or not password_ok:
            return error("invalid username or password", 401)

        token = create_access_token(identity=str(user["id"]))
        return jsonify({"access_token": token, "token_type": "Bearer", "expires_in": 900})

    @app.get("/api/data")
    @jwt_required()
    def list_posts():
        rows = get_db().execute(
            """
            SELECT p.id, u.username AS author, p.title, p.body, p.created_at
            FROM posts p JOIN users u ON u.id = p.author_id
            ORDER BY p.id DESC
            """
        ).fetchall()
        return jsonify({"posts": [serialize_post(r) for r in rows]})

    @app.post("/api/posts")
    @jwt_required()
    def create_post():
        body = read_json("title", "body")
        if body is None:
            return error("title and body are required", 400)
        title, text = (v.strip() for v in body)
        if not title or len(title) > TITLE_MAX_LEN:
            return error(f"title must be 1-{TITLE_MAX_LEN} chars", 400)
        if not text or len(text) > BODY_MAX_LEN:
            return error(f"body must be 1-{BODY_MAX_LEN} chars", 400)

        db = get_db()
        cur = db.execute(
            "INSERT INTO posts (author_id, title, body, created_at) VALUES (?, ?, ?, ?)",
            (int(get_jwt_identity()), title, text, datetime.now(timezone.utc).isoformat()),
        )
        db.commit()
        row = db.execute(
            """
            SELECT p.id, u.username AS author, p.title, p.body, p.created_at
            FROM posts p JOIN users u ON u.id = p.author_id
            WHERE p.id = ?
            """,
            (cur.lastrowid,),
        ).fetchone()
        return jsonify(serialize_post(row)), 201

    @app.get("/api/me")
    @jwt_required()
    def me():
        return jsonify({"id": current_user["id"], "username": str(escape(current_user["username"]))})

    return app


if __name__ == "__main__":
    # Для локального запуска; debug выключен намеренно.
    create_app().run(host="127.0.0.1", port=5000, debug=False)
