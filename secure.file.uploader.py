#!/usr/bin/env python3
"""
Secure minimal user-management + file upload web app.

Features:
- Login/logout
- Admin: add/delete/change password
- Per-user file upload, list, download, delete (SFTP-like)
- Flat-file user DB with bcrypt hashes (username:bcrypt_hash)
- CSRF protection (token in session)
- Simple in-memory rate limiting
- Cloudflare-aware real-client IP logging (CF-Connecting-IP, X-Forwarded-For)
- HTTPS support (ssl_context if CERT_FILE and KEY_FILE exist); intended to run behind cloudflared on port 444
"""

import os
import time
import secrets
import logging
import tempfile
from logging.handlers import RotatingFileHandler
from functools import wraps
from html import escape

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort, send_from_directory
)
import bcrypt
from werkzeug.utils import secure_filename

VERSION = "01.01.00.00"

# -------------------- Configuration --------------------
APP_DIR = os.path.abspath(os.path.dirname(__file__))

USER_DB_FILE = os.environ.get("USER_DB_FILE", os.path.join(APP_DIR, "/var/opt/secure.file.uploader/instance/users.db"))
LOG_FILE = os.environ.get("LOG_FILE", os.path.join(APP_DIR, "/var/log/secure.file.uploader.log"))
CERT_FILE = os.environ.get("CERT_FILE", os.path.join(APP_DIR, "/etc/secure_file_uploader/certs/secure.crt"))
KEY_FILE  = os.environ.get("KEY_FILE", os.path.join(APP_DIR, "/etc/secure_file_uploader/certs/secure.key"))

# sudo mkdir storage
# sudo chmod 700 storage
STORAGE_ROOT = os.environ.get("STORAGE_ROOT", os.path.join(APP_DIR, "/var/opt/secure.file.uploader/instance/storage"))
QUARANTINE_DIR = os.path.join(APP_DIR, "/opt/clstools/farpointone.web/bin/quarantine")
ALLOWED_EXTENSIONS = {"pcap", "iso", "pdf", "xlsx", "docx", "pptx", "zip", "txt", "log"}
MAX_UPLOAD_SIZE = 10 * 1024 * 1024 * 1024  # 10 GB per upload

# Security settings
MIN_PASSWORD_LEN = 8
RATE_LIMIT_MAX_ATTEMPTS = 6
RATE_LIMIT_WINDOW = 300

# Network settings
PORT_NUMBER=444

# Flask app and session config
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_urlsafe(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,   # requires HTTPS
    MAX_CONTENT_LENGTH=MAX_UPLOAD_SIZE
)

# Ensure storage dirs exist
os.makedirs(STORAGE_ROOT, exist_ok=True)
os.makedirs(os.path.dirname(LOG_FILE) or ".", exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# -------------------- Logging (simplified) --------------------
handler = RotatingFileHandler(LOG_FILE, maxBytes=10_000_000, backupCount=5)
fmt = "%(asctime)s [%(levelname)s] %(message)s"  # simplified
handler.setFormatter(logging.Formatter(fmt))
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

def get_client_ip():
    cf = request.headers.get("CF-Connecting-IP")
    if cf:
        return cf
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "N/A"

def log_info(msg):
    app.logger.info(msg)

def log_warn(msg):
    app.logger.warning(msg)

# -------------------- Rate limiter (in-memory) --------------------
_attempts = {}  # ip -> list of timestamps

def rate_limited(ip):
    now = time.time()
    attempts = _attempts.get(ip, [])
    attempts = [t for t in attempts if now - t <= RATE_LIMIT_WINDOW]
    _attempts[ip] = attempts
    return len(attempts) >= RATE_LIMIT_MAX_ATTEMPTS

def add_attempt(ip):
    now = time.time()
    _attempts.setdefault(ip, []).append(now)

# -------------------- User DB helpers --------------------
def read_users():
    users = {}
    if not os.path.exists(USER_DB_FILE):
        return users
    with open(USER_DB_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            username, hashed = line.split(":", 1)
            users[username] = hashed
    return users

def atomic_write_users(users_dict):
    dirpath = os.path.dirname(USER_DB_FILE) or "."
    fd, tmp = tempfile.mkstemp(dir=dirpath)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for user, h in users_dict.items():
                f.write(f"{user}:{h}\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, USER_DB_FILE)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass

def check_credentials(username, password):
    if not os.path.exists(USER_DB_FILE):
        return False
    with open(USER_DB_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            if ':' in line:
                stored_user, stored_hash = line.strip().split(':', 1)
                if stored_user == username:
                    try:
                        return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
                    except Exception:
                        return False
    return False

def add_user(username, password):
    if ":" in username or not username:
        raise ValueError("Invalid username")
    if len(password) < MIN_PASSWORD_LEN:
        raise ValueError("Password too short")
    users = read_users()
    if username in users:
        raise ValueError("User exists")
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    users[username] = hashed
    atomic_write_users(users)

def delete_user(username):
    users = read_users()
    if username not in users:
        raise ValueError("User not found")
    del users[username]
    atomic_write_users(users)

def change_password(username, new_password):
    if len(new_password) < MIN_PASSWORD_LEN:
        raise ValueError("Password too short")
    users = read_users()
    if username not in users:
        raise ValueError("User not found")
    hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    users[username] = hashed
    atomic_write_users(users)

# -------------------- Auth helpers --------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped

# -------------------- CSRF helpers --------------------
def ensure_csrf():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]

def validate_csrf(token):
    stored = session.get("csrf_token")
    return stored and token and secrets.compare_digest(stored, token)

# -------------------- File helpers --------------------
def allowed_file(filename):
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS

def user_storage_dir(username):
    p = os.path.join(STORAGE_ROOT, username)
    os.makedirs(p, exist_ok=True)
    return p

def atomic_save_file(stream, dest_path):
    dirpath = os.path.dirname(dest_path)
    fd, tmp = tempfile.mkstemp(dir=dirpath)
    try:
        with os.fdopen(fd, "wb") as f:
            while True:
                chunk = stream.read(8192)
                if not chunk:
                    break
                f.write(chunk)
        os.replace(tmp, dest_path)
        os.chmod(dest_path, 0o600)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass

def scan_file_with_clam(file_path):
    try:
        import subprocess
        res = subprocess.run(["clamscan", "--no-summary", file_path], capture_output=True, text=True, timeout=60)
        stdout = (res.stdout or "") + (res.stderr or "")
        if "Infected files: 0" in stdout or res.returncode == 0:
            return True
        return False
    except Exception as e:
        log_info(f"ClamAV scan skipped/failed: {e}")
        return True

# -------------------- Routes --------------------

@app.route("/")
@login_required
def view_main():
    ensure_csrf()
    users = sorted(read_users().keys())
    username = session.get("username")
    storage = user_storage_dir(username)
    files = sorted(os.listdir(storage)) if os.path.exists(storage) else []
    return render_template("main.html", version=VERSION, users=users, current_user=escape(username),
                           files=files, csrf_token=session["csrf_token"])

@app.route("/login", methods=["GET", "POST"])
def login():
    ensure_csrf()
    error = None
    if request.method == "POST":
        ip = get_client_ip()
        if rate_limited(ip):
            log_warn(f"RATE LIMIT exceeded IP={ip}")
            return "Too many attempts, try later", 429
        username = request.form.get("fname", "").strip()
        password = request.form.get("pname", "")
        form_csrf = request.form.get("csrf_token", "")
        if not validate_csrf(form_csrf):
            log_warn(f"CSRF validation failure on login IP={ip}")
            abort(400)
        if check_credentials(username, password):
            session.clear()
            session["username"] = username
            session["csrf_token"] = secrets.token_urlsafe(32)
            log_info(f"LOGIN SUCCESS - user={username} IP={ip}")
            return redirect(url_for("view_main"))
        else:
            add_attempt(ip)
            log_warn(f"LOGIN FAILED IP={ip}")
            error = "Invalid username or password"
    return render_template("login.html", version=VERSION, error=error, csrf_token=session["csrf_token"])

@app.route("/logout", methods=["GET"])
def logout():
    user = session.pop("username", None)
    session.pop("csrf_token", None)
    ip = get_client_ip()
    log_info(f"LOGOUT - user={user} IP={ip}")
    flash("Logged out")
    return redirect(url_for("login"))

# ---- Admin user management
def require_admin():
    u = session.get("username")
    if not u or u != "admin":
        abort(403)

@app.route("/users/add", methods=["POST"])
@login_required
def web_add_user():
    require_admin()
    if not validate_csrf(request.form.get("csrf_token", "")):
        abort(400)
    username = request.form.get("new_username", "").strip()
    password = request.form.get("new_password", "")
    ip = get_client_ip()
    try:
        add_user(username, password)
        log_info(f"USER ADDED - admin={session.get('username')} user={username} IP={ip}")
        flash("User added")
    except Exception as e:
        flash(f"Error adding user: {e}")
    return redirect(url_for("view_main"))

@app.route("/users/delete", methods=["POST"])
@login_required
def web_delete_user():
    require_admin()
    if not validate_csrf(request.form.get("csrf_token", "")):
        abort(400)
    username = request.form.get("del_username", "").strip()
    ip = get_client_ip()
    if username == "admin":
        flash("Cannot delete admin user")
        return redirect(url_for("view_main"))
    try:
        delete_user(username)
        log_info(f"USER DELETED - admin={session.get('username')} user={username} IP={ip}")
        flash("User deleted")
    except Exception as e:
        flash(f"Error deleting user: {e}")
    return redirect(url_for("view_main"))

@app.route("/users/change_password", methods=["POST"])
@login_required
def web_change_password():
    require_admin()
    if not validate_csrf(request.form.get("csrf_token", "")):
        abort(400)
    username = request.form.get("chg_username", "").strip()
    new_password = request.form.get("chg_new_password", "")
    ip = get_client_ip()
    try:
        change_password(username, new_password)
        log_info(f"PASSWORD CHANGED - admin={session.get('username')} user={username} IP={ip}")
        flash("Password changed")
    except Exception as e:
        flash(f"Error changing password: {e}")
    return redirect(url_for("view_main"))

# ---- File upload/download/delete
@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    if not validate_csrf(request.form.get("csrf_token", "")):
        abort(400)
    ip = get_client_ip()
    if 'file' not in request.files:
        flash("No file selected")
        return redirect(url_for("view_main"))
    file = request.files['file']
    if file.filename == "":
        flash("No file selected")
        return redirect(url_for("view_main"))
    filename = secure_filename(file.filename)
    if not allowed_file(filename):
        flash("File type not allowed")
        log_warn(f"UPLOAD BLOCKED - user={session.get('username')} file={filename} IP={ip}")
        return redirect(url_for("view_main"))
    user = session.get("username")
    storage_dir = user_storage_dir(user)
    dest_path = os.path.join(storage_dir, filename)
    try:
        atomic_save_file(file.stream, dest_path)
        clean = scan_file_with_clam(dest_path)
        if not clean:
            qpath = os.path.join(QUARANTINE_DIR, f"{user}_{filename}")
            os.replace(dest_path, qpath)
            flash("File quarantined: Virus detected")
            log_warn(f"FILE QUARANTINED - user={user} file={filename} IP={ip}")
        else:
            flash("File uploaded successfully")
            log_info(f"FILE UPLOADED - user={user} file={filename} IP={ip}")
    except Exception as e:
        log_warn(f"UPLOAD FAILED - user={user} file={filename} error={e} IP={ip}")
        flash(f"Upload failed: {e}")
    return redirect(url_for("view_main"))

@app.route("/download/<path:filename>", methods=["GET"])
@login_required
def download_file(filename):
    user = session.get("username")
    storage_dir = user_storage_dir(user)
    safe_name = secure_filename(filename)
    if safe_name != filename:
        abort(400)
    file_path = os.path.join(storage_dir, filename)
    if not os.path.exists(file_path):
        abort(404)
    ip = get_client_ip()
    log_info(f"FILE DOWNLOAD - user={user} file={filename} IP={ip}")
    return send_from_directory(storage_dir, filename, as_attachment=True)

@app.route("/delete_file", methods=["POST"])
@login_required
def delete_file():
    if not validate_csrf(request.form.get("csrf_token", "")):
        abort(400)
    user = session.get("username")
    filename = request.form.get("del_file", "").strip()
    safe_name = secure_filename(filename)
    if safe_name != filename:
        flash("Invalid filename")
        return redirect(url_for("view_main"))
    file_path = os.path.join(user_storage_dir(user), filename)
    if not os.path.exists(file_path):
        flash("File not found")
        return redirect(url_for("view_main"))
    ip = get_client_ip()
    try:
        os.remove(file_path)
        log_info(f"FILE DELETED - user={user} file={filename} IP={ip}")
        flash("File deleted")
    except Exception as e:
        log_warn(f"DELETE FAILED - user={user} file={filename} error={e} IP={ip}")
        flash("Delete failed")
    return redirect(url_for("view_main"))

# -------------------- Initialization --------------------
def ensure_admin_exists():
    users = read_users()
    if "admin" not in users:
        hashed = bcrypt.hashpw("admin".encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        users["admin"] = hashed
        atomic_write_users(users)
        app.logger.info("Default admin user created (username: admin / password: admin)")

with app.app_context():
    ensure_admin_exists()

# -------------------- Run --------------------
if __name__ == "__main__":
    app.logger.info("Starting secure file upload web app")
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        app.run(host="0.0.0.0", port=444, ssl_context=(CERT_FILE, KEY_FILE))
    else:
        app.logger.warning("CERT/KEY missing; starting without SSL (not recommended).")
        app.config['SESSION_COOKIE_SECURE'] = False
        app.run(host="0.0.0.0", port=(PORT_NUMBER))
