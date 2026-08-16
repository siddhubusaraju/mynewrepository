from flask import Flask, render_template, request, redirect, session, send_from_directory, flash
import sqlite3
import os
from datetime import datetime, timezone, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersecretkey")

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# ================= DATABASE SETUP =================

def init_db():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT
                )""")

    c.execute("""CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT,
                    owner TEXT
                )""")

    c.execute("""CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    filename TEXT,
                    action TEXT,
                    timestamp TEXT
                )""")

    c.execute("""CREATE TABLE IF NOT EXISTS shared_access (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT,
                    owner TEXT,
                    shared_with TEXT,
                    expiry_time TEXT
                )""")

    try:
        c.execute("ALTER TABLE shared_access ADD COLUMN expiry_time TEXT")
    except sqlite3.OperationalError:
        pass # Column already exists

    conn.commit()
    conn.close()

init_db()

# ================= HELPERS =================

def has_access(filename, username):
    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    c.execute("SELECT * FROM files WHERE filename=? AND owner=?", (filename, username))
    owner_file = c.fetchone()

    ist = timezone(timedelta(hours=5, minutes=30))
    current_time = datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S")

    c.execute("""SELECT * FROM shared_access 
                 WHERE filename=? AND shared_with=? 
                 AND (expiry_time IS NULL OR expiry_time > ?)""", (filename, username, current_time))
    shared_file = c.fetchone()

    conn.close()

    return owner_file or shared_file

# ================= ROUTES =================

@app.route("/")
def home():
    return redirect("/login")

# ---------- REGISTER ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = generate_password_hash(request.form["password"])

        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("register.html", error="Username already exists")
        except Exception as e:
            conn.close()
            return render_template("register.html", error="An error occurred")
        conn.close()
        return redirect("/login")

    return render_template("register.html")

# ---------- LOGIN ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        # user is a tuple: (id, username, password_hash)
        if user and check_password_hash(user[2], password):
            session["user"] = username
            return redirect("/dashboard")
        else:
            return render_template("login.html", error="Invalid username or password.")

    return render_template("login.html", error=None)

# ---------- DASHBOARD ----------
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user" not in session:
        return redirect("/login")

    username = session["user"]

    if request.method == "POST":
        file = request.files["file"]
        if file and file.filename:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(file_path)

            conn = sqlite3.connect("database.db")
            c = conn.cursor()
            c.execute("INSERT INTO files (filename, owner) VALUES (?, ?)", (filename, username))
            conn.commit()
            conn.close()
            flash(f"File '{filename}' successfully uploaded.", "success")

    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    c.execute("SELECT filename FROM files WHERE owner=?", (username,))
    owned_files = c.fetchall()

    ist = timezone(timedelta(hours=5, minutes=30))
    current_time = datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S")

    c.execute("""SELECT filename, expiry_time FROM shared_access 
                 WHERE shared_with=? AND (expiry_time IS NULL OR expiry_time > ?)""", (username, current_time))
    shared_files = c.fetchall()

    conn.close()

    return render_template("dashboard.html",
                           owned_files=owned_files,
                           shared_files=shared_files)

# ---------- FILE LOGS (OWNER ONLY) ----------
@app.route("/file_logs/<filename>")
def file_logs(filename):
    if "user" not in session:
        return redirect("/login")

    username = session["user"]

    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    # Only owner can access logs
    c.execute("SELECT * FROM files WHERE filename=? AND owner=?", (filename, username))
    if not c.fetchone():
        conn.close()
        return "Unauthorized Access"

    c.execute("SELECT username, action, timestamp FROM logs WHERE filename=? ORDER BY id DESC",
              (filename,))
    logs = c.fetchall()

    conn.close()

    return render_template("file_logs.html", logs=logs, filename=filename)

# ---------- SHARE ----------
@app.route("/share_file/<filename>", methods=["POST"])
def share_file(filename):
    if "user" not in session:
        return redirect("/login")

    owner = session["user"]
    target_user = request.form["username"]

    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    c.execute("SELECT * FROM files WHERE filename=? AND owner=?", (filename, owner))
    if not c.fetchone():
        conn.close()
        return redirect("/dashboard")

    c.execute("SELECT * FROM users WHERE username=?", (target_user,))
    if not c.fetchone():
        conn.close()
        flash(f"User '{target_user}' does not exist.", "error")
        return redirect("/dashboard")

    expiry_hours = request.form.get("expiry_hours", "0")
    expiry_time = None

    if expiry_hours and expiry_hours != "0":
        try:
            hours = int(expiry_hours)
            ist = timezone(timedelta(hours=5, minutes=30))
            expiry_datetime = datetime.now(ist) + timedelta(hours=hours)
            expiry_time = expiry_datetime.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

    c.execute("""SELECT * FROM shared_access 
                 WHERE filename=? AND owner=? AND shared_with=?""",
              (filename, owner, target_user))

    existing = c.fetchone()
    if not existing:
        c.execute("""INSERT INTO shared_access (filename, owner, shared_with, expiry_time)
                     VALUES (?, ?, ?, ?)""",
                  (filename, owner, target_user, expiry_time))
    else:
        # If it exists, update the timer
        c.execute("""UPDATE shared_access SET expiry_time=? 
                     WHERE filename=? AND owner=? AND shared_with=?""",
                  (expiry_time, filename, owner, target_user))

    conn.commit()
    conn.close()
    flash(f"Successfully shared '{filename}' with '{target_user}'.", "success")
    return redirect("/dashboard")

# ---------- MANAGE ACCESS ----------
@app.route("/manage_access/<filename>")
def manage_access(filename):
    if "user" not in session:
        return redirect("/login")

    owner = session["user"]

    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    # Ensure owner
    c.execute("SELECT * FROM files WHERE filename=? AND owner=?", (filename, owner))
    if not c.fetchone():
        conn.close()
        return "Unauthorized Access"

    c.execute("SELECT shared_with, expiry_time FROM shared_access WHERE filename=? AND owner=?",
              (filename, owner))
    users = c.fetchall()

    conn.close()

    return render_template("manage_access.html",
                           filename=filename,
                           users=users)

# ---------- REVOKE ----------
@app.route("/revoke_access/<filename>/<shared_user>", methods=["POST"])
def revoke_access(filename, shared_user):
    if "user" not in session:
        return redirect("/login")

    owner = session["user"]

    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    c.execute("""DELETE FROM shared_access
                 WHERE filename=? AND owner=? AND shared_with=?""",
              (filename, owner, shared_user))

    conn.commit()
    conn.close()

    flash(f"Revoked access for '{shared_user}' on '{filename}'.", "success")
    return redirect(f"/manage_access/{filename}")

# ---------- VIEW ----------
@app.route("/view/<filename>")
def view_file(filename):
    if "user" not in session:
        return redirect("/login")

    username = session["user"]

    if not has_access(filename, username):
        return "Unauthorized Access"

    ist = timezone(timedelta(hours=5, minutes=30))
    current_time = datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("""INSERT INTO logs (username, filename, action, timestamp)
                 VALUES (?, ?, ?, ?)""",
              (username, filename, "Viewed", current_time))
    conn.commit()
    conn.close()

    return render_template("viewer.html", filename=filename)

# ---------- SECURE FILE ----------
@app.route("/secure_file/<filename>")
def secure_file(filename):
    if "user" not in session:
        return "Unauthorized"

    username = session["user"]

    if not has_access(filename, username):
        return "Unauthorized Access"

    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# ---------- DELETE ----------
@app.route("/delete_file/<filename>", methods=["POST"])
def delete_file(filename):
    if "user" not in session:
        return redirect("/login")

    username = session["user"]

    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    c.execute("SELECT * FROM files WHERE filename=? AND owner=?", (filename, username))
    if not c.fetchone():
        conn.close()
        return "Unauthorized"

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    if os.path.exists(file_path):
        os.remove(file_path)

    c.execute("DELETE FROM files WHERE filename=?", (filename,))
    c.execute("DELETE FROM logs WHERE filename=?", (filename,))
    c.execute("DELETE FROM shared_access WHERE filename=?", (filename,))

    conn.commit()
    conn.close()

    flash(f"File '{filename}' has been deleted.", "success")
    return redirect("/dashboard")

# ---------- LOGOUT ----------
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")

if __name__ == "__main__":
    app.run(debug=True)