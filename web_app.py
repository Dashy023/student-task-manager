from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import secrets
import time

app = Flask(__name__)
app.secret_key = "change_this_secret_key"
app.permanent_session_lifetime = timedelta(days=7)

# ---------- DATABASE ----------
def get_db():
    return sqlite3.connect("tasks.db")

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            subject TEXT,
            due_date TEXT,
            priority TEXT,
            status TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            token TEXT,
            created_at INTEGER
        )
    """)

    conn.commit()
    conn.close()

init_db()

# ---------- REGISTER ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])

        conn = get_db()
        c = conn.cursor()
        try:
            c.execute(
                "INSERT INTO users (email, password) VALUES (?, ?)",
                (email, password)
            )
            conn.commit()
            conn.close()
            return redirect("/login")
        except:
            conn.close()
            flash("Email already registered", "error")
            return redirect("/register")

    return render_template("register.html")

# ---------- LOGIN ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id, password FROM users WHERE email=?", (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password):
            session.permanent = True
            session["user_id"] = user[0]
            return redirect("/")
        else:
            flash("Invalid email or password", "error")
            return redirect("/login")

    return render_template("login.html")

# ---------- LOGOUT ----------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ---------- FORGOT PASSWORD ----------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email=?", (email,))
        user = c.fetchone()

        if not user:
            conn.close()
            flash("Email not found", "error")
            return redirect("/forgot-password")

        token = secrets.token_urlsafe(32)
        created_at = int(time.time())

        c.execute(
            "INSERT INTO password_resets (user_id, token, created_at) VALUES (?, ?, ?)",
            (user[0], token, created_at)
        )
        conn.commit()
        conn.close()

        # TEMP: show reset link instead of sending email
        flash(f"Reset link: http://127.0.0.1:5000/reset/{token}", "info")
        return redirect("/login")

    return render_template("forgot_password.html")

# ---------- RESET PASSWORD ----------
@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT user_id, created_at FROM password_resets WHERE token=?", (token,))
    row = c.fetchone()

    if not row:
        conn.close()
        flash("Invalid or expired reset link", "error")
        return redirect("/login")

    # expire after 15 minutes
    if int(time.time()) - row[1] > 900:
        conn.close()
        flash("Reset link expired", "error")
        return redirect("/login")

    if request.method == "POST":
        new_password = generate_password_hash(request.form["password"])

        c.execute("UPDATE users SET password=? WHERE id=?", (new_password, row[0]))
        c.execute("DELETE FROM password_resets WHERE token=?", (token,))
        conn.commit()
        conn.close()

        flash("Password reset successful. Login now.", "success")
        return redirect("/login")

    conn.close()
    return render_template("reset_password.html")

# ---------- MAIN ----------
@app.route("/", methods=["GET", "POST"])
def index():
    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]
    conn = get_db()
    c = conn.cursor()

    if request.method == "POST":
        c.execute("""
            INSERT INTO tasks (user_id, title, subject, due_date, priority, status)
            VALUES (?, ?, ?, ?, ?, 'Pending')
        """, (
            user_id,
            request.form["title"],
            request.form["subject"],
            request.form["due_date"],
            request.form["priority"]
        ))
        conn.commit()

    status_filter = request.args.get("status", "All")
    priority_filter = request.args.get("priority", "All")
    search = request.args.get("search", "")

    query = "SELECT * FROM tasks WHERE user_id=?"
    params = [user_id]

    if status_filter != "All":
        query += " AND status=?"
        params.append(status_filter)

    if priority_filter != "All":
        query += " AND priority=?"
        params.append(priority_filter)

    if search:
        query += " AND (title LIKE ? OR subject LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])

    c.execute(query, params)
    tasks = c.fetchall()
    conn.close()

    total = pending = done = high = 0
    for t in tasks:
        total += 1
        if t[6] == "Pending":
            pending += 1
        if t[6] == "Done":
            done += 1
        if t[5] == "High":
            high += 1

    return render_template(
        "index.html",
        tasks=tasks,
        total=total,
        pending=pending,
        done=done,
        high=high,
        status_filter=status_filter,
        priority_filter=priority_filter,
        search=search
    )

# ---------- DONE ----------
@app.route("/done/<int:task_id>")
def done(task_id):
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "UPDATE tasks SET status='Done' WHERE id=? AND user_id=?",
        (task_id, session["user_id"])
    )
    conn.commit()
    conn.close()
    return redirect("/")

# ---------- DELETE ----------
@app.route("/delete/<int:task_id>")
def delete(task_id):
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "DELETE FROM tasks WHERE id=? AND user_id=?",
        (task_id, session["user_id"])
    )
    conn.commit()
    conn.close()
    return redirect("/")

# ---------- EDIT ----------
@app.route("/edit/<int:task_id>", methods=["GET", "POST"])
def edit(task_id):
    conn = get_db()
    c = conn.cursor()

    if request.method == "POST":
        c.execute("""
            UPDATE tasks
            SET title=?, due_date=?, priority=?
            WHERE id=? AND user_id=?
        """, (
            request.form["title"],
            request.form["due_date"],
            request.form["priority"],
            task_id,
            session["user_id"]
        ))
        conn.commit()
        conn.close()
        return redirect("/")

    c.execute(
        "SELECT * FROM tasks WHERE id=? AND user_id=?",
        (task_id, session["user_id"])
    )
    task = c.fetchone()
    conn.close()

    return render_template("edit.html", task=task)

# ---------- RUN ----------
if __name__ == "__main__":
    app.run()