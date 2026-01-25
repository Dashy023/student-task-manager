print("🔥 WEB_APP.PY IS RUNNING 🔥")

import os
from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta

db_initialized = False

# ================== APP CONFIG ==================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key")
app.permanent_session_lifetime = timedelta(days=7)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

# create data folder if it doesn't exist (IMPORTANT)
os.makedirs(DATA_DIR, exist_ok=True)

DB_NAME = os.path.join(DATA_DIR, "tasks.db")

# ================== DATABASE ==================
def get_db():
    return sqlite3.connect(DB_NAME)

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
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

    conn.commit()
    conn.close()

@app.before_request
def ensure_db():
    global db_initialized
    if not db_initialized:
        init_db()
        db_initialized = True


# ================== AUTH ==================
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


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ================== TASKS PAGE (MAIN) ==================
@app.route("/", methods=["GET", "POST"])
def index():
    if "user_id" not in session:
        return redirect("/login")

    # ADD TASK
    if request.method == "POST":
        conn = get_db()
        c = conn.cursor()
        c.execute("""
            INSERT INTO tasks (user_id, title, subject, due_date, priority, status)
            VALUES (?, ?, ?, ?, ?, 'Pending')
        """, (
            session["user_id"],
            request.form["title"],
            request.form["subject"],
            request.form["due_date"],
            request.form["priority"]
        ))
        conn.commit()
        conn.close()

        # AFTER ADD → GO TO TASKS PAGE
        return redirect("/tasks")

    # JUST SHOW ADD TASK PAGE
    return render_template("index.html")

@app.route("/tasks")
def tasks_page():
    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]
    conn = get_db()
    c = conn.cursor()

    # FILTERS
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

    # STATS
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
        "tasks.html",
        tasks=tasks,
        total=total,
        pending=pending,
        done=done,
        high=high,
        status_filter=status_filter,
        priority_filter=priority_filter,
        search=search
    )


# ================== PROGRESS PAGE ==================
@app.route("/progress")
def progress():
    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]
    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT * FROM tasks WHERE user_id=?", (user_id,))
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
        "progress.html",
        total=total,
        pending=pending,
        done=done,
        high=high
    )

# ================== TASK ACTIONS ==================
@app.route("/done/<int:task_id>")
def done(task_id):
    if "user_id" not in session:
        return redirect("/login")

    conn = get_db()
    c = conn.cursor()
    c.execute(
        "UPDATE tasks SET status='Done' WHERE id=? AND user_id=?",
        (task_id, session["user_id"])
    )
    conn.commit()
    conn.close()
    return redirect("/tasks")


@app.route("/delete/<int:task_id>")
def delete(task_id):
    if "user_id" not in session:
        return redirect("/login")

    conn = get_db()
    c = conn.cursor()
    c.execute(
        "DELETE FROM tasks WHERE id=? AND user_id=?",
        (task_id, session["user_id"])
    )
    conn.commit()
    conn.close()
    return redirect("/tasks")


@app.route("/edit/<int:task_id>", methods=["GET", "POST"])
def edit(task_id):
    if "user_id" not in session:
        return redirect("/login")

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
        return redirect("/tasks")

    c.execute(
        "SELECT * FROM tasks WHERE id=? AND user_id=?",
        (task_id, session["user_id"])
    )
    task = c.fetchone()
    conn.close()

    return render_template("edit.html", task=task)

# ================== RUN ==================
if __name__ == "__main__":
    app.run()
