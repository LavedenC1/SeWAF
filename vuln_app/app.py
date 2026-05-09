# vuln_app/app.py
from pathlib import Path
import sqlite3

from flask import Flask, request, render_template_string, make_response, send_from_directory
import requests

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "demo.db"
FILES_DIR = BASE_DIR / "files"


def init_data() -> None:
    FILES_DIR.mkdir(parents=True, exist_ok=True)

    sample_file = FILES_DIR / "readme.txt"
    if not sample_file.exists():
        sample_file.write_text("hello from the vuln app\n", encoding="utf-8")

    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
        )
        cur.execute("DELETE FROM users")
        cur.executemany(
            "INSERT INTO users(username, password) VALUES (?, ?)",
            [("alice", "alice123"), ("bob", "bob123")],
        )
        conn.commit()
    finally:
        conn.close()


@app.get("/")
def index():
    # serve the static frontend
    return send_from_directory(BASE_DIR / "static", "index.html")


@app.get('/set_admin')
def set_admin():
    resp = make_response('Admin cookie set')
    resp.set_cookie('is_admin', '1')
    return resp


@app.get('/admin')
def admin():
    # insecure admin check via cookie
    if request.cookies.get('is_admin') == '1':
        return '<h1>Admin Panel</h1><p>secret: 42</p>'
    return 'Forbidden', 403


@app.get("/xss")
def xss():
    q = request.args.get("q", "")
    return render_template_string(
        f"""
        <h1>Search</h1>
        <p>Results for: {q}</p>
        """
    )


@app.get("/login")
def sqli():
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        query = (
            f"SELECT id, username FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        rows = cur.execute(query).fetchall()
    except sqlite3.Error as exc:
        return f"SQL error: {exc}", 500
    finally:
        conn.close()

    if rows:
        return f"Welcome, {rows[0][1]}"

    return "Access denied", 403


@app.get("/file")
def file_read():
    name = request.args.get("name", "readme.txt")
    path = FILES_DIR / name

    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        return f"File error: {exc}", 500


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'GET':
        return render_template_string(
            '''
            <h1>Upload File</h1>
            <form method="post" enctype="multipart/form-data">
              <input type="file" name="file" />
              <input type="submit" value="Upload" />
            </form>
            '''
        )

    f = request.files.get('file')
    if not f:
        return 'No file', 400

    # insecurely save uploaded file without validation
    dest = FILES_DIR / f.filename
    f.save(dest)
    return f'Uploaded: {f.filename}'


@app.get('/ssrf')
def ssrf():
    url = request.args.get('url')
    if not url:
        return 'Provide ?url=', 400
    try:
        # fetch arbitrary URL (no validation)
        r = requests.get(url, timeout=5)
        return r.text[:2000]
    except Exception as e:
        return f'Fetch error: {e}', 500


@app.get("/echo")
def echo():
    msg = request.args.get("msg", "")
    return render_template_string(
        f"""
        <h1>Echo</h1>
        <div>{msg}</div>
        """
    )


if __name__ == "__main__":
    init_data()
    app.run(host="0.0.0.0", port=5001, debug=True)