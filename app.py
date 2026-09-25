from flask import Flask, render_template, request, redirect, url_for, session, send_file
import sqlite3
import os
import uuid

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from cryptography.fernet import Fernet


app = Flask(__name__)

app.secret_key = "secure_file_encryption_2026"


# ==================================================
# BASE DIRECTORY
# ==================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ==================================================
# FOLDERS
# ==================================================

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ENCRYPTED_FOLDER = os.path.join(BASE_DIR, "encrypted_files")
DECRYPTED_FOLDER = os.path.join(BASE_DIR, "decrypted_files")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["ENCRYPTED_FOLDER"] = ENCRYPTED_FOLDER
app.config["DECRYPTED_FOLDER"] = DECRYPTED_FOLDER


# ==================================================
# ENCRYPTION KEY
# ==================================================

KEY_FILE = os.path.join(BASE_DIR, "secret.key")


def get_encryption_key():

    if not os.path.exists(KEY_FILE):

        key = Fernet.generate_key()

        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)

    else:

        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()

    return key


fernet = Fernet(get_encryption_key())


# ==================================================
# DATABASE
# ==================================================

DATABASE = os.path.join(BASE_DIR, "database.db")


def get_db():

    conn = sqlite3.connect(DATABASE)

    conn.row_factory = sqlite3.Row

    return conn


# ==================================================
# DATABASE INITIALIZATION
# ==================================================

def init_db():

    conn = get_db()

    # USERS TABLE
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # FILES TABLE
    conn.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            filepath TEXT NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Check existing columns
    columns = conn.execute(
        "PRAGMA table_info(files)"
    ).fetchall()

    column_names = [column["name"] for column in columns]

    # encrypted
    if "encrypted" not in column_names:

        conn.execute("""
            ALTER TABLE files
            ADD COLUMN encrypted INTEGER DEFAULT 0
        """)

    # encrypted_path
    if "encrypted_path" not in column_names:

        conn.execute("""
            ALTER TABLE files
            ADD COLUMN encrypted_path TEXT
        """)

    # decrypted
    if "decrypted" not in column_names:

        conn.execute("""
            ALTER TABLE files
            ADD COLUMN decrypted INTEGER DEFAULT 0
        """)

    # decrypted_path
    if "decrypted_path" not in column_names:

        conn.execute("""
            ALTER TABLE files
            ADD COLUMN decrypted_path TEXT
        """)

    conn.commit()

    conn.close()


# ==================================================
# HOME
# ==================================================

@app.route("/")
def home():

    return render_template("index.html")


# ==================================================
# REGISTER
# ==================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form["name"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]

        if not name or not email or not password:

            return "All fields are required!"

        hashed_password = generate_password_hash(password)

        # Make sure database exists
        init_db()

        conn = get_db()

        try:

            conn.execute(
                """
                INSERT INTO users
                (name, email, password)
                VALUES (?, ?, ?)
                """,
                (
                    name,
                    email,
                    hashed_password
                )
            )

            conn.commit()

        except sqlite3.IntegrityError:

            conn.close()

            return "Email already registered!"

        conn.close()

        return redirect(url_for("login"))

    return render_template("register.html")


# ==================================================
# LOGIN
# ==================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"].strip()
        password = request.form["password"]

        init_db()

        conn = get_db()

        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(
            user["password"],
            password
        ):

            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["user_email"] = user["email"]

            return redirect(url_for("dashboard"))

        return "Invalid email or password!"

    return render_template("login.html")


# ==================================================
# DASHBOARD
# ==================================================

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:

        return redirect(url_for("login"))

    # Make sure database exists
    init_db()

    conn = get_db()

    # Current user's files
    files = conn.execute(
        """
        SELECT *
        FROM files
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (session["user_id"],)
    ).fetchall()

    # Total files
    total_files = conn.execute(
        """
        SELECT COUNT(*)
        FROM files
        WHERE user_id = ?
        """,
        (session["user_id"],)
    ).fetchone()[0]

    # Encrypted files
    encrypted_files = conn.execute(
        """
        SELECT COUNT(*)
        FROM files
        WHERE user_id = ?
        AND encrypted = 1
        """,
        (session["user_id"],)
    ).fetchone()[0]

    # Decrypted files
    decrypted_files = conn.execute(
        """
        SELECT COUNT(*)
        FROM files
        WHERE user_id = ?
        AND decrypted = 1
        """,
        (session["user_id"],)
    ).fetchone()[0]

    conn.close()

    return render_template(
        "dashboard.html",

        name=session["user_name"],

        email=session["user_email"],

        files=files,

        total_files=total_files,

        encrypted_files=encrypted_files,

        decrypted_files=decrypted_files
    )


# ==================================================
# UPLOAD FILE
# ==================================================

@app.route("/upload", methods=["POST"])
def upload_file():

    if "user_id" not in session:

        return redirect(url_for("login"))

    if "file" not in request.files:

        return "No file selected!"

    file = request.files["file"]

    if file.filename == "":

        return "No file selected!"

    # Secure original filename
    original_filename = secure_filename(file.filename)

    if not original_filename:

        return "Invalid file name!"

    # ==================================================
    # CREATE UNIQUE SERVER FILE NAME
    # ==================================================

    unique_filename = (
        uuid.uuid4().hex
        + "_"
        + original_filename
    )

    filepath = os.path.join(
        app.config["UPLOAD_FOLDER"],
        unique_filename
    )

    try:

        # ==================================================
        # SAVE FILE
        # ==================================================

        file.save(filepath)

        # ==================================================
        # SAVE DATABASE INFORMATION
        # ==================================================

        conn = get_db()

        conn.execute(
            """
            INSERT INTO files
            (
                user_id,
                filename,
                filepath,
                encrypted,
                decrypted
            )
            VALUES (?, ?, ?, 0, 0)
            """,
            (
                session["user_id"],
                original_filename,
                filepath
            )
        )

        conn.commit()

        conn.close()

    except Exception as e:

        # Remove partially uploaded file
        if os.path.exists(filepath):

            try:
                os.remove(filepath)

            except Exception:
                pass

        return f"Upload failed: {str(e)}"

    return redirect(url_for("dashboard"))


# ==================================================
# ENCRYPT FILE
# ==================================================

@app.route("/encrypt/<int:file_id>", methods=["POST"])
def encrypt_file(file_id):

    if "user_id" not in session:

        return redirect(url_for("login"))

    conn = get_db()

    file = conn.execute(
        """
        SELECT *
        FROM files
        WHERE id = ?
        AND user_id = ?
        """,
        (
            file_id,
            session["user_id"]
        )
    ).fetchone()

    if not file:

        conn.close()

        return "File not found!"

    # Already encrypted
    if file["encrypted"] == 1:

        conn.close()

        return redirect(url_for("dashboard"))

    original_path = file["filepath"]

    if not original_path or not os.path.exists(original_path):

        conn.close()

        return "Original file not found!"

    try:

        # Read original file
        with open(original_path, "rb") as original_file:

            file_data = original_file.read()

        # Encrypt
        encrypted_data = fernet.encrypt(file_data)

        # Create encrypted filename
        encrypted_filename = (
            file["filename"]
            + ".encrypted"
        )

        encrypted_path = os.path.join(
            app.config["ENCRYPTED_FOLDER"],
            encrypted_filename
        )

        # Save encrypted file
        with open(
            encrypted_path,
            "wb"
        ) as encrypted_file:

            encrypted_file.write(encrypted_data)

        # Update database
        conn.execute(
            """
            UPDATE files

            SET encrypted = 1,
                encrypted_path = ?

            WHERE id = ?
            AND user_id = ?
            """,
            (
                encrypted_path,
                file_id,
                session["user_id"]
            )
        )

        conn.commit()

    except Exception as e:

        conn.close()

        return f"Encryption failed: {str(e)}"

    conn.close()

    return redirect(url_for("dashboard"))


# ==================================================
# DECRYPT FILE
# ==================================================

@app.route("/decrypt/<int:file_id>", methods=["POST"])
def decrypt_file(file_id):

    if "user_id" not in session:

        return redirect(url_for("login"))

    conn = get_db()

    file = conn.execute(
        """
        SELECT *
        FROM files
        WHERE id = ?
        AND user_id = ?
        """,
        (
            file_id,
            session["user_id"]
        )
    ).fetchone()

    if not file:

        conn.close()

        return "File not found!"

    # Must be encrypted
    if file["encrypted"] != 1:

        conn.close()

        return "File is not encrypted!"

    encrypted_path = file["encrypted_path"]

    if not encrypted_path:

        conn.close()

        return "Encrypted file path not found!"

    if not os.path.exists(encrypted_path):

        conn.close()

        return "Encrypted file not found!"

    try:

        # Read encrypted file
        with open(
            encrypted_path,
            "rb"
        ) as encrypted_file:

            encrypted_data = encrypted_file.read()

        # Decrypt
        decrypted_data = fernet.decrypt(
            encrypted_data
        )

        # Create decrypted path
        decrypted_filename = file["filename"]

        decrypted_path = os.path.join(
            app.config["DECRYPTED_FOLDER"],
            decrypted_filename
        )

        # Save decrypted file
        with open(
            decrypted_path,
            "wb"
        ) as decrypted_file:

            decrypted_file.write(decrypted_data)

        # Update database
        conn.execute(
            """
            UPDATE files

            SET decrypted = 1,
                decrypted_path = ?

            WHERE id = ?
            AND user_id = ?
            """,
            (
                decrypted_path,
                file_id,
                session["user_id"]
            )
        )

        conn.commit()

    except Exception as e:

        conn.close()

        return f"Decryption failed: {str(e)}"

    conn.close()

    return redirect(url_for("dashboard"))


# ==================================================
# DOWNLOAD ORIGINAL
# ==================================================

@app.route("/download/original/<int:file_id>")
def download_original(file_id):

    if "user_id" not in session:

        return redirect(url_for("login"))

    conn = get_db()

    file = conn.execute(
        """
        SELECT *
        FROM files
        WHERE id = ?
        AND user_id = ?
        """,
        (
            file_id,
            session["user_id"]
        )
    ).fetchone()

    conn.close()

    if not file:

        return "File not found!"

    filepath = file["filepath"]

    if not filepath:

        return "Original file path not found!"

    if not os.path.exists(filepath):

        return "Original file not found!"

    return send_file(
        filepath,
        as_attachment=True,
        download_name=file["filename"]
    )


# ==================================================
# DOWNLOAD ENCRYPTED
# ==================================================

@app.route("/download/encrypted/<int:file_id>")
def download_encrypted(file_id):

    if "user_id" not in session:

        return redirect(url_for("login"))

    conn = get_db()

    file = conn.execute(
        """
        SELECT *
        FROM files
        WHERE id = ?
        AND user_id = ?
        """,
        (
            file_id,
            session["user_id"]
        )
    ).fetchone()

    conn.close()

    if not file:

        return "File not found!"

    if file["encrypted"] != 1:

        return "File is not encrypted yet!"

    encrypted_path = file["encrypted_path"]

    if not encrypted_path:

        return "Encrypted file path not found!"

    if not os.path.exists(encrypted_path):

        return "Encrypted file not found!"

    return send_file(
        encrypted_path,
        as_attachment=True,
        download_name=file["filename"] + ".encrypted"
    )


# ==================================================
# DOWNLOAD DECRYPTED
# ==================================================

@app.route("/download/decrypted/<int:file_id>")
def download_decrypted(file_id):

    if "user_id" not in session:

        return redirect(url_for("login"))

    conn = get_db()

    file = conn.execute(
        """
        SELECT *
        FROM files
        WHERE id = ?
        AND user_id = ?
        """,
        (
            file_id,
            session["user_id"]
        )
    ).fetchone()

    conn.close()

    if not file:

        return "File not found!"

    if file["decrypted"] != 1:

        return "File has not been decrypted yet!"

    decrypted_path = file["decrypted_path"]

    if not decrypted_path:

        return "Decrypted file path not found!"

    if not os.path.exists(decrypted_path):

        return "Decrypted file not found!"

    return send_file(
        decrypted_path,
        as_attachment=True,
        download_name=file["filename"]
    )


# ==================================================
# DELETE FILE
# ==================================================

@app.route("/delete/<int:file_id>", methods=["POST"])
def delete_file(file_id):

    if "user_id" not in session:

        return redirect(url_for("login"))

    conn = get_db()

    file = conn.execute(
        """
        SELECT *
        FROM files
        WHERE id = ?
        AND user_id = ?
        """,
        (
            file_id,
            session["user_id"]
        )
    ).fetchone()

    if not file:

        conn.close()

        return "File not found!"

    # Delete original
    original_path = file["filepath"]

    if original_path and os.path.exists(original_path):

        try:
            os.remove(original_path)
        except Exception:
            pass

    # Delete encrypted
    encrypted_path = file["encrypted_path"]

    if encrypted_path and os.path.exists(encrypted_path):

        try:
            os.remove(encrypted_path)
        except Exception:
            pass

    # Delete decrypted
    decrypted_path = file["decrypted_path"]

    if decrypted_path and os.path.exists(decrypted_path):

        try:
            os.remove(decrypted_path)
        except Exception:
            pass

    # Delete database record
    conn.execute(
        """
        DELETE FROM files
        WHERE id = ?
        AND user_id = ?
        """,
        (
            file_id,
            session["user_id"]
        )
    )

    conn.commit()

    conn.close()

    return redirect(url_for("dashboard"))


# ==================================================
# LOGOUT
# ==================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("home"))


# ==================================================
# INITIALIZE DATABASE
# ==================================================

init_db()


# ==================================================
# START APPLICATION
# ==================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )