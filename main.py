import os
import re
import json
import uuid
import sqlite3
import hashlib
import secrets
import mimetypes
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Header
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

try:
    from google import genai
    from google.genai import types
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

# ==========================================================
# CONFIGURATION: Paste your Gemini API Key below
# ==========================================================
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

app = FastAPI(title="SmritiAI — Smart Conversational Memory Vault v2.1")

os.makedirs("uploads", exist_ok=True)
os.makedirs("static", exist_ok=True)

app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")
app.mount("/static", StaticFiles(directory="static"), name="static")

DB_NAME = "smriti_vault.db"


def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000
    ).hex()
    return f"{salt}${pwd_hash}"


def verify_password(password: str, stored_value: str) -> bool:
    try:
        salt, pwd_hash = stored_value.split("$", 1)
        check_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000
        ).hex()
        return secrets.compare_digest(pwd_hash, check_hash)
    except Exception:
        return False


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='folders'")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(folders)")
        cols = [row["name"] for row in cursor.fetchall()]
        if "user_id" not in cols:
            cursor.execute("ALTER TABLE folders RENAME TO folders_v1")
            cursor.execute("""
                CREATE TABLE folders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(user_id, name)
                )
            """)
            cursor.execute("""
                INSERT INTO folders (id, user_id, name, created_at)
                SELECT id, 1, name, created_at FROM folders_v1
            """)
            cursor.execute("DROP TABLE folders_v1")
    else:
        cursor.execute("""
            CREATE TABLE folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(user_id, name)
            )
        """)

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='memories'")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(memories)")
        cols = [row["name"] for row in cursor.fetchall()]
        if "user_id" not in cols:
            cursor.execute("ALTER TABLE memories ADD COLUMN user_id INTEGER NOT NULL DEFAULT 1")
        if "ocr_text" not in cols:
            cursor.execute("ALTER TABLE memories ADD COLUMN ocr_text TEXT DEFAULT ''")
    else:
        cursor.execute("""
            CREATE TABLE memories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                folder_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                ocr_text TEXT DEFAULT '',
                image_path TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (folder_id) REFERENCES folders (id)
            )
        """)

    conn.commit()
    conn.close()


init_db()


class AuthPayload(BaseModel):
    full_name: Optional[str] = ""
    username: str
    password: str


def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Login required")
    token = authorization.replace("Bearer ", "").strip()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.id, u.full_name, u.username
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token = ?
    """, (token,))
    user = cursor.fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return dict(user)


def get_date_badge(dt_str: str) -> str:
    try:
        record_date = datetime.strptime(dt_str[:10], "%Y-%m-%d").date()
        today = datetime.now().date()
        yesterday = today - timedelta(days=1)
        if record_date == today:
            return "Today"
        elif record_date == yesterday:
            return "Yesterday"
        else:
            return record_date.strftime("%d %b %Y")
    except Exception:
        return dt_str[:10]


def get_or_create_folder(conn, user_id: int, folder_name: str) -> int:
    clean_name = folder_name.strip().title()
    if not clean_name:
        clean_name = "General"
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM folders WHERE user_id = ? AND LOWER(name) = LOWER(?)",
        (user_id, clean_name),
    )
    row = cursor.fetchone()
    if row:
        return row["id"]
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO folders (user_id, name, created_at) VALUES (?, ?, ?)",
        (user_id, clean_name, now_str),
    )
    conn.commit()
    return cursor.lastrowid


def smart_ai_processor(
    user_text: str,
    image_bytes: Optional[bytes],
    mime_type: Optional[str],
    existing_folders: list,
):
    has_image = image_bytes is not None
    use_gemini = (
        GEMINI_AVAILABLE
        and GEMINI_API_KEY
        and GEMINI_API_KEY != "APNI_GEMINI_API_KEY_YAHAN_DALEIN"
    )

    if use_gemini:
        try:
            client = genai.Client(api_key=GEMINI_API_KEY)
            prompt = f"""
            You are 'SmritiAI', a smart personal and family memory vault assistant.
            User message: "{user_text}"
            Did the user attach an image?: {has_image}
            User's existing folders: {existing_folders}

            Instructions:
            1. Determine whether the user wants to STORE new data/image ('SAVE') or RETRIEVE/QUERY existing data ('SEARCH').
               (If an image is attached, the intent is always 'SAVE').
            2. If 'SAVE':
               - Identify the best target folder (e.g., 'Tractor', 'Warranty', 'Medical', 'Bills', 'Documents').
               - Reuse an existing matching folder name if available, otherwise create a concise 1-2 word Title-Case folder name.
               - Write a clean, clear note in natural English for 'clean_data'.
               - If an image is provided, extract key text from it (company/product name, bill amount, warranty period, date) and write a concise summary in English (max 200 characters) in 'ocr_text'. If no image is provided, leave 'ocr_text' as "".
            3. If 'SEARCH':
               - Extract the main search keyword in 'search_keyword' (e.g., 'tractor', 'warranty', 'samsung').
            4. Write a short, polite, clear reply in English for 'ai_reply'.

            Return ONLY valid JSON matching this exact schema:
            {{
                "intent": "SAVE" or "SEARCH",
                "folder_name": "Folder Name",
                "clean_data": "Clean English note text",
                "ocr_text": "Extracted text from image or empty",
                "search_keyword": "Keyword if SEARCH else empty",
                "ai_reply": "Friendly English reply"
            }}
            """
            contents = [prompt]
            if has_image and mime_type:
                contents.append(types.Part.from_bytes(data=image_bytes, mime_type=mime_type))

            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=contents,
                config={"response_mime_type": "application/json"},
            )
            return json.loads(response.text)
        except Exception as e:
            print("Gemini API Fallback triggered:", e)

    text_lower = user_text.lower()
    is_question = (
        not has_image
        and any(w in text_lower for w in ["what", "show", "tell", "how much", "when", "who", "search", "find", "kya", "dikhao", "batao", "?"])
        and not any(w in text_lower for w in ["store", "save", "keep", "add", "put", "rakh", "likh", "daal"])
    )

    folder_name = "Warranty" if has_image else "General"
    match = re.search(r"([a-zA-Z0-9_-]+)\s+(?:wale|wali|ka|ki|ke)?\s*folder", text_lower)
    if not match:
        match = re.search(r"in\s+(?:the\s+)?([a-zA-Z0-9_-]+)", text_lower)
    if match:
        folder_name = match.group(1).title()
    else:
        for f in existing_folders:
            if f.lower() in text_lower:
                folder_name = f
                break

    if is_question:
        clean_kw = re.sub(
            r"\b(what|is|was|show|tell|me|my|the|in|data|folder|kya|hai|tha|dikhao|batao)\b",
            "",
            text_lower,
        ).strip()
        return {
            "intent": "SEARCH",
            "folder_name": folder_name,
            "clean_data": user_text,
            "ocr_text": "",
            "search_keyword": clean_kw if clean_kw else folder_name,
            "ai_reply": f"Searching your vault for memories related to '{clean_kw or folder_name}'...",
        }

    clean_note = user_text.strip() if user_text.strip() else "Saved image document"
    return {
        "intent": "SAVE",
        "folder_name": folder_name,
        "clean_data": clean_note,
        "ocr_text": "",
        "search_keyword": "",
        "ai_reply": f"Done! I have safely stored your memory in the '{folder_name}' folder under today's date.",
    }


@app.get("/")
def serve_home():
    return FileResponse("static/index.html")


@app.post("/api/register")
def register_user(payload: AuthPayload):
    username = payload.username.strip().lower()
    full_name = (payload.full_name or username).strip()
    if len(username) < 3 or len(payload.password) < 4:
        raise HTTPException(
            status_code=400,
            detail="Username must be at least 3 characters and password at least 4 characters.",
        )

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="This mobile number or username is already registered. Please log in.")

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pwd_hash = hash_password(payload.password)
    cursor.execute(
        "INSERT INTO users (full_name, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (full_name, username, pwd_hash, now_str),
    )
    user_id = cursor.lastrowid
    token = secrets.token_hex(24)
    cursor.execute(
        "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
        (token, user_id, now_str),
    )
    conn.commit()
    conn.close()
    return {"token": token, "user": {"id": user_id, "full_name": full_name, "username": username}}


@app.post("/api/login")
def login_user(payload: AuthPayload):
    username = payload.username.strip().lower()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user or not verify_password(payload.password, user["password_hash"]):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid username or password!")

    token = secrets.token_hex(24)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
        (token, user["id"], now_str),
    )
    conn.commit()
    conn.close()
    return {
        "token": token,
        "user": {"id": user["id"], "full_name": user["full_name"], "username": user["username"]},
    }


@app.get("/api/data")
def get_all_data(
    folder_id: Optional[int] = None,
    search: Optional[str] = None,
    authorization: Optional[str] = Header(None),
):
    user = get_current_user(authorization)
    user_id = user["id"]

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT f.id, f.name, COUNT(m.id) as count
        FROM folders f
        LEFT JOIN memories m ON f.id = m.folder_id AND m.user_id = ?
        WHERE f.user_id = ?
        GROUP BY f.id
        ORDER BY f.name ASC
    """, (user_id, user_id))
    folders = [dict(row) for row in cursor.fetchall()]

    query = """
        SELECT m.id, m.folder_id, f.name as folder_name, m.content, m.ocr_text, m.image_path, m.created_at
        FROM memories m
        JOIN folders f ON m.folder_id = f.id
        WHERE m.user_id = ?
    """
    params = [user_id]
    if folder_id:
        query += " AND m.folder_id = ?"
        params.append(folder_id)
    if search:
        query += " AND (LOWER(m.content) LIKE ? OR LOWER(m.ocr_text) LIKE ? OR LOWER(f.name) LIKE ?)"
        kw = f"%{search.lower()}%"
        params.extend([kw, kw, kw])

    query += " ORDER BY m.created_at DESC, m.id DESC"
    cursor.execute(query, params)

    memories = []
    for row in cursor.fetchall():
        item = dict(row)
        item["date_badge"] = get_date_badge(item["created_at"])
        item["time_only"] = datetime.strptime(item["created_at"], "%Y-%m-%d %H:%M:%S").strftime("%I:%M %p")
        memories.append(item)

    conn.close()
    gemini_active = GEMINI_AVAILABLE and GEMINI_API_KEY != "APNI_GEMINI_API_KEY_YAHAN_DALEIN"
    return {
        "user": user,
        "folders": folders,
        "memories": memories,
        "gemini_active": gemini_active,
    }


@app.post("/api/chat")
async def process_chat(
    message: str = Form(""),
    image: Optional[UploadFile] = File(None),
    authorization: Optional[str] = Header(None),
):
    user = get_current_user(authorization)
    user_id = user["id"]

    if not message.strip() and not image:
        raise HTTPException(status_code=400, detail="Please type a note, speak, or attach an image.")

    image_bytes = None
    mime_type = None
    if image and image.filename:
        image_bytes = await image.read()
        mime_type = image.content_type or mimetypes.guess_type(image.filename)[0] or "image/jpeg"

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM folders WHERE user_id = ?", (user_id,))
    existing_folders = [r["name"] for r in cursor.fetchall()]

    ai_result = smart_ai_processor(message, image_bytes, mime_type, existing_folders)
    intent = ai_result.get("intent", "SAVE")

    if intent == "SEARCH":
        kw = ai_result.get("search_keyword", "").strip()
        cursor.execute("""
            SELECT m.id
            FROM memories m
            JOIN folders f ON m.folder_id = f.id
            WHERE m.user_id = ?
              AND (LOWER(m.content) LIKE ? OR LOWER(m.ocr_text) LIKE ? OR LOWER(f.name) LIKE ?)
        """, (user_id, f"%{kw.lower()}%", f"%{kw.lower()}%", f"%{kw.lower()}%"))
        results = cursor.fetchall()
        conn.close()

        if results:
            reply = f"Found {len(results)} matching record(s) for '{kw}' in your timeline below:"
        else:
            reply = f"Sorry {user['full_name']}, no saved memories were found matching '{kw}'."

        return {
            "status": "search",
            "ai_reply": reply,
            "search_keyword": kw,
            "count": len(results),
        }

    folder_name = ai_result.get("folder_name", "General")
    clean_data = ai_result.get("clean_data", message.strip() or "Saved Image Document")
    ocr_text = ai_result.get("ocr_text", "").strip()
    folder_id = get_or_create_folder(conn, user_id, folder_name)

    saved_image_url = None
    if image_bytes and image and image.filename:
        ext = os.path.splitext(image.filename)[1] or ".jpg"
        unique_name = f"{uuid.uuid4().hex}{ext}"
        file_location = os.path.join("uploads", unique_name)
        with open(file_location, "wb") as buffer:
            buffer.write(image_bytes)
        saved_image_url = f"/uploads/{unique_name}"

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        """
        INSERT INTO memories (user_id, folder_id, content, ocr_text, image_path, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_id, folder_id, clean_data, ocr_text, saved_image_url, now_str),
    )
    conn.commit()
    conn.close()

    return {
        "status": "saved",
        "ai_reply": ai_result.get("ai_reply", f"Saved to the '{folder_name}' folder!"),
        "folder_name": folder_name,
    }


@app.delete("/api/memory/{memory_id}")
def delete_memory(memory_id: int, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT image_path FROM memories WHERE id = ? AND user_id = ?",
        (memory_id, user["id"]),
    )
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Record not found")

    if row["image_path"]:
        disk_path = row["image_path"].lstrip("/")
        if os.path.exists(disk_path):
            os.remove(disk_path)

    cursor.execute("DELETE FROM memories WHERE id = ? AND user_id = ?", (memory_id, user["id"]))
    conn.commit()
    conn.close()
    return {"status": "deleted"}


@app.delete("/api/folder/{folder_id}")
def delete_folder(folder_id: int, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id FROM folders WHERE id = ? AND user_id = ?",
        (folder_id, user["id"]),
    )
    folder = cursor.fetchone()
    if not folder:
        conn.close()
        raise HTTPException(status_code=404, detail="Folder not found")

    # Delete all image files belonging to memories inside this folder
    cursor.execute(
        "SELECT image_path FROM memories WHERE folder_id = ? AND user_id = ?",
        (folder_id, user["id"]),
    )
    for row in cursor.fetchall():
        if row["image_path"]:
            disk_path = row["image_path"].lstrip("/")
            if os.path.exists(disk_path):
                os.remove(disk_path)

    # Delete all memories inside this folder, then delete the folder
    cursor.execute(
        "DELETE FROM memories WHERE folder_id = ? AND user_id = ?",
        (folder_id, user["id"]),
    )
    cursor.execute(
        "DELETE FROM folders WHERE id = ? AND user_id = ?",
        (folder_id, user["id"]),
    )
    conn.commit()
    conn.close()
    return {"status": "deleted"}