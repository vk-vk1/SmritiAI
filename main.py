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
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

try:
    from google import genai
    from google.genai import types
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

# ==========================================================
# CONFIGURATION: Reads GEMINI_API_KEY from Render Environment
# ==========================================================
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()

app = FastAPI(title="SmritiAI — Smart Conversational Memory Vault v2.5")

os.makedirs("uploads", exist_ok=True)
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

DB_NAME = "smriti_vault.db"

STOP_WORDS = {
    "a", "an", "the", "my", "this", "that", "new", "folder", "folders",
    "create", "make", "add", "open", "save", "store", "put", "keep",
    "in", "into", "inside", "to", "for", "of", "named", "called", "with",
    "ek", "ak", "ik", "ka", "ki", "ke", "ko", "me", "mein", "se", "par",
    "wale", "wali", "naam", "name", "naya", "nayi", "naye", "bnao", "banao",
    "banado", "bana", "do", "de", "dijiye", "rakh", "rakho", "daal", "dal", "likh", "likho"
}


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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS folders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, name)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS memories (
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


class FolderCreatePayload(BaseModel):
    name: str


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
    if not clean_name or clean_name.lower() in STOP_WORDS:
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


def extract_folder_name_smart(user_text: str, existing_folders: list, default_name: str = "General") -> str:
    text_lower = user_text.lower()
    for f in existing_folders:
        if re.search(rf"\b{re.escape(f.lower())}\b", text_lower):
            return f

    m1 = re.search(r"\b([a-zA-Z0-9_-]+)\s+(?:naam\s+)?(?:ka|ki|ke|wale|wali)\s+folder\b", text_lower)
    if m1 and m1.group(1) not in STOP_WORDS:
        return m1.group(1).title()

    m2 = re.search(r"\bfolder\s+(?:named|called|for|of)\s+([a-zA-Z0-9_-]+)\b", text_lower)
    if m2 and m2.group(1) not in STOP_WORDS:
        return m2.group(1).title()

    m3 = re.search(r"\b([a-zA-Z0-9_-]+)\s+folder\b", text_lower)
    if m3 and m3.group(1) not in STOP_WORDS:
        return m3.group(1).title()

    m4 = re.search(r"\bfolder\s+([a-zA-Z0-9_-]+)\b", text_lower)
    if m4 and m4.group(1) not in STOP_WORDS:
        return m4.group(1).title()

    return default_name


def smart_ai_processor(
    user_text: str,
    image_bytes: Optional[bytes],
    mime_type: Optional[str],
    existing_folders: list,
    active_folder_name: Optional[str] = None,
):
    has_image = image_bytes is not None
    use_gemini = GEMINI_AVAILABLE and bool(GEMINI_API_KEY)

    if use_gemini:
        try:
            client = genai.Client(api_key=GEMINI_API_KEY)
            active_ctx = (
                f'The user currently has the folder "{active_folder_name}" open. Store new memories inside "{active_folder_name}".'
                if active_folder_name
                else "No specific folder is open; auto-select or create the best matching folder."
            )
            prompt = f"""
            You are 'SmritiAI', an intelligent personal & family memory vault assistant.
            You naturally understand conversational English, Hindi, and Hinglish (e.g., "ak Vishnu ka folder bnao", "kal tractor ke 1500 diye likh do", "Vishnu folder me kya hai?").

            User message: "{user_text}"
            Image attached?: {has_image}
            Existing folders: {existing_folders}
            Active folder context: {active_ctx}

            Choose ONE intent:
            1. "CREATE_FOLDER": User ONLY wants to create a folder without saving a note/image (e.g., "ak Vishnu ka folder bnao"). Put Title-Case folder name in 'folder_name' (NEVER grammar words like "Ka", "Ki", "Ke", "Ek", "Ak").
            2. "SAVE": User wants to save a note, expense, reminder, or attached image. Put target folder in 'folder_name', clean English note in 'clean_data', and image OCR summary in 'ocr_text' (max 200 chars, or "" if no image).
            3. "SEARCH": User wants to find/view saved memories. Put search keyword in 'search_keyword'.

            Write a friendly, natural English reply in 'ai_reply'.
            Return ONLY valid JSON:
            {{
                "intent": "CREATE_FOLDER" or "SAVE" or "SEARCH",
                "folder_name": "Folder Name",
                "clean_data": "Clean English note",
                "ocr_text": "Extracted image text or empty",
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
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    temperature=0.2,
                ),
            )
            raw_text = response.text.strip()
            if raw_text.startswith("```"):
                raw_text = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw_text, flags=re.DOTALL).strip()
            return json.loads(raw_text)
        except Exception as e:
            print("Gemini API Error (using smart fallback):", e)

    text_lower = user_text.lower().strip()
    default_folder = active_folder_name if active_folder_name else ("Warranty" if has_image else "General")
    folder_name = active_folder_name if active_folder_name else extract_folder_name_smart(user_text, existing_folders, default_folder)

    create_triggers = ["bnao", "banao", "banado", "bana do", "bana de", "create", "make", "new folder", "naya folder"]
    meaningful_words = [w for w in re.findall(r"[a-zA-Z0-9_-]+", text_lower) if w not in STOP_WORDS]

    if not has_image and "folder" in text_lower and any(t in text_lower for t in create_triggers) and len(meaningful_words) <= 2:
        extracted_new = extract_folder_name_smart(user_text, existing_folders, "General")
        return {
            "intent": "CREATE_FOLDER",
            "folder_name": extracted_new,
            "clean_data": "",
            "ocr_text": "",
            "search_keyword": "",
            "ai_reply": f"Done! I have created a new folder named '{extracted_new}' for you.",
        }

    is_question = (
        not has_image
        and any(w in text_lower for w in ["what", "show", "tell", "how much", "when", "who", "search", "find", "kya", "dikhao", "batao", "?"])
        and not any(w in text_lower for w in ["store", "save", "keep", "add", "put", "rakh", "likh", "daal"])
    )

    if is_question:
        clean_kw = " ".join(meaningful_words).strip()
        return {
            "intent": "SEARCH",
            "folder_name": folder_name,
            "clean_data": user_text,
            "ocr_text": "",
            "search_keyword": clean_kw if clean_kw else folder_name,
            "ai_reply": f"Searching your vault for '{clean_kw or folder_name}'...",
        }

    clean_note = user_text.strip() if user_text.strip() else "Saved image document"
    return {
        "intent": "SAVE",
        "folder_name": folder_name,
        "clean_data": clean_note,
        "ocr_text": "",
        "search_keyword": "",
        "ai_reply": f"Done! Stored safely in '{folder_name}' under today's date.",
    }


HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SmritiAI — Smart Conversational Memory Vault</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background: radial-gradient(circle at top left, #0f172a, #020617);
            color: #f8fafc;
            font-family: 'Segoe UI', system-ui, sans-serif;
            min-height: 100vh;
        }
        .hidden { display: none !important; }
        .glass {
            background: rgba(30, 41, 59, 0.78);
            backdrop-filter: blur(14px);
            border: 1px solid rgba(148, 163, 184, 0.22);
        }
        .auth-wrap {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 16px;
        }
        .auth-box {
            width: 100%;
            max-width: 410px;
            border-radius: 22px;
            padding: 28px;
            box-shadow: 0 20px 45px rgba(0, 0, 0, 0.65);
        }
        .brand { display: flex; align-items: center; gap: 12px; margin-bottom: 20px; }
        .logo {
            width: 44px; height: 44px; border-radius: 12px;
            background: linear-gradient(135deg, #6366f1, #22d3ee);
            display: flex; align-items: center; justify-content: center;
            font-weight: 800; color: #020617; font-size: 22px; flex-shrink: 0;
        }
        .tabs {
            display: grid; grid-template-columns: 1fr 1fr; gap: 6px;
            background: #0f172a; padding: 5px; border-radius: 12px; margin-bottom: 18px;
        }
        .tab {
            padding: 10px; border: none; border-radius: 8px; font-size: 13px;
            font-weight: 600; cursor: pointer; background: transparent; color: #94a3b8;
        }
        .tab.active { background: #4f46e5; color: #fff; }
        .field { margin-bottom: 14px; }
        .field label { display: block; font-size: 12px; color: #94a3b8; margin-bottom: 5px; }
        .inp {
            width: 100%; background: #0f172a; border: 1px solid #334155;
            border-radius: 10px; padding: 11px 13px; font-size: 14px; color: #fff; outline: none;
        }
        .inp:focus { border-color: #22d3ee; }
        .err {
            font-size: 12px; color: #fda4af; background: rgba(136, 19, 55, 0.55);
            border: 1px solid #f43f5e; border-radius: 8px; padding: 9px; margin-bottom: 12px;
        }
        .btn-main {
            width: 100%; background: linear-gradient(90deg, #4f46e5, #06b6d4);
            color: #fff; font-weight: 600; font-size: 14px; padding: 12px;
            border: none; border-radius: 10px; cursor: pointer;
        }
        .btn-main:disabled { opacity: 0.6; cursor: not-allowed; }
        .layout { min-height: 100vh; display: flex; flex-direction: column; }
        @media (min-width: 768px) { .layout { flex-direction: row; } }
        .sidebar {
            width: 100%; padding: 20px; border-bottom: 1px solid #1e293b;
            display: flex; flex-direction: column; justify-content: space-between;
        }
        @media (min-width: 768px) {
            .sidebar { width: 280px; flex-shrink: 0; border-bottom: none; border-right: 1px solid #1e293b; }
        }
        .row-between { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
        .btn-sm {
            font-size: 12px; background: #1e293b; color: #cbd5e1;
            border: 1px solid #334155; padding: 5px 10px; border-radius: 8px; cursor: pointer;
        }
        .btn-new {
            font-size: 12px; font-weight: 600; background: #4f46e5; color: #fff;
            border: none; padding: 5px 10px; border-radius: 8px; cursor: pointer;
        }
        .folder-list { display: flex; flex-direction: column; gap: 6px; margin-top: 12px; max-height: 48vh; overflow-y: auto; }
        .f-row {
            display: flex; align-items: center; justify-content: space-between;
            padding: 8px 10px; border-radius: 10px; border: 1px solid transparent;
        }
        .f-row:hover { background: rgba(30, 41, 59, 0.75); }
        .f-row.active { background: rgba(79, 70, 229, 0.3); border-color: rgba(99, 102, 241, 0.5); }
        .f-btn {
            flex: 1; display: flex; align-items: center; justify-content: space-between;
            background: transparent; border: none; color: #e2e8f0; font-size: 14px;
            cursor: pointer; text-align: left; padding-right: 8px; overflow: hidden;
        }
        .f-row.active .f-btn { color: #67e8f9; font-weight: 600; }
        .pill { font-size: 11px; background: #1e293b; color: #cbd5e1; padding: 2px 8px; border-radius: 99px; }
        .del-f { background: transparent; border: none; color: #64748b; cursor: pointer; font-size: 14px; padding: 2px 6px; }
        .del-f:hover { color: #fb7185; }
        .main { flex: 1; max-width: 960px; width: 100%; margin: 0 auto; padding: 20px; }
        .card { border-radius: 18px; padding: 20px; margin-bottom: 22px; }
        .banner {
            display: flex; align-items: center; justify-content: space-between;
            background: rgba(30, 27, 75, 0.9); border: 1px solid #22d3ee;
            padding: 8px 12px; border-radius: 10px; font-size: 12px; color: #a5f3fc; margin: 12px 0;
        }
        .chat-bar { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 14px; }
        .input-box {
            flex: 1; min-width: 240px; display: flex; align-items: center;
            background: #0f172a; border: 1px solid #334155; border-radius: 10px; padding: 4px 8px;
        }
        .input-box input {
            flex: 1; background: transparent; border: none; color: #fff;
            font-size: 14px; padding: 8px; outline: none;
        }
        .icon-btn {
            background: transparent; border: none; color: #94a3b8;
            font-size: 16px; padding: 6px 8px; cursor: pointer;
        }
        .icon-btn:hover { color: #22d3ee; }
        .send-btn {
            background: linear-gradient(90deg, #4f46e5, #06b6d4); color: #fff;
            font-weight: 600; border: none; border-radius: 10px; padding: 11px 20px; cursor: pointer;
        }
        .grid { display: grid; grid-template-columns: 1fr; gap: 14px; margin-top: 10px; }
        @media (min-width: 768px) { .grid { grid-template-columns: 1fr 1fr; } }
        .mem-card { border-radius: 14px; padding: 15px; }
        .tag {
            font-size: 11px; font-weight: 600; padding: 3px 9px; border-radius: 6px;
            background: rgba(99, 102, 241, 0.25); color: #a5b4fc;
        }
        .modal-bg {
            position: fixed; inset: 0; background: rgba(0, 0, 0, 0.82);
            z-index: 50; display: flex; align-items: center; justify-content: center; padding: 16px;
        }
        .modal-box { width: 100%; max-width: 360px; border-radius: 16px; padding: 22px; }
        .dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 6px; }
    </style>
</head>
<body>

    <!-- AUTH SCREEN -->
    <div id="authScreen" class="auth-wrap">
        <div class="glass auth-box">
            <div class="brand">
                <div class="logo">S</div>
                <div>
                    <h1 style="font-size:22px;">Smriti<span style="color:#22d3ee;">AI</span> <span style="font-size:11px;color:#34d399;font-weight:600;">v2.5</span></h1>
                    <p style="font-size:12px;color:#94a3b8;">Personal & Family Smart Memory Vault</p>
                </div>
            </div>

            <div class="tabs">
                <button type="button" id="tabLogin" class="tab active" onclick="switchAuthTab('login')">Login</button>
                <button type="button" id="tabRegister" class="tab" onclick="switchAuthTab('register')">Create Account</button>
            </div>

            <form onsubmit="handleAuth(event)">
                <div id="nameFieldBox" class="field hidden">
                    <label for="authName">Full Name</label>
                    <input type="text" id="authName" placeholder="Enter your full name" class="inp">
                </div>
                <div class="field">
                    <label for="authUsername">Mobile Number or Username</label>
                    <input type="text" id="authUsername" required placeholder="e.g. vishnu" class="inp">
                </div>
                <div class="field">
                    <label for="authPassword">Password</label>
                    <input type="password" id="authPassword" required placeholder="Minimum 4 characters" class="inp">
                </div>
                <p id="authError" class="err hidden"></p>
                <button type="submit" id="authSubmitBtn" class="btn-main">Open Vault</button>
            </form>
        </div>
    </div>

    <!-- MAIN DASHBOARD -->
    <div id="appScreen" class="hidden layout">
        <aside class="glass sidebar">
            <div>
                <div class="row-between" style="margin-bottom:22px;">
                    <div style="display:flex;align-items:center;gap:10px;">
                        <div class="logo" style="width:36px;height:36px;font-size:18px;">S</div>
                        <div>
                            <h2 style="font-size:18px;">Smriti<span style="color:#22d3ee;">AI</span></h2>
                            <p id="userDisplayName" style="font-size:12px;color:#67e8f9;">User</p>
                        </div>
                    </div>
                    <button type="button" onclick="logout()" class="btn-sm">Logout</button>
                </div>

                <div class="row-between">
                    <span style="font-size:11px;font-weight:700;color:#94a3b8;text-transform:uppercase;">Your Private Folders</span>
                    <button type="button" onclick="openFolderModal()" class="btn-new">+ New</button>
                </div>
                <nav id="folderList" class="folder-list"></nav>
            </div>

            <div style="margin-top:20px;padding-top:14px;border-top:1px solid #1e293b;display:flex;flex-direction:column;gap:8px;">
                <button type="button" onclick="toggleVoiceReply()" class="btn-sm row-between" style="width:100%;padding:8px 10px;">
                    <span>AI Voice Reply</span>
                    <span id="voiceStatusText" style="color:#34d399;font-weight:700;">ON</span>
                </button>
                <div id="aiModeBadge" style="font-size:12px;padding:8px 10px;border-radius:8px;background:#0f172a;color:#cbd5e1;">
                    Checking AI...
                </div>
            </div>
        </aside>

        <main class="main">
            <section class="glass card">
                <h2 id="aiGreeting" style="font-size:18px;">Welcome! What special memory would you like to save today?</h2>
                <p id="aiSubReply" style="font-size:13px;color:#67e8f9;margin-top:4px;">Click any folder on the left to write inside it, or type/speak naturally below.</p>

                <div id="activeFolderBanner" class="banner hidden">
                    <span>📁 Writing inside folder: <strong id="activeFolderLabel" style="color:#fff;"></strong></span>
                    <button type="button" onclick="resetFilters()" class="btn-sm" style="padding:3px 8px;">Exit Folder ×</button>
                </div>

                <div id="imagePreviewBox" class="hidden" style="margin-top:10px;display:flex;align-items:center;gap:10px;background:#0f172a;padding:8px;border-radius:10px;">
                    <img id="imagePreview" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7" alt="Preview" style="width:44px;height:44px;object-fit:cover;border-radius:6px;">
                    <span id="imageName" style="font-size:12px;color:#cbd5e1;"></span>
                    <button type="button" onclick="clearImage()" class="icon-btn" style="color:#fb7185;">×</button>
                </div>

                <form onsubmit="handleSend(event)" class="chat-bar">
                    <div class="input-box">
                        <input type="file" id="imageInput" accept="image/*" class="hidden" onchange="previewSelectedImage(event)">
                        <button type="button" onclick="document.getElementById('imageInput').click()" title="Attach Photo" class="icon-btn">📎</button>
                        <input type="text" id="userInput" autocomplete="off" placeholder="Type a note or click mic to speak...">
                        <button type="button" id="micBtn" onclick="startVoiceInput()" title="Speak" class="icon-btn">🎤</button>
                    </div>
                    <button type="submit" id="sendBtn" class="send-btn"><span id="sendBtnText">Save / Ask AI</span></button>
                </form>
            </section>

            <div class="row-between" style="margin-bottom:14px;flex-wrap:wrap;">
                <h3 id="timelineTitle" style="font-size:16px;">All Memories (Date-Wise Timeline)</h3>
                <div style="display:flex;gap:8px;align-items:center;">
                    <input type="text" id="quickSearchInput" oninput="handleQuickSearch(this.value)" placeholder="Search notes..." class="inp" style="padding:6px 10px;font-size:12px;width:180px;">
                    <button type="button" onclick="resetFilters()" class="btn-sm">Reset</button>
                </div>
            </div>

            <div id="timelineContainer"></div>
        </main>
    </div>

    <!-- NEW FOLDER MODAL -->
    <div id="folderModal" class="modal-bg hidden">
        <div class="glass modal-box">
            <div class="row-between" style="margin-bottom:14px;">
                <h3 style="font-size:16px;">Create New Folder</h3>
                <button type="button" onclick="closeFolderModal()" class="icon-btn">×</button>
            </div>
            <form onsubmit="handleCreateFolder(event)">
                <input type="text" id="newFolderNameInput" required placeholder="e.g., Vishnu, Medical, Bills" class="inp">
                <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:14px;">
                    <button type="button" onclick="closeFolderModal()" class="btn-sm">Cancel</button>
                    <button type="submit" id="createFolderSubmitBtn" class="btn-new" style="padding:8px 14px;">Create & Open</button>
                </div>
            </form>
        </div>
    </div>

    <!-- FULL IMAGE MODAL -->
    <div id="imageModal" onclick="closeModal()" class="modal-bg hidden" style="cursor:pointer;">
        <img id="modalImg" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7" alt="Full Preview" style="max-height:90vh;max-width:95vw;border-radius:10px;">
    </div>

    <script>
        var BLANK_IMG = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";
        var authMode = "login";
        var authToken = localStorage.getItem("smriti_token") || "";
        var activeFolderId = null;
        var activeFolderName = null;
        var voiceReplyEnabled = true;
        var searchTimer = null;

        function esc(t) {
            return String(t || "").replace(/&/g,"&").replace(/</g,"<").replace(/>/g,">").replace(/"/g,""");
        }

        function switchAuthTab(mode) {
            authMode = mode;
            document.getElementById("authError").className = "err hidden";
            var isReg = (mode === "register");
            document.getElementById("tabRegister").className = isReg ? "tab active" : "tab";
            document.getElementById("tabLogin").className = isReg ? "tab" : "tab active";
            document.getElementById("nameFieldBox").className = isReg ? "field" : "field hidden";
            document.getElementById("authSubmitBtn").innerText = isReg ? "Create Private Vault" : "Open Vault";
        }

        async function handleAuth(e) {
            e.preventDefault();
            var full_name = document.getElementById("authName").value;
            var username = document.getElementById("authUsername").value;
            var password = document.getElementById("authPassword").value;
            var errBox = document.getElementById("authError");
            var btn = document.getElementById("authSubmitBtn");
            errBox.className = "err hidden";
            btn.disabled = true;
            btn.innerText = "Please wait...";

            try {
                var res = await fetch(authMode === "register" ? "/api/register" : "/api/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ full_name: full_name, username: username, password: password })
                });
                var rawText = await res.text();
                var data = {};
                try { data = JSON.parse(rawText); } catch (err) { data = { detail: "Server is waking up. Please wait 30 seconds and click again." }; }

                if (!res.ok) {
                    errBox.innerText = data.detail || "Authentication failed.";
                    errBox.className = "err";
                    return;
                }
                authToken = data.token;
                localStorage.setItem("smriti_token", authToken);
                showAppScreen();
            } catch (err) {
                errBox.innerText = "Network error. Please wait 30 seconds and try again.";
                errBox.className = "err";
            } finally {
                btn.disabled = false;
                btn.innerText = authMode === "register" ? "Create Private Vault" : "Open Vault";
            }
        }

        function logout() {
            localStorage.removeItem("smriti_token");
            authToken = ""; activeFolderId = null; activeFolderName = null;
            document.getElementById("appScreen").className = "hidden layout";
            document.getElementById("authScreen").className = "auth-wrap";
        }

        function showAppScreen() {
            document.getElementById("authScreen").className = "hidden auth-wrap";
            document.getElementById("appScreen").className = "layout";
            loadVaultData();
        }

        function openFolderModal() {
            document.getElementById("newFolderNameInput").value = "";
            document.getElementById("folderModal").className = "modal-bg";
            setTimeout(function() { document.getElementById("newFolderNameInput").focus(); }, 50);
        }

        function closeFolderModal() {
            document.getElementById("folderModal").className = "modal-bg hidden";
        }

        async function handleCreateFolder(e) {
            e.preventDefault();
            var name = document.getElementById("newFolderNameInput").value.trim();
            if (!name) return;
            var res = await fetch("/api/folder", {
                method: "POST",
                headers: { "Content-Type": "application/json", "Authorization": "Bearer " + authToken },
                body: JSON.stringify({ name: name })
            });
            var data = await res.json();
            if (res.ok) {
                closeFolderModal();
                document.getElementById("aiSubReply").innerText = "Folder '" + data.folder.name + "' is open. Type a note below to save inside it.";
                await loadVaultData(data.folder.id, null, data.folder.name + " Folder", data.folder.name);
            }
        }

        function toggleVoiceReply() {
            voiceReplyEnabled = !voiceReplyEnabled;
            var el = document.getElementById("voiceStatusText");
            el.innerText = voiceReplyEnabled ? "ON" : "OFF";
            el.style.color = voiceReplyEnabled ? "#34d399" : "#64748b";
        }

        function speakText(text) {
            if (!voiceReplyEnabled || !("speechSynthesis" in window)) return;
            window.speechSynthesis.cancel();
            var u = new SpeechSynthesisUtterance(text);
            u.lang = "en-IN";
            window.speechSynthesis.speak(u);
        }

        async function deleteFolder(id, name) {
            if (!confirm("Delete '" + name + "' folder and all memories inside it?")) return;
            await fetch("/api/folder/" + id, { method: "DELETE", headers: { "Authorization": "Bearer " + authToken } });
            if (activeFolderId === id) { activeFolderId = null; activeFolderName = null; }
            loadVaultData(activeFolderId, null, activeFolderName ? activeFolderName + " Folder" : null, activeFolderName);
        }

        async function loadVaultData(folderId, searchKw, customTitle, folderName) {
            if (folderId === undefined) folderId = null;
            if (searchKw === undefined) searchKw = null;
            if (customTitle === undefined) customTitle = null;
            if (folderName === undefined) folderName = null;

            activeFolderId = folderId;
            activeFolderName = folderId === null ? null : (folderName || activeFolderName);

            var banner = document.getElementById("activeFolderBanner");
            if (activeFolderId && activeFolderName) {
                document.getElementById("activeFolderLabel").innerText = activeFolderName;
                banner.className = "banner";
                document.getElementById("userInput").placeholder = "Write a note inside '" + activeFolderName + "'...";
                document.getElementById("sendBtnText").innerText = "Save in " + activeFolderName;
            } else {
                banner.className = "banner hidden";
                document.getElementById("userInput").placeholder = "Type a note or click mic to speak...";
                document.getElementById("sendBtnText").innerText = "Save / Ask AI";
            }

            var url = "/api/data?";
            if (folderId) url += "folder_id=" + folderId + "&";
            if (searchKw) url += "search=" + encodeURIComponent(searchKw) + "&";

            var res = await fetch(url, { headers: { "Authorization": "Bearer " + authToken } });
            if (res.status === 401) { logout(); return; }
            var data = await res.json();

            document.getElementById("userDisplayName").innerText = data.user.full_name;
            document.getElementById("aiGreeting").innerText = "Welcome, " + data.user.full_name + "! What special memory would you like to save today?";
            document.getElementById("aiModeBadge").innerHTML = data.gemini_active
                ? '<span class="dot" style="background:#34d399;"></span>Gemini 2.5 Vision AI Active'
                : '<span class="dot" style="background:#fbbf24;"></span>Smart Local Mode Active';

            var total = data.folders.reduce(function(a, f) { return a + f.count; }, 0);
            var fHtml = '<div class="f-row ' + (!activeFolderId && !searchKw ? 'active' : '') + '">' +
                '<button type="button" class="f-btn" onclick="loadVaultData(null,null,\'All Memories (Date-Wise Timeline)\',null)">' +
                '<span>All Memories</span><span class="pill">' + total + '</span></button></div>';

            data.folders.forEach(function(f) {
                fHtml += '<div class="f-row ' + (activeFolderId === f.id ? 'active' : '') + '">' +
                    '<button type="button" class="f-btn" data-id="' + f.id + '" data-name="' + esc(f.name) + '" ' +
                    'onclick="loadVaultData(Number(this.dataset.id),null,this.dataset.name+\' Folder\',this.dataset.name)">' +
                    '<span>📁 ' + esc(f.name) + '</span><span class="pill">' + f.count + '</span></button>' +
                    '<button type="button" class="del-f" data-id="' + f.id + '" data-name="' + esc(f.name) + '" ' +
                    'onclick="deleteFolder(Number(this.dataset.id),this.dataset.name)" title="Delete Folder">🗑</button></div>';
            });
            document.getElementById("folderList").innerHTML = fHtml;
            document.getElementById("timelineTitle").innerText = customTitle || (activeFolderName ? activeFolderName + " Folder" : "All Memories (Date-Wise Timeline)");

            var container = document.getElementById("timelineContainer");
            if (!data.memories.length) {
                container.innerHTML = '<div class="glass card" style="text-align:center;color:#94a3b8;padding:36px;">No memories saved here yet.</div>';
                return;
            }
            var grouped = {};
            data.memories.forEach(function(m) {
                if (!grouped[m.date_badge]) grouped[m.date_badge] = [];
                grouped[m.date_badge].push(m);
            });
            var mHtml = "";
            Object.keys(grouped).forEach(function(badge) {
                var items = grouped[badge];
                mHtml += '<div style="margin-bottom:20px;"><span class="pill" style="background:#1e293b;color:#6ee7b7;font-weight:700;">' + esc(badge) + '</span><div class="grid">';
                items.forEach(function(it) {
                    mHtml += '<div class="glass mem-card">' +
                        '<div class="row-between" style="margin-bottom:8px;">' +
                        '<span class="tag">📁 ' + esc(it.folder_name) + '</span>' +
                        '<span style="font-size:11px;color:#94a3b8;">' + esc(it.time_only) +
                        '<button type="button" onclick="deleteMemory(' + it.id + ')" style="background:none;border:none;color:#fb7185;cursor:pointer;margin-left:6px;font-weight:700;">×</button></span></div>' +
                        '<p style="font-size:14px;line-height:1.5;">' + esc(it.content) + '</p>' +
                        (it.ocr_text ? '<div style="margin-top:8px;padding:7px;background:#020617;border-radius:6px;font-size:12px;color:#67e8f9;"><strong>AI Scan:</strong> ' + esc(it.ocr_text) + '</div>' : '') +
                        (it.image_path ? '<img src="' + esc(it.image_path) + '" onclick="openModal(this.src)" style="margin-top:10px;width:100%;height:150px;object-fit:cover;border-radius:8px;cursor:pointer;">' : '') +
                        '</div>';
                });
                mHtml += '</div></div>';
            });
            container.innerHTML = mHtml;
        }

        async function handleSend(e) {
            e.preventDefault();
            var inp = document.getElementById("userInput");
            var file = document.getElementById("imageInput");
            if (!inp.value.trim() && !file.files.length) return;

            var fd = new FormData();
            fd.append("message", inp.value);
            if (activeFolderId) fd.append("target_folder_id", String(activeFolderId));
            if (file.files.length) fd.append("image", file.files[0]);

            var btn = document.getElementById("sendBtn");
            btn.disabled = true;
            try {
                var res = await fetch("/api/chat", { method: "POST", headers: { "Authorization": "Bearer " + authToken }, body: fd });
                var data = await res.json();
                document.getElementById("aiSubReply").innerText = data.ai_reply;
                speakText(data.ai_reply);
                inp.value = ""; clearImage();
                if (data.status === "search") loadVaultData(null, data.search_keyword, "Search: '" + data.search_keyword + "'", null);
                else if (data.status === "folder_created") loadVaultData(data.folder_id, null, data.folder_name + " Folder", data.folder_name);
                else loadVaultData(activeFolderId, null, activeFolderName ? activeFolderName + " Folder" : null, activeFolderName);
            } finally { btn.disabled = false; }
        }

        function handleQuickSearch(v) {
            clearTimeout(searchTimer);
            searchTimer = setTimeout(function() {
                if (v.trim()) loadVaultData(null, v.trim(), "Search: '" + v.trim() + "'", null);
                else loadVaultData(activeFolderId);
            }, 250);
        }
        function resetFilters() { document.getElementById("quickSearchInput").value = ""; loadVaultData(null, null, "All Memories (Date-Wise Timeline)", null); }
        function previewSelectedImage(e) {
            var f = e.target.files[0]; if (!f) return;
            document.getElementById("imagePreview").src = URL.createObjectURL(f);
            document.getElementById("imageName").innerText = f.name;
            document.getElementById("imagePreviewBox").style.display = "flex";
        }
        function clearImage() {
            document.getElementById("imageInput").value = "";
            document.getElementById("imagePreview").src = BLANK_IMG;
            document.getElementById("imagePreviewBox").style.display = "none";
        }
        async function deleteMemory(id) {
            if (!confirm("Delete this memory?")) return;
            await fetch("/api/memory/" + id, { method: "DELETE", headers: { "Authorization": "Bearer " + authToken } });
            loadVaultData(activeFolderId);
        }
        function openModal(src) { document.getElementById("modalImg").src = src; document.getElementById("imageModal").className = "modal-bg"; }
        function closeModal() { document.getElementById("imageModal").className = "modal-bg hidden"; document.getElementBy
