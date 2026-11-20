from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict
import sqlite3
import hashlib
import secrets
import uuid
import os

app = FastAPI(title="usonly")

DB_PATH = os.getenv("USONLY_DB_PATH", "usonly.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def hash_secret(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        handle TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        apple_sub TEXT,
        provider TEXT NOT NULL,
        password_hash TEXT,
        pronouns TEXT DEFAULT '',
        bio TEXT DEFAULT '',
        links TEXT DEFAULT '',
        banners TEXT DEFAULT '',
        gender TEXT DEFAULT '',
        ai_creator INTEGER DEFAULT 0,
        avatar TEXT NOT NULL,
        posts_count INTEGER DEFAULT 0,
        followers INTEGER DEFAULT 0,
        following INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS close_friends (
        user_id TEXT NOT NULL,
        friend_username TEXT NOT NULL,
        PRIMARY KEY(user_id, friend_username)
    );

    CREATE TABLE IF NOT EXISTS notes (
        id TEXT PRIMARY KEY,
        author_username TEXT NOT NULL,
        text TEXT NOT NULL,
        song TEXT DEFAULT '',
        preview_url TEXT DEFAULT '',
        clip_start INTEGER DEFAULT 0,
        clip_duration INTEGER DEFAULT 40,
        audience TEXT DEFAULT 'friends',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS stories (
        id TEXT PRIMARY KEY,
        kind TEXT DEFAULT 'Story',
        author_username TEXT NOT NULL,
        text TEXT DEFAULT '',
        image TEXT,
        is_close_friends INTEGER DEFAULT 0,
        allowed_users_json TEXT DEFAULT '[]',
        created_at TEXT DEFAULT 'Now'
    );

    CREATE TABLE IF NOT EXISTS posts (
        id TEXT PRIMARY KEY,
        author_username TEXT NOT NULL,
        badge TEXT DEFAULT 'Post',
        caption TEXT NOT NULL,
        image TEXT,
        likes INTEGER DEFAULT 0,
        liked_by_json TEXT DEFAULT '[]',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS direct_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_a TEXT NOT NULL,
        user_b TEXT NOT NULL,
        sender_username TEXT NOT NULL,
        text TEXT NOT NULL,
        pinned INTEGER DEFAULT 0,
        muted INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS groups_chat (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        owner_username TEXT NOT NULL,
        members_json TEXT NOT NULL,
        pinned INTEGER DEFAULT 0,
        muted INTEGER DEFAULT 0,
        messages_json TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS message_requests (
        id TEXT PRIMARY KEY,
        to_username TEXT NOT NULL,
        sender_username TEXT NOT NULL,
        sender_handle TEXT NOT NULL,
        text TEXT NOT NULL
    );
    """)
    conn.commit()
    conn.close()


init_db()


class AuthEmailPhone(BaseModel):
    identifier: str
    password: Optional[str] = None
    username: Optional[str] = None
    name: Optional[str] = None
    mode: str = "login_or_register"


class AuthApple(BaseModel):
    apple_email: Optional[str] = None
    apple_name: Optional[str] = None
    username: Optional[str] = None


class ProfileUpdate(BaseModel):
    username: str
    name: str
    pronouns: str = ""
    bio: str = ""
    links: str = ""
    banners: str = ""
    gender: str = ""
    ai_creator: bool = False


class NoteCreate(BaseModel):
    text: str
    song: str = ""
    preview_url: str = ""
    clip_start: int = 0
    clip_duration: int = 40
    audience: str = "friends"


class StoryCreate(BaseModel):
    kind: str = "Story"
    text: str = ""
    image: Optional[str] = None
    is_close_friends: bool = False
    selected_friends: List[str] = []


class PostCreate(BaseModel):
    kind: str = "Post"
    caption: str
    image: Optional[str] = None


class CloseFriendsUpdate(BaseModel):
    friends: List[str]


class DirectMsgCreate(BaseModel):
    target: str
    text: str


class ChatMetaAction(BaseModel):
    target: str
    action: str


class GroupCreate(BaseModel):
    name: str
    members: List[str]


class GroupMsgCreate(BaseModel):
    text: str


def get_current_user(authorization: Optional[str] = Header(default=None)) -> Optional[dict]:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.replace("Bearer ", "", 1).strip()
    if not token:
        return None
    conn = get_conn()
    row = conn.execute(
        """
        SELECT u.* FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token = ?
        """,
        (token,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def require_user(authorization: Optional[str] = Header(default=None)) -> dict:
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user


def normalize_handle(raw_username: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in raw_username.strip().lower())
    cleaned = cleaned.strip("_")
    return cleaned or f"user_{uuid.uuid4().hex[:6]}"


def issue_session(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    conn = get_conn()
    conn.execute("INSERT INTO sessions (token, user_id) VALUES (?, ?)", (token, user_id))
    conn.commit()
    conn.close()
    return token


def can_view_story(story: dict, viewer_username: str) -> bool:
    if story["author"] == viewer_username:
        return True
    if not story["is_close_friends"]:
        return True
    return viewer_username in story.get("allowed_users", [])


def generate_ai_reply(prompt: str) -> str:
    p = prompt.strip()
    if not p:
        return "اكتب اللي تحتاجه ونساعدك فوراً."
    return f"فكرة واضحة بخصوص «{p}». تحب نرتبها في منشور أو نوتة أو خطوة عملية؟"


@app.post("/api/auth/email-phone")
def auth_email_phone(payload: AuthEmailPhone):
    ident = payload.identifier.strip()
    if not ident:
        return JSONResponse({"ok": False, "error": "أدخل البريد الإلكتروني أو رقم الجوال"}, status_code=400)

    is_email = "@" in ident
    email_val = ident.lower() if is_email else None
    phone_val = ident if not is_email else None

    conn = get_conn()
    existing = conn.execute(
        "SELECT * FROM users WHERE (email IS NOT NULL AND email = ?) OR (phone IS NOT NULL AND phone = ?)",
        (email_val, phone_val),
    ).fetchone()

    if existing:
        if payload.password and existing["password_hash"] and existing["password_hash"] != hash_secret(payload.password):
            conn.close()
            return JSONResponse({"ok": False, "error": "كلمة المرور غير صحيحة"}, status_code=401)
        conn.close()
        token = issue_session(existing["id"])
        return {"ok": True, "token": token, "user": dict(existing)}

    base_name = (payload.name or "").strip() or (ident.split("@")[0] if is_email else f"مستخدم {ident[-4:]}")
    chosen_username = (payload.username or "").strip() or base_name
    handle = normalize_handle(chosen_username)
    while conn.execute("SELECT 1 FROM users WHERE handle = ?", (handle,)).fetchone():
        handle = f"{handle}_{uuid.uuid4().hex[:3]}"

    user_id = f"usr-{uuid.uuid4().hex[:10]}"
    avatar_char = base_name[0] if base_name else "U"
    pw_hash = hash_secret(payload.password) if payload.password else None

    conn.execute(
        """
        INSERT INTO users (id, username, handle, name, email, phone, provider, password_hash, avatar)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            chosen_username,
            handle,
            base_name,
            email_val,
            phone_val,
            "email" if is_email else "phone",
            pw_hash,
            avatar_char,
        ),
    )
    conn.commit()
    user_row = dict(conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())
    conn.close()
    token = issue_session(user_id)
    return {"ok": True, "token": token, "user": user_row}


@app.post("/api/auth/apple")
def auth_apple(payload: AuthApple):
    apple_email = (payload.apple_email or "").strip().lower() or None
    apple_name = (payload.apple_name or "").strip() or "مستخدم Apple"
    chosen_username = (payload.username or "").strip() or apple_name
    handle = normalize_handle(chosen_username)

    conn = get_conn()
    existing = None
    if apple_email:
        existing = conn.execute("SELECT * FROM users WHERE email = ?", (apple_email,)).fetchone()
    if existing:
        conn.close()
        token = issue_session(existing["id"])
        return {"ok": True, "token": token, "user": dict(existing)}

    while conn.execute("SELECT 1 FROM users WHERE handle = ?", (handle,)).fetchone():
        handle = f"{handle}_{uuid.uuid4().hex[:3]}"

    user_id = f"usr-{uuid.uuid4().hex[:10]}"
    avatar_char = apple_name[0] if apple_name else "A"
    conn.execute(
        """
        INSERT INTO users (id, username, handle, name, email, provider, avatar)
        VALUES (?, ?, ?, ?, ?, 'apple', ?)
        """,
        (user_id, chosen_username, handle, apple_name, apple_email, avatar_char),
    )
    conn.commit()
    user_row = dict(conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())
    conn.close()
    token = issue_session(user_id)
    return {"ok": True, "token": token, "user": user_row}


@app.post("/api/auth/logout")
def logout(authorization: Optional[str] = Header(default=None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "", 1).strip()
        conn = get_conn()
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
    return {"ok": True}


@app.get("/api/state")
def get_state(authorization: Optional[str] = Header(default=None)):
    current = get_current_user(authorization)
    if not current:
        return JSONResponse({"authenticated": False}, status_code=401)

    viewer = current["username"]
    conn = get_conn()

    users_rows = [dict(r) for r in conn.execute("SELECT * FROM users ORDER BY created_at ASC").fetchall()]
    cf_rows = conn.execute("SELECT friend_username FROM close_friends WHERE user_id = ?", (current["id"],)).fetchall()
    close_friends = [r["friend_username"] for r in cf_rows]

    notes_rows = [dict(r) for r in conn.execute("SELECT * FROM notes ORDER BY created_at DESC").fetchall()]
    notes = [
        {
            "id": n["id"],
            "author": n["author_username"],
            "text": n["text"],
            "song": n["song"],
            "preview_url": n["preview_url"],
            "clip_start": n["clip_start"],
            "clip_duration": n["clip_duration"],
            "audience": n["audience"],
        }
        for n in notes_rows
    ]

    import json
    stories_raw = [dict(r) for r in conn.execute("SELECT * FROM stories").fetchall()]
    stories = []
    for s in stories_raw:
        item = {
            "id": s["id"],
            "kind": s["kind"],
            "author": s["author_username"],
            "text": s["text"],
            "image": s["image"],
            "is_close_friends": bool(s["is_close_friends"]),
            "allowed_users": json.loads(s["allowed_users_json"] or "[]"),
            "created_at": s["created_at"],
        }
        if can_view_story(item, viewer):
            stories.append(item)

    user_story_status = {}
    for u in users_rows:
        uname = u["username"]
        u_stories = [s for s in stories if s["author"] == uname]
        if not u_stories:
            user_story_status[uname] = "none"
        elif any(s["is_close_friends"] for s in u_stories):
            user_story_status[uname] = "close"
        else:
            user_story_status[uname] = "normal"

    posts_raw = [dict(r) for r in conn.execute("SELECT * FROM posts ORDER BY created_at DESC").fetchall()]
    posts = [
        {
            "id": p["id"],
            "author": p["author_username"],
            "badge": p["badge"],
            "caption": p["caption"],
            "image": p["image"],
            "likes": p["likes"],
            "liked": viewer in json.loads(p["liked_by_json"] or "[]"),
            "comments": [],
        }
        for p in posts_raw
    ]

    conversations: Dict[str, Dict] = {
        "usonly AI": {
            "name": "usonly AI",
            "handle": "@ai",
            "pinned": True,
            "muted": False,
            "messages": [
                {"sender": "usonly AI", "text": "أهلاً بك في usonly. كيف أقدر أساعدك اليوم؟"}
            ],
        }
    }

    dm_rows = [
        dict(r)
        for r in conn.execute(
            "SELECT * FROM direct_messages WHERE user_a = ? OR user_b = ? ORDER BY id ASC",
            (viewer, viewer),
        ).fetchall()
    ]
    for m in dm_rows:
        peer = m["user_b"] if m["user_a"] == viewer else m["user_a"]
        if peer not in conversations:
            peer_u = next((u for u in users_rows if u["username"] == peer), None)
            conversations[peer] = {
                "name": peer,
                "handle": f"@{peer_u['handle']}" if peer_u else f"@{peer}",
                "pinned": bool(m["pinned"]),
                "muted": bool(m["muted"]),
                "messages": [],
            }
        conversations[peer]["pinned"] = bool(m["pinned"])
        conversations[peer]["muted"] = bool(m["muted"])
        conversations[peer]["messages"].append({"sender": m["sender_username"], "text": m["text"]})

    req_rows = [
        dict(r)
        for r in conn.execute("SELECT * FROM message_requests WHERE to_username = ?", (viewer,)).fetchall()
    ]
    requests_list = [
        {
            "id": r["id"],
            "sender": r["sender_username"],
            "handle": r["sender_handle"],
            "text": r["text"],
        }
        for r in req_rows
    ]

    grp_rows = [dict(r) for r in conn.execute("SELECT * FROM groups_chat").fetchall()]
    groups = []
    for g in grp_rows:
        members = json.loads(g["members_json"] or "[]")
        if viewer in members:
            groups.append(
                {
                    "id": g["id"],
                    "name": g["name"],
                    "members": members,
                    "pinned": bool(g["pinned"]),
                    "muted": bool(g["muted"]),
                    "messages": json.loads(g["messages_json"] or "[]"),
                }
            )

    conn.close()

    return {
        "authenticated": True,
        "current_user": viewer,
        "current_user_obj": current,
        "users": users_rows,
        "close_friends": close_friends,
        "notes": notes,
        "stories": stories,
        "story_status": user_story_status,
        "posts": posts,
        "conversations": conversations,
        "requests": requests_list,
        "groups": groups,
    }


@app.post("/api/profile")
def update_profile(payload: ProfileUpdate, authorization: Optional[str] = Header(default=None)):
    current = require_user(authorization)
    conn = get_conn()
    new_username = payload.username.strip() or current["username"]
    new_name = payload.name.strip() or current["name"]
    new_handle = normalize_handle(new_username)
    avatar_char = new_name[0] if new_name else "U"

    conn.execute(
        """
        UPDATE users
        SET username = ?, handle = ?, name = ?, pronouns = ?, bio = ?, links = ?, banners = ?, gender = ?, ai_creator = ?, avatar = ?
        WHERE id = ?
        """,
        (
            new_username,
            new_handle,
            new_name,
            payload.pronouns.strip(),
            payload.bio.strip(),
            payload.links.strip(),
            payload.banners.strip(),
            payload.gender.strip(),
            1 if payload.ai_creator else 0,
            avatar_char,
            current["id"],
        ),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "current_user": new_username}


@app.post("/api/notes")
def create_note(payload: NoteCreate, authorization: Optional[str] = Header(default=None)):
    current = require_user(authorization)
    viewer = current["username"]
    note = {
        "id": f"note-{uuid.uuid4().hex[:6]}",
        "author": viewer,
        "text": payload.text.strip() or "Your thoughts go here...",
        "song": payload.song.strip(),
        "preview_url": payload.preview_url.strip(),
        "clip_start": max(0, int(payload.clip_start)),
        "clip_duration": payload.clip_duration if payload.clip_duration in (15, 25, 40) else 40,
        "audience": payload.audience,
    }
    conn = get_conn()
    conn.execute("DELETE FROM notes WHERE author_username = ?", (viewer,))
    conn.execute(
        """
        INSERT INTO notes (id, author_username, text, song, preview_url, clip_start, clip_duration, audience)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            note["id"],
            viewer,
            note["text"],
            note["song"],
            note["preview_url"],
            note["clip_start"],
            note["clip_duration"],
            note["audience"],
        ),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "note": note}


@app.post("/api/stories")
def create_story(payload: StoryCreate, authorization: Optional[str] = Header(default=None)):
    current = require_user(authorization)
    viewer = current["username"]
    import json
    allowed = list(dict.fromkeys(payload.selected_friends + [viewer])) if payload.is_close_friends else []
    story_id = f"st-{uuid.uuid4().hex[:6]}"
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO stories (id, kind, author_username, text, image, is_close_friends, allowed_users_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'Now')
        """,
        (
            story_id,
            payload.kind,
            viewer,
            payload.text.strip(),
            (payload.image or "").strip() or None,
            1 if payload.is_close_friends else 0,
            json.dumps(allowed),
        ),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "id": story_id}


@app.post("/api/close-friends")
def update_close_friends(payload: CloseFriendsUpdate, authorization: Optional[str] = Header(default=None)):
    current = require_user(authorization)
    viewer = current["username"]
    friends = [f for f in payload.friends if f != viewer]
    conn = get_conn()
    conn.execute("DELETE FROM close_friends WHERE user_id = ?", (current["id"],))
    for f in friends:
        conn.execute("INSERT OR IGNORE INTO close_friends (user_id, friend_username) VALUES (?, ?)", (current["id"], f))
    conn.commit()
    conn.close()
    return {"ok": True, "close_friends": friends}


@app.post("/api/posts")
def create_post(payload: PostCreate, authorization: Optional[str] = Header(default=None)):
    current = require_user(authorization)
    viewer = current["username"]
    post_id = f"p-{uuid.uuid4().hex[:6]}"
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO posts (id, author_username, badge, caption, image, likes, liked_by_json)
        VALUES (?, ?, ?, ?, ?, 0, '[]')
        """,
        (post_id, viewer, payload.kind, payload.caption.strip(), (payload.image or "").strip() or None),
    )
    conn.execute("UPDATE users SET posts_count = posts_count + 1 WHERE id = ?", (current["id"],))
    conn.commit()
    conn.close()
    return {"ok": True, "id": post_id}


@app.post("/api/posts/{post_id}/like")
def toggle_like(post_id: str, authorization: Optional[str] = Header(default=None)):
    current = require_user(authorization)
    viewer = current["username"]
    import json
    conn = get_conn()
    row = conn.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()
    if not row:
        conn.close()
        return JSONResponse({"ok": False}, status_code=404)
    liked_by = json.loads(row["liked_by_json"] or "[]")
    if viewer in liked_by:
        liked_by.remove(viewer)
    else:
        liked_by.append(viewer)
    likes_count = len(liked_by)
    conn.execute(
        "UPDATE posts SET likes = ?, liked_by_json = ? WHERE id = ?",
        (likes_count, json.dumps(liked_by), post_id),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "likes": likes_count}


@app.post("/api/direct")
def send_direct(payload: DirectMsgCreate, authorization: Optional[str] = Header(default=None)):
    current = require_user(authorization)
    viewer = current["username"]
    target = payload.target.strip()
    text = payload.text.strip()
    if not target or not text:
        return JSONResponse({"ok": False}, status_code=400)

    conn = get_conn()
    conn.execute(
        "INSERT INTO direct_messages (user_a, user_b, sender_username, text) VALUES (?, ?, ?, ?)",
        (viewer, target, viewer, text),
    )
    if target == "usonly AI":
        reply = generate_ai_reply(text)
        conn.execute(
            "INSERT INTO direct_messages (user_a, user_b, sender_username, text) VALUES (?, ?, ?, ?)",
            (viewer, target, "usonly AI", reply),
        )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/api/conversations/action")
def conversation_action(payload: ChatMetaAction, authorization: Optional[str] = Header(default=None)):
    current = require_user(authorization)
    viewer = current["username"]
    t = payload.target
    act = payload.action
    import json

    conn = get_conn()
    if act == "pin":
        conn.execute(
            "UPDATE direct_messages SET pinned = CASE WHEN pinned = 1 THEN 0 ELSE 1 END WHERE (user_a = ? AND user_b = ?) OR (user_a = ? AND user_b = ?)",
            (viewer, t, t, viewer),
        )
        conn.execute("UPDATE groups_chat SET pinned = CASE WHEN pinned = 1 THEN 0 ELSE 1 END WHERE id = ?", (t,))
    elif act == "mute":
        conn.execute(
            "UPDATE direct_messages SET muted = CASE WHEN muted = 1 THEN 0 ELSE 1 END WHERE (user_a = ? AND user_b = ?) OR (user_a = ? AND user_b = ?)",
            (viewer, t, t, viewer),
        )
        conn.execute("UPDATE groups_chat SET muted = CASE WHEN muted = 1 THEN 0 ELSE 1 END WHERE id = ?", (t,))
    elif act == "delete":
        conn.execute(
            "DELETE FROM direct_messages WHERE (user_a = ? AND user_b = ?) OR (user_a = ? AND user_b = ?)",
            (viewer, t, t, viewer),
        )
        grp = conn.execute("SELECT * FROM groups_chat WHERE id = ?", (t,)).fetchone()
        if grp:
            members = json.loads(grp["members_json"] or "[]")
            if viewer in members:
                members.remove(viewer)
                if members:
                    conn.execute("UPDATE groups_chat SET members_json = ? WHERE id = ?", (json.dumps(members), t))
                else:
                    conn.execute("DELETE FROM groups_chat WHERE id = ?", (t,))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/api/requests/{req_id}/{action}")
def handle_request(req_id: str, action: str, authorization: Optional[str] = Header(default=None)):
    current = require_user(authorization)
    viewer = current["username"]
    conn = get_conn()
    req = conn.execute("SELECT * FROM message_requests WHERE id = ? AND to_username = ?", (req_id, viewer)).fetchone()
    if not req:
        conn.close()
        return JSONResponse({"ok": False}, status_code=404)
    conn.execute("DELETE FROM message_requests WHERE id = ?", (req_id,))
    if action == "accept":
        conn.execute(
            "INSERT INTO direct_messages (user_a, user_b, sender_username, text) VALUES (?, ?, ?, ?)",
            (viewer, req["sender_username"], req["sender_username"], req["text"]),
        )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/api/groups")
def create_group(payload: GroupCreate, authorization: Optional[str] = Header(default=None)):
    current = require_user(authorization)
    viewer = current["username"]
    import json
    members = list(dict.fromkeys([viewer] + payload.members))
    grp_id = f"grp-{uuid.uuid4().hex[:6]}"
    grp = {
        "id": grp_id,
        "name": payload.name.strip() or "Group chat",
        "members": members,
        "pinned": False,
        "muted": False,
        "messages": [{"sender": viewer, "text": "Group created."}],
    }
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO groups_chat (id, name, owner_username, members_json, pinned, muted, messages_json)
        VALUES (?, ?, ?, ?, 0, 0, ?)
        """,
        (grp_id, grp["name"], viewer, json.dumps(members), json.dumps(grp["messages"])),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "group": grp}


@app.post("/api/groups/{group_id}/message")
def send_group_msg(group_id: str, payload: GroupMsgCreate, authorization: Optional[str] = Header(default=None)):
    current = require_user(authorization)
    viewer = current["username"]
    import json
    conn = get_conn()
    grp = conn.execute("SELECT * FROM groups_chat WHERE id = ?", (group_id,)).fetchone()
    if not grp:
        conn.close()
        return JSONResponse({"ok": False}, status_code=404)
    msgs = json.loads(grp["messages_json"] or "[]")
    msgs.append({"sender": viewer, "text": payload.text.strip()})
    conn.execute("UPDATE groups_chat SET messages_json = ? WHERE id = ?", (json.dumps(msgs), group_id))
    conn.commit()
    conn.close()
    return {"ok": True}


HTML_PAGE = """<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
  <title>usonly</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@700;800;900&family=Plus+Jakarta+Sans:wght@700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #050506;
      --surface: #0c0d10;
      --card: #121318;
      --border: #20222b;
      --text: #eef0f4;
      --muted: #8f95a3;
      --accent: #4f6ef7;
      --close-green: #22c55e;
    }
    * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, sans-serif;
      padding-bottom: 64px;
    }
    .shell {
      max-width: 460px;
      margin: 0 auto;
      min-height: 100vh;
      background: var(--bg);
      border-left: 1px solid #15161c;
      border-right: 1px solid #15161c;
    }

    /* Onboarding / Auth Gate */
    .auth-gate {
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      justify-content: center;
      padding: 24px 20px;
      gap: 14px;
    }
    .auth-brand {
      font-family: 'Outfit', 'Plus Jakarta Sans', sans-serif;
      font-size: 36px;
      font-weight: 900;
      letter-spacing: -0.8px;
      text-align: center;
      direction: ltr;
      margin-bottom: 4px;
    }
    .auth-sub {
      text-align: center;
      color: var(--muted);
      font-size: 13px;
      margin-bottom: 10px;
    }
    .auth-btn-apple {
      width: 100%;
      background: #ffffff;
      color: #050506;
      border: none;
      border-radius: 12px;
      padding: 12px 14px;
      font-size: 14px;
      font-weight: 800;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
    }
    .auth-divider {
      text-align: center;
      font-size: 11px;
      color: var(--muted);
      margin: 4px 0;
    }

    .topbar {
      position: sticky;
      top: 0;
      z-index: 20;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 10px 14px;
      background: rgba(5, 5, 6, 0.92);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid #17181f;
    }
    .brand {
      font-family: 'Outfit', 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      font-size: 24px;
      font-weight: 800;
      letter-spacing: -0.6px;
      direction: ltr;
      color: #ffffff;
    }
    .icon-btn {
      background: none;
      border: none;
      color: var(--text);
      font-size: 22px;
      cursor: pointer;
      padding: 4px 6px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }
    .lang-select {
      background: var(--surface);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 4px 8px;
      font-size: 12px;
    }
    .row-scroll {
      display: flex;
      gap: 14px;
      overflow-x: auto;
      padding: 12px 14px;
      border-bottom: 1px solid #17181f;
      scrollbar-width: none;
    }
    .row-scroll::-webkit-scrollbar { display: none; }
    .story-col {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 6px;
      min-width: 84px;
      flex-shrink: 0;
      cursor: pointer;
    }
    .ring {
      width: 70px;
      height: 70px;
      border-radius: 50%;
      padding: 3px;
      position: relative;
      background: #232630;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .ring.normal { background: linear-gradient(45deg, #f43f5e, #f97316, #a855f7); }
    .ring.close { background: var(--close-green); box-shadow: 0 0 10px rgba(34, 197, 94, 0.28); }
    .avatar-circle {
      width: 100%;
      height: 100%;
      border-radius: 50%;
      background: var(--card);
      border: 2.5px solid var(--bg);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      font-size: 18px;
    }
    .cf-tag {
      position: absolute;
      bottom: -4px;
      background: var(--close-green);
      color: #041309;
      font-size: 9px;
      font-weight: 800;
      padding: 1px 5px;
      border-radius: 6px;
    }
    .note-bubble {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 7px 10px;
      font-size: 11px;
      max-width: 112px;
      text-align: center;
      line-height: 1.35;
      color: var(--text);
    }
    .post { border-bottom: 1px solid #16171e; padding-bottom: 12px; }
    .post-head { display: flex; justify-content: space-between; align-items: center; padding: 10px 14px; }
    .post-img { width: 100%; max-height: 450px; object-fit: cover; display: block; background: var(--surface); }
    .post-acts { display: flex; gap: 14px; padding: 10px 14px 4px; }
    .btn {
      background: var(--accent);
      color: #fff;
      border: none;
      border-radius: 10px;
      padding: 9px 13px;
      font-size: 13px;
      font-weight: 700;
      cursor: pointer;
    }
    .btn-ghost {
      background: var(--surface);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 8px 12px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
    }
    .btn-green {
      background: var(--close-green);
      color: #05140a;
      border: none;
      border-radius: 10px;
      padding: 8px 13px;
      font-size: 13px;
      font-weight: 800;
      cursor: pointer;
    }
    .inp {
      width: 100%;
      background: var(--surface);
      border: 1px solid var(--border);
      color: var(--text);
      border-radius: 10px;
      padding: 10px 12px;
      font-size: 13px;
      margin-bottom: 8px;
    }
    .bottom-5 {
      position: fixed;
      bottom: 0;
      left: 50%;
      transform: translateX(-50%);
      width: 100%;
      max-width: 460px;
      height: 54px;
      background: var(--bg);
      border-top: 1px solid #181921;
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      z-index: 25;
    }
    .nav-item {
      background: none;
      border: none;
      color: var(--muted);
      font-size: 11px;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      gap: 2px;
      cursor: pointer;
    }
    .nav-item.active { color: #fff; font-weight: 700; }
    .modal {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.82);
      z-index: 60;
      display: none;
      align-items: center;
      justify-content: center;
      padding: 14px;
    }
    .modal.open { display: flex; }
    .modal-card {
      width: 100%;
      max-width: 420px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 16px;
      max-height: 90vh;
      overflow-y: auto;
    }
    .sheet-option {
      width: 100%;
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: var(--card);
      border: 1px solid var(--border);
      color: var(--text);
      border-radius: 11px;
      padding: 11px 12px;
      margin-bottom: 7px;
      font-size: 14px;
      cursor: pointer;
    }
    .field-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 10px 0;
      border-bottom: 1px solid #1a1b22;
    }

    /* IG-style DM Inbox */
    .ig-dm-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 10px;
    }
    .ig-search-pill {
      width: 100%;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 10px 14px;
      color: var(--text);
      font-size: 13px;
      margin-bottom: 10px;
    }
    .ig-notes-strip {
      display: flex;
      flex-direction: row;
      gap: 14px;
      overflow-x: auto;
      padding: 8px 2px 14px;
      border-bottom: 1px solid #17181f;
      scrollbar-width: none;
    }
    .ig-notes-strip::-webkit-scrollbar { display: none; }
    .ig-sec-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 10px 2px 6px;
      font-size: 14px;
      font-weight: 700;
    }
    .thread-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 10px 6px;
      border-radius: 12px;
      cursor: pointer;
      user-select: none;
    }
    .thread-row:hover { background: var(--card); }
    .thread-left {
      display: flex;
      align-items: center;
      gap: 11px;
    }
    .thread-avatar {
      width: 50px;
      height: 50px;
      border-radius: 50%;
      background: var(--card);
      border: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 17px;
    }

    /* Fullscreen IG-style Conversation Screen */
    .full-thread-screen {
      display: none;
      flex-direction: column;
      min-height: calc(100vh - 118px);
      justify-content: space-between;
    }
    .full-thread-screen.open {
      display: flex;
    }
    .full-thread-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 6px 2px 12px;
      border-bottom: 1px solid #191b23;
    }
    .full-thread-user {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .full-thread-avatar {
      width: 38px;
      height: 38px;
      border-radius: 50%;
      background: var(--card);
      border: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 15px;
    }
    .full-thread-messages {
      flex: 1;
      display: flex;
      flex-direction: column;
      gap: 8px;
      padding: 14px 2px;
      overflow-y: auto;
      min-height: 56vh;
      max-height: 66vh;
    }
    .msg-row {
      display: flex;
      flex-direction: column;
      max-width: 78%;
    }
    .msg-row.mine {
      align-self: flex-start;
    }
    .msg-row.theirs {
      align-self: flex-end;
    }
    .msg-sender-label {
      font-size: 10px;
      color: var(--muted);
      margin-bottom: 2px;
      padding: 0 4px;
    }
    .bubble {
      border-radius: 18px;
      padding: 9px 13px;
      font-size: 13.5px;
      line-height: 1.4;
      word-break: break-word;
    }
    .msg-row.mine .bubble {
      background: var(--accent);
      color: #fff;
      border-bottom-right-radius: 5px;
    }
    .msg-row.theirs .bubble {
      background: #181a22;
      color: var(--text);
      border: 1px solid #242733;
      border-bottom-left-radius: 5px;
    }

    .modern-chat-actions {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .modern-icon-btn {
      width: 34px;
      height: 34px;
      border-radius: 50%;
      background: var(--card);
      border: 1px solid var(--border);
      color: var(--text);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
    }
    .modern-input-bar {
      display: flex;
      align-items: center;
      gap: 8px;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 6px 8px 6px 12px;
      margin-top: 8px;
    }
    .modern-input-bar input {
      flex: 1;
      background: transparent;
      border: none;
      color: var(--text);
      font-size: 13px;
      outline: none;
    }

    /* Note Composer & Trimmer */
    .note-stage {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 10px 0 14px;
      gap: 8px;
    }
    .note-preview-bubble {
      background: var(--card);
      border: 1px solid #2b2e3b;
      border-radius: 18px;
      padding: 10px 14px;
      max-width: 240px;
      text-align: center;
      font-size: 13px;
      color: var(--text);
    }
    .note-avatar-wrap {
      width: 74px;
      height: 74px;
      border-radius: 50%;
      background: var(--card);
      border: 2px solid #2a2d3a;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 24px;
      font-weight: 800;
    }
    .music-picker-box {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 10px;
      margin-bottom: 10px;
    }
    .track-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      padding: 8px 6px;
      border-bottom: 1px solid #1d1f28;
      font-size: 12px;
      cursor: pointer;
    }
    .track-row:last-child { border-bottom: none; }
    .track-row.selected { background: #1a1e2e; border-radius: 8px; }
    .trim-controls-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-top: 8px;
    }
    .circle-dur-group {
      display: flex;
      gap: 7px;
      align-items: center;
    }
    .dur-circle {
      width: 38px;
      height: 38px;
      border-radius: 50%;
      background: var(--surface);
      border: 1px solid #2c303d;
      color: var(--muted);
      font-size: 11px;
      font-weight: 800;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
    }
    .dur-circle.active {
      background: var(--accent);
      border-color: var(--accent);
      color: #fff;
    }
    .range-track-wrap {
      flex: 1;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 8px 10px;
    }
    .range-track-wrap input[type="range"] {
      width: 100%;
      accent-color: var(--accent);
      cursor: pointer;
    }
  </style>
</head>
<body>
<audio id="noteAudioPlayer"></audio>

<div class="shell">
  <!-- Auth Screen (First launch for any new user) -->
  <section id="authGate" class="auth-gate" style="display:none;">
    <div class="auth-brand">usonly</div>
    <div class="auth-sub">سجّل دخولك أو أنشئ حسابك الجديد للمتابعة</div>

    <button class="auth-btn-apple" onclick="openAppleModal()">
      <span></span>
      <span>المتابعة باستخدام Apple / iCloud</span>
    </button>

    <div class="auth-divider">أو بالبريد الإلكتروني / رقم الجوال</div>

    <input class="inp" id="authIdentifier" placeholder="البريد الإلكتروني أو رقم الجوال" />
    <input class="inp" id="authUsername" placeholder="اسم المستخدم (@username)" />
    <input class="inp" id="authName" placeholder="الاسم الظاهر (اختياري)" />
    <input class="inp" id="authPassword" type="password" placeholder="كلمة المرور (اختياري)" />
    <button class="btn" style="width:100%;" onclick="submitEmailPhoneAuth()">دخول / إنشاء حساب</button>
    <div id="authErrorMsg" style="color:#f87171;font-size:12px;text-align:center;"></div>
  </section>

  <!-- Main Authenticated App -->
  <div id="mainAppShell" style="display:none;">
    <header class="topbar">
      <div style="display:flex;align-items:center;gap:6px;">
        <button class="icon-btn" onclick="openCreateMenu()">+</button>
        <span class="brand">usonly</span>
      </div>
      <div style="display:flex;align-items:center;gap:8px;">
        <select class="lang-select" id="langSelect" onchange="changeLang(this.value)">
          <option value="ar">العربية</option>
          <option value="en">English</option>
          <option value="fr">Français</option>
        </select>
        <button class="btn-ghost" onclick="logoutUser()">خروج</button>
      </div>
    </header>

    <!-- 1. Home -->
    <section id="view-home">
      <div class="row-scroll" id="storiesRow"></div>
      <div id="postsList"></div>
    </section>

    <!-- 2. Search -->
    <section id="view-search" style="display:none;padding:14px;">
      <input class="inp" id="searchInput" placeholder="Search by @username or name..." oninput="renderSearch()" />
      <div id="searchResults"></div>
    </section>

    <!-- 3. Messages -->
    <section id="view-messages" style="display:none;padding:14px;">
      <div id="dmInboxView">
        <div class="ig-dm-top">
          <strong style="font-size:18px;" id="dmHandleTitle">@user ⌄</strong>
          <div style="display:flex;align-items:center;gap:6px;">
            <button class="btn-ghost" style="padding:5px 10px;font-size:11px;" onclick="openNoteModal()">+ Note</button>
            <button class="icon-btn" onclick="openNewMessageSheet()" title="New message or Group chat">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 20h9"></path>
                <path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"></path>
              </svg>
            </button>
          </div>
        </div>

        <input class="ig-search-pill" id="dmSearchAiInput" placeholder="Search or ask usonly AI" onkeydown="handleDmSearchOrAi(event)" />

        <!-- Horizontal Notes Strip -->
        <div class="ig-notes-strip" id="dmNotesStrip"></div>

        <div class="ig-sec-head">
          <span>Messages</span>
          <button class="btn-ghost" style="background:none;border:none;color:var(--muted);padding:2px 4px;font-size:13px;" onclick="openRequestsModal()" id="reqBtn">Requests</button>
        </div>

        <div id="threadsList"></div>
      </div>

      <!-- Fullscreen Thread View -->
      <div id="fullThreadView" class="full-thread-screen">
        <div>
          <div class="full-thread-header">
            <div class="full-thread-user">
              <button class="icon-btn" style="padding:2px 6px;font-size:20px;" onclick="closeActiveChat()" title="Back to chats">←</button>
              <div class="full-thread-avatar" id="activeChatAvatar">U</div>
              <div>
                <div style="font-weight:800;font-size:15px;" id="activeChatTitle">Chat</div>
                <div style="font-size:11px;color:var(--muted);" id="activeChatSub">Active</div>
              </div>
            </div>

            <div class="modern-chat-actions">
              <button class="modern-icon-btn" title="Voice call" onclick="alert('Voice call ready')">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.12.96.36 1.9.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.91.34 1.85.58 2.81.7A2 2 0 0 1 22 16.92z"></path>
                </svg>
              </button>
              <button class="modern-icon-btn" title="Video call" onclick="alert('Video call ready')">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <polygon points="23 7 16 12 23 17 23 7"></polygon>
                  <rect x="1" y="5" width="15" height="14" rx="2" ry="2"></rect>
                </svg>
              </button>
            </div>
          </div>

          <div class="full-thread-messages" id="activeChatMessages"></div>
        </div>

        <div class="modern-input-bar">
          <button class="icon-btn" style="padding:0;font-size:16px;" title="Camera" onclick="quickAttachMedia('Camera')">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"></path>
              <circle cx="12" cy="13" r="4"></circle>
            </svg>
          </button>
          <input id="activeChatInput" placeholder="Message..." onkeydown="if(event.key==='Enter') sendActiveChatMessage()" />
          <button class="icon-btn" style="padding:0;font-size:16px;" title="Voice note" onclick="quickAttachMedia('Voice')">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"></path>
              <path d="M19 10v2a7 7 0 0 1-14 0v-2"></path>
              <line x1="12" y1="19" x2="12" y2="23"></line>
              <line x1="8" y1="23" x2="16" y2="23"></line>
            </svg>
          </button>
          <button class="icon-btn" style="padding:0;font-size:16px;" title="Photo" onclick="quickAttachMedia('Photo')">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
              <circle cx="8.5" cy="8.5" r="1.5"></circle>
              <polyline points="21 15 16 10 5 21"></polyline>
            </svg>
          </button>
          <button class="icon-btn" style="padding:0;color:var(--accent);" title="Send" onclick="sendActiveChatMessage()">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="transform: rotate(-18deg);">
              <path d="M22 2L11 13"></path>
              <path d="M22 2L15 22L11 13L2 9L22 2Z"></path>
            </svg>
          </button>
        </div>
      </div>
    </section>

    <!-- 4. Create Shortcut Tab -->
    <section id="view-create" style="display:none;padding:14px;">
      <h3 style="margin-top:0;">Create</h3>
      <button class="sheet-option" onclick="openCreateModal('Reel')"><span>Reel</span><span>▶</span></button>
      <button class="sheet-option" onclick="openCreateModal('Edits')"><span>Edits</span><span>✂</span></button>
      <button class="sheet-option" onclick="openCreateModal('Post')"><span>Post</span><span>▦</span></button>
      <button class="sheet-option" onclick="openCreateModal('Story')"><span>Story</span><span>⊕</span></button>
      <button class="sheet-option" onclick="openCreateModal('Instants')"><span>Instants</span><span>✦</span></button>
      <button class="sheet-option" onclick="openCreateModal('Highlights')"><span>Highlights</span><span>♡</span></button>
      <button class="sheet-option" onclick="openCreateModal('Live')"><span>Live</span><span>◉</span></button>
    </section>

    <!-- 5. Profile -->
    <section id="view-profile" style="display:none;padding:14px;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
        <div class="ring" style="width:74px;height:74px;">
          <div class="avatar-circle" id="pAvatar">U</div>
        </div>
        <div style="display:flex;gap:18px;text-align:center;">
          <div><div style="font-weight:800;" id="pPosts">0</div><div style="font-size:11px;color:var(--muted);">Posts</div></div>
          <div><div style="font-weight:800;" id="pFollowers">0</div><div style="font-size:11px;color:var(--muted);">Followers</div></div>
          <div><div style="font-weight:800;" id="pFollowing">0</div><div style="font-size:11px;color:var(--muted);">Following</div></div>
        </div>
      </div>
      <div style="font-weight:800;font-size:15px;" id="pName"></div>
      <div style="font-size:12px;color:var(--muted);" id="pHandle"></div>
      <div style="font-size:13px;margin:6px 0 12px;" id="pBio"></div>
      <div style="display:flex;gap:8px;margin-bottom:14px;">
        <button class="btn-ghost" style="flex:1;" onclick="openEditProfile()">Edit profile</button>
        <button class="btn-ghost" style="flex:1;" onclick="alert('usonly/u/' + STATE.current_user)">Share profile</button>
        <button class="btn-green" onclick="openCloseFriendsModal()">Close ★</button>
      </div>
      <div style="font-size:12px;color:var(--close-green);margin-bottom:12px;" id="pCloseList"></div>
    </section>

    <!-- 5-item Bottom Navigation -->
    <nav class="bottom-5">
      <button class="nav-item active" id="n-home" onclick="setTab('home')"><span>⌂</span><span id="lbl-home">Home</span></button>
      <button class="nav-item" id="n-search" onclick="setTab('search')"><span>⌕</span><span id="lbl-search">Search</span></button>
      <button class="nav-item" id="n-messages" onclick="setTab('messages')">
        <svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="transform: rotate(-18deg);">
          <path d="M22 2L11 13"></path>
          <path d="M22 2L15 22L11 13L2 9L22 2Z"></path>
        </svg>
        <span id="lbl-chat">Chats</span>
      </button>
      <button class="nav-item" id="n-create" onclick="setTab('create')"><span>⊞</span><span id="lbl-add">Add</span></button>
      <button class="nav-item" id="n-profile" onclick="setTab('profile')"><span>◉</span><span id="lbl-profile">Profile</span></button>
    </nav>
  </div>
</div>

<!-- Apple / iCloud Sign-In Modal -->
<div class="modal" id="appleAuthModal">
  <div class="modal-card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
      <strong>تسجيل الدخول بـ Apple / iCloud</strong>
      <button class="icon-btn" onclick="closeModal('appleAuthModal')">✕</button>
    </div>
    <input class="inp" id="appleEmailInput" placeholder="بريد iCloud / Apple ID (اختياري)" />
    <input class="inp" id="appleNameInput" placeholder="الاسم الكامل" />
    <input class="inp" id="appleUsernameInput" placeholder="اسم المستخدم (@username)" />
    <button class="auth-btn-apple" onclick="submitAppleAuth()">المتابعة</button>
  </div>
</div>

<!-- New Message / Group Chat Sheet -->
<div class="modal" id="newMsgSheetModal">
  <div class="modal-card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
      <strong>New message</strong>
      <button class="icon-btn" onclick="closeModal('newMsgSheetModal')">✕</button>
    </div>
    <button class="sheet-option" onclick="openGroupModalFromSheet()">
      <span><strong>Group chat</strong></span>
      <span>›</span>
    </button>
    <div style="font-size:12px;color:var(--muted);margin:8px 0 6px;">Suggested</div>
    <div id="newMsgSuggestedList"></div>
  </div>
</div>

<!-- Long-press / Context Action Sheet for Chats -->
<div class="modal" id="chatActionsModal">
  <div class="modal-card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
      <strong id="ctxChatName">Chat options</strong>
      <button class="icon-btn" onclick="closeModal('chatActionsModal')">✕</button>
    </div>
    <button class="sheet-option" onclick="runChatAction('pin')" id="ctxPinBtn"><span>Pin</span><span>📌</span></button>
    <button class="sheet-option" onclick="runChatAction('mute')" id="ctxMuteBtn"><span>Mute</span><span>🔇</span></button>
    <button class="sheet-option" style="color:#f87171;" onclick="runChatAction('delete')"><span>Delete</span><span>🗑</span></button>
  </div>
</div>

<!-- Create Sheet Modal -->
<div class="modal" id="createMenuModal">
  <div class="modal-card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
      <strong>Create</strong>
      <button class="icon-btn" onclick="closeModal('createMenuModal')">✕</button>
    </div>
    <button class="sheet-option" onclick="pickCreate('Reel')"><span>Reel</span><span>▶</span></button>
    <button class="sheet-option" onclick="pickCreate('Edits')"><span>Edits</span><span>✂</span></button>
    <button class="sheet-option" onclick="pickCreate('Post')"><span>Post</span><span>▦</span></button>
    <button class="sheet-option" onclick="pickCreate('Story')"><span>Story</span><span>⊕</span></button>
    <button class="sheet-option" onclick="pickCreate('Instants')"><span>Instants</span><span>✦</span></button>
    <button class="sheet-option" onclick="pickCreate('Highlights')"><span>Highlights</span><span>♡</span></button>
    <button class="sheet-option" onclick="pickCreate('Live')"><span>Live</span><span>◉</span></button>
  </div>
</div>

<!-- Create Item Form Modal -->
<div class="modal" id="itemFormModal">
  <div class="modal-card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
      <strong id="itemFormTitle">Create</strong>
      <button class="icon-btn" onclick="closeModal('itemFormModal')">✕</button>
    </div>
    <input class="inp" id="itemText" placeholder="Text / Caption..." />
    <input class="inp" id="itemImage" placeholder="Image URL (optional, https://...)" />
    <div id="storyCloseBlock" style="display:none;margin-bottom:10px;">
      <label style="display:flex;align-items:center;justify-content:space-between;background:var(--card);padding:9px;border-radius:9px;margin-bottom:8px;">
        <span style="color:var(--close-green);font-weight:700;">Close Friends (Green Ring)</span>
        <input type="checkbox" id="itemIsClose" onchange="toggleStoryFriends()" />
      </label>
      <div id="storyFriendChecks" style="display:none;"></div>
    </div>
    <button class="btn" style="width:100%;" onclick="submitCreatedItem()">Publish</button>
  </div>
</div>

<!-- Edit Profile Modal -->
<div class="modal" id="editProfileModal">
  <div class="modal-card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
      <strong>Edit profile</strong>
      <button class="icon-btn" onclick="closeModal('editProfileModal')">✕</button>
    </div>
    <div class="field-row"><span style="width:95px;color:var(--muted);">Name</span><input class="inp" style="margin:0;" id="epName" /></div>
    <div class="field-row"><span style="width:95px;color:var(--muted);">Username</span><input class="inp" style="margin:0;" id="epUsername" /></div>
    <div class="field-row"><span style="width:95px;color:var(--muted);">Pronouns</span><input class="inp" style="margin:0;" id="epPronouns" /></div>
    <div class="field-row"><span style="width:95px;color:var(--muted);">Bio</span><input class="inp" style="margin:0;" id="epBio" /></div>
    <div class="field-row"><span style="width:95px;color:var(--muted);">Links</span><input class="inp" style="margin:0;" id="epLinks" /></div>
    <div class="field-row"><span style="width:95px;color:var(--muted);">Banners</span><input class="inp" style="margin:0;" id="epBanners" /></div>
    <div class="field-row"><span style="width:95px;color:var(--muted);">Gender</span><input class="inp" style="margin:0;" id="epGender" /></div>
    <div class="field-row">
      <span>AI creator</span>
      <input type="checkbox" id="epAiCreator" />
    </div>
    <button class="btn" style="width:100%;margin-top:12px;" onclick="saveProfile()">Save</button>
  </div>
</div>

<!-- Notes Modal -->
<div class="modal" id="noteModal">
  <div class="modal-card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
      <strong>Note</strong>
      <button class="icon-btn" onclick="closeModal('noteModal')">✕</button>
    </div>

    <div class="note-stage">
      <div class="note-preview-bubble" id="noteLiveBubble">Your thoughts go here...</div>
      <div class="note-avatar-wrap" id="noteLiveAvatar">U</div>
    </div>

    <input class="inp" id="noteTextInput" placeholder="Your thoughts go here..." oninput="syncNoteBubble()" />

    <div class="music-picker-box">
      <input class="inp" style="margin-bottom:6px;" id="noteSongSearch" placeholder="Search..." oninput="searchSongsLive(this.value)" />
      <div id="songTrackList" style="max-height:125px;overflow-y:auto;"></div>

      <div id="trimmerPanel" style="display:none;margin-top:8px;padding-top:8px;border-top:1px solid #232632;">
        <div style="display:flex;justify-content:space-between;align-items:center;font-size:11px;color:var(--muted);margin-bottom:6px;">
          <span id="selectedSongCaption" style="color:var(--text);font-weight:700;"></span>
          <span id="trimRangeText">0s – 40s</span>
        </div>

        <div class="trim-controls-row">
          <div class="range-track-wrap">
            <input type="range" id="clipStartSlider" min="0" max="120" value="0" oninput="updateTrimWindow()" />
          </div>
          <div class="circle-dur-group">
            <button type="button" class="dur-circle active" id="dur-40" onclick="setClipDuration(40)">40s</button>
            <button type="button" class="dur-circle" id="dur-25" onclick="setClipDuration(25)">25s</button>
            <button type="button" class="dur-circle" id="dur-15" onclick="setClipDuration(15)">15s</button>
          </div>
        </div>
      </div>
    </div>

    <select class="inp" id="noteAudience">
      <option value="friends">Share with friends</option>
      <option value="close">Close friends</option>
    </select>
    <button class="btn" style="width:100%;" onclick="saveNote()">Share</button>
  </div>
</div>

<!-- Requests Modal -->
<div class="modal" id="requestsModal">
  <div class="modal-card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
      <strong>Message requests</strong>
      <button class="icon-btn" onclick="closeModal('requestsModal')">✕</button>
    </div>
    <div id="requestsListBox"></div>
  </div>
</div>

<!-- Group Chat Modal -->
<div class="modal" id="groupModal">
  <div class="modal-card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
      <strong>Group chat</strong>
      <button class="icon-btn" onclick="closeModal('groupModal')">✕</button>
    </div>
    <input class="inp" id="grpNameInput" placeholder="Group name..." />
    <input class="inp" id="grpSearchInput" placeholder="Search by @username..." oninput="renderGroupMemberPicker()" />
    <div id="grpMemberPicker"></div>
    <button class="btn" style="width:100%;margin-top:8px;" onclick="createGroup()">Create group</button>
  </div>
</div>

<!-- Close Friends Modal -->
<div class="modal" id="cfModal">
  <div class="modal-card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
      <strong style="color:var(--close-green);">Close Friends</strong>
      <button class="icon-btn" onclick="closeModal('cfModal')">✕</button>
    </div>
    <div id="cfPicker"></div>
    <button class="btn-green" style="width:100%;margin-top:8px;" onclick="saveCloseFriends()">Save Close Friends</button>
  </div>
</div>

<script>
const I18N = {
  ar: { dir: "rtl", home: "الرئيسية", search: "بحث", chat: "الرسائل", add: "إضافة", profile: "حسابي" },
  en: { dir: "ltr", home: "Home", search: "Search", chat: "Chats", add: "Add", profile: "Profile" },
  fr: { dir: "ltr", home: "Accueil", search: "Recherche", chat: "Messages", add: "Créer", profile: "Profil" }
};

const FEATURED_TRACKS = [
  { title: "Night Owl — Synth Wave", url: "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-1.mp3", duration: 180 },
  { title: "Midnight Focus — Lo-Fi", url: "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-2.mp3", duration: 180 },
  { title: "Desert Horizon — Ambient", url: "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-3.mp3", duration: 180 },
  { title: "Late Drive — Chill", url: "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-4.mp3", duration: 180 }
];

let AUTH_TOKEN = localStorage.getItem("usonly_token") || "";
let STATE = null;
let currentCreateKind = "Post";
let activeChatKey = null;
let activeChatIsGroup = false;
let contextTargetKey = null;
let songSearchTimer = null;
let activeTracksList = FEATURED_TRACKS.slice();
let selectedTrack = null;
let selectedClipDuration = 40;
let selectedClipStart = 0;
let noteClipStopTimer = null;
let currentlyPlayingNoteId = null;

function authHeaders(extra = {}) {
  const h = Object.assign({}, extra);
  if (AUTH_TOKEN) h["Authorization"] = `Bearer ${AUTH_TOKEN}`;
  return h;
}

function changeLang(lang) {
  const cfg = I18N[lang] || I18N.en;
  document.documentElement.lang = lang;
  document.documentElement.dir = cfg.dir;
  document.getElementById("lbl-home").textContent = cfg.home;
  document.getElementById("lbl-search").textContent = cfg.search;
  document.getElementById("lbl-chat").textContent = cfg.chat;
  document.getElementById("lbl-add").textContent = cfg.add;
  document.getElementById("lbl-profile").textContent = cfg.profile;
}

function showAuthGate(message = "") {
  document.getElementById("mainAppShell").style.display = "none";
  document.getElementById("authGate").style.display = "flex";
  if (message) document.getElementById("authErrorMsg").textContent = message;
}

function showMainShell() {
  document.getElementById("authGate").style.display = "none";
  document.getElementById("mainAppShell").style.display = "block";
}

async function submitEmailPhoneAuth() {
  const identifier = document.getElementById("authIdentifier").value.trim();
  const username = document.getElementById("authUsername").value.trim();
  const name = document.getElementById("authName").value.trim();
  const password = document.getElementById("authPassword").value;
  document.getElementById("authErrorMsg").textContent = "";

  const res = await fetch("/api/auth/email-phone", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ identifier, username, name, password })
  });
  const data = await res.json();
  if (!res.ok || !data.ok) {
    document.getElementById("authErrorMsg").textContent = data.error || "تعذر إتمام الدخول";
    return;
  }
  AUTH_TOKEN = data.token;
  localStorage.setItem("usonly_token", AUTH_TOKEN);
  await loadState();
}

function openAppleModal() {
  document.getElementById("appleAuthModal").classList.add("open");
}

async function submitAppleAuth() {
  const apple_email = document.getElementById("appleEmailInput").value.trim();
  const apple_name = document.getElementById("appleNameInput").value.trim();
  const username = document.getElementById("appleUsernameInput").value.trim();

  const res = await fetch("/api/auth/apple", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ apple_email, apple_name, username })
  });
  const data = await res.json();
  if (data.ok && data.token) {
    AUTH_TOKEN = data.token;
    localStorage.setItem("usonly_token", AUTH_TOKEN);
    closeModal("appleAuthModal");
    await loadState();
  }
}

async function logoutUser() {
  await fetch("/api/auth/logout", { method: "POST", headers: authHeaders() });
  AUTH_TOKEN = "";
  localStorage.removeItem("usonly_token");
  STATE = null;
  showAuthGate();
}

async function loadState() {
  const r = await fetch("/api/state", { headers: authHeaders() });
  if (r.status === 401) {
    showAuthGate();
    return;
  }
  STATE = await r.json();
  showMainShell();
  renderAll();
}

function renderAll() {
  const meObj = STATE.current_user_obj || STATE.users.find(u => u.username === STATE.current_user);
  document.getElementById("dmHandleTitle").textContent = `@${meObj ? meObj.handle : STATE.current_user} ⌄`;
  document.getElementById("reqBtn").textContent = `Requests (${STATE.requests.length})`;
  renderStories();
  renderPosts();
  renderSearch();
  renderDmScreen();
  renderProfile();
}

function renderStories() {
  const row = document.getElementById("storiesRow");
  row.innerHTML = "";
  const me = STATE.current_user;
  const myStatus = STATE.story_status[me] || "none";
  const myEl = document.createElement("div");
  myEl.className = "story-col";
  myEl.innerHTML = `<div class="ring ${myStatus}"><div class="avatar-circle">${me[0]}</div>${myStatus === "close" ? '<div class="cf-tag">CLOSE</div>' : ""}</div><span style="font-size:11px;">Your story</span>`;
  myEl.onclick = () => pickCreate("Story");
  row.appendChild(myEl);

  STATE.users.filter(u => u.username !== me).forEach(u => {
    const st = STATE.story_status[u.username] || "none";
    const el = document.createElement("div");
    el.className = "story-col";
    el.innerHTML = `<div class="ring ${st}"><div class="avatar-circle">${u.avatar}</div>${st === "close" ? '<div class="cf-tag">CLOSE</div>' : ""}</div><span style="font-size:11px;">${u.username}</span>`;
    const userStories = STATE.stories.filter(s => s.author === u.username);
    if (userStories.length) {
      el.onclick = () => {
        const s = userStories[0];
        alert(`${s.author}${s.is_close_friends ? " [Close Friends]" : ""}: ${s.text || ""}`);
      };
    }
    row.appendChild(el);
  });
}

function renderDmNotesStrip() {
  const strip = document.getElementById("dmNotesStrip");
  const me = STATE.current_user;
  const myNote = STATE.notes.find(n => n.author === me);
  const friendNotes = STATE.notes.filter(n => n.author !== me);

  const myPlaying = myNote && currentlyPlayingNoteId === myNote.id;
  const myDur = myNote ? (myNote.clip_duration || 40) : 40;

  const myCardHtml = `
    <div class="story-col">
      <div class="note-bubble" onclick="${myNote && myNote.preview_url ? `playNoteClip('${myNote.id}')` : `openNoteModal()`}">
        ${myNote ? myNote.text : "Leave a note"}
        ${myNote && myNote.song ? `<div style="color:#60a5fa;margin-top:3px;font-size:10px;font-weight:700;">${myPlaying ? "❚❚ Playing" : "▶ Play"} • ${myNote.song} (${myDur}s)</div>` : ""}
      </div>
      <div style="position:relative;" onclick="openNoteModal()">
        <div class="ring ${myNote && myNote.audience === "close" ? "close" : ""}" style="width:58px;height:58px;">
          <div class="avatar-circle" style="font-size:16px;">${me[0]}</div>
        </div>
        <span style="position:absolute;bottom:-2px;left:-2px;background:#181a22;border:1px solid #2b2f3d;color:#fff;font-size:9px;padding:1px 5px;border-radius:999px;">Edit</span>
      </div>
      <span style="font-size:10px;color:var(--muted);">Your note</span>
    </div>
  `;

  const friendsHtml = friendNotes.map(n => {
    const isPlaying = currentlyPlayingNoteId === n.id;
    const dur = n.clip_duration || 40;
    return `
      <div class="story-col" onclick="playNoteClip('${n.id}')">
        <div class="note-bubble">
          ${n.text}
          ${n.song ? `<div style="color:#60a5fa;margin-top:3px;font-size:10px;font-weight:700;">${isPlaying ? "❚❚ Playing" : "▶ Play"} • ${n.song} (${dur}s)</div>` : ""}
        </div>
        <div class="ring ${n.audience === "close" ? "close" : ""}" style="width:58px;height:58px;">
          <div class="avatar-circle" style="font-size:16px;">${n.author[0]}</div>
        </div>
        <span style="font-size:10px;color:var(--muted);">${n.author}</span>
      </div>
    `;
  }).join("");

  strip.innerHTML = myCardHtml + friendsHtml;
}

function renderDmScreen() {
  renderDmNotesStrip();
  const q = (document.getElementById("dmSearchAiInput").value || "").trim().toLowerCase();
  const list = document.getElementById("threadsList");

  const dmEntries = Object.entries(STATE.conversations).map(([key, c]) => ({
    key,
    title: c.name,
    subtitle: c.messages.length ? c.messages[c.messages.length - 1].text : "",
    pinned: !!c.pinned,
    muted: !!c.muted,
    isGroup: false
  }));

  const grpEntries = STATE.groups.map(g => ({
    key: g.id,
    title: g.name,
    subtitle: g.messages.length ? g.messages[g.messages.length - 1].text : "Group chat",
    pinned: !!g.pinned,
    muted: !!g.muted,
    isGroup: true
  }));

  const combined = [...dmEntries, ...grpEntries]
    .filter(item => !q || item.title.toLowerCase().includes(q) || item.subtitle.toLowerCase().includes(q))
    .sort((a, b) => Number(b.pinned) - Number(a.pinned));

  list.innerHTML = combined.map(item => {
    const badges = `${item.pinned ? "📌 " : ""}${item.muted ? "🔇 " : ""}`;
    return `
      <div class="thread-row"
           onclick="openConversation('${item.key.replace(/'/g, "\\'")}', ${item.isGroup})"
           oncontextmenu="event.preventDefault(); openChatContext('${item.key.replace(/'/g, "\\'")}');"
           onpointerdown="startLongPress('${item.key.replace(/'/g, "\\'")}')"
           onpointerup="cancelLongPress()"
           onpointerleave="cancelLongPress()">
        <div class="thread-left">
          <div class="thread-avatar">${item.title[0]}</div>
          <div>
            <div style="font-weight:700;font-size:14px;">${badges}${item.title}</div>
            <div style="font-size:12px;color:var(--muted);">${item.subtitle}</div>
          </div>
        </div>
        <span style="color:var(--muted);font-size:11px;">Hold</span>
      </div>
    `;
  }).join("");

  if (activeChatKey) {
    document.getElementById("dmInboxView").style.display = "none";
    document.getElementById("fullThreadView").classList.add("open");
    renderActiveChatDrawer();
  } else {
    document.getElementById("dmInboxView").style.display = "block";
    document.getElementById("fullThreadView").classList.remove("open");
  }
}

let longPressTimer = null;
function startLongPress(key) {
  cancelLongPress();
  longPressTimer = setTimeout(() => openChatContext(key), 520);
}
function cancelLongPress() {
  clearTimeout(longPressTimer);
}

function openChatContext(key) {
  contextTargetKey = key;
  const c = STATE.conversations[key];
  const g = STATE.groups.find(x => x.id === key);
  const obj = c || g;
  if (!obj) return;
  document.getElementById("ctxChatName").textContent = c ? c.name : g.name;
  document.getElementById("ctxPinBtn").innerHTML = `<span>${obj.pinned ? "Unpin" : "Pin"}</span><span>📌</span>`;
  document.getElementById("ctxMuteBtn").innerHTML = `<span>${obj.muted ? "Unmute" : "Mute"}</span><span>🔇</span>`;
  document.getElementById("chatActionsModal").classList.add("open");
}

async function runChatAction(action) {
  if (!contextTargetKey) return;
  await fetch("/api/conversations/action", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ target: contextTargetKey, action })
  });
  if (action === "delete" && activeChatKey === contextTargetKey) {
    closeActiveChat();
  }
  closeModal("chatActionsModal");
  await loadState();
}

function openConversation(key, isGroup) {
  activeChatKey = key;
  activeChatIsGroup = isGroup;
  document.getElementById("dmInboxView").style.display = "none";
  document.getElementById("fullThreadView").classList.add("open");
  renderActiveChatDrawer();
}

function closeActiveChat() {
  activeChatKey = null;
  document.getElementById("fullThreadView").classList.remove("open");
  document.getElementById("dmInboxView").style.display = "block";
}

function renderActiveChatDrawer() {
  if (!activeChatKey) return;
  const me = STATE.current_user;
  const box = document.getElementById("activeChatMessages");

  if (activeChatIsGroup) {
    const grp = STATE.groups.find(g => g.id === activeChatKey);
    if (!grp) return closeActiveChat();
    document.getElementById("activeChatAvatar").textContent = grp.name[0] || "G";
    document.getElementById("activeChatTitle").textContent = grp.name;
    document.getElementById("activeChatSub").textContent = `${grp.members.length} members`;
    box.innerHTML = grp.messages.map(m => {
      const mine = m.sender === me;
      return `
        <div class="msg-row ${mine ? "mine" : "theirs"}">
          <div class="msg-sender-label">${m.sender}</div>
          <div class="bubble">${m.text}</div>
        </div>
      `;
    }).join("");
  } else {
    const conv = STATE.conversations[activeChatKey];
    if (!conv) return closeActiveChat();
    document.getElementById("activeChatAvatar").textContent = conv.name[0] || "U";
    document.getElementById("activeChatTitle").textContent = conv.name;
    document.getElementById("activeChatSub").textContent = conv.handle || "";
    box.innerHTML = conv.messages.map(m => {
      const mine = m.sender === me;
      return `
        <div class="msg-row ${mine ? "mine" : "theirs"}">
          <div class="bubble">${m.text}</div>
        </div>
      `;
    }).join("");
  }
  box.scrollTop = box.scrollHeight;
}

async function sendActiveChatMessage() {
  const inp = document.getElementById("activeChatInput");
  const txt = inp.value.trim();
  if (!txt || !activeChatKey) return;
  if (activeChatIsGroup) {
    await fetch(`/api/groups/${activeChatKey}/message`, {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ text: txt })
    });
  } else {
    await fetch("/api/direct", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ target: activeChatKey, text: txt })
    });
  }
  inp.value = "";
  await loadState();
}

async function quickAttachMedia(kind) {
  const inp = document.getElementById("activeChatInput");
  const sample = kind === "Camera"
    ? "[Camera capture]"
    : kind === "Voice"
      ? "[Voice message • 0:06]"
      : "[Photo attachment]";
  inp.value = inp.value.trim() ? `${inp.value.trim()} ${sample}` : sample;
  await sendActiveChatMessage();
}

async function handleDmSearchOrAi(e) {
  if (e.key !== "Enter") return;
  const val = e.target.value.trim();
  if (!val) return;
  const matchedUser = STATE.users.find(u =>
    u.username.toLowerCase() === val.toLowerCase() ||
    u.handle.toLowerCase() === val.replace(/^@/, "").toLowerCase()
  );
  if (matchedUser) {
    openConversation(matchedUser.username, false);
    return;
  }
  openConversation("usonly AI", false);
  await fetch("/api/direct", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ target: "usonly AI", text: val })
  });
  e.target.value = "";
  await loadState();
}

function openNewMessageSheet() {
  const list = document.getElementById("newMsgSuggestedList");
  const others = STATE.users.filter(u => u.username !== STATE.current_user);
  list.innerHTML = others.length
    ? others.map(u => `
      <div class="sheet-option" onclick="closeModal('newMsgSheetModal'); openConversation('${u.username}', false);">
        <div>
          <div style="font-weight:700;">${u.name}</div>
          <div style="font-size:11px;color:var(--muted);">@${u.handle}</div>
        </div>
        <span>›</span>
      </div>
    `).join("")
    : `<div style="color:var(--muted);font-size:12px;">لا يوجد مستخدمون آخرون مسجلون بعد.</div>`;
  document.getElementById("newMsgSheetModal").classList.add("open");
}

function openGroupModalFromSheet() {
  closeModal("newMsgSheetModal");
  openGroupModal();
}

function playNoteClip(noteId) {
  const note = STATE.notes.find(n => n.id === noteId);
  if (!note || !note.preview_url) return;

  if (currentlyPlayingNoteId === noteId) {
    stopNotePlayback();
    renderDmNotesStrip();
    return;
  }

  stopNotePlayback();
  const player = document.getElementById("noteAudioPlayer");
  const startSec = Math.max(0, Number(note.clip_start || 0));
  const durSec = Number(note.clip_duration || 40);

  player.src = note.preview_url;
  player.currentTime = startSec;
  player.play().then(() => {
    currentlyPlayingNoteId = noteId;
    renderDmNotesStrip();
    noteClipStopTimer = setTimeout(() => {
      stopNotePlayback();
      renderDmNotesStrip();
    }, durSec * 1000);
  }).catch(() => {
    alert("تعذر تشغيل المقطع الصوتي في المتصفح حالياً.");
  });
}

function stopNotePlayback() {
  const player = document.getElementById("noteAudioPlayer");
  player.pause();
  clearTimeout(noteClipStopTimer);
  currentlyPlayingNoteId = null;
}

function renderPosts() {
  const box = document.getElementById("postsList");
  box.innerHTML = STATE.posts.map(p => `
    <article class="post">
      <div class="post-head">
        <div><strong>${p.author}</strong> <span style="font-size:11px;color:var(--muted);">• ${p.badge}</span></div>
        <button class="btn-ghost" style="padding:4px 10px;font-size:11px;">Follow</button>
      </div>
      ${p.image ? `<img class="post-img" src="${p.image}" alt="" />` : ""}
      <div class="post-acts">
        <button class="icon-btn" style="padding:0;" onclick="likePost('${p.id}')">${p.liked ? "♥" : "♡"}</button>
        <span style="font-size:13px;align-self:center;">${p.likes}</span>
      </div>
      <div style="padding:2px 14px;font-size:13px;"><strong>${p.author}</strong> ${p.caption}</div>
    </article>
  `).join("");
}

function renderSearch() {
  const q = (document.getElementById("searchInput").value || "").trim().toLowerCase();
  const list = STATE.users.filter(u =>
    u.username.toLowerCase().includes(q) ||
    u.handle.toLowerCase().includes(q) ||
    u.name.toLowerCase().includes(q)
  );
  document.getElementById("searchResults").innerHTML = list.map(u => `
    <div class="field-row">
      <div>
        <div style="font-weight:700;">@${u.handle} <span style="font-weight:400;color:var(--muted);">(${u.name})</span></div>
        <div style="font-size:12px;color:var(--muted);">${u.bio || ""}</div>
      </div>
      <button class="btn-ghost" onclick="setTab('messages'); openConversation('${u.username}', false);">Message</button>
    </div>
  `).join("");
}

function openRequestsModal() {
  document.getElementById("requestsListBox").innerHTML = STATE.requests.length
    ? STATE.requests.map(r => `
      <div class="field-row">
        <div>
          <div style="font-weight:700;">${r.sender} <span style="color:var(--muted);font-size:11px;">${r.handle}</span></div>
          <div style="font-size:12px;">${r.text}</div>
        </div>
        <div style="display:flex;gap:6px;">
          <button class="btn" onclick="handleReq('${r.id}','accept')">Accept</button>
          <button class="btn-ghost" onclick="handleReq('${r.id}','decline')">Decline</button>
        </div>
      </div>
    `).join("")
    : `<div style="color:var(--muted);font-size:13px;">No pending requests.</div>`;
  document.getElementById("requestsModal").classList.add("open");
}

async function handleReq(id, action) {
  await fetch(`/api/requests/${id}/${action}`, { method: "POST", headers: authHeaders() });
  closeModal("requestsModal");
  await loadState();
}

function openGroupModal() {
  document.getElementById("grpNameInput").value = "";
  document.getElementById("grpSearchInput").value = "";
  renderGroupMemberPicker();
  document.getElementById("groupModal").classList.add("open");
}

function renderGroupMemberPicker() {
  const q = (document.getElementById("grpSearchInput").value || "").trim().toLowerCase();
  const users = STATE.users.filter(u =>
    u.username !== STATE.current_user &&
    (u.username.toLowerCase().includes(q) || u.handle.toLowerCase().includes(q))
  );
  document.getElementById("grpMemberPicker").innerHTML = users.map(u => `
    <label class="field-row">
      <span>${u.name} (@${u.handle})</span>
      <input type="checkbox" class="grp-cb" value="${u.username}" />
    </label>
  `).join("");
}

async function createGroup() {
  const name = document.getElementById("grpNameInput").value;
  const members = Array.from(document.querySelectorAll(".grp-cb:checked")).map(c => c.value);
  const res = await fetch("/api/groups", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ name, members })
  });
  const data = await res.json();
  closeModal("groupModal");
  await loadState();
  if (data.group) openConversation(data.group.id, true);
}

function renderProfile() {
  const u = STATE.current_user_obj || STATE.users.find(x => x.username === STATE.current_user);
  if (!u) return;
  document.getElementById("pAvatar").textContent = u.avatar || "U";
  document.getElementById("pPosts").textContent = u.posts_count || 0;
  document.getElementById("pFollowers").textContent = u.followers || 0;
  document.getElementById("pFollowing").textContent = u.following || 0;
  document.getElementById("pName").textContent = u.name || "";
  document.getElementById("pHandle").textContent = `@${u.handle || u.username} ${u.pronouns ? "• " + u.pronouns : ""}`;
  document.getElementById("pBio").textContent = u.bio || "";
  document.getElementById("pCloseList").textContent = STATE.close_friends.length
    ? `Close Friends: ${STATE.close_friends.join(", ")}`
    : "Close Friends: none";
}

function openEditProfile() {
  const u = STATE.current_user_obj || STATE.users.find(x => x.username === STATE.current_user);
  if (!u) return;
  document.getElementById("epName").value = u.name || "";
  document.getElementById("epUsername").value = u.username || "";
  document.getElementById("epPronouns").value = u.pronouns || "";
  document.getElementById("epBio").value = u.bio || "";
  document.getElementById("epLinks").value = u.links || "";
  document.getElementById("epBanners").value = u.banners || "";
  document.getElementById("epGender").value = u.gender || "";
  document.getElementById("epAiCreator").checked = !!u.ai_creator;
  document.getElementById("editProfileModal").classList.add("open");
}

async function saveProfile() {
  await fetch("/api/profile", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({
      name: document.getElementById("epName").value,
      username: document.getElementById("epUsername").value,
      pronouns: document.getElementById("epPronouns").value,
      bio: document.getElementById("epBio").value,
      links: document.getElementById("epLinks").value,
      banners: document.getElementById("epBanners").value,
      gender: document.getElementById("epGender").value,
      ai_creator: document.getElementById("epAiCreator").checked,
    })
  });
  closeModal("editProfileModal");
  await loadState();
}

function openCloseFriendsModal() {
  document.getElementById("cfPicker").innerHTML = STATE.users
    .filter(u => u.username !== STATE.current_user)
    .map(u => `
      <label class="field-row">
        <span>${u.name} (@${u.handle})</span>
        <input type="checkbox" class="cf-cb" value="${u.username}" ${STATE.close_friends.includes(u.username) ? "checked" : ""} />
      </label>
    `).join("");
  document.getElementById("cfModal").classList.add("open");
}

async function saveCloseFriends() {
  const friends = Array.from(document.querySelectorAll(".cf-cb:checked")).map(c => c.value);
  await fetch("/api/close-friends", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ friends })
  });
  closeModal("cfModal");
  await loadState();
}

function openNoteModal() {
  const u = STATE.current_user_obj || STATE.users.find(x => x.username === STATE.current_user);
  document.getElementById("noteLiveAvatar").textContent = (u && u.avatar) || "U";
  document.getElementById("noteTextInput").value = "";
  document.getElementById("noteSongSearch").value = "";
  document.getElementById("trimmerPanel").style.display = "none";
  selectedTrack = null;
  selectedClipDuration = 40;
  selectedClipStart = 0;
  setClipDuration(40, false);
  syncNoteBubble();
  activeTracksList = FEATURED_TRACKS.slice();
  renderTrackList();
  document.getElementById("noteModal").classList.add("open");
}

function syncNoteBubble() {
  const val = document.getElementById("noteTextInput").value.trim();
  const base = val || "Your thoughts go here...";
  document.getElementById("noteLiveBubble").textContent = selectedTrack
    ? `${base} • ♪ ${selectedTrack.title} (${selectedClipDuration}s)`
    : base;
}

function renderTrackList() {
  const box = document.getElementById("songTrackList");
  box.innerHTML = activeTracksList.map((tr, idx) => {
    const isSel = selectedTrack && selectedTrack.url === tr.url && selectedTrack.title === tr.title;
    return `
      <div class="track-row ${isSel ? "selected" : ""}" onclick="chooseTrack(${idx})">
        <span><strong>${tr.title}</strong></span>
        <span style="color:#60a5fa;">Select</span>
      </div>
    `;
  }).join("");
}

function chooseTrack(idx) {
  const tr = activeTracksList[idx];
  if (!tr) return;
  selectedTrack = tr;
  const maxStart = Math.max(0, (tr.duration || 180) - selectedClipDuration);
  const slider = document.getElementById("clipStartSlider");
  slider.max = maxStart;
  slider.value = Math.min(selectedClipStart, maxStart);
  document.getElementById("trimmerPanel").style.display = "block";
  document.getElementById("selectedSongCaption").textContent = tr.title;
  renderTrackList();
  updateTrimWindow(true);
  syncNoteBubble();
}

function setClipDuration(sec, previewNow = true) {
  selectedClipDuration = sec;
  [40, 25, 15].forEach(d => {
    document.getElementById(`dur-${d}`).classList.toggle("active", d === sec);
  });
  if (selectedTrack) {
    const maxStart = Math.max(0, (selectedTrack.duration || 180) - sec);
    const slider = document.getElementById("clipStartSlider");
    slider.max = maxStart;
    if (Number(slider.value) > maxStart) slider.value = maxStart;
    updateTrimWindow(previewNow);
    syncNoteBubble();
  }
}

function updateTrimWindow(previewNow = false) {
  const start = Number(document.getElementById("clipStartSlider").value || 0);
  selectedClipStart = start;
  const end = start + selectedClipDuration;
  document.getElementById("trimRangeText").textContent = `${start}s – ${end}s`;
  syncNoteBubble();

  if (previewNow && selectedTrack && selectedTrack.url) {
    stopNotePlayback();
    const player = document.getElementById("noteAudioPlayer");
    player.src = selectedTrack.url;
    player.currentTime = start;
    player.play().catch(() => {});
    noteClipStopTimer = setTimeout(() => {
      player.pause();
    }, selectedClipDuration * 1000);
  }
}

function searchSongsLive(query) {
  clearTimeout(songSearchTimer);
  const q = (query || "").trim();
  if (!q) {
    activeTracksList = FEATURED_TRACKS.slice();
    renderTrackList();
    return;
  }

  const localMatches = FEATURED_TRACKS.filter(t => t.title.toLowerCase().includes(q.toLowerCase()));
  if (localMatches.length) {
    activeTracksList = localMatches;
    renderTrackList();
  }

  songSearchTimer = setTimeout(async () => {
    try {
      const url = `https://itunes.apple.com/search?term=${encodeURIComponent(q)}&media=music&limit=8`;
      const res = await fetch(url);
      const data = await res.json();
      const tracks = (data.results || [])
        .filter(item => item.trackName && item.previewUrl)
        .map(item => ({
          title: `${item.trackName} — ${item.artistName}`,
          url: item.previewUrl,
          duration: 30
        }));
      if (tracks.length) {
        activeTracksList = tracks;
        renderTrackList();
      }
    } catch (e) {
      if (!localMatches.length) {
        activeTracksList = FEATURED_TRACKS.slice();
        renderTrackList();
      }
    }
  }, 250);
}

async function saveNote() {
  const text = document.getElementById("noteTextInput").value;
  const audience = document.getElementById("noteAudience").value;
  stopNotePlayback();

  await fetch("/api/notes", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({
      text,
      song: selectedTrack ? selectedTrack.title : "",
      preview_url: selectedTrack ? selectedTrack.url : "",
      clip_start: selectedClipStart,
      clip_duration: selectedClipDuration,
      audience
    })
  });
  closeModal("noteModal");
  await loadState();
}

function openCreateMenu() {
  document.getElementById("createMenuModal").classList.add("open");
}

function pickCreate(kind) {
  closeModal("createMenuModal");
  openCreateModal(kind);
}

function openCreateModal(kind) {
  currentCreateKind = kind;
  document.getElementById("itemFormTitle").textContent = `Create — ${kind}`;
  document.getElementById("itemText").value = "";
  document.getElementById("itemImage").value = "";
  document.getElementById("itemIsClose").checked = false;
  document.getElementById("storyFriendChecks").style.display = "none";
  document.getElementById("storyCloseBlock").style.display = kind === "Story" ? "block" : "none";
  document.getElementById("itemFormModal").classList.add("open");
}

function toggleStoryFriends() {
  const checked = document.getElementById("itemIsClose").checked;
  const box = document.getElementById("storyFriendChecks");
  box.style.display = checked ? "block" : "none";
  if (checked) {
    box.innerHTML = STATE.users
      .filter(u => u.username !== STATE.current_user)
      .map(u => `
        <label class="field-row">
          <span>${u.username}</span>
          <input type="checkbox" class="sf-cb" value="${u.username}" ${STATE.close_friends.includes(u.username) ? "checked" : ""} />
        </label>
      `).join("");
  }
}

async function submitCreatedItem() {
  const text = document.getElementById("itemText").value;
  const image = document.getElementById("itemImage").value;
  if (currentCreateKind === "Story") {
    const isClose = document.getElementById("itemIsClose").checked;
    const selectedFriends = Array.from(document.querySelectorAll(".sf-cb:checked")).map(c => c.value);
    await fetch("/api/stories", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ kind: currentCreateKind, text, image, is_close_friends: isClose, selected_friends: selectedFriends })
    });
  } else {
    await fetch("/api/posts", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ kind: currentCreateKind, caption: text, image })
    });
  }
  closeModal("itemFormModal");
  await loadState();
}

async function likePost(id) {
  await fetch(`/api/posts/${id}/like`, { method: "POST", headers: authHeaders() });
  await loadState();
}

function setTab(tab) {
  if (tab === "messages") {
    closeActiveChat();
  }
  ["home", "search", "messages", "create", "profile"].forEach(t => {
    document.getElementById(`view-${t}`).style.display = t === tab ? "block" : "none";
    document.getElementById(`n-${t}`).classList.toggle("active", t === tab);
  });
}

function closeModal(id) {
  document.getElementById(id).classList.remove("open");
}

loadState();
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def index():
    return HTML_PAGE