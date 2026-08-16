import os
import re
import io
import zipfile
import hashlib
import base64
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
import time
import uuid
from fastapi import FastAPI, File, Form, HTTPException, UploadFile, Request, Header
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import Column, Integer, String, Float, DateTime, create_engine, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import bcrypt
from starlette.middleware.sessions import SessionMiddleware
import asyncio

# === CONFIG ===
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
DEFAULT_QUOTA_BYTES = 10 * 1024 * 1024  # 10 MB default per user
MAX_SINGLE_FILE_BYTES = 5 * 1024 * 1024  # 5 MB per individual file
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
SESSION_TIMEOUT_SECONDS = 1800  # 30 minutes inactivity

# Username validation: alphanumeric + underscores + hyphens, 3-30 chars
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_\-]{3,30}$")

# Rate limiting & concurrent upload protection
last_upload_time: dict = {}
_upload_lock = asyncio.Lock()

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# === DATABASE ===
Base = declarative_base()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///vinnodrive.db")

if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(bind=engine)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_admin = Column(Integer, default=0)
    custom_quota_bytes = Column(Integer, default=10 * 1024 * 1024)
    api_key = Column(String, unique=True, nullable=True, index=True)
    totp_secret = Column(String, nullable=True)
    totp_enabled = Column(Integer, default=0)


class UserFile(Base):
    __tablename__ = "user_files"
    id = Column(Integer, primary_key=True)
    filename = Column(String, index=True)
    filepath = Column(String)
    filehash = Column(String, index=True)
    username = Column(String, index=True)
    is_reference = Column(Integer, default=0)
    size = Column(Float, default=0)
    upload_date = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    folder = Column(String, index=True, default="/")
    is_public = Column(Integer, default=0)
    share_token = Column(String, unique=True, nullable=True, index=True)
    share_password = Column(String, nullable=True)
    share_expires_at = Column(DateTime, nullable=True)
    share_max_downloads = Column(Integer, nullable=True)
    download_count = Column(Integer, default=0)
    is_starred = Column(Integer, default=0, index=True)
    tags = Column(String, default="")
    is_trashed = Column(Integer, default=0, index=True)
    trashed_at = Column(DateTime, nullable=True)
    version = Column(Integer, default=1)


class FileVersion(Base):
    __tablename__ = "file_versions"
    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, index=True)
    version_number = Column(Integer, default=1)
    filename = Column(String)
    filepath = Column(String)
    filehash = Column(String)
    size = Column(Float)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    username = Column(String, index=True)


class ActivityLog(Base):
    __tablename__ = "activity_logs"
    id = Column(Integer, primary_key=True)
    username = Column(String, index=True)
    action = Column(String)  # upload, trash, restore, delete, share, edit, rollback, star, unstar, remote_upload, api_upload
    details = Column(String)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    ip_address = Column(String, nullable=True)


class FileComment(Base):
    __tablename__ = "file_comments"
    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, index=True)
    username = Column(String, index=True)
    comment_text = Column(String)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class SharedFile(Base):
    __tablename__ = "shared_files"
    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, index=True)
    shared_with = Column(String, index=True)
    shared_by = Column(String, index=True)


Base.metadata.create_all(bind=engine)


# === SECURITY & PASSWORD HELPERS ===

def hash_password(password: str) -> str:
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8")[:72], hashed_password.encode("utf-8"))
    except Exception:
        return False


def sanitize_filename(filename: str) -> str:
    base = os.path.basename(filename).strip()
    base = re.sub(r"[\x00-\x1f\x7f]", "", base)
    base = re.sub(r'[\\/*?:"<>|]', "_", base)
    if len(base) > 255:
        name, ext = os.path.splitext(base)
        base = name[: 255 - len(ext)] + ext
    return base or "unnamed_file"


def get_current_user(request: Request) -> str | None:
    username = request.session.get("username")
    if not username:
        return None
    last_activity = request.session.get("last_activity")
    now = time.time()
    if last_activity and (now - float(last_activity) > SESSION_TIMEOUT_SECONDS):
        request.session.clear()
        return None
    request.session["last_activity"] = now
    return username


def calculate_hash(file_path: str) -> str:
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha.update(chunk)
    return sha.hexdigest()


def log_activity(db, username: str, action: str, details: str, ip: str | None = None):
    try:
        log = ActivityLog(
            username=username,
            action=action,
            details=details,
            timestamp=datetime.now(timezone.utc),
            ip_address=ip
        )
        db.add(log)
        db.commit()
    except Exception:
        pass


def is_user_admin(db, username: str) -> bool:
    """Determine if a user has administrator rights."""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if user.is_admin == 1 or user.username.lower() == "admin":
        return True
    first_user = db.query(User).order_by(User.id.asc()).first()
    if first_user and first_user.id == user.id:
        return True
    return False


def get_user_quota_bytes(db, username: str) -> int:
    user = db.query(User).filter(User.username == username).first()
    if user and user.custom_quota_bytes:
        return user.custom_quota_bytes
    return DEFAULT_QUOTA_BYTES


def cleanup_disk_file_if_unreferenced(db, filehash: str, filepath: str):
    """Global Dedup: delete disk file only if zero user files or historical versions reference it."""
    if not filehash or not filepath:
        return
    count_active = db.query(UserFile).filter(UserFile.filehash == filehash).count()
    count_versions = db.query(FileVersion).filter(FileVersion.filehash == filehash).count()
    if count_active == 0 and count_versions == 0 and os.path.exists(filepath):
        try:
            os.remove(filepath)
        except Exception:
            pass


def get_actual_storage(username: str) -> int:
    """Disk storage charged to user: non-trashed, non-reference, non-marker files."""
    db = SessionLocal()
    try:
        res = db.query(func.coalesce(func.sum(UserFile.size), 0)).filter(
            UserFile.username == username,
            UserFile.is_reference == 0,
            UserFile.is_trashed == 0,
            ~UserFile.filename.like(".folder_marker_%"),
        ).scalar()
        return int(res or 0)
    finally:
        db.close()


def get_user_space_saved(username: str) -> int:
    """Space saved via deduplication for this user."""
    db = SessionLocal()
    try:
        res = db.query(func.coalesce(func.sum(UserFile.size), 0)).filter(
            UserFile.username == username,
            UserFile.is_reference == 1,
            UserFile.is_trashed == 0,
        ).scalar()
        return int(res or 0)
    finally:
        db.close()


def get_original_uploaded(username: str) -> int:
    """Total logical size of non-trashed files."""
    db = SessionLocal()
    try:
        res = db.query(func.coalesce(func.sum(UserFile.size), 0)).filter(
            UserFile.username == username,
            UserFile.is_trashed == 0,
            ~UserFile.filename.like(".folder_marker_%"),
        ).scalar()
        return int(res or 0)
    finally:
        db.close()


def get_storage_breakdown(username: str) -> dict:
    """Category breakdown of active files."""
    db = SessionLocal()
    try:
        files = db.query(UserFile).filter(
            UserFile.username == username,
            UserFile.is_trashed == 0,
            ~UserFile.filename.like(".folder_marker_%"),
        ).all()

        categories = {
            "images": 0,
            "documents": 0,
            "videos": 0,
            "audio": 0,
            "code": 0,
            "archives": 0,
            "other": 0
        }

        for f in files:
            ext = f.filename.split(".")[-1].lower() if "." in f.filename else ""
            if ext in ["jpg", "jpeg", "png", "gif", "bmp", "webp", "svg"]:
                categories["images"] += f.size
            elif ext in ["pdf", "doc", "docx", "txt", "rtf", "xls", "xlsx", "ppt", "pptx"]:
                categories["documents"] += f.size
            elif ext in ["mp4", "webm", "mov", "avi", "mkv"]:
                categories["videos"] += f.size
            elif ext in ["mp3", "wav", "ogg", "flac", "aac", "m4a"]:
                categories["audio"] += f.size
            elif ext in ["py", "js", "html", "css", "json", "xml", "csv", "sql", "md", "sh", "yaml", "yml"]:
                categories["code"] += f.size
            elif ext in ["zip", "tar", "gz", "7z", "rar"]:
                categories["archives"] += f.size
            else:
                categories["other"] += f.size

        return categories
    finally:
        db.close()


def normalize_folder_path(folder: str) -> str:
    """Normalize folder path to /sub/dir/ format and resolve traversal."""
    if not folder:
        return "/"
    folder = folder.strip().replace("\\", "/")
    parts = []
    for p in folder.split("/"):
        p = p.strip()
        if not p or p == ".":
            continue
        if p == "..":
            if parts:
                parts.pop()
            continue
        clean_p = re.sub(r'[\\/*?:"<>|]', "", p)
        if clean_p:
            parts.append(clean_p)
    if not parts:
        return "/"
    return "/" + "/".join(parts) + "/"


# === AUTH & MAIN ROUTES ===

@app.get("/")
async def root(request: Request):
    if get_current_user(request):
        return RedirectResponse("/dashboard")
    return templates.TemplateResponse("landing.html", {"request": request})


@app.get("/login")
async def login_page(request: Request):
    if get_current_user(request):
        return RedirectResponse("/dashboard")
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/signup")
async def signup_page(request: Request):
    if get_current_user(request):
        return RedirectResponse("/dashboard")
    return templates.TemplateResponse("signup.html", {"request": request})


@app.post("/signup")
async def signup(request: Request, username: str = Form(...), password: str = Form(...)):
    username = username.strip()
    if not USERNAME_RE.match(username):
        return templates.TemplateResponse("signup.html", {
            "request": request,
            "error": "Username must be 3-30 characters: letters, numbers, _ or - only."
        })
    if len(password) < 6:
        return templates.TemplateResponse("signup.html", {
            "request": request,
            "error": "Password must be at least 6 characters."
        })
    db = SessionLocal()
    try:
        if db.query(User).filter(User.username == username).first():
            return templates.TemplateResponse("signup.html", {
                "request": request,
                "error": "Username already taken."
            })
        is_admin_user = 1 if (db.query(User).count() == 0 or username.lower() == "admin") else 0
        new_user = User(
            username=username,
            hashed_password=hash_password(password),
            is_admin=is_admin_user,
            custom_quota_bytes=DEFAULT_QUOTA_BYTES
        )
        db.add(new_user)
        db.commit()
        log_activity(db, username, "signup", f"Account registered for {username}")
        return RedirectResponse("/login", status_code=303)
    finally:
        db.close()


@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username.strip()).first()
        if not user or not verify_password(password, user.hashed_password):
            return templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Wrong username or password."
            })
        request.session["username"] = user.username
        request.session["last_activity"] = time.time()
        log_activity(db, user.username, "login", f"User {user.username} logged in")
        return RedirectResponse("/dashboard", status_code=303)
    finally:
        db.close()


@app.get("/dashboard")
async def dashboard(request: Request, status: str | None = None, error: str | None = None):
    username = get_current_user(request)
    if not username:
        return RedirectResponse("/login")

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        user_is_admin = is_user_admin(db, username)
        user_quota_bytes = get_user_quota_bytes(db, username)
        quota_mb = int(user_quota_bytes / (1024 * 1024))

        # Active files (non-trashed)
        own_files = db.query(UserFile).filter(
            UserFile.username == username,
            UserFile.is_trashed == 0
        ).order_by(UserFile.upload_date.desc()).all()

        # Starred files
        starred_files = [f for f in own_files if f.is_starred == 1 and not f.filename.startswith(".folder_marker_")]

        # Trashed files
        trashed_files = db.query(UserFile).filter(
            UserFile.username == username,
            UserFile.is_trashed == 1
        ).order_by(UserFile.trashed_at.desc()).all()

        # Shared with me
        shared_with_me_entries = db.query(SharedFile).filter(SharedFile.shared_with == username).all()
        shared_with_me_ids = [s.file_id for s in shared_with_me_entries]
        shared_with_me_files = (
            db.query(UserFile).filter(UserFile.id.in_(shared_with_me_ids), UserFile.is_trashed == 0).all()
            if shared_with_me_ids else []
        )

        # Shared by me batch query
        shared_by_me = []
        own_file_ids = [f.id for f in own_files]
        if own_file_ids:
            all_shared = db.query(SharedFile).filter(SharedFile.file_id.in_(own_file_ids)).all()
            shares_map = {}
            for s in all_shared:
                shares_map.setdefault(s.file_id, []).append(s.shared_with)
            
            for file in own_files:
                if file.id in shares_map:
                    shared_by_me.append({
                        "file": file,
                        "shared_with": shares_map[file.id],
                    })

        # Activity logs
        recent_logs = db.query(ActivityLog).filter(
            ActivityLog.username == username
        ).order_by(ActivityLog.timestamp.desc()).limit(30).all()

        # Top 5 largest files
        top_files = sorted([f for f in own_files if not f.filename.startswith(".folder_marker_")], key=lambda x: x.size, reverse=True)[:5]

        actual_used = get_actual_storage(username)
        original_uploaded = get_original_uploaded(username)
        saved_space = get_user_space_saved(username)
        savings_percent = (saved_space / original_uploaded * 100) if original_uploaded > 0 else 0
        breakdown = get_storage_breakdown(username)
    finally:
        db.close()

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "files": own_files,
        "starred_files": starred_files,
        "trashed_files": trashed_files,
        "shared_with_me_files": shared_with_me_files,
        "shared_by_me": shared_by_me,
        "activity_logs": recent_logs,
        "top_files": top_files,
        "breakdown": breakdown,
        "username": username,
        "is_admin": user_is_admin,
        "api_key": user.api_key if user else None,
        "actual_used": actual_used,
        "original_uploaded": original_uploaded,
        "saved_space": saved_space,
        "savings_percent": savings_percent,
        "quota_bytes": user_quota_bytes,
        "quota_mb": quota_mb,
        "status_msg": status,
        "error_msg": error,
    })


# === ADMIN CONTROL PANEL ===

@app.get("/admin")
async def admin_dashboard(request: Request, status: str | None = None):
    username = get_current_user(request)
    if not username:
        return RedirectResponse("/login")

    db = SessionLocal()
    try:
        if not is_user_admin(db, username):
            raise HTTPException(403, detail="Admin privileges required.")

        all_users = db.query(User).all()
        user_list = []
        server_disk_bytes = 0
        server_saved_bytes = 0

        # Physical files on disk
        unique_hashes = db.query(UserFile.filehash, UserFile.filepath, UserFile.size).filter(
            ~UserFile.filename.like(".folder_marker_%")
        ).distinct().all()
        server_disk_bytes = sum(f.size for f in unique_hashes if f.size)

        for u in all_users:
            u_storage = get_actual_storage(u.username)
            u_saved = get_user_space_saved(u.username)
            server_saved_bytes += u_saved
            u_files_count = db.query(UserFile).filter(UserFile.username == u.username, UserFile.is_trashed == 0).count()
            user_list.append({
                "username": u.username,
                "is_admin": u.is_admin == 1 or u.username.lower() == "admin",
                "file_count": u_files_count,
                "storage_used": u_storage,
                "quota_bytes": u.custom_quota_bytes or DEFAULT_QUOTA_BYTES,
                "api_key": u.api_key
            })

        total_logical = server_disk_bytes + server_saved_bytes
        dedup_percent = (server_saved_bytes / total_logical * 100) if total_logical > 0 else 0

        return templates.TemplateResponse("admin.html", {
            "request": request,
            "current_user": username,
            "users": user_list,
            "server_disk_bytes": server_disk_bytes,
            "server_saved_bytes": server_saved_bytes,
            "dedup_percent": dedup_percent,
            "status_msg": status
        })
    finally:
        db.close()


@app.post("/admin/update_quota")
async def admin_update_quota(request: Request, target_username: str = Form(...), quota_mb: int = Form(...)):
    username = get_current_user(request)
    if not username:
        return RedirectResponse("/login")

    db = SessionLocal()
    try:
        if not is_user_admin(db, username):
            raise HTTPException(403)

        user = db.query(User).filter(User.username == target_username).first()
        if user:
            user.custom_quota_bytes = quota_mb * 1024 * 1024
            db.commit()
            log_activity(db, username, "admin", f"Updated quota for {target_username} to {quota_mb} MB")
    finally:
        db.close()

    return RedirectResponse(f"/admin?status=Quota+updated+for+{target_username}", status_code=303)


@app.post("/admin/delete_user")
async def admin_delete_user(request: Request, target_username: str = Form(...)):
    username = get_current_user(request)
    if not username:
        return RedirectResponse("/login")

    db = SessionLocal()
    try:
        if not is_user_admin(db, username):
            raise HTTPException(403)
        if target_username == username:
            return RedirectResponse("/admin?status=Cannot+delete+own+admin+account", status_code=303)

        target_user = db.query(User).filter(User.username == target_username).first()
        if target_user:
            user_files = db.query(UserFile).filter(UserFile.username == target_username).all()
            for f in user_files:
                target_hash = f.filehash
                target_path = f.filepath
                db.query(SharedFile).filter(SharedFile.file_id == f.id).delete()
                db.query(FileVersion).filter(FileVersion.file_id == f.id).delete()
                db.query(FileComment).filter(FileComment.file_id == f.id).delete()
                db.delete(f)
                db.flush()
                cleanup_disk_file_if_unreferenced(db, target_hash, target_path)

            db.query(ActivityLog).filter(ActivityLog.username == target_username).delete()
            db.delete(target_user)
            db.commit()
            log_activity(db, username, "admin", f"Deleted user account {target_username}")
    finally:
        db.close()

    return RedirectResponse(f"/admin?status=User+{target_username}+deleted", status_code=303)


# === UPLOAD (GLOBAL CROSS-USER DEDUP) ===

@app.post("/upload")
async def upload(request: Request, folder: str = Form("/"), files: list[UploadFile] = File(...)):
    username = get_current_user(request)
    if not username:
        return JSONResponse({"results": [], "error": "Session expired. Please login again."}, status_code=401)

    if not files or all(not f.filename for f in files):
        return JSONResponse({"results": [], "error": "No files selected."}, status_code=400)

    db_user = SessionLocal()
    user_quota = get_user_quota_bytes(db_user, username)
    db_user.close()

    async with _upload_lock:
        now = time.time()
        stale = [u for u, t in last_upload_time.items() if now - t > 60]
        for u in stale:
            del last_upload_time[u]
        if username in last_upload_time and now - last_upload_time[username] < 0.5:
            return JSONResponse({"results": [], "error": "Too many uploads! Wait a moment."}, status_code=429)
        last_upload_time[username] = now

        folder = normalize_folder_path(folder)
        current_used = get_actual_storage(username)
        new_charged_size = 0
        temp_files = []

        try:
            seen_batch_hashes: set = set()

            for file in files:
                if not file.filename:
                    continue

                safe_name = sanitize_filename(file.filename)
                content = await file.read()
                file_size = len(content)

                if file_size > MAX_SINGLE_FILE_BYTES:
                    return JSONResponse(
                        {"results": [], "error": f"'{safe_name}' exceeds the 5 MB per-file limit."},
                        status_code=400,
                    )

                temp_path = os.path.join(UPLOAD_FOLDER, f"temp_{uuid.uuid4()}_{safe_name}")
                with open(temp_path, "wb") as f:
                    f.write(content)

                file_hash = calculate_hash(temp_path)

                db = SessionLocal()
                try:
                    existing_user_file = db.query(UserFile).filter(
                        UserFile.filehash == file_hash,
                        UserFile.username == username,
                        UserFile.is_reference == 0,
                        UserFile.is_trashed == 0
                    ).first()
                    
                    if not existing_user_file and file_hash not in seen_batch_hashes:
                        new_charged_size += file_size
                        seen_batch_hashes.add(file_hash)
                finally:
                    db.close()

                temp_files.append((temp_path, safe_name, file_hash, file_size))

            if current_used + new_charged_size > user_quota:
                for temp_path, *_ in temp_files:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                return JSONResponse({"results": [], "error": f"Storage quota exceeded ({int(user_quota/(1024*1024))} MB limit)."}, status_code=400)

            results = []
            db = SessionLocal()
            try:
                for temp_path, filename, file_hash, file_size in temp_files:
                    global_path = os.path.join(UPLOAD_FOLDER, file_hash)
                    if os.path.exists(global_path):
                        if os.path.exists(temp_path):
                            os.remove(temp_path)
                        filepath = global_path
                    else:
                        os.replace(temp_path, global_path)
                        filepath = global_path

                    existing_user_file = db.query(UserFile).filter(
                        UserFile.filehash == file_hash,
                        UserFile.username == username,
                        UserFile.is_reference == 0,
                        UserFile.is_trashed == 0
                    ).first()

                    if existing_user_file:
                        message = "Duplicate (saved zero additional quota)"
                        is_ref = 1
                    else:
                        message = "Uploaded successfully"
                        is_ref = 0

                    entry = UserFile(
                        filename=filename,
                        filepath=filepath,
                        filehash=file_hash,
                        username=username,
                        is_reference=is_ref,
                        size=file_size,
                        folder=folder,
                        is_public=0,
                        download_count=0,
                        version=1
                    )
                    db.add(entry)
                    db.commit()
                    db.refresh(entry)

                    v1 = FileVersion(
                        file_id=entry.id,
                        version_number=1,
                        filename=filename,
                        filepath=filepath,
                        filehash=file_hash,
                        size=file_size,
                        created_at=datetime.now(timezone.utc),
                        username=username
                    )
                    db.add(v1)
                    db.commit()

                    log_activity(db, username, "upload", f"Uploaded {filename} ({round(file_size/1024, 2)} KB) to {folder}")
                    results.append({"filename": filename, "message": message})
            finally:
                db.close()

            return JSONResponse({"results": results})

        except Exception as e:
            for temp_path, *_ in temp_files:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            return JSONResponse({"results": [], "error": f"Upload failed: {str(e)}"}, status_code=500)


# === REMOTE URL UPLOADER (CLOUD DOWNLOADER) ===

@app.post("/api/remote_upload")
async def remote_upload(request: Request):
    username = get_current_user(request)
    if not username:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    data = await request.json()
    url = data.get("url", "").strip()
    folder = normalize_folder_path(data.get("folder", "/"))

    if not url or not (url.startswith("http://") or url.startswith("https://")):
        return JSONResponse({"error": "Invalid URL format"}, status_code=400)

    db_user = SessionLocal()
    user_quota = get_user_quota_bytes(db_user, username)
    db_user.close()

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VinnoDrive-RemoteUploader/1.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > MAX_SINGLE_FILE_BYTES:
                return JSONResponse({"error": "Remote file exceeds 5 MB size limit"}, status_code=400)

            content = response.read(MAX_SINGLE_FILE_BYTES + 1024)
            if len(content) > MAX_SINGLE_FILE_BYTES:
                return JSONResponse({"error": "Remote file exceeds 5 MB limit"}, status_code=400)

            parsed_url = urllib.parse.urlparse(url)
            derived_name = os.path.basename(parsed_url.path) or "downloaded_file.bin"
            safe_name = sanitize_filename(derived_name)
            file_size = len(content)

            current_used = get_actual_storage(username)
            if current_used + file_size > user_quota:
                return JSONResponse({"error": "Storage quota exceeded"}, status_code=400)

            sha = hashlib.sha256(content)
            file_hash = sha.hexdigest()
            global_path = os.path.join(UPLOAD_FOLDER, file_hash)

            if not os.path.exists(global_path):
                with open(global_path, "wb") as f:
                    f.write(content)

            db = SessionLocal()
            try:
                existing = db.query(UserFile).filter(
                    UserFile.filehash == file_hash,
                    UserFile.username == username,
                    UserFile.is_reference == 0,
                    UserFile.is_trashed == 0
                ).first()

                is_ref = 1 if existing else 0
                entry = UserFile(
                    filename=safe_name,
                    filepath=global_path,
                    filehash=file_hash,
                    username=username,
                    is_reference=is_ref,
                    size=file_size,
                    folder=folder,
                    version=1
                )
                db.add(entry)
                db.commit()
                db.refresh(entry)

                db.add(FileVersion(
                    file_id=entry.id,
                    version_number=1,
                    filename=safe_name,
                    filepath=global_path,
                    filehash=file_hash,
                    size=file_size,
                    created_at=datetime.now(timezone.utc),
                    username=username
                ))
                db.commit()
                log_activity(db, username, "remote_upload", f"Imported {safe_name} via URL into {folder}")
            finally:
                db.close()

            return JSONResponse({"success": True, "filename": safe_name, "size": file_size})

    except Exception as e:
        return JSONResponse({"error": f"Remote download failed: {str(e)}"}, status_code=500)


# === API KEYS & DEVELOPER REST API ===

@app.post("/api/keys/generate")
async def generate_api_key(request: Request):
    username = get_current_user(request)
    if not username:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    new_key = f"vno_live_{uuid.uuid4().hex}"
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if user:
            user.api_key = new_key
            db.commit()
            log_activity(db, username, "api_key", "Generated new Personal API Key")
        return JSONResponse({"api_key": new_key})
    finally:
        db.close()


@app.post("/api/v1/upload")
async def api_v1_upload(
    file: UploadFile = File(...),
    folder: str = Form("/"),
    x_api_key: str | None = Header(None),
    authorization: str | None = Header(None)
):
    api_token = x_api_key
    if not api_token and authorization and authorization.startswith("Bearer "):
        api_token = authorization.split("Bearer ")[1].strip()

    if not api_token:
        raise HTTPException(401, detail="Missing API Key. Pass 'X-API-Key: <key>' or 'Authorization: Bearer <key>'")

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.api_key == api_token).first()
        if not user:
            raise HTTPException(401, detail="Invalid API Key.")
        username = user.username
        user_quota = user.custom_quota_bytes or DEFAULT_QUOTA_BYTES
    finally:
        db.close()

    content = await file.read()
    file_size = len(content)
    if file_size > MAX_SINGLE_FILE_BYTES:
        raise HTTPException(400, detail="File exceeds 5 MB limit.")

    safe_name = sanitize_filename(file.filename or "uploaded_file.bin")
    folder = normalize_folder_path(folder)

    current_used = get_actual_storage(username)
    if current_used + file_size > user_quota:
        raise HTTPException(400, detail="Quota exceeded.")

    file_hash = hashlib.sha256(content).hexdigest()
    global_path = os.path.join(UPLOAD_FOLDER, file_hash)
    if not os.path.exists(global_path):
        with open(global_path, "wb") as f:
            f.write(content)

    db = SessionLocal()
    try:
        existing = db.query(UserFile).filter(
            UserFile.filehash == file_hash,
            UserFile.username == username,
            UserFile.is_reference == 0,
            UserFile.is_trashed == 0
        ).first()

        is_ref = 1 if existing else 0
        entry = UserFile(
            filename=safe_name,
            filepath=global_path,
            filehash=file_hash,
            username=username,
            is_reference=is_ref,
            size=file_size,
            folder=folder,
            version=1
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)

        db.add(FileVersion(
            file_id=entry.id,
            version_number=1,
            filename=safe_name,
            filepath=global_path,
            filehash=file_hash,
            size=file_size,
            created_at=datetime.now(timezone.utc),
            username=username
        ))
        db.commit()
        log_activity(db, username, "api_upload", f"Uploaded {safe_name} via REST API")

        return JSONResponse({
            "success": True,
            "file_id": entry.id,
            "filename": safe_name,
            "size": file_size,
            "folder": folder,
            "is_duplicate": is_ref == 1
        })
    finally:
        db.close()


# === FULL-TEXT SEARCH ===

@app.get("/api/search/content")
async def search_content(q: str, request: Request):
    username = get_current_user(request)
    if not username:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    query = q.strip().lower()
    if not query:
        return JSONResponse({"results": []})

    db = SessionLocal()
    try:
        files = db.query(UserFile).filter(
            UserFile.username == username,
            UserFile.is_trashed == 0,
            ~UserFile.filename.like(".folder_marker_%")
        ).all()

        text_exts = ["txt", "md", "py", "js", "html", "css", "json", "csv", "sql", "yaml", "yml", "xml", "log", "sh"]
        results = []

        for f in files:
            ext = f.filename.split(".")[-1].lower() if "." in f.filename else ""
            if ext in text_exts and f.filepath and os.path.exists(f.filepath) and f.size < 1024 * 1024:
                try:
                    with open(f.filepath, "r", encoding="utf-8", errors="ignore") as file_handle:
                        lines = file_handle.readlines()
                    
                    matches = []
                    for idx, line in enumerate(lines, 1):
                        if query in line.lower():
                            matches.append({"line_number": idx, "snippet": line.strip()[:140]})
                            if len(matches) >= 3:
                                break
                    
                    if matches:
                        results.append({
                            "file_id": f.id,
                            "filename": f.filename,
                            "folder": f.folder,
                            "matches": matches
                        })
                except Exception:
                    continue

        return JSONResponse({"results": results})
    finally:
        db.close()


# === IN-BROWSER IMAGE CANVAS STUDIO ===

@app.post("/api/file/save_image/{file_id}")
async def save_edited_image(file_id: int, request: Request):
    username = get_current_user(request)
    if not username:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    data = await request.json()
    image_data = data.get("image_data", "")

    if not image_data or not image_data.startswith("data:image/"):
        return JSONResponse({"error": "Invalid image payload"}, status_code=400)

    header, encoded = image_data.split(",", 1)
    img_bytes = base64.b64decode(encoded)
    new_size = len(img_bytes)

    if new_size > MAX_SINGLE_FILE_BYTES:
        return JSONResponse({"error": "Image exceeds 5 MB limit"}, status_code=400)

    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.id == file_id, UserFile.username == username).first()
        if not file:
            return JSONResponse({"error": "File not found"}, status_code=404)

        new_hash = hashlib.sha256(img_bytes).hexdigest()
        new_filepath = os.path.join(UPLOAD_FOLDER, new_hash)

        if not os.path.exists(new_filepath):
            with open(new_filepath, "wb") as f:
                f.write(img_bytes)

        file.version += 1
        file.filepath = new_filepath
        file.filehash = new_hash
        file.size = new_size
        file.upload_date = datetime.now(timezone.utc)

        db.add(FileVersion(
            file_id=file.id,
            version_number=file.version,
            filename=file.filename,
            filepath=new_filepath,
            filehash=new_hash,
            size=new_size,
            created_at=datetime.now(timezone.utc),
            username=username
        ))
        db.commit()
        log_activity(db, username, "image_edit", f"Applied canvas edits to {file.filename} (v{file.version})")

        return JSONResponse({"success": True, "version": file.version})
    finally:
        db.close()


# === FILE COMMENTS & DISCUSSION ===

@app.get("/api/file/comments/{file_id}")
async def get_comments(file_id: int, request: Request):
    username = get_current_user(request)
    if not username:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    db = SessionLocal()
    try:
        comments = db.query(FileComment).filter(
            FileComment.file_id == file_id
        ).order_by(FileComment.created_at.asc()).all()

        results = [
            {
                "id": c.id,
                "username": c.username,
                "text": c.comment_text,
                "created_at": c.created_at.strftime("%b %d, %H:%M") if c.created_at else ""
            }
            for c in comments
        ]
        return JSONResponse({"comments": results})
    finally:
        db.close()


@app.post("/api/file/comments/{file_id}")
async def post_comment(file_id: int, request: Request):
    username = get_current_user(request)
    if not username:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    data = await request.json()
    text = data.get("comment", "").strip()
    if not text:
        return JSONResponse({"error": "Comment cannot be empty"}, status_code=400)

    db = SessionLocal()
    try:
        new_comment = FileComment(
            file_id=file_id,
            username=username,
            comment_text=text,
            created_at=datetime.now(timezone.utc)
        )
        db.add(new_comment)
        db.commit()
        log_activity(db, username, "comment", f"Commented on file #{file_id}")

        return JSONResponse({
            "success": True,
            "comment": {
                "id": new_comment.id,
                "username": username,
                "text": text,
                "created_at": new_comment.created_at.strftime("%b %d, %H:%M")
            }
        })
    finally:
        db.close()


# === DOWNLOADS & ZIP ARCHIVES ===

@app.get("/download/{file_id}")
async def download(file_id: int, request: Request):
    username = get_current_user(request)
    if not username:
        return RedirectResponse("/login")

    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.id == file_id).first()
        if not file:
            raise HTTPException(404, detail="File not found.")

        if file.username != username:
            shared = db.query(SharedFile).filter(
                SharedFile.file_id == file_id,
                SharedFile.shared_with == username,
            ).first()
            if not shared:
                raise HTTPException(403, detail="Access denied.")

        if not file.filepath or not os.path.exists(file.filepath):
            raise HTTPException(404, detail="File not available on disk.")

        file.download_count += 1
        db.commit()
        log_activity(db, username, "download", f"Downloaded {file.filename}")

        return FileResponse(file.filepath, filename=file.filename)
    finally:
        db.close()


@app.get("/download_folder_zip")
async def download_folder_zip(request: Request, folder: str = "/"):
    username = get_current_user(request)
    if not username:
        return RedirectResponse("/login")

    folder_path = normalize_folder_path(folder)
    db = SessionLocal()
    try:
        files = db.query(UserFile).filter(
            UserFile.username == username,
            UserFile.folder.like(f"{folder_path}%"),
            UserFile.is_trashed == 0,
            ~UserFile.filename.like(".folder_marker_%")
        ).all()

        if not files:
            raise HTTPException(404, detail="No files found in folder.")

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for f in files:
                if f.filepath and os.path.exists(f.filepath):
                    rel_folder = f.folder[len(folder_path):].lstrip("/")
                    arcname = os.path.join(rel_folder, f.filename) if rel_folder else f.filename
                    zip_file.write(f.filepath, arcname=arcname)

        zip_buffer.seek(0)
        folder_display_name = folder_path.strip("/").replace("/", "_") or "root"
        log_activity(db, username, "zip_download", f"Downloaded folder {folder_path} as ZIP")

        return StreamingResponse(
            zip_buffer,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="VinnoDrive_{folder_display_name}.zip"'}
        )
    finally:
        db.close()


@app.post("/download_bulk_zip")
async def download_bulk_zip(request: Request):
    username = get_current_user(request)
    if not username:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    data = await request.json()
    file_ids = data.get("file_ids", [])
    if not file_ids:
        return JSONResponse({"error": "No files selected"}, status_code=400)

    db = SessionLocal()
    try:
        files = db.query(UserFile).filter(
            UserFile.id.in_(file_ids),
            UserFile.username == username,
            UserFile.is_trashed == 0
        ).all()

        if not files:
            return JSONResponse({"error": "Files not found"}, status_code=404)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            seen_names = set()
            for f in files:
                if f.filepath and os.path.exists(f.filepath):
                    name = f.filename
                    counter = 1
                    while name in seen_names:
                        base, ext = os.path.splitext(f.filename)
                        name = f"{base}_{counter}{ext}"
                        counter += 1
                    seen_names.add(name)
                    zip_file.write(f.filepath, arcname=name)

        zip_buffer.seek(0)
        log_activity(db, username, "zip_download", f"Downloaded {len(files)} files as ZIP archive")

        return StreamingResponse(
            zip_buffer,
            media_type="application/zip",
            headers={"Content-Disposition": 'attachment; filename="VinnoDrive_Selected_Files.zip"'}
        )
    finally:
        db.close()


# === PUBLIC SHARING & PASSWORD/EXPIRY ===

@app.post("/update_share_settings")
async def update_share_settings(
    request: Request,
    file_id: int = Form(...),
    is_public: int = Form(1),
    password: str = Form(""),
    expires_hours: int = Form(0),
    max_downloads: int = Form(0)
):
    username = get_current_user(request)
    if not username:
        return RedirectResponse("/login")

    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.id == file_id, UserFile.username == username).first()
        if not file:
            raise HTTPException(404)

        file.is_public = 1 if is_public else 0
        if file.is_public:
            if not file.share_token:
                file.share_token = str(uuid.uuid4())
            file.share_password = hash_password(password.strip()) if password.strip() else None
            file.share_expires_at = (datetime.now(timezone.utc) + timedelta(hours=expires_hours)) if expires_hours > 0 else None
            file.share_max_downloads = max_downloads if max_downloads > 0 else None
            log_activity(db, username, "share", f"Updated share link settings for {file.filename}")
        else:
            file.share_token = None
            file.share_password = None
            file.share_expires_at = None
            file.share_max_downloads = None
            log_activity(db, username, "share", f"Revoked public share link for {file.filename}")

        db.commit()
    finally:
        db.close()

    return RedirectResponse("/dashboard#my-files", status_code=303)


@app.get("/public/{token}")
async def public_landing(token: str, request: Request):
    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.share_token == token, UserFile.is_public == 1).first()
        if not file or file.is_trashed == 1:
            return templates.TemplateResponse("public_share.html", {
                "request": request, "error": "This link is invalid or the file has been removed."
            })

        if file.share_expires_at:
            expire_utc = file.share_expires_at.replace(tzinfo=timezone.utc) if file.share_expires_at.tzinfo is None else file.share_expires_at
            if datetime.now(timezone.utc) > expire_utc:
                return templates.TemplateResponse("public_share.html", {
                    "request": request, "error": "This link has expired."
                })

        if file.share_max_downloads and file.download_count >= file.share_max_downloads:
            return templates.TemplateResponse("public_share.html", {
                "request": request, "error": "Download limit for this link has been reached."
            })

        if file.share_password:
            return templates.TemplateResponse("public_share.html", {
                "request": request, "file": file, "token": token, "requires_password": True
            })

        return templates.TemplateResponse("public_share.html", {
            "request": request, "file": file, "token": token, "requires_password": False
        })
    finally:
        db.close()


@app.post("/public/{token}/verify")
async def public_verify_password(token: str, request: Request, password: str = Form(...)):
    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.share_token == token, UserFile.is_public == 1).first()
        if not file or not file.share_password or not verify_password(password, file.share_password):
            return templates.TemplateResponse("public_share.html", {
                "request": request,
                "file": file,
                "token": token,
                "requires_password": True,
                "password_error": "Incorrect passcode. Please try again."
            })

        file.download_count += 1
        db.commit()

        return FileResponse(file.filepath, filename=file.filename, media_type="application/octet-stream")
    finally:
        db.close()


@app.get("/public/{token}/download")
async def public_download_direct(token: str, request: Request):
    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.share_token == token, UserFile.is_public == 1).first()
        if not file or not file.filepath or not os.path.exists(file.filepath):
            raise HTTPException(404, detail="File unavailable.")

        if file.share_expires_at and datetime.now(timezone.utc) > (file.share_expires_at.replace(tzinfo=timezone.utc) if file.share_expires_at.tzinfo is None else file.share_expires_at):
            raise HTTPException(400, detail="Link expired.")

        if file.share_max_downloads and file.download_count >= file.share_max_downloads:
            raise HTTPException(400, detail="Download limit exceeded.")

        if file.share_password:
            return RedirectResponse(f"/public/{token}")

        file.download_count += 1
        db.commit()

        return FileResponse(file.filepath, filename=file.filename, media_type="application/octet-stream")
    finally:
        db.close()


# === IN-BROWSER CODE & TEXT EDITOR ===

@app.get("/api/file/content/{file_id}")
async def get_file_content(file_id: int, request: Request):
    username = get_current_user(request)
    if not username:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.id == file_id, UserFile.username == username).first()
        if not file or not file.filepath or not os.path.exists(file.filepath):
            return JSONResponse({"error": "File not found"}, status_code=404)

        if file.size > 2 * 1024 * 1024:
            return JSONResponse({"error": "File too large for live editor (max 2 MB)"}, status_code=400)

        with open(file.filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        return JSONResponse({
            "id": file.id,
            "filename": file.filename,
            "content": content,
            "version": file.version,
            "size": file.size
        })
    finally:
        db.close()


@app.post("/api/file/save_content/{file_id}")
async def save_file_content(file_id: int, request: Request):
    username = get_current_user(request)
    if not username:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    data = await request.json()
    new_content = data.get("content", "")
    content_bytes = new_content.encode("utf-8")
    new_size = len(content_bytes)

    if new_size > MAX_SINGLE_FILE_BYTES:
        return JSONResponse({"error": "File exceeds 5 MB limit"}, status_code=400)

    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.id == file_id, UserFile.username == username).first()
        if not file:
            return JSONResponse({"error": "File not found"}, status_code=404)

        sha = hashlib.sha256(content_bytes)
        new_hash = sha.hexdigest()
        new_filepath = os.path.join(UPLOAD_FOLDER, new_hash)

        if not os.path.exists(new_filepath):
            with open(new_filepath, "wb") as f:
                f.write(content_bytes)

        file.version += 1
        file.filepath = new_filepath
        file.filehash = new_hash
        file.size = new_size
        file.upload_date = datetime.now(timezone.utc)

        db.add(FileVersion(
            file_id=file.id,
            version_number=file.version,
            filename=file.filename,
            filepath=new_filepath,
            filehash=new_hash,
            size=new_size,
            created_at=datetime.now(timezone.utc),
            username=username
        ))
        db.commit()

        log_activity(db, username, "edit", f"Edited {file.filename} (saved v{file.version})")

        return JSONResponse({
            "success": True,
            "version": file.version,
            "size": file.size,
            "message": f"Saved version v{file.version} successfully"
        })
    finally:
        db.close()


# === FILE REVISION HISTORY & ROLLBACK ===

@app.get("/api/file/versions/{file_id}")
async def get_file_versions(file_id: int, request: Request):
    username = get_current_user(request)
    if not username:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.id == file_id, UserFile.username == username).first()
        if not file:
            return JSONResponse({"error": "File not found"}, status_code=404)

        versions = db.query(FileVersion).filter(
            FileVersion.file_id == file_id
        ).order_by(FileVersion.version_number.desc()).all()

        results = [
            {
                "id": v.id,
                "version_number": v.version_number,
                "filename": v.filename,
                "size": v.size,
                "created_at": v.created_at.strftime("%b %d, %Y %H:%M UTC") if v.created_at else "N/A",
                "is_current": v.version_number == file.version
            }
            for v in versions
        ]
        return JSONResponse({"versions": results, "current_version": file.version, "filename": file.filename})
    finally:
        db.close()


@app.post("/api/file/rollback/{version_id}")
async def rollback_file_version(version_id: int, request: Request):
    username = get_current_user(request)
    if not username:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    db = SessionLocal()
    try:
        ver = db.query(FileVersion).filter(FileVersion.id == version_id, FileVersion.username == username).first()
        if not ver:
            return JSONResponse({"error": "Version not found"}, status_code=404)

        file = db.query(UserFile).filter(UserFile.id == ver.file_id, UserFile.username == username).first()
        if not file:
            return JSONResponse({"error": "File not found"}, status_code=404)

        file.filepath = ver.filepath
        file.filehash = ver.filehash
        file.size = ver.size
        file.version = ver.version_number
        db.commit()

        log_activity(db, username, "rollback", f"Rolled back {file.filename} to v{ver.version_number}")
        return JSONResponse({"success": True, "message": f"Rolled back to v{ver.version_number}"})
    finally:
        db.close()


# === STARRED & TAGGING ===

@app.post("/api/file/toggle_star/{file_id}")
async def toggle_star(file_id: int, request: Request):
    username = get_current_user(request)
    if not username:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.id == file_id, UserFile.username == username).first()
        if not file:
            return JSONResponse({"error": "File not found"}, status_code=404)

        file.is_starred = 1 - file.is_starred
        db.commit()

        action = "star" if file.is_starred else "unstar"
        log_activity(db, username, action, f"{'Starred' if file.is_starred else 'Unstarred'} {file.filename}")

        return JSONResponse({"is_starred": file.is_starred})
    finally:
        db.close()


@app.post("/api/file/update_tags/{file_id}")
async def update_tags(file_id: int, request: Request):
    username = get_current_user(request)
    if not username:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    data = await request.json()
    new_tags = data.get("tags", "").strip()

    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.id == file_id, UserFile.username == username).first()
        if not file:
            return JSONResponse({"error": "File not found"}, status_code=404)

        file.tags = new_tags
        db.commit()
        log_activity(db, username, "tags", f"Updated tags on {file.filename}: '{new_tags}'")
        return JSONResponse({"success": True, "tags": file.tags})
    finally:
        db.close()


# === TRASH / RECYCLE BIN & PERMANENT DELETE ===

@app.post("/trash/{file_id}")
async def trash_file(file_id: int, request: Request):
    username = get_current_user(request)
    if not username:
        return RedirectResponse("/login")

    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.id == file_id, UserFile.username == username).first()
        if not file:
            raise HTTPException(404)

        file.is_trashed = 1
        file.trashed_at = datetime.now(timezone.utc)
        db.commit()

        log_activity(db, username, "trash", f"Moved {file.filename} to Trash")
    finally:
        db.close()

    return RedirectResponse("/dashboard#my-files", status_code=303)


@app.post("/restore/{file_id}")
async def restore_file(file_id: int, request: Request):
    username = get_current_user(request)
    if not username:
        return RedirectResponse("/login")

    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.id == file_id, UserFile.username == username).first()
        if not file:
            raise HTTPException(404)

        file.is_trashed = 0
        file.trashed_at = None
        db.commit()

        log_activity(db, username, "restore", f"Restored {file.filename} from Trash")
    finally:
        db.close()

    return RedirectResponse("/dashboard#trash", status_code=303)


@app.post("/empty_trash")
async def empty_trash(request: Request):
    username = get_current_user(request)
    if not username:
        return RedirectResponse("/login")

    db = SessionLocal()
    try:
        trashed = db.query(UserFile).filter(UserFile.username == username, UserFile.is_trashed == 1).all()
        count = len(trashed)

        for file in trashed:
            target_hash = file.filehash
            target_path = file.filepath
            db.query(SharedFile).filter(SharedFile.file_id == file.id).delete()
            db.query(FileVersion).filter(FileVersion.file_id == file.id).delete()
            db.query(FileComment).filter(FileComment.file_id == file.id).delete()
            db.delete(file)
            db.flush()
            cleanup_disk_file_if_unreferenced(db, target_hash, target_path)

        db.commit()
        log_activity(db, username, "empty_trash", f"Emptied Trash ({count} files permanently deleted)")
    finally:
        db.close()

    return RedirectResponse("/dashboard?status=Trash+emptied+successfully#trash", status_code=303)


@app.post("/delete")
async def delete(request: Request, file_id: int = Form(...)):
    username = get_current_user(request)
    if not username:
        return RedirectResponse("/login")

    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.id == file_id, UserFile.username == username).first()
        if not file:
            raise HTTPException(404)

        target_hash = file.filehash
        target_path = file.filepath

        db.query(SharedFile).filter(SharedFile.file_id == file_id).delete()
        db.query(FileVersion).filter(FileVersion.file_id == file_id).delete()
        db.query(FileComment).filter(FileComment.file_id == file_id).delete()
        db.delete(file)
        db.flush()

        cleanup_disk_file_if_unreferenced(db, target_hash, target_path)
        db.commit()

        log_activity(db, username, "delete", f"Permanently deleted {file.filename}")
    finally:
        db.close()

    return RedirectResponse("/dashboard#my-files", status_code=303)


@app.post("/bulk_delete")
async def bulk_delete(request: Request):
    username = get_current_user(request)
    if not username:
        return JSONResponse({"error": "Session expired. Please login again."}, status_code=401)

    data = await request.json()
    file_ids = data.get("file_ids", [])

    if not file_ids:
        return JSONResponse({"error": "No files selected."}, status_code=400)

    db = SessionLocal()
    try:
        deleted_count = 0
        for file_id in file_ids:
            file = db.query(UserFile).filter(UserFile.id == file_id, UserFile.username == username).first()
            if not file:
                continue

            target_hash = file.filehash
            target_path = file.filepath

            db.query(SharedFile).filter(SharedFile.file_id == file_id).delete()
            db.query(FileVersion).filter(FileVersion.file_id == file_id).delete()
            db.query(FileComment).filter(FileComment.file_id == file_id).delete()
            db.delete(file)
            db.flush()

            cleanup_disk_file_if_unreferenced(db, target_hash, target_path)
            deleted_count += 1

        db.commit()
        log_activity(db, username, "bulk_delete", f"Bulk deleted {deleted_count} files")
        return JSONResponse({"success": True, "deleted_count": deleted_count})
    except Exception as e:
        db.rollback()
        return JSONResponse({"error": str(e)}, status_code=500)
    finally:
        db.close()


# === FOLDER MANAGEMENT ===

@app.post("/create_folder")
async def create_folder(request: Request, folder_name: str = Form(...)):
    username = get_current_user(request)
    if not username:
        return RedirectResponse("/login")

    folder_name = folder_name.strip()
    if not folder_name:
        return RedirectResponse("/dashboard?error=Folder+name+cannot+be+empty#my-files", status_code=303)

    full_path = normalize_folder_path(folder_name)
    if full_path == "/":
        return RedirectResponse("/dashboard?error=Invalid+folder+name#my-files", status_code=303)

    db = SessionLocal()
    try:
        existing = db.query(UserFile).filter(
            UserFile.username == username,
            UserFile.folder == full_path,
            UserFile.filename.like(".folder_marker_%"),
        ).first()

        if existing:
            return RedirectResponse("/dashboard?error=Folder+already+exists#my-files", status_code=303)

        folder_display_name = full_path.strip("/").split("/")[-1]
        db.add(UserFile(
            filename=f".folder_marker_{folder_display_name}",
            filepath="",
            filehash="folder_marker",
            username=username,
            is_reference=0,
            size=0,
            folder=full_path,
            is_public=0,
            download_count=0,
        ))
        db.commit()
        log_activity(db, username, "folder_create", f"Created folder {full_path}")
    finally:
        db.close()

    return RedirectResponse("/dashboard?status=Folder+created+successfully#my-files", status_code=303)


@app.post("/delete_folder")
async def delete_folder(request: Request, folder_path: str = Form(...)):
    username = get_current_user(request)
    if not username:
        return RedirectResponse("/login")

    folder_path = normalize_folder_path(folder_path)
    if folder_path == "/":
        return RedirectResponse("/dashboard?error=Cannot+delete+root+folder#my-files", status_code=303)

    db = SessionLocal()
    try:
        folder_files = db.query(UserFile).filter(
            UserFile.username == username,
            UserFile.folder == folder_path
        ).all()

        for file in folder_files:
            target_hash = file.filehash
            target_path = file.filepath

            db.query(SharedFile).filter(SharedFile.file_id == file.id).delete()
            db.query(FileVersion).filter(FileVersion.file_id == file.id).delete()
            db.query(FileComment).filter(FileComment.file_id == file.id).delete()
            db.delete(file)
            db.flush()

            cleanup_disk_file_if_unreferenced(db, target_hash, target_path)

        db.commit()
        log_activity(db, username, "folder_delete", f"Deleted folder {folder_path} and its contents")
    finally:
        db.close()

    return RedirectResponse("/dashboard?status=Folder+deleted+successfully#my-files", status_code=303)


@app.post("/share_with_user")
async def share_with_user(request: Request, file_id: int = Form(...), target_username: str = Form(...)):
    username = get_current_user(request)
    if not username:
        return RedirectResponse("/login")

    target_username = target_username.strip()
    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.id == file_id, UserFile.username == username).first()
        if not file:
            return RedirectResponse("/dashboard?error=File+not+found#my-files", status_code=303)

        if not db.query(User).filter(User.username == target_username).first():
            return RedirectResponse(f"/dashboard?error=User+'{target_username}'+does+not+exist#my-files", status_code=303)

        if target_username == username:
            return RedirectResponse("/dashboard?error=Cannot+share+file+with+yourself#my-files", status_code=303)

        if db.query(SharedFile).filter(
            SharedFile.file_id == file_id,
            SharedFile.shared_with == target_username,
        ).first():
            return RedirectResponse(f"/dashboard?error=File+already+shared+with+'{target_username}'#my-files", status_code=303)

        db.add(SharedFile(file_id=file_id, shared_with=target_username, shared_by=username))
        db.commit()
        log_activity(db, username, "share", f"Shared {file.filename} with {target_username}")
    finally:
        db.close()

    return RedirectResponse(f"/dashboard?status=File+shared+successfully+with+'{target_username}'#my-files", status_code=303)


@app.get("/logout")
async def logout_get(request: Request):
    request.session.clear()
    return RedirectResponse("/login")


@app.post("/logout")
async def logout_post(request: Request):
    request.session.clear()
    return JSONResponse({"status": "logged out"})


# === PREVIEWS & DETAILS API ===

@app.get("/api/file/duplicate-locations/{file_id}")
async def get_duplicate_locations(file_id: int, request: Request):
    username = get_current_user(request)
    if not username:
        return JSONResponse({"error": "Session expired. Please login again."}, status_code=401)

    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.id == file_id, UserFile.username == username).first()
        if not file:
            return JSONResponse({"error": "File not found."}, status_code=404)

        duplicates = db.query(UserFile).filter(
            UserFile.filehash == file.filehash,
            UserFile.username == username,
            UserFile.is_trashed == 0
        ).all()

        locations = [
            {
                "id": dup.id,
                "filename": dup.filename,
                "folder": dup.folder,
                "upload_date": dup.upload_date.strftime("%b %d, %Y %H:%M UTC") if dup.upload_date else "N/A",
                "is_current": dup.id == file_id,
            }
            for dup in duplicates
        ]
        return JSONResponse({"locations": locations})
    finally:
        db.close()


@app.get("/api/file/preview/{file_id}")
async def preview_file(file_id: int, request: Request):
    username = get_current_user(request)
    if not username:
        return JSONResponse({"error": "Session expired. Please login again."}, status_code=401)

    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.id == file_id).first()
        if not file:
            return JSONResponse({"error": "File not found."}, status_code=404)

        if file.username != username:
            shared = db.query(SharedFile).filter(
                SharedFile.file_id == file_id,
                SharedFile.shared_with == username,
            ).first()
            if not shared:
                return JSONResponse({"error": "Access denied."}, status_code=403)

        file_ext = file.filename.split(".")[-1].lower() if "." in file.filename else ""
        file_type = "unknown"

        if file_ext in ["jpg", "jpeg", "png", "gif", "bmp", "webp", "svg"]:
            file_type = "image"
        elif file_ext == "pdf":
            file_type = "pdf"
        elif file_ext in ["txt", "md", "json", "xml", "csv", "log", "py", "js", "html", "css", "yaml", "yml", "sql"]:
            file_type = "text"
        elif file_ext in ["mp4", "webm", "mov"]:
            file_type = "video"
        elif file_ext in ["mp3", "wav", "ogg", "flac"]:
            file_type = "audio"

        return JSONResponse({
            "id": file.id,
            "filename": file.filename,
            "size": file.size,
            "type": file_type,
            "extension": file_ext,
            "version": file.version,
            "download_url": f"/download/{file.id}",
        })
    finally:
        db.close()