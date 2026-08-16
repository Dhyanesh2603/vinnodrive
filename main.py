import os
import re
import hashlib
from datetime import datetime, timezone
import time
import uuid
from fastapi import FastAPI, File, Form, HTTPException, UploadFile, Request
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse
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
USER_QUOTA_BYTES = 10 * 1024 * 1024  # 10 MB per user
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

# check_same_thread is SQLite-only; do not pass it for other databases
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


class UserFile(Base):
    __tablename__ = "user_files"
    id = Column(Integer, primary_key=True)
    filename = Column(String)
    filepath = Column(String)
    filehash = Column(String, index=True)
    username = Column(String, index=True)
    is_reference = Column(Integer, default=0)
    size = Column(Float)
    upload_date = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    folder = Column(String, index=True, default="/")
    is_public = Column(Integer, default=0)
    share_token = Column(String, unique=True, nullable=True, index=True)
    download_count = Column(Integer, default=0)



class SharedFile(Base):
    __tablename__ = "shared_files"
    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, index=True)
    shared_with = Column(String, index=True)
    shared_by = Column(String, index=True)


Base.metadata.create_all(bind=engine)


def hash_password(password: str) -> str:
    """Generate bcrypt password hash safely with max 72-byte truncation."""
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8")[:72], hashed_password.encode("utf-8"))
    except Exception:
        return False



# === HELPERS ===

def sanitize_filename(filename: str) -> str:
    """Sanitize uploaded filename to prevent directory traversal and null byte injections."""
    base = os.path.basename(filename).strip()
    base = re.sub(r"[\x00-\x1f\x7f]", "", base)
    base = re.sub(r'[\\/*?:"<>|]', "_", base)
    if len(base) > 255:
        name, ext = os.path.splitext(base)
        base = name[: 255 - len(ext)] + ext
    return base or "unnamed_file"


def get_current_user(request: Request) -> str | None:
    """Returns username if session is valid and not timed out; else clears session."""
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


def get_actual_storage(username: str) -> int:
    """Disk storage used: real files only (no references, no folder markers) via DB sum."""
    db = SessionLocal()
    try:
        res = db.query(func.coalesce(func.sum(UserFile.size), 0)).filter(
            UserFile.username == username,
            UserFile.is_reference == 0,
            ~UserFile.filename.like(".folder_marker_%"),
        ).scalar()
        return int(res or 0)
    finally:
        db.close()


def get_user_space_saved(username: str) -> int:
    """Space saved via deduplication (reference entries) via DB sum."""
    db = SessionLocal()
    try:
        res = db.query(func.coalesce(func.sum(UserFile.size), 0)).filter(
            UserFile.username == username,
            UserFile.is_reference == 1,
        ).scalar()
        return int(res or 0)
    finally:
        db.close()


def get_original_uploaded(username: str) -> int:
    """Total logical size of all real files (excludes folder markers) via DB sum."""
    db = SessionLocal()
    try:
        res = db.query(func.coalesce(func.sum(UserFile.size), 0)).filter(
            UserFile.username == username,
            ~UserFile.filename.like(".folder_marker_%"),
        ).scalar()
        return int(res or 0)
    finally:
        db.close()


def normalize_folder_path(folder: str) -> str:
    """Normalize to /segment/path/ format and prevent directory traversal."""
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


# === ROUTES ===

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
        db.add(User(username=username, hashed_password=hash_password(password)))
        db.commit()
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
        own_files = db.query(UserFile).filter(UserFile.username == username).all()

        shared_with_me_entries = db.query(SharedFile).filter(SharedFile.shared_with == username).all()
        shared_with_me_ids = [s.file_id for s in shared_with_me_entries]
        shared_with_me_files = (
            db.query(UserFile).filter(UserFile.id.in_(shared_with_me_ids)).all()
            if shared_with_me_ids else []
        )

        # Batch query SharedFile to eliminate N+1 query loop
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

        actual_used = get_actual_storage(username)
        original_uploaded = get_original_uploaded(username)
        saved_space = get_user_space_saved(username)
        savings_percent = (saved_space / original_uploaded * 100) if original_uploaded > 0 else 0
    finally:
        db.close()

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "files": own_files,
        "shared_with_me_files": shared_with_me_files,
        "shared_by_me": shared_by_me,
        "username": username,
        "actual_used": actual_used,
        "original_uploaded": original_uploaded,
        "saved_space": saved_space,
        "savings_percent": savings_percent,
        "quota_bytes": USER_QUOTA_BYTES,
        "quota_mb": 10,
        "status_msg": status,
        "error_msg": error,
    })


@app.post("/upload")
async def upload(request: Request, folder: str = Form("/"), files: list[UploadFile] = File(...)):
    username = get_current_user(request)
    if not username:
        return JSONResponse({"results": [], "error": "Session expired. Please login again."}, status_code=401)

    if not files or all(not f.filename for f in files):
        return JSONResponse({"results": [], "error": "No files selected."}, status_code=400)

    # Protect upload quota calculation and rate limiting with lock
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
        new_original_size = 0
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
                    ).first()
                    if not existing_user_file and file_hash not in seen_batch_hashes:
                        new_original_size += file_size
                        seen_batch_hashes.add(file_hash)
                finally:
                    db.close()

                temp_files.append((temp_path, safe_name, file_hash, file_size))

            if current_used + new_original_size > USER_QUOTA_BYTES:
                for temp_path, *_ in temp_files:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                return JSONResponse({"results": [], "error": "Storage quota exceeded (10 MB limit)."}, status_code=400)

            results = []
            db = SessionLocal()
            try:
                for temp_path, filename, file_hash, file_size in temp_files:
                    existing_user_file = db.query(UserFile).filter(
                        UserFile.filehash == file_hash,
                        UserFile.username == username,
                        UserFile.is_reference == 0,
                    ).first()

                    if existing_user_file:
                        if os.path.exists(temp_path):
                            os.remove(temp_path)
                        filepath = existing_user_file.filepath
                        message = "Duplicate (you already uploaded this file)"
                        is_ref = 1
                    else:
                        final_path = os.path.join(UPLOAD_FOLDER, f"{username}_{file_hash}")
                        os.replace(temp_path, final_path)
                        filepath = final_path
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
                    )
                    db.add(entry)
                    db.commit()
                    db.refresh(entry)
                    results.append({"filename": filename, "message": message})
            finally:
                db.close()

            return JSONResponse({"results": results})

        except Exception as e:
            for temp_path, *_ in temp_files:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            return JSONResponse({"results": [], "error": f"Upload failed: {str(e)}"}, status_code=500)


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

        # Increment download count
        file.download_count += 1
        db.commit()

        return FileResponse(file.filepath, filename=file.filename)
    finally:
        db.close()


@app.get("/public/{token}")
async def public_download(token: str):
    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(
            UserFile.share_token == token,
            UserFile.is_public == 1,
        ).first()
        if not file:
            raise HTTPException(status_code=404, detail="Invalid or expired link.")
        if not file.filepath or not os.path.exists(file.filepath):
            raise HTTPException(status_code=404, detail="File not available.")

        file.download_count += 1
        db.commit()

        return FileResponse(
            path=file.filepath,
            filename=file.filename,
            media_type="application/octet-stream",
        )
    finally:
        db.close()


@app.post("/toggle_share")
async def toggle_share(request: Request, file_id: int = Form(...)):
    username = get_current_user(request)
    if not username:
        return RedirectResponse("/login")

    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.id == file_id, UserFile.username == username).first()
        if not file:
            raise HTTPException(404, detail="File not found.")
        file.is_public = 1 - file.is_public
        file.share_token = str(uuid.uuid4()) if file.is_public else None
        db.commit()
    finally:
        db.close()

    return RedirectResponse("/dashboard#my-files", status_code=303)


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
            return RedirectResponse("/dashboard?error=User+'" + target_username + "'+does+not+exist#my-files", status_code=303)

        if target_username == username:
            return RedirectResponse("/dashboard?error=Cannot+share+file+with+yourself#my-files", status_code=303)

        if db.query(SharedFile).filter(
            SharedFile.file_id == file_id,
            SharedFile.shared_with == target_username,
        ).first():
            return RedirectResponse("/dashboard?error=File+already+shared+with+'" + target_username + "'#my-files", status_code=303)

        db.add(SharedFile(file_id=file_id, shared_with=target_username, shared_by=username))
        db.commit()
    finally:
        db.close()

    return RedirectResponse("/dashboard?status=File+shared+successfully+with+'" + target_username + "'#my-files", status_code=303)


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
            if file.filename.startswith(".folder_marker_"):
                db.delete(file)
                continue

            target_hash = file.filehash
            is_ref = file.is_reference
            file_path_on_disk = file.filepath

            db.query(SharedFile).filter(SharedFile.file_id == file.id).delete()

            user_ref_count = db.query(UserFile).filter(
                UserFile.filehash == target_hash,
                UserFile.username == username,
            ).count()

            db.delete(file)
            db.flush()

            if is_ref == 0 and user_ref_count > 1:
                next_ref = db.query(UserFile).filter(
                    UserFile.filehash == target_hash,
                    UserFile.username == username,
                ).first()
                if next_ref:
                    next_ref.is_reference = 0
                    next_ref.filepath = file_path_on_disk

            if is_ref == 0 and user_ref_count == 1 and file_path_on_disk and os.path.exists(file_path_on_disk):
                os.remove(file_path_on_disk)

        db.commit()
    finally:
        db.close()

    return RedirectResponse("/dashboard?status=Folder+deleted+successfully#my-files", status_code=303)


@app.post("/delete")
async def delete(request: Request, file_id: int = Form(...)):
    username = get_current_user(request)
    if not username:
        return RedirectResponse("/login")

    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.id == file_id, UserFile.username == username).first()
        if not file:
            raise HTTPException(404, detail="File not found.")

        target_hash = file.filehash
        is_ref = file.is_reference
        file_path_on_disk = file.filepath

        db.query(SharedFile).filter(SharedFile.file_id == file_id).delete()

        user_ref_count = db.query(UserFile).filter(
            UserFile.filehash == target_hash,
            UserFile.username == username,
        ).count()

        db.delete(file)
        db.flush()

        if is_ref == 0 and user_ref_count > 1:
            next_ref = db.query(UserFile).filter(
                UserFile.filehash == target_hash,
                UserFile.username == username,
            ).first()
            if next_ref:
                next_ref.is_reference = 0
                next_ref.filepath = file_path_on_disk

        db.commit()

        if is_ref == 0 and user_ref_count == 1 and file_path_on_disk and os.path.exists(file_path_on_disk):
            os.remove(file_path_on_disk)
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
            is_ref = file.is_reference
            file_path_on_disk = file.filepath

            db.query(SharedFile).filter(SharedFile.file_id == file_id).delete()

            user_ref_count = db.query(UserFile).filter(
                UserFile.filehash == target_hash,
                UserFile.username == username,
            ).count()

            db.delete(file)
            db.flush()
            deleted_count += 1

            if is_ref == 0 and user_ref_count > 1:
                next_ref = db.query(UserFile).filter(
                    UserFile.filehash == target_hash,
                    UserFile.username == username,
                ).first()
                if next_ref:
                    next_ref.is_reference = 0
                    next_ref.filepath = file_path_on_disk

            if is_ref == 0 and user_ref_count == 1 and file_path_on_disk and os.path.exists(file_path_on_disk):
                os.remove(file_path_on_disk)

        db.commit()
        return JSONResponse({"success": True, "deleted_count": deleted_count})
    except Exception as e:
        db.rollback()
        return JSONResponse({"error": str(e)}, status_code=500)
    finally:
        db.close()


@app.get("/logout")
async def logout_get(request: Request):
    request.session.clear()
    return RedirectResponse("/login")


@app.post("/logout")
async def logout_post(request: Request):
    request.session.clear()
    return JSONResponse({"status": "logged out"})


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
        ).all()

        locations = [
            {
                "id": dup.id,
                "filename": dup.filename,
                "folder": dup.folder,
                "upload_date": dup.upload_date.strftime("%b %d, %Y %H:%M"),
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
        elif file_ext in ["txt", "md", "json", "xml", "csv", "log"]:
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
            "download_url": f"/download/{file.id}",
        })
    finally:
        db.close()