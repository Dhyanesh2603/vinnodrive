import os
import shutil
import hashlib
from datetime import datetime
import time
import uuid
from fastapi import FastAPI, File, Form, HTTPException, UploadFile, Request
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import Column, Integer, String, Float, DateTime, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext
from starlette.middleware.sessions import SessionMiddleware

# === CONFIG ===
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
USER_QUOTA_BYTES = 10 * 1024 * 1024  # 10 MB limit
SECRET_KEY = "change_this_to_a_strong_random_string_in_production!!!"
SESSION_TIMEOUT_MINUTES = 20  # Auto-logout after 20 minutes of inactivity

# Rate limiting
last_upload_time = {}

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# === DATABASE ===
Base = declarative_base()
engine = create_engine("sqlite:///vinnodrive.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    hashed_password = Column(String)

class UserFile(Base):
    __tablename__ = "user_files"
    id = Column(Integer, primary_key=True)
    filename = Column(String)
    filepath = Column(String)
    filehash = Column(String)
    username = Column(String)
    is_reference = Column(Integer, default=0)
    size = Column(Float)
    upload_date = Column(DateTime, default=datetime.utcnow)
    folder = Column(String, default="/")
    is_public = Column(Integer, default=0)
    share_token = Column(String, unique=True, nullable=True)
    download_count = Column(Integer, default=0)

class SharedFile(Base):
    __tablename__ = "shared_files"
    id = Column(Integer, primary_key=True)
    file_id = Column(Integer)
    shared_with = Column(String)
    shared_by = Column(String)

Base.metadata.create_all(bind=engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# === HELPERS ===
def calculate_hash(file_path: str) -> str:
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha.update(chunk)
    return sha.hexdigest()

def get_actual_storage(username: str) -> int:
    db = SessionLocal()
    try:
        return sum(f.size for f in db.query(UserFile).filter(
            UserFile.username == username,
            UserFile.is_reference == 0
        ).all())
    finally:
        db.close()

def get_user_space_saved(username: str) -> int:
    db = SessionLocal()
    try:
        return sum(f.size for f in db.query(UserFile).filter(
            UserFile.username == username,
            UserFile.is_reference == 1
        ).all())
    finally:
        db.close()

def get_original_uploaded(username: str) -> int:
    db = SessionLocal()
    try:
        return sum(f.size for f in db.query(UserFile).filter(UserFile.username == username).all())
    finally:
        db.close()

def normalize_folder_path(folder: str) -> str:
    """Normalize folder path to always have leading and trailing slashes"""
    if not folder:
        return "/"
    # Remove whitespace and convert backslashes to forward slashes
    folder = folder.strip().replace("\\", "/")
    # Remove multiple consecutive slashes
    while "//" in folder:
        folder = folder.replace("//", "/")
    # Ensure leading slash
    if not folder.startswith("/"):
        folder = "/" + folder
    # Ensure trailing slash
    if not folder.endswith("/"):
        folder = folder + "/"
    return folder

def check_session_timeout(request: Request):
    """Check if session has timed out due to inactivity"""
    if "username" not in request.session:
        return True
    
    last_activity = request.session.get("last_activity")
    if not last_activity:
        # First time, set last activity
        request.session["last_activity"] = datetime.utcnow().isoformat()
        return False
    
    # Parse last activity time
    last_activity_time = datetime.fromisoformat(last_activity)
    time_elapsed = datetime.utcnow() - last_activity_time
    
    # Check if more than SESSION_TIMEOUT_MINUTES have passed
    if time_elapsed.total_seconds() > (SESSION_TIMEOUT_MINUTES * 60):
        # Session expired
        request.session.clear()
        return True
    
    # Update last activity time
    request.session["last_activity"] = datetime.utcnow().isoformat()
    return False

# === ROUTES ===
@app.get("/")
async def root(request: Request):
    if request.session.get("username"):
        return RedirectResponse("/dashboard")
    return templates.TemplateResponse("landing.html", {"request": request})

@app.get("/login")
async def login_page(request: Request):
    if request.session.get("username"):
        return RedirectResponse("/dashboard")
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/signup")
async def signup_page(request: Request):
    if request.session.get("username"):
        return RedirectResponse("/dashboard")
    return templates.TemplateResponse("signup.html", {"request": request})

@app.post("/signup")
async def signup(request: Request, username: str = Form(...), password: str = Form(...)):
    db = SessionLocal()
    try:
        if db.query(User).filter(User.username == username).first():
            return templates.TemplateResponse("signup.html", {"request": request, "error": "Username already taken"})
        db.add(User(username=username, hashed_password=pwd_context.hash(password)))
        db.commit()
        return RedirectResponse("/", status_code=303)
    finally:
        db.close()

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user or not pwd_context.verify(password, user.hashed_password):
            return templates.TemplateResponse("login.html", {"request": request, "error": "Wrong username or password"})
        request.session["username"] = username
        request.session["last_activity"] = datetime.utcnow().isoformat()
        return RedirectResponse("/dashboard", status_code=303)
    finally:
        db.close()

@app.get("/dashboard")
async def dashboard(request: Request):
    username = request.session.get("username")
    if not username or check_session_timeout(request):
        return RedirectResponse("/")
    
    db = SessionLocal()
    try:
        # Own files
        own_files = db.query(UserFile).filter(UserFile.username == username).all()
        
        # Files shared WITH me (by others)
        shared_with_me_entries = db.query(SharedFile).filter(SharedFile.shared_with == username).all()
        shared_with_me_ids = [s.file_id for s in shared_with_me_entries]
        shared_with_me_files = db.query(UserFile).filter(UserFile.id.in_(shared_with_me_ids)).all() if shared_with_me_ids else []
        
        # Files shared BY me (to others) - with recipient information
        shared_by_me = []
        for file in own_files:
            recipients = db.query(SharedFile).filter(SharedFile.file_id == file.id).all()
            if recipients:
                shared_by_me.append({
                    'file': file,
                    'shared_with': [r.shared_with for r in recipients]
                })
        
        # Stats
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
        "session_timeout_minutes": SESSION_TIMEOUT_MINUTES
    })

@app.post("/upload")
async def upload(request: Request, folder: str = Form("/"), files: list[UploadFile] = File(...)):
    username = request.session.get("username")
    if not username or check_session_timeout(request):
        return JSONResponse({"results": [], "error": "Session expired. Please login again."}, status_code=401)

    if not files or all(not f.filename for f in files):
        return JSONResponse({"results": [], "error": "No files selected"}, status_code=400)

    # Rate limit
    now = time.time()
    if username in last_upload_time and now - last_upload_time[username] < 0.5:
        return JSONResponse({"results": [], "error": "Too many uploads! Wait a second."}, status_code=429)
    last_upload_time[username] = now

    # Normalize folder
    folder = normalize_folder_path(folder)

    # Quota check
    current_used = get_actual_storage(username)
    new_original_size = 0
    temp_files = []

    try:
        for file in files:
            if not file.filename:
                continue
            
            temp_path = os.path.join(UPLOAD_FOLDER, f"temp_{uuid.uuid4()}_{file.filename}")
            
            # Write file to disk
            with open(temp_path, "wb") as f:
                content = await file.read()
                f.write(content)

            file_hash = calculate_hash(temp_path)
            file_size = os.path.getsize(temp_path)

            db = SessionLocal()
            try:
                # Check if THIS USER already has this file (per-user deduplication)
                existing_user_file = db.query(UserFile).filter(
                    UserFile.filehash == file_hash,
                    UserFile.username == username,
                    UserFile.is_reference == 0
                ).first()
                
                if not existing_user_file:
                    new_original_size += file_size
            finally:
                db.close()

            temp_files.append((temp_path, file.filename, file_hash, file_size))

        # Check quota
        if current_used + new_original_size > USER_QUOTA_BYTES:
            for temp_path, *_ in temp_files:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            return JSONResponse({"results": [], "error": "Storage quota exceeded (10MB limit)"}, status_code=400)

        # Save files
        results = []
        db = SessionLocal()
        try:
            for temp_path, filename, file_hash, file_size in temp_files:
                # Check if THIS USER already uploaded this exact file
                existing_user_file = db.query(UserFile).filter(
                    UserFile.filehash == file_hash,
                    UserFile.username == username,
                    UserFile.is_reference == 0
                ).first()
                
                if existing_user_file:
                    # User is re-uploading their own duplicate
                    os.remove(temp_path)
                    filepath = existing_user_file.filepath
                    message = "Duplicate (you already uploaded this file)"
                    is_ref = 1
                else:
                    # This is a new file for this user
                    # Store it with a unique path per user
                    final_path = os.path.join(UPLOAD_FOLDER, f"{username}_{file_hash}")
                    os.rename(temp_path, final_path)
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
                    download_count=0
                )
                db.add(entry)
                db.commit()
                results.append({"filename": filename, "message": message})
        finally:
            db.close()
            
        return JSONResponse({"results": results})
        
    except Exception as e:
        # Clean up temp files on error
        for temp_path, *_ in temp_files:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        return JSONResponse({"results": [], "error": f"Upload failed: {str(e)}"}, status_code=500)

@app.get("/download/{file_id}")
async def download(file_id: int, request: Request):
    username = request.session.get("username")
    if not username or check_session_timeout(request):
        return RedirectResponse("/")
    
    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.id == file_id).first()
        if not file:
            raise HTTPException(404, detail="File not found")
            
        # Check if user owns the file
        if file.username != username:
            # Check if file is shared with user
            shared = db.query(SharedFile).filter(
                SharedFile.file_id == file_id,
                SharedFile.shared_with == username
            ).first()
            if not shared:
                raise HTTPException(403, detail="Access denied")
                
        if not os.path.exists(file.filepath):
            raise HTTPException(404, detail="File not available")
            
        return FileResponse(file.filepath, filename=file.filename)
    finally:
        db.close()

@app.get("/public/{token}")
async def public_download(token: str):
    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.share_token == token, UserFile.is_public == 1).first()
        if not file:
            raise HTTPException(status_code=404, detail="Invalid or expired link")
        if not os.path.exists(file.filepath):
            raise HTTPException(status_code=404, detail="File not available")
        
        file.download_count += 1
        db.commit()
        
        return FileResponse(
            path=file.filepath,
            filename=file.filename,
            media_type="application/octet-stream"
        )
    finally:
        db.close()

@app.post("/toggle_share")
async def toggle_share(request: Request, file_id: int = Form(...)):
    username = request.session.get("username")
    if not username or check_session_timeout(request):
        return RedirectResponse("/")
    
    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.id == file_id, UserFile.username == username).first()
        if not file:
            raise HTTPException(404)
        file.is_public = 1 - file.is_public
        file.share_token = str(uuid.uuid4()) if file.is_public else None
        db.commit()
    finally:
        db.close()
    
    return RedirectResponse("/dashboard", status_code=303)

@app.post("/share_with_user")
async def share_with_user(request: Request, file_id: int = Form(...), target_username: str = Form(...)):
    username = request.session.get("username")
    if not username or check_session_timeout(request):
        return RedirectResponse("/")
    
    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.id == file_id, UserFile.username == username).first()
        if not file:
            return RedirectResponse("/dashboard")
        
        if not db.query(User).filter(User.username == target_username).first():
            return RedirectResponse("/dashboard")
        
        if target_username == username:
            return RedirectResponse("/dashboard")
        
        if db.query(SharedFile).filter(
            SharedFile.file_id == file_id,
            SharedFile.shared_with == target_username
        ).first():
            return RedirectResponse("/dashboard")
        
        db.add(SharedFile(
            file_id=file_id,
            shared_with=target_username,
            shared_by=username
        ))
        db.commit()
    finally:
        db.close()
    
    return RedirectResponse("/dashboard", status_code=303)

@app.post("/create_folder")
async def create_folder(request: Request, folder_name: str = Form(...)):
    username = request.session.get("username")
    if not username or check_session_timeout(request):
        return RedirectResponse("/")
    
    # Clean and normalize folder name
    folder_name = folder_name.strip()
    if not folder_name:
        return RedirectResponse("/dashboard", status_code=303)
    
    # Normalize the path
    full_path = normalize_folder_path(folder_name)
    
    # Prevent creating root folder
    if full_path == "/":
        return RedirectResponse("/dashboard", status_code=303)
    
    db = SessionLocal()
    try:
        # Check if folder already exists
        existing = db.query(UserFile).filter(
            UserFile.username == username,
            UserFile.folder == full_path,
            UserFile.filename.like(".folder_marker_%")
        ).first()
        
        if existing:
            return RedirectResponse("/dashboard", status_code=303)
        
        # Create folder marker
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
            download_count=0
        ))
        db.commit()
    finally:
        db.close()
    
    return RedirectResponse("/dashboard", status_code=303)

@app.post("/delete")
async def delete(request: Request, file_id: int = Form(...)):
    username = request.session.get("username")
    if not username or check_session_timeout(request):
        return RedirectResponse("/")
    
    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.id == file_id, UserFile.username == username).first()
        if not file:
            raise HTTPException(404)
        
        # Count how many times THIS USER has this file hash
        user_ref_count = db.query(UserFile).filter(
            UserFile.filehash == file.filehash,
            UserFile.username == username
        ).count()
        
        db.delete(file)
        db.commit()
        
        # Only delete physical file if this was the user's last reference to it
        if user_ref_count == 1 and file.filepath and os.path.exists(file.filepath):
            os.remove(file.filepath)
    finally:
        db.close()
    
    return RedirectResponse("/dashboard", status_code=303)

@app.get("/logout")
async def logout_get(request: Request):
    request.session.clear()
    return RedirectResponse("/")

@app.post("/logout")
async def logout_post(request: Request):
    request.session.clear()
    return JSONResponse({"status": "logged out"})

@app.get("/api/file/duplicate-locations/{file_id}")
async def get_duplicate_locations(file_id: int, request: Request):
    """Get all locations where duplicate files exist"""
    username = request.session.get("username")
    if not username or check_session_timeout(request):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    
    db = SessionLocal()
    try:
        # Get the file
        file = db.query(UserFile).filter(UserFile.id == file_id, UserFile.username == username).first()
        if not file:
            return JSONResponse({"error": "File not found"}, status_code=404)
        
        # Find all files with the same hash for this user
        duplicates = db.query(UserFile).filter(
            UserFile.filehash == file.filehash,
            UserFile.username == username
        ).all()
        
        locations = []
        for dup in duplicates:
            locations.append({
                "id": dup.id,
                "filename": dup.filename,
                "folder": dup.folder,
                "upload_date": dup.upload_date.strftime('%b %d, %Y %H:%M'),
                "is_current": dup.id == file_id
            })
        
        return JSONResponse({"locations": locations})
    finally:
        db.close()

@app.get("/api/file/preview/{file_id}")
async def preview_file(file_id: int, request: Request):
    """Get file info for preview"""
    username = request.session.get("username")
    if not username or check_session_timeout(request):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    
    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.id == file_id).first()
        if not file:
            return JSONResponse({"error": "File not found"}, status_code=404)
        
        # Check permissions
        if file.username != username:
            shared = db.query(SharedFile).filter(
                SharedFile.file_id == file_id,
                SharedFile.shared_with == username
            ).first()
            if not shared:
                return JSONResponse({"error": "Access denied"}, status_code=403)
        
        # Determine file type
        file_ext = file.filename.split('.')[-1].lower() if '.' in file.filename else ''
        file_type = 'unknown'
        
        if file_ext in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg']:
            file_type = 'image'
        elif file_ext in ['pdf']:
            file_type = 'pdf'
        elif file_ext in ['txt', 'md', 'json', 'xml', 'csv', 'log']:
            file_type = 'text'
        elif file_ext in ['mp4', 'webm', 'ogg', 'mov']:
            file_type = 'video'
        elif file_ext in ['mp3', 'wav', 'ogg', 'flac']:
            file_type = 'audio'
        
        return JSONResponse({
            "id": file.id,
            "filename": file.filename,
            "size": file.size,
            "type": file_type,
            "extension": file_ext,
            "download_url": f"/download/{file.id}"
        })
    finally:
        db.close()
