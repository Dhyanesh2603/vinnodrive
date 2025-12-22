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

# Constants
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
USER_QUOTA_BYTES = 10 * 1024 * 1024  # 10 MB limit

# Rate limiting
last_upload_time = {}

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
app.add_middleware(SessionMiddleware, secret_key="mysecretkey12345changeit")  # CHANGE THIS IN PRODUCTION

# Database
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
    is_reference = Column(Integer)
    size = Column(Float)
    upload_date = Column(DateTime, default=datetime.utcnow)
    folder = Column(String, default="/")
    is_public = Column(Integer, default=0)
    share_token = Column(String, unique=True, nullable=True)
    download_count = Column(Integer, default=0)

Base.metadata.create_all(bind=engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Helpers
def calculate_hash(file_path: str) -> str:
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha.update(chunk)
    return sha.hexdigest()

def get_user_space_saved(username: str):
    db = SessionLocal()
    files = db.query(UserFile).filter(UserFile.username == username).all()
    saved = sum(f.size for f in files if f.is_reference == 1)
    db.close()
    return saved

def get_actual_storage(username: str):
    db = SessionLocal()
    originals = db.query(UserFile).filter(UserFile.username == username, UserFile.is_reference == 0).all()
    total = sum(f.size for f in originals)
    db.close()
    return total

def get_original_uploaded(username: str):
    db = SessionLocal()
    all_files = db.query(UserFile).filter(UserFile.username == username).all()
    total = sum(f.size for f in all_files)
    db.close()
    return total

# Routes
@app.get("/")
async def root(request: Request):
    if request.session.get("username"):
        return RedirectResponse("/dashboard")
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/signup")
async def signup_page(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})

@app.post("/signup")
async def signup(request: Request, username: str = Form(...), password: str = Form(...)):
    db = SessionLocal()
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        db.close()
        return templates.TemplateResponse("signup.html", {"request": request, "error": "Username already taken"})
    hashed = pwd_context.hash(password)
    new_user = User(username=username, hashed_password=hashed)
    db.add(new_user)
    db.commit()
    db.close()
    return RedirectResponse("/", status_code=303)

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    db.close()
    if not user or not pwd_context.verify(password, user.hashed_password):
        return templates.TemplateResponse("index.html", {"request": request, "error": "Wrong username or password"})
    request.session["username"] = username
    return RedirectResponse("/dashboard", status_code=303)

@app.get("/dashboard")
async def dashboard(request: Request):
    username = request.session.get("username")
    if not username:
        return RedirectResponse("/")
    db = SessionLocal()
    files = db.query(UserFile).filter(UserFile.username == username).all()
    saved = get_user_space_saved(username)
    actual_used = get_actual_storage(username)
    original_uploaded = get_original_uploaded(username)
    savings_percent = (saved / original_uploaded * 100) if original_uploaded > 0 else 0
    db.close()
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "files": files,
        "saved_space": saved,
        "actual_used": actual_used,
        "original_uploaded": original_uploaded,
        "savings_percent": savings_percent,
        "username": username,
        "quota_bytes": USER_QUOTA_BYTES,
        "quota_mb": 10
    })

@app.post("/upload")
async def upload(request: Request, folder: str = Form("/"), files: list[UploadFile] = File(None)):
    username = request.session.get("username")
    if not username:
        return RedirectResponse("/")

    if not files or len(files) == 0:
        return JSONResponse(content={"results": [], "error": "No files selected."}, status_code=400)

    # Rate Limiting
    now = time.time()
    if username in last_upload_time and now - last_upload_time[username] < 0.5:
        return JSONResponse(content={"results": [], "error": "Rate limit exceeded! Max 2 uploads per second."}, status_code=429)
    last_upload_time[username] = now

    # Normalize folder path
    folder = "/" + folder.strip("/") + "/" if folder.strip("/") else "/"

    # Quota Check
    current_actual = get_actual_storage(username)
    potential_new_original = 0
    temp_files = []

    try:
        for file in files:
            if not file.filename:
                continue
            temp_path = os.path.join(UPLOAD_FOLDER, f"temp_{uuid.uuid4()}_{file.filename}")
            with open(temp_path, "wb") as buf:
                shutil.copyfileobj(file.file, buf)

            file_hash = calculate_hash(temp_path)
            file_size = os.path.getsize(temp_path)

            db = SessionLocal()
            existing = db.query(UserFile).filter(UserFile.filehash == file_hash, UserFile.is_reference == 0).first()
            db.close()

            if not existing:
                potential_new_original += file_size

            temp_files.append((temp_path, file.filename, file_hash, file_size))

        if current_actual + potential_new_original > USER_QUOTA_BYTES:
            for temp_path, _, _, _ in temp_files:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            return JSONResponse(content={"results": [], "error": "Storage quota exceeded! Max 10MB per user."}, status_code=400)

        # Process uploads
        results = []
        db = SessionLocal()
        for temp_path, filename, file_hash, file_size in temp_files:
            existing = db.query(UserFile).filter(UserFile.filehash == file_hash, UserFile.is_reference == 0).first()
            if existing:
                os.remove(temp_path)
                filepath = existing.filepath
                message = "Duplicate (reference stored)"
                is_ref = 1
            else:
                final_path = os.path.join(UPLOAD_FOLDER, file_hash)
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
        db.close()

    except Exception as e:
        for temp_path, _, _, _ in temp_files:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        return JSONResponse(content={"results": [], "error": f"Server error: {str(e)}"}, status_code=500)

    return {"results": results, "space_saved_bytes": get_user_space_saved(username)}

@app.get("/download/{file_id}")
async def download(file_id: int, request: Request):
    username = request.session.get("username")
    if not username:
        return RedirectResponse("/")
    db = SessionLocal()
    file = db.query(UserFile).filter(UserFile.id == file_id, UserFile.username == username).first()
    db.close()
    if not file or not os.path.exists(file.filepath):
        raise HTTPException(404)
    return FileResponse(file.filepath, filename=file.filename)

@app.get("/public/{token}")
async def public_download(token: str):
    db = SessionLocal()
    try:
        file = db.query(UserFile).filter(UserFile.share_token == token, UserFile.is_public == 1).first()
        if not file:
            raise HTTPException(status_code=404, detail="Invalid or expired link")
        if not os.path.exists(file.filepath):
            raise HTTPException(status_code=404, detail="File no longer available")
        
        # Increment download count while session is open
        file.download_count += 1
        db.commit()
        
        # Return file
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
    if not username:
        return RedirectResponse("/")
    db = SessionLocal()
    file = db.query(UserFile).filter(UserFile.id == file_id, UserFile.username == username).first()
    if not file:
        db.close()
        raise HTTPException(404)
    if file.is_public == 1:
        file.is_public = 0
        file.share_token = None
    else:
        file.is_public = 1
        file.share_token = str(uuid.uuid4())
    db.commit()
    db.close()
    return RedirectResponse("/dashboard", status_code=303)

@app.post("/create_folder")
async def create_folder(request: Request, folder_name: str = Form(...)):
    username = request.session.get("username")
    if not username:
        return RedirectResponse("/")
    
    # Clean and normalize folder name (allow nested like photos/vacation)
    folder_name = folder_name.strip()
    if not folder_name or folder_name == "/" or folder_name.startswith("/") or folder_name.endswith("/"):
        return RedirectResponse("/dashboard")
    
    full_path = "/" + folder_name.replace("\\", "/") + "/"
    
    # Prevent duplicates
    db = SessionLocal()
    existing = db.query(UserFile).filter(UserFile.username == username, UserFile.folder == full_path).first()
    if existing:
        db.close()
        return RedirectResponse("/dashboard")
    
    # Create dummy marker entry for the folder
    dummy = UserFile(
        filename=".folder_marker_" + folder_name.split("/")[-1],
        filepath="",
        filehash="folder_marker",
        username=username,
        is_reference=0,
        size=0,
        folder=full_path,
        is_public=0,
        download_count=0
    )
    db.add(dummy)
    db.commit()
    db.close()
    
    return RedirectResponse("/dashboard", status_code=303)

# Fixed public download route
@app.get("/public/{token}")
async def public_download(token: str):
    db = SessionLocal()
    file = db.query(UserFile).filter(UserFile.share_token == token, UserFile.is_public == 1).first()
    db.close()
    if not file:
        raise HTTPException(status_code=404, detail="Link invalid or file not public")
    if not os.path.exists(file.filepath):
        raise HTTPException(status_code=404, detail="File not found on server")
    
    # Increment counter
    db = SessionLocal()
    file.download_count += 1
    db.commit()
    db.close()
    
    return FileResponse(file.filepath, filename=file.filename)

@app.post("/delete")
async def delete(request: Request, file_id: int = Form(...)):
    username = request.session.get("username")
    if not username:
        return RedirectResponse("/")
    db = SessionLocal()
    file = db.query(UserFile).filter(UserFile.id == file_id, UserFile.username == username).first()
    if not file:
        db.close()
        raise HTTPException(404)
    ref_count = db.query(UserFile).filter(UserFile.filehash == file.filehash).count()
    db.delete(file)
    db.commit()
    if ref_count == 1 and os.path.exists(file.filepath):
        os.remove(file.filepath)
    db.close()
    return RedirectResponse("/dashboard", status_code=303)

@app.get("/logout")
async def logout(request: Request):
    request.session.pop("username", None)
    return RedirectResponse("/")
