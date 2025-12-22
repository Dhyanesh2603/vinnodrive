import os
import shutil
import hashlib
from datetime import datetime
from fastapi import FastAPI, File, Form, UploadFile, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import Column, Integer, String, Float, DateTime, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext
from starlette.middleware.sessions import SessionMiddleware

# Setup
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

app.add_middleware(SessionMiddleware, secret_key="mysecretkey12345changeit")

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
        "username": username
    })

@app.post("/upload")
async def upload(request: Request, files: list[UploadFile] = File(...)):
    username = request.session.get("username")
    if not username:
        return RedirectResponse("/")
    db = SessionLocal()
    results = []
    for file in files:
        if not file.filename:
            continue
        temp_path = os.path.join(UPLOAD_FOLDER, f"temp_{file.filename}")
        with open(temp_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
        file_hash = calculate_hash(temp_path)
        file_size = os.path.getsize(temp_path)
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
        entry = UserFile(filename=file.filename, filepath=filepath, filehash=file_hash, username=username, is_reference=is_ref, size=file_size)
        db.add(entry)
        db.commit()
        results.append({"filename": file.filename, "message": message})
    db.close()
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