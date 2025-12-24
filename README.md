# VinnoDrive ☁️

A personal cloud drive with **smart file deduplication**, built as my **first full-stack web project**.

VinnoDrive stores identical files only once on disk and creates references for duplicates — saving real storage space, just like modern cloud services.

---

## 🚀 Features

- Drag & drop **multi-file upload**
- **Smart deduplication** using SHA-256 hashing
- Original vs duplicate (reference) file detection
- Real disk space saving (not just logical)
- Clean and responsive dashboard
- View all uploaded files with:
  - Filename
  - Size
  - Upload date
  - Uploader
  - Deduplication status
- Download and delete files
- Storage usage statistics
- Fast and lightweight backend

---

## 🛠 Tech Stack

**Backend**
- FastAPI (Python)
- SQLAlchemy ORM
- SQLite database

**Frontend**
- Jinja2 templating engine
- HTML, CSS, Vanilla JavaScript

**Other**
- SHA-256 hashing for deduplication
- Uvicorn ASGI server

---

## 📁 Project Structure

vinnodrive/
│
├── main.py
├── vinnodrive.db
├── uploads/
├── templates/
│ ├── index.html
│ └── dashboard.html
├── static/
│ └── style.css
└── README.md


## ⚡ How to Run Locally

### 1️⃣ Clone the repository
```bash
git clone https://github.com/Dhyanesh2603/vinnodrive.git
cd vinnodrive
2️⃣ Create a virtual environment (recommended)
bash
Copy code
python -m venv venv
Activate it:

Windows

bash
Copy code
venv\Scripts\activate
Linux / macOS

bash
Copy code
source venv/bin/activate
3️⃣ Install dependencies
bash
Copy code
pip install fastapi uvicorn sqlalchemy jinja2 python-multipart
4️⃣ Run the app
bash
Copy code
uvicorn main:app --reload
5️⃣ Open in browser
cpp
Copy code
http://127.0.0.1:8000
🌟 Why This Project Matters
This project helped me learn and apply:

Backend routing with FastAPI

Database modeling using SQLAlchemy

File handling and hashing

Real deduplication logic

Frontend–backend integration

Debugging real-world issues

It’s not just a CRUD app — it solves a real storage problem.

🔮 Future Improvements
User authentication (login/signup)

Folder support

Public file sharing links

File previews (images, PDFs)

Cloud deployment

Storage quotas per user

Dark mode 🌙

🙌 Acknowledgements
Built with curiosity, persistence, and many late-night debugging sessions.

👨‍💻 Author
Dhyanesh S
First Full-Stack Project
December 2025.
