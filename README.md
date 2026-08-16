# VinnoDrive

VinnoDrive is a high-performance, multi-tenant cloud storage platform engineered with content-addressed global deduplication, in-browser code and markdown editing, granular link expiration controls, file revision tracking, and developer REST APIs.

---

## Key Capabilities

### Content-Addressed Global Deduplication
- Server-wide SHA-256 deduplication stores unique physical files once across all users.
- Individual user privacy and ownership boundaries are strictly preserved.
- Zero-quota penalties for duplicate re-uploads within accounts.
- Automated reference-counting garbage collection guarantees zero dangling physical files.

### In-Browser Code & Markdown Studio
- Edit `.py`, `.js`, `.json`, `.csv`, `.txt`, `.html`, `.css`, and `.yaml` files directly in the browser.
- Real-time split-view Markdown preview renderer for `.md` documentation.
- Automatic incremental version creation (`v1`, `v2`, `v3`) on save.

### Revision History & Historical Rollback
- Complete revision histories with timestamps and byte metrics for every edited file.
- One-click rollback restores files to any historical state.

### Protected & Expiring Sharing
- Advanced public link controls with optional passcode protection.
- Configurable link expiration timers (1 hour, 24 hours, 7 days, 30 days).
- Download limits automatically invalidate links after reaching maximum threshold.
- Secure direct user-to-user sharing within the platform.

### Developer REST API & Personal Access Tokens
- Generate and manage Personal Access Tokens (`vno_live_...`) directly from the dashboard.
- Upload programmatically using standard HTTP clients (`curl`, Python `requests`, Node.js) via `POST /api/v1/upload`.

### Remote URL Cloud Importer
- Import files, datasets, and archives directly into any folder from a remote URL.
- Background chunked streaming with size limit safeguards and automated deduplication.

### Full-Text Content Search
- Search within text, code, logs, and document contents across the entire drive.
- Live snippet previews with line numbers and keyword matching.

### Interactive Image Canvas Studio
- In-browser image editor supporting 90-degree rotations and horizontal flipping.
- Real-time brightness, contrast, and grayscale filter adjustments.
- Instant versioned save back to the user's drive.

### Trash & Recycle Bin (Soft Delete)
- Two-stage deletion prevents accidental data loss.
- Trashed items do not consume active storage quota.
- One-click restoration back to original folders or permanent disk purge.

### Folder & Bulk Archive Downloads
- Stream entire folders or multi-file selections as compressed `.zip` archives.

### Administrator Console
- Centralized management dashboard accessible to system administrators.
- Global physical disk consumption metrics, space savings calculations, and deduplication efficiency ratios.
- Granular per-user storage quota adjustments and account lifecycle management.

---

## Architecture & Technology Stack

### Backend
- **Framework**: FastAPI (Asynchronous Python ASGI)
- **Database**: SQLite (Development) / PostgreSQL (Production) via SQLAlchemy ORM
- **Security**: Direct `bcrypt` hashing with salt rounds, session management, and path traversal sanitization
- **Concurrency**: Asynchronous lock controls for atomic quota calculations and disk operations

### Frontend
- **Interface**: Semantic HTML5 and Vanilla JavaScript (zero heavy framework runtime overhead)
- **Styling**: Executive Minimalist Design System with native CSS Custom Properties
- **Icons**: Standardized Lucide SVG icon set (zero emoji dependencies)
- **Theme**: Persistent light and dark mode with automated preference detection

---

## Getting Started

### Prerequisites
- Python 3.10+ installed
- Git

### Installation

1. Clone the repository:
```bash
git clone https://github.com/your-username/vinnodrive.git
cd vinnodrive
```

2. Create and activate a virtual environment:
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Launch the application:
```bash
uvicorn main:app --reload
```

5. Access the application in your browser:
```
http://127.0.0.1:8000
```

---

## API Reference

### Upload File via API

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/upload" \
  -H "X-API-Key: YOUR_API_KEY" \
  -F "folder=/documents/" \
  -F "file=@/path/to/local_document.pdf"
```

**Response:**
```json
{
  "success": true,
  "file_id": 42,
  "filename": "local_document.pdf",
  "size": 1048576,
  "folder": "/documents/",
  "is_duplicate": false
}
```

---

## Project Structure

```
├── main.py                     # FastAPI application, database models, and route controllers
├── requirements.txt            # Python dependencies
├── Procfile                    # Deployment configuration
├── runtime.txt                 # Python runtime version
├── static/
│   └── style.css               # Design system tokens and component styles
└── templates/
    ├── landing.html            # Public landing page
    ├── login.html              # Authentication sign-in
    ├── signup.html             # User registration
    ├── dashboard.html          # Main drive management workspace
    ├── admin.html              # Administrator management console
    └── public_share.html       # Public share access and passcode verification
```

---

## Author

**Dhyanesh S**
