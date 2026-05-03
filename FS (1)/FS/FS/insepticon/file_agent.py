"""
advanced_agent.py
Comprehesive insider-threat monitoring agent for Windows (and partly cross-platform).
(Modified: safer optional imports, admin detection for Windows Event Log access,
and more robust config username expansion.)
"""

import os
import re
import time
import json
import hashlib
import queue
import threading
import requests
import base64
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
import sys
import ctypes
import platform
import socket

# third-party libs (optional imports handled individually)
MISSING_DEPS = []
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except Exception:
    Observer = None
    FileSystemEventHandler = object
    MISSING_DEPS.append("watchdog")

try:
    import psutil
except Exception:
    psutil = None
    MISSING_DEPS.append("psutil")

try:
    import pyperclip
except Exception:
    pyperclip = None
    MISSING_DEPS.append("pyperclip")

try:
    import docx
except Exception:
    docx = None
    MISSING_DEPS.append("python-docx")

try:
    import PyPDF2
except Exception:
    PyPDF2 = None
    MISSING_DEPS.append("PyPDF2")

try:
    from PIL import Image
except Exception:
    Image = None
    MISSING_DEPS.append("Pillow")

try:
    import pytesseract
except Exception:
    pytesseract = None
    MISSING_DEPS.append("pytesseract")

try:
    import mss
except Exception:
    mss = None
    MISSING_DEPS.append("mss")

try:
    import imapclient
    import email
except Exception:
    imapclient = None
    # email is stdlib; keep it
    if 'imapclient' not in MISSING_DEPS:
        MISSING_DEPS.append("imapclient")

try:
    from cryptography.fernet import Fernet
except Exception:
    Fernet = None
    MISSING_DEPS.append("cryptography")

# pywin32 optional (Windows-only)
win32evtlog = None
win32com = None
win32api = None
win32con = None
pythoncom = None
try:
    if os.name == "nt":
        import win32evtlog
        import win32con
        import win32api
        import win32com.client
        import pythoncom
        win32com = win32com  # just to indicate available
except Exception:
    # keep as None if not available
    win32evtlog = None
    win32com = None
    win32api = None
    win32con = None
    pythoncom = None
    # don't append to MISSING_DEPS since pywin32 is optional

OUTLOOK_AVAILABLE = win32com is not None and os.name == "nt"

# Warn about missing deps (but don't crash)
if MISSING_DEPS:
    print("⚠️ Warning: missing optional dependencies:", ", ".join(MISSING_DEPS))
    print("Install them for full functionality (see README).")

# ---------------------------
# Config (load or create)
# ---------------------------
DEFAULT_CONFIG = {
    "agent_id": "DESKTOP-HOST-001",
    # default to localhost receiver so running agent and server on same machine works out-of-the-box
    "server_url": "http://127.0.0.1:5000/receive_log",
    "watch_paths": [
        "C:\\Users\\%USERNAME%\\Desktop",
        "C:\\Users\\%USERNAME%\\Documents",
        "C:\\Users\\%USERNAME%\\Downloads",
        "C:\\Users\\%USERNAME%\\OneDrive"
    ],
    "email_folders": ["Outlook", "Thunderbird", "Teams", "Slack"],
    "cloud_folders": ["OneDrive", "Google Drive", "Dropbox"],
    "sensitive_keywords": ["password", "secret", "confidential", "salary", "client"],
    "sensitive_extensions": [".doc", ".docx", ".pdf", ".txt", ".xls", ".xlsx", ".ppt", ".pptx"],
    "max_upload_risk_size_mb": 50,
    "blacklist_processes": ["uTorrent.exe", "bittorrent.exe", "shareaza.exe"],
    "whitelist_processes": [],
    "min_scan_file_size": 1,
    "scan_images_with_ocr": True,
    "tesseract_cmd": "", # if blank, assume tesseract is in PATH
    "risk_threshold": 6,
    "alert_batch_size": 1,
    "alert_flush_seconds": 1,
    "enable_process_monitor": True,
    "enable_outlook_monitor": False,
    "enable_imap_monitor": False,
    "imap": {
        "host": "",
        "user": "",
        "password": "",
        "port": 993,
        "use_ssl": True
    },
    "encryption_key": None, # optional: provide base64 key, else key file will be created
    "take_screenshot_on_alert": False  # DISABLED - No screenshot alerts
}

CONFIG_PATH = "config.json"
KEY_PATH = "agent_key.key"
LOCAL_STORE = "secure_local_log.bin"

def get_system_info():
    """Get detailed system and user information"""
    try:
        # Get system hostname
        hostname = os.environ.get('COMPUTERNAME') or os.environ.get('HOSTNAME') or platform.node()

        # Get username with domain if available
        username = (os.environ.get('USERNAME') or os.environ.get('USER') or "").strip()
        domain = (os.environ.get('USERDOMAIN') or "").strip()

        if domain and username:
            full_username = f"{domain}\\{username}"
        else:
            full_username = username

        # Get additional system info
        system_info = {
            'hostname': hostname,
            'os': platform.system(),
            'os_version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor()
        }

        return full_username, hostname, system_info
    except Exception as e:
        print(f"Error getting system info: {e}")
        return "unknown", "unknown-host", {}

def safe_get_username():
    username, _, _ = get_system_info()
    return username

def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            conf = json.load(f)
            merged = DEFAULT_CONFIG.copy()
            merged.update(conf)
            # expand %USERNAME% safely
            uname = (os.environ.get('USERNAME') or os.environ.get('USER') or "").strip()
            merged["watch_paths"] = [p.replace("%USERNAME%", uname) for p in merged["watch_paths"]]
            # Do NOT auto-append the current working directory to watch paths
            # (this prevents the agent from monitoring its own project/server files and creating noise).
            # If you need to include extra paths, add them explicitly to config.json.
            return merged
    else:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        merged = DEFAULT_CONFIG.copy()
        merged["watch_paths"] = [p.replace("%USERNAME%", safe_get_username()) for p in merged["watch_paths"]]
        # DO NOT append current working directory automatically; user can add extra paths in config.json
        return merged

cfg = load_config()
AGENT_ID = cfg["agent_id"]
SERVER_URL = cfg["server_url"]


def server_base_url():
    """Base URL for /get_commands (strip /receive_log from agent server_url)."""
    s = (SERVER_URL or "").strip().rstrip("/")
    if s.lower().endswith("/receive_log"):
        return s[: -len("/receive_log")]
    return s or "http://127.0.0.1:5000"

# Setup encryption key for local logs
def get_or_create_key():
    if not Fernet:
        print("⚠️ cryptography.Fernet not available — local encrypted logs disabled.")
        return None
    if cfg.get("encryption_key"):
        k = cfg["encryption_key"]
        # if string, ensure bytes
        if isinstance(k, str):
            return k.encode()
        else:
            return k
    if os.path.exists(KEY_PATH):
        return open(KEY_PATH, "rb").read()
    key = Fernet.generate_key()
    with open(KEY_PATH, "wb") as f:
        f.write(key)
    return key

FERNET_KEY = get_or_create_key()
fernet = Fernet(FERNET_KEY) if FERNET_KEY and Fernet else None

# ---------------------------
# Helpers & globals
# ---------------------------
DATA_EXTENSIONS = set(cfg["sensitive_extensions"])
CLOUD_FOLDERS = [s.lower() for s in cfg["cloud_folders"]]
EMAIL_FOLDERS = [s.lower() for s in cfg["email_folders"]]
SENSITIVE_KEYWORDS = [w.lower() for w in cfg["sensitive_keywords"]]
BLACKLIST = set(n.lower() for n in cfg["blacklist_processes"])
WHITELIST = set(n.lower() for n in cfg["whitelist_processes"])
RISK_THRESHOLD = cfg["risk_threshold"]
ALERT_QUEUE = queue.Queue()
BATCH_LOCK = threading.Lock()
NOISY_SYSTEM_USERS = {
    "system", "local service", "network service"
}
SUSPICIOUS_PROCESS_NAMES = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wmic.exe", "rundll32.exe",
    "regsvr32.exe", "mshta.exe", "cscript.exe", "wscript.exe",
    "psexec.exe", "bitsadmin.exe", "certutil.exe", "schtasks.exe"
}

def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def is_after_office_hours(hour):
    try:
        hour = int(hour)
    except Exception:
        hour = datetime.now().hour
    return hour < 9 or hour >= 17


def enrich_event(ev: dict):
    """Ensure every event has consistent identity fields for multi-LAN dashboard."""
    try:
        if isinstance(ev, dict):
            ev.setdefault("agent_id", AGENT_ID)
            ev.setdefault("user", safe_get_username() or "unknown")
            ev.setdefault("hostname", socket.gethostname())
    except Exception:
        pass
    return ev


def should_ignore_logon_event(user, logon_type):
    user_norm = str(user or "").strip().lower()
    logon_type_norm = str(logon_type or "").strip()
    if not user_norm:
        return True
    if user_norm in NOISY_SYSTEM_USERS:
        return True
    if user_norm.endswith("$"):
        return True
    if user_norm.startswith("dwm-") or user_norm.startswith("umfd-"):
        return True
    if logon_type_norm == "5":
        return True
    return False


def is_interesting_process(process_details):
    name = str((process_details or {}).get("name") or "").strip().lower()
    username = str((process_details or {}).get("username") or "").strip().lower()
    cmdline = str((process_details or {}).get("cmdline") or "").strip().lower()

    if not name:
        return False
    if name in BLACKLIST:
        return True
    if name in SUSPICIOUS_PROCESS_NAMES:
        return True
    if any(token in cmdline for token in ["powershell", "wmic", "rundll32", "regsvr32", "mshta", "certutil", "psexec"]):
        return True
    if username in NOISY_SYSTEM_USERS and name not in BLACKLIST:
        return False
    return False

def sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def store_local_encrypted(record: dict):
    """Store event locally in encrypted format (or plain JSON fallback).
    
    WARNING: Automatically filters out events that would create infinite loops
    (e.g., logging about the log file itself being modified).
    """
    # Prevent logging the log files themselves - breaks the feedback loop
    if isinstance(record, dict) and record.get("event_type") == "file":
        event_path = str(record.get("path", "")).lower()
        if "secure_local_log.bin" in event_path:
            # Silently skip - this prevents infinite self-referential logging
            return
    
    try:
        if not fernet:
            # fallback to plain JSON append (less secure) if encryption not available
            with open(LOCAL_STORE + ".jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
            return
        txt = (json.dumps(record) + "\n").encode("utf-8")
        enc = fernet.encrypt(txt)
        with open(LOCAL_STORE, "ab") as f:
            f.write(enc + b"\n")
    except Exception as e:
        print("Error storing local log:", e)

def send_batch(batch):
    try:
        out = []
        for item in batch:
            if isinstance(item, dict):
                enrich_event(item)
                out.append(item)
            else:
                out.append(item)
        resp = requests.post(SERVER_URL, json={"agent_id": AGENT_ID, "events": out}, timeout=6)
        return resp.status_code == 200
    except Exception:
        return False


def immediate_send_event(event):
    """Try to send a single event immediately to the server. If it fails, store locally.

    This is used for session/logon events so alerts appear quickly in the server/dashboard
    instead of waiting for the batch flush interval.
    """
    try:
        if isinstance(event, dict):
            enrich_event(event)
        ok = send_batch([event])
        if ok:
            print("📤 Event sent to server immediately (session/high-risk).")
            return True
        else:
            print("⚠️ Immediate send failed; event stored locally.")
            try:
                store_local_encrypted(event)
            except Exception:
                pass
            return False
    except Exception as e:
        print("⚠️ Immediate send error:", e)
        try:
            store_local_encrypted(event)
        except Exception:
            pass
        return False

# Batching thread
def alert_batcher():
    buffer = []
    last_flush = time.time()
    while True:
        try:
            item = ALERT_QUEUE.get(timeout=cfg["alert_flush_seconds"])
            buffer.append(item)
            if len(buffer) >= cfg["alert_batch_size"]:
                ok = send_batch(buffer)
                if ok:
                    buffer = []
                else:
                    for b in buffer:
                        store_local_encrypted(b)
                    buffer = []
            ALERT_QUEUE.task_done()
        except queue.Empty:
            if buffer:
                ok = send_batch(buffer)
                if not ok:
                    for b in buffer:
                        store_local_encrypted(b)
                buffer = []

t = threading.Thread(target=alert_batcher, daemon=True)
t.start()

# ---------------------------
# Risk Scoring
# ---------------------------
def compute_risk_score(event):
    score = 0
    evtype = event.get("event_type", "")
    action = str(event.get("action", "")).lower()
    
    # Handle logon events first - check for after-hours login
    if evtype == "logon":
        current_hour = int(event.get("hour_of_day", datetime.now().hour) or datetime.now().hour)
        if is_after_office_hours(current_hour):
            print("\n" + "!" * 80)
            print("🚨 CRITICAL SECURITY ALERT 🚨")
            print("!" * 80)
            activity = "Logoff" if "logoff" in action or "logout" in action else "Login"
            print(f"After-hours {activity} Detected at {current_hour:02d}:00")
            print(f"User: {event.get('user', 'unknown')}")
            print("Business Hours: 09:00-17:00")
            print("Risk Level: HIGH - Security Policy Violation")
            print("Required Action: Investigate unauthorized access")
            print("!" * 80 + "\n")
            score += 8  # Significantly higher risk for after-hours session activity
            event["alert"] = True
            event["alert_message"] = f"SECURITY ALERT: {activity} at {current_hour:02d}:00 - Outside business hours (09:00-17:00)"
    
    # Handle other event types
    if evtype == "usb":
        score += 3
        if action in ("large_file_transfer", "file_copied", "file_created", "file_modified"):
            try:
                threshold_bytes = float(cfg.get("max_upload_risk_size_mb", 50)) * 1024 * 1024
                file_size = float(event.get("file_size", 0) or 0)
                if file_size >= threshold_bytes:
                    score += 6
                    event["alert"] = True
                    event["alert_message"] = f"SECURITY ALERT: Large file transferred to USB ({file_size / (1024 * 1024):.1f} MB)"
            except Exception:
                pass
    if evtype == "file":
        if event.get("file_size", 0) > 100 * 1024 * 1024:
            score += 3
        if event.get("keywords_found"):
            score += 5
        if event.get("copied_to_cloud"):
            score += 4
        if event.get("is_executable"):
            score += 2
    
    return score



# ---------------------------
# Content Extraction Utilities
# ---------------------------
def extract_text_from_docx(path):
    if not docx:
        return ""
    try:
        document = docx.Document(path)
        full = []
        for para in document.paragraphs:
            full.append(para.text)
        return "\n".join(full)
    except Exception:
        return ""

def extract_text_from_pdf(path):
    if not PyPDF2:
        return ""
    try:
        text = []
        with open(path, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            for page in reader.pages:
                try:
                    text.append(page.extract_text() or "")
                except Exception:
                    continue
        return "\n".join(text)
    except Exception:
        return ""

def extract_text_from_txt(path):
    try:
        with open(path, "r", errors="ignore", encoding="utf-8") as f:
            return f.read()
    except:
        return ""

def extract_text_from_image(path):
    if not Image or not pytesseract:
        return ""
    try:
        if cfg.get("tesseract_cmd"):
            pytesseract.pytesseract.tesseract_cmd = cfg["tesseract_cmd"]
        img = Image.open(path)
        return pytesseract.image_to_string(img)
    except Exception:
        return ""

def extract_text_by_extension(path):
    p = Path(path)
    ext = p.suffix.lower()
    if ext in [".txt"]:
        return extract_text_from_txt(path)
    if ext in [".docx", ".doc"]:
        return extract_text_from_docx(path)
    if ext in [".pdf"]:
        return extract_text_from_pdf(path)
    if ext in [".png", ".jpg", ".jpeg", ".bmp", ".tiff"] and cfg.get("scan_images_with_ocr", True):
        return extract_text_from_image(path)
    return ""

# ---------------------------
# Clipboard Monitor (simple poller)
# ---------------------------
def clipboard_monitor():
    if not pyperclip:
        print("Clipboard monitor disabled (pyperclip missing).")
        return
    last = None
    while True:
        try:
            txt = pyperclip.paste()
            if txt and txt != last:
                text_lower = txt.lower()
                sensitive_found = False
                for kw in SENSITIVE_KEYWORDS:
                    if kw in text_lower:
                        sensitive_found = True
                        break

                if sensitive_found:
                    event = {
                        "event_type": "clipboard",
                        "action": "sensitive_clipboard_copy",
                        "timestamp": now_ts(),
                        "content_snippet": txt[:200],
                        "hour_of_day": datetime.now().hour
                    }
                    enrich_event(event)
                    event["risk_score"] = compute_risk_score(event)
                    if cfg.get("take_screenshot_on_alert", True):
                        sev = "CRITICAL" if event.get("risk_score", 0) >= (RISK_THRESHOLD + 2) else "HIGH"
                        _attach_screenshot_b64(event, severity=sev)
                    ALERT_QUEUE.put(event)
                    print("⚠️ Sensitive clipboard content detected")

                    break
                last = txt
        except Exception:
            pass
        time.sleep(1.5)

# Single clipboard path: enhanced_clipboard_monitor (below) handles sensitive security events.
# The legacy clipboard_monitor is not started to avoid duplicate paste handling.

# ---------------------------
# Screenshot helper
# ---------------------------
SCREENSHOT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'screenshots')
os.makedirs(SCREENSHOT_DIR, exist_ok=True)


def take_screenshot(save_to=None):
    """Take a screenshot and save it under the project's data/screenshots folder by default."""
    if not mss:
        return None
    try:
        # mss.tools isn't always imported automatically
        try:
            import mss.tools  # type: ignore
        except Exception:
            return None
        with mss.mss() as sct:
            monitor = sct.monitors[1]
            img = sct.grab(monitor)
            filename = save_to or f"screenshot_{int(time.time())}.png"
            # If given a bare filename, write into SCREENSHOT_DIR
            if not os.path.isabs(filename):
                filename = os.path.join(SCREENSHOT_DIR, filename)
            # ensure parent exists
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            mss.tools.to_png(img.rgb, img.size, output=filename)
            return filename
    except Exception:
        return None


def _attach_screenshot_b64(event: dict, severity: str = "HIGH"):
    """Attach a screenshot taken on the AGENT machine (for the server dashboard)."""
    try:
        path = take_screenshot()
        if not path or not os.path.exists(path):
            return
        with open(path, "rb") as f:
            raw = f.read()
        event["has_screenshot"] = True
        event["screenshot_b64"] = base64.b64encode(raw).decode("ascii")
        event["screenshot_severity"] = severity
        try:
            os.remove(path)
        except Exception:
            pass
    except Exception:
        return

# ---------------------------
# File System Handler
# ---------------------------
class AdvancedHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.hash_registry = {}
        self.move_temp = {}
        self.recent_events = defaultdict(float)
        # Exclude agent's own directory from monitoring
        self.agent_dir = os.path.dirname(os.path.abspath(__file__))

    def is_user_path(self, path):
        p = str(path).lower()
        if any(x.lower() in p for x in ["\\windows\\", "\\program files\\", "\\appdata\\local\\temp\\"]):
            return False
        # Exclude agent's own files and directories
        if p.startswith(self.agent_dir.lower()):
            return False
        # Exclude project data directory (avoid noisy self-monitoring)
        data_dir = os.path.join(self.agent_dir, 'data').lower()
        if data_dir in p:
            return False
        # CRITICAL: Exclude log files to prevent infinite self-referential logging loops
        # The agent writes to these files, which triggers file modification events,
        # which would then be logged, causing the file to be written to again (infinite loop)
        log_file_names = {'secure_local_log.bin', 'secure_local_log.bin.jsonl'}
        if any(log_name in p for log_name in log_file_names):
            return False
        return True

    def on_created(self, event):
        if getattr(event, "is_directory", False):
            return
        path = event.src_path
        if not self.is_user_path(path):
            return
        key = f"created:{path}"
        if time.time() - self.recent_events.get(key, 0) < 1.5:
            return
        self.recent_events[key] = time.time()
        self.handle_event("created", path)

    def on_deleted(self, event):
        if getattr(event, "is_directory", False):
            return
        path = event.src_path
        if not self.is_user_path(path):
            return
        key = f"deleted:{path}"
        if time.time() - self.recent_events.get(key, 0) < 1.5:
            return
        self.recent_events[key] = time.time()
        self.handle_event("deleted", path)

    def on_modified(self, event):
        if getattr(event, "is_directory", False):
            return
        path = event.src_path
        if not self.is_user_path(path):
            return
        key = f"modified:{path}"
        if time.time() - self.recent_events.get(key, 0) < 0.8:
            return
        self.recent_events[key] = time.time()
        self.handle_event("modified", path)

    def on_moved(self, event):
        src = event.src_path
        dest = event.dest_path
        if not self.is_user_path(src) and not self.is_user_path(dest):
            return
        key = f"moved:{src}:{dest}"
        if time.time() - self.recent_events.get(key, 0) < 1.5:
            return
        self.recent_events[key] = time.time()
        self.handle_move(src, dest)

    def handle_move(self, src, dest):
        try:
            if not self.is_user_path(dest):
                return
            dest_low = dest.lower()
            copied_to_cloud = any(cf.lower() in dest_low for cf in CLOUD_FOLDERS)
            p = Path(dest)
            file_ext = p.suffix.lower()

            # Check if this is actually a file creation (moved from temp or source doesn't exist)
            is_temp_move = ('\\temp\\' in src.lower() or '\\tmp\\' in src.lower() or
                           src.lower().startswith('~') or 'temporary' in src.lower())
            src_exists = os.path.exists(src)

            # Also treat as creation if source is not in watched paths (likely external copy/move)
            # Exclude request directory from src watch paths to treat moves from there as creations
            watch_paths_for_src = [wp.lower() for wp in cfg["watch_paths"] if 'request_' not in wp]
            src_in_watch = any(wp in src.lower() for wp in watch_paths_for_src)

            # If source doesn't exist, it's a temp move, or source not in watch paths, treat as file creation
            is_creation = not src_exists or is_temp_move or not src_in_watch

            action = "file_created" if is_creation else "file_moved"

            ev = {
                "event_type": "file",
                "action": action,
                "src": src if src_exists else None,  # Only include src if it exists
                "dest": dest,
                "timestamp": now_ts(),
                "hour_of_day": datetime.now().hour,
                "file_extension": file_ext
            }
            enrich_event(ev)
            if copied_to_cloud:
                ev["copied_to_cloud"] = True
            ev["risk_score"] = compute_risk_score(ev)
            immediate_send_event(ev)
            print(f"{'➕' if is_creation else '↪️'} File {'created' if is_creation else 'moved'}: {Path(dest).name} (to {dest})")
        except Exception:
            pass

    def handle_event(self, action, path):
        p = Path(path)
        ext = p.suffix.lower()
        size = 0
        try:
            if p.exists():
                size = p.stat().st_size
        except Exception:
            size = 0

        path_low = str(path).lower()
        copied_to_cloud = any(cloud in path_low for cloud in CLOUD_FOLDERS)
        file_hash = None
        if cfg.get("min_scan_file_size", 1) <= size and p.exists():
            file_hash = sha256(path)

        content_snippet = ""
        keywords_found = []
        if ext in DATA_EXTENSIONS or ext in DATA_EXTENSIONS.union({".png", ".jpg", ".jpeg"}):
            try:
                content = extract_text_by_extension(path)
                if content:
                    content_lower = content.lower()
                    for kw in SENSITIVE_KEYWORDS:
                        if kw in content_lower:
                            keywords_found.append(kw)
                    content_snippet = content[:1000]
            except Exception:
                pass

        event = {
            "event_type": "file",
            # normalize to consistent action names used by server/UI
            "action": {
                'created': 'file_created',
                'modified': 'file_modified',
                'deleted': 'file_deleted',
                'moved': 'file_moved'
            }.get(action, action),
            "path": path,
            "file_extension": ext,
            "file_size": size,
            "sha256": file_hash,
            "timestamp": now_ts(),
            "hour_of_day": datetime.now().hour,
            "copied_to_cloud": copied_to_cloud,
            "keywords_found": keywords_found,
            "content_snippet": content_snippet
        }
        enrich_event(event)

        if action == "created":
            print(f"➕ File created: {p.name} (at {path})")
            if copied_to_cloud and ext in DATA_EXTENSIONS:
                print("⚠️ Possible sensitive file placed in cloud folder")
        elif action == "modified":
            print(f"✏️ File modified: {p.name} (at {path})")
        elif action == "deleted":
            print(f"🗑️ File deleted: {p.name} (at {path})")
        if action in ("created", "modified") and keywords_found:
            print(f"⚠️ Sensitive keywords found in file: {p.name} -> {keywords_found}")

        if ext in [".zip", ".rar"]:
            event["compressed_archive"] = True

        event["risk_score"] = compute_risk_score(event)

        # Attach screenshot only for suspicious file activity (keywords or high risk),
        # not for normal file modifications.
        if (keywords_found or event.get("risk_score", 0) >= RISK_THRESHOLD) and cfg.get("take_screenshot_on_alert", True):
            sev = "CRITICAL" if event.get("risk_score", 0) >= (RISK_THRESHOLD + 2) else "HIGH"
            _attach_screenshot_b64(event, severity=sev)
        immediate_send_event(event)

# ---------------------------
# File watcher starter
# ---------------------------
def start_watchers():
    if not Observer:
        print("File system watchers disabled (watchdog not installed).")
        # keep main thread alive if other monitors run
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        return

    observer = Observer()
    handler = AdvancedHandler()
    for p in cfg["watch_paths"]:
        try:
            if os.path.exists(p):
                observer.schedule(handler, p, recursive=True)
                print(f"Monitoring: {p}")
            else:
                # path may not exist on this machine; that's OK
                print(f"Path not found (skipping): {p}")
        except Exception as e:
            print("Could not monitor path:", p, e)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# ---------------------------
# USB Monitor (periodic)
# ---------------------------
def usb_monitor():
    if not psutil:
        print("USB monitor disabled (psutil missing).")
        return
    prev = set()
    while True:
        try:
            cur = set()
            for part in psutil.disk_partitions(all=False):
                opts = (part.opts or "").lower()
                device = part.device
                if ('removable' in opts) or device.startswith(("D:", "E:", "F:")):
                    cur.add(device)
            added = cur - prev
            removed = prev - cur
            for d in added:
                ev = {
                    "event_type": "usb",
                    "action": "plugged",
                    "drive": d,
                    "timestamp": now_ts(),
                    "hour_of_day": datetime.now().hour
                }
                enrich_event(ev)
                ev["risk_score"] = compute_risk_score(ev)
                print(f"🔌 USB plugged: {d}")
                ALERT_QUEUE.put(ev)
                store_local_encrypted(ev)
            for d in removed:
                ev = {
                    "event_type": "usb",
                    "action": "unplugged",
                    "drive": d,
                    "timestamp": now_ts(),
                    "hour_of_day": datetime.now().hour
                }
                enrich_event(ev)
                ev["risk_score"] = compute_risk_score(ev)
                print(f"🔌 USB unplugged: {d}")
                ALERT_QUEUE.put(ev)
                store_local_encrypted(ev)
            prev = cur
        except Exception:
            pass
        time.sleep(3)

if psutil:
    threading.Thread(target=usb_monitor, daemon=True).start()

# ---------------------------
# Outlook & IMAP Sent Monitoring
# ---------------------------
def parse_mail_message(msg):
    text_parts = []
    attachments = []
    try:
        if hasattr(msg, "is_multipart") and msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = part.get_content_disposition()
                if disp == "attachment":
                    fname = part.get_filename()
                    attachments.append(fname)
                elif ctype == "text/plain":
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            text_parts.append(payload.decode(errors="ignore"))
                    except:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    text_parts.append(payload.decode(errors="ignore"))
            except:
                pass
    except Exception:
        pass
    return "\n".join(text_parts), attachments

def monitor_outlook_sent():
    if not OUTLOOK_AVAILABLE:
        print("Outlook monitoring not available on this machine.")
        return
    try:
        # Initialize COM for this thread
        if pythoncom:
            pythoncom.CoInitialize()
        outlook = win32com.client.Dispatch("Outlook.Application")
        # Check if Outlook is properly connected
        try:
            namespace = outlook.GetNamespace("MAPI")
            sent = namespace.GetDefaultFolder(5)  # 5 == olFolderSentMail
            # Test access to sent items
            list(sent.Items)[:1]  # Try to access first item to verify connection
        except Exception as conn_error:
            print("Outlook connection failed:", conn_error)
            print("Outlook monitoring disabled - Outlook may not be running or configured.")
            return
        print("Outlook Sent Items monitoring enabled")
        seen = set()
        while True:
            try:
                for item in list(sent.Items):
                    try:
                        entry_id = getattr(item, "EntryID", None)
                        if not entry_id or entry_id in seen:
                            continue
                        seen.add(entry_id)
                        subject = getattr(item, "Subject", "") or ""
                        body = getattr(item, "Body", "") or ""
                        recipients = []
                        try:
                            for r in item.Recipients:
                                recipients.append(getattr(r, "Address", ""))
                        except Exception:
                            pass
                        attachments = []
                        try:
                            for a in item.Attachments:
                                attachments.append(getattr(a, "FileName", ""))
                        except:
                            pass
                        found = []
                        for kw in SENSITIVE_KEYWORDS:
                            if kw in (subject + " " + body).lower():
                                found.append(kw)
                        ev = {
                            "event_type": "outlook",
                            "action": "outlook_sent",
                            "subject": subject,
                            "recipients": recipients,
                            "attachments_count": len(attachments),
                            "keywords_found": found,
                            "timestamp": now_ts(),
                            "hour_of_day": datetime.now().hour
                        }
                        enrich_event(ev)
                        ev["risk_score"] = compute_risk_score(ev)
                        ALERT_QUEUE.put(ev)
                        store_local_encrypted(ev)
                        # Screenshot alerts DISABLED
                        # if ev["risk_score"] >= RISK_THRESHOLD and cfg.get("take_screenshot_on_alert", True):
                        #     ss = take_screenshot()
                        #     if ss:
                        #         ev["screenshot"] = ss
                    except Exception:
                        continue
            except Exception:
                pass
            time.sleep(4)
    except Exception as e:
        print("Outlook monitor error:", e)

def monitor_imap_sent():
    if not imapclient:
        print("IMAP monitor disabled (imapclient missing).")
        return
    im = None
    try:
        host = cfg["imap"]["host"]
        port = cfg["imap"].get("port", 993)
        ssl = cfg["imap"].get("use_ssl", True)
        user = cfg["imap"]["user"]
        password = cfg["imap"]["password"]
        if not host or not user:
            print("IMAP not configured.")
            return
        im = imapclient.IMAPClient(host, port=port, use_uid=True, ssl=ssl)
        im.login(user, password)
        folders = im.list_folders()
        sent_folder = None
        for f in folders:
            if "sent" in f[2].lower():
                sent_folder = f[2]
                break
        if not sent_folder:
            sent_folder = folders[0][2]
        im.select_folder(sent_folder)
        print("IMAP Sent monitoring enabled on", sent_folder)
        seen = set()
        while True:
            try:
                uids = im.search(['SINCE', (datetime.now() - timedelta(days=1)).strftime("%d-%b-%Y")])
                for uid in uids:
                    if uid in seen:
                        continue
                    msg_data = im.fetch(uid, ['RFC822'])[uid][b'RFC822']
                    msg = email.message_from_bytes(msg_data)
                    body, attachments = parse_mail_message(msg)
                    found = [kw for kw in SENSITIVE_KEYWORDS if kw in body.lower()]
                    ev = {
                        "event_type": "imap",
                        "action": "imap_sent",
                        "subject": msg.get('Subject'),
                        "attachments_count": len(attachments),
                        "keywords_found": found,
                        "timestamp": now_ts(),
                        "hour_of_day": datetime.now().hour
                    }
                    enrich_event(ev)
                    ev["risk_score"] = compute_risk_score(ev)
                    ALERT_QUEUE.put(ev)
                    store_local_encrypted(ev)
                    seen.add(uid)
            except Exception:
                pass
            time.sleep(8)
    except Exception as e:
        print("IMAP monitor error:", e)
    finally:
        try:
            if im:
                im.logout()
        except:
            pass

if cfg.get("enable_outlook_monitor", True) and OUTLOOK_AVAILABLE:
    threading.Thread(target=monitor_outlook_sent, daemon=True).start()
elif cfg.get("enable_outlook_monitor", True):
    print("Outlook monitoring requested but unavailable.")

if cfg.get("enable_imap_monitor", False):
    threading.Thread(target=monitor_imap_sent, daemon=True).start()

# ---------------------------
# Session logon/logoff (Windows)
# ---------------------------
def is_windows():
    return os.name == "nt"

def is_admin():
    # portable admin check on Windows; returns False on non-Windows
    try:
        if not is_windows():
            return False
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def monitor_windows_logon():
    # Only run on Windows and only if pywin32 is available and user is admin
    if not is_windows():
        print("Logon monitor skipped: not running on Windows.")
        return
    if not win32evtlog:
        print("Win32 event log not available; skipping logon monitoring.")
        return
    if not is_admin():
        print("Logon monitor needs admin privileges; current process is not elevated.")
        print("→ To enable logon monitoring, run this script as Administrator.")
        return

    server = 'localhost'
    logtype = 'Security'
    try:
        try:
            hand = win32evtlog.OpenEventLog(server, logtype)
        except Exception as e:
            # common privilege / access error: don't crash, just inform and stop
            print(f"Logon monitor error opening {logtype} event log: {e}")
            print("Ensure the script is running with administrative privileges.")
            return

        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        seen = set()
        while True:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if events:
                for ev in events:
                    try:
                        eid = getattr(ev, "EventID", None) or getattr(ev, "EventIdentifier", None)
                        # on some pywin32 versions EventID is a tuple or has server-specific bits; normalize:
                        try:
                            eid = int(eid & 0xFFFF) if isinstance(eid, int) else int(eid)
                        except Exception:
                            pass
                        if eid in (4624, 4634):
                            inserts = getattr(ev, "StringInserts", None) or []
                            user = inserts[5] if len(inserts) > 5 else "Unknown"
                            logon_type = inserts[8] if len(inserts) > 8 else ""
                            if should_ignore_logon_event(user, logon_type):
                                continue
                            action = "user_logon" if eid == 4624 else "user_logoff"
                            key = f"{eid}:{getattr(ev, 'TimeGenerated', '')}:{user}"
                            if key in seen:
                                continue
                            seen.add(key)
                            # Get the hour from the event time, not current time
                            time_generated = getattr(ev, 'TimeGenerated', None)
                            if time_generated:
                                try:
                                    hour_of_day = time_generated.hour
                                except:
                                    hour_of_day = datetime.now().hour
                            else:
                                hour_of_day = datetime.now().hour
                            evd = {
                                "event_type": "logon",
                                "action": action,
                                "user": user,  # Use the user from the event log, not current user
                                "logon_type": logon_type,
                                "logon_type_name": logon_type,  # Add for server compatibility
                                "timestamp": now_ts(),
                                "hour_of_day": hour_of_day
                            }
                            enrich_event(evd)
                            evd["risk_score"] = compute_risk_score(evd)
                            immediate_send_event(evd)
                    except Exception:
                        continue
            time.sleep(3)
    except Exception as e:
        print("Logon monitor error (read loop):", e)

# Start logon monitor if appropriate
threading.Thread(target=monitor_windows_logon, daemon=True).start()



# ---------------------------
# Simple daily/weekly summary generator
# ---------------------------
SUMMARY = defaultdict(lambda: {"files_created": 0, "usb_plugs": 0, "risk_sum": 0, "events": 0})

def summary_aggregator():
    while True:
        time.sleep(24*3600)
        try:
            if not os.path.exists(LOCAL_STORE):
                continue
            if fernet:
                with open(LOCAL_STORE, "rb") as f:
                    for line in f:
                        try:
                            line = line.strip()
                            if not line:
                                continue
                            dec = fernet.decrypt(line)
                            rec = json.loads(dec.decode("utf-8"))
                            aid = rec.get("agent_id", AGENT_ID)
                            SUMMARY[aid]["events"] += 1
                            if rec.get("event_type") == "file" and rec.get("action") == "created":
                                SUMMARY[aid]["files_created"] += 1
                            if rec.get("event_type") == "usb" and rec.get("action") == "plugged":
                                SUMMARY[aid]["usb_plugs"] += 1
                            SUMMARY[aid]["risk_sum"] += rec.get("risk_score", 0)
                        except Exception:
                            continue
            else:
                # fallback JSONL file
                if os.path.exists(LOCAL_STORE + ".jsonl"):
                    with open(LOCAL_STORE + ".jsonl", "r", encoding="utf-8") as f:
                        for line in f:
                            try:
                                rec = json.loads(line)
                                aid = rec.get("agent_id", AGENT_ID)
                                SUMMARY[aid]["events"] += 1
                                if rec.get("event_type") == "file" and rec.get("action") == "created":
                                    SUMMARY[aid]["files_created"] += 1
                                if rec.get("event_type") == "usb" and rec.get("action") == "plugged":
                                    SUMMARY[aid]["usb_plugs"] += 1
                                SUMMARY[aid]["risk_sum"] += rec.get("risk_score", 0)
                            except Exception:
                                continue
            SUMMARY.clear()
        except Exception:
            pass

threading.Thread(target=summary_aggregator, daemon=True).start()

# ---------------------------
# Activity Logger
# ---------------------------
def log_activity(event_type, details):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    normalized_type = str(event_type or "unknown").lower()
    
    # Create event object
    event = {
        "timestamp": timestamp,
        "event_type": normalized_type,
        "details": details,
        "user": safe_get_username(),
        "agent_id": AGENT_ID
    }
    enrich_event(event)
    
    # Send to server
    try:
        requests.post(SERVER_URL, 
                     json={"agent_id": AGENT_ID, "events": [event]},
                     timeout=2)
    except Exception as e:
        # If server is unavailable, store locally
        try:
            store_local_encrypted(event)
        except Exception:
            pass

def update_process_monitor():
    if not psutil:
        return
    old_procs = {}
    while True:
        try:
            current_procs = {}
            for proc in psutil.process_iter(["pid", "name", "username", "create_time", "exe", "cmdline"]):
                try:
                    proc_info = proc.info
                    pid = proc_info['pid']
                    name = proc_info['name']
                    
                    # Get detailed process info
                    process_details = {
                        'name': name,
                        'pid': pid,
                        'username': proc_info.get('username', 'unknown'),
                        'exe_path': proc_info.get('exe', ''),
                        'cmdline': ' '.join(proc_info.get('cmdline', [])),
                        'create_time': proc_info.get('create_time', 0)
                    }
                    
                    process_details["interesting"] = is_interesting_process(process_details)
                    current_procs[pid] = process_details
                    
                    # New process detected
                    if pid not in old_procs and process_details["interesting"]:
                        event = {
                            "event_type": "process",
                            "action": "process_started",
                            "process_info": process_details,
                            "timestamp": now_ts(),
                            "hour_of_day": datetime.now().hour
                        }
                        # Add risk scoring
                        if name.lower() in BLACKLIST:
                            event["risk_score"] = 0.8
                            print(f"⚠️ Blacklisted process detected: {name}")
                        else:
                            event["risk_score"] = 0.2
                        
                        enrich_event(event)
                        immediate_send_event(event)
                except:
                    continue
            
            # Detect closed processes
            for old_pid, old_info in old_procs.items():
                if old_pid not in current_procs and old_info.get("interesting"):
                    event = {
                        "event_type": "process",
                        "action": "process_ended",
                        "process_info": old_info,
                        "timestamp": now_ts(),
                        "hour_of_day": datetime.now().hour,
                        "risk_score": 0.1
                    }
                    enrich_event(event)
                    immediate_send_event(event)
            
            old_procs = current_procs
        except Exception as e:
            print(f"Process monitor error: {e}")
            pass
        time.sleep(2)

# Enhance USB monitoring
def scan_usb_files(mountpoint, max_files=5000):
    snapshot = {}
    files_info = []
    if not os.path.exists(mountpoint):
        return snapshot, files_info
    scanned = 0
    try:
        for root, dirs, files in os.walk(mountpoint):
            for file in files:
                if scanned >= max_files:
                    return snapshot, files_info
                file_path = os.path.join(root, file)
                try:
                    stats = os.stat(file_path)
                    rel_path = os.path.relpath(file_path, mountpoint)
                    meta = {
                        "name": file,
                        "size": stats.st_size,
                        "mtime": stats.st_mtime,
                        "modified": datetime.fromtimestamp(stats.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                        "path": rel_path,
                        "full_path": file_path,
                    }
                    snapshot[rel_path] = meta
                    files_info.append({
                        "name": meta["name"],
                        "size": meta["size"],
                        "modified": meta["modified"],
                        "path": meta["path"],
                    })
                    scanned += 1
                except Exception:
                    continue
    except Exception:
        pass
    return snapshot, files_info


def enhanced_usb_monitor():
    if not psutil:
        return
    prev_devices = set()
    prev_file_snapshots = {}
    large_file_threshold = float(cfg.get("max_upload_risk_size_mb", 50)) * 1024 * 1024
    while True:
        try:
            current_devices = set()
            for part in psutil.disk_partitions(all=False):
                try:
                    if 'removable' in (part.opts or '').lower() or part.device.startswith(("D:", "E:", "F:")):
                        # Get detailed device info
                        usage = psutil.disk_usage(part.mountpoint)
                        device_info = {
                            'device': part.device,
                            'mountpoint': part.mountpoint,
                            'fstype': part.fstype,
                            'total_size': usage.total,
                            'used_size': usage.used,
                            'free_size': usage.free
                        }
                        
                        device_key = f"{part.device}:{part.mountpoint}"
                        current_devices.add(device_key)
                        current_snapshot, files_info = scan_usb_files(part.mountpoint)
                        
                        # New device detected
                        if device_key not in prev_devices:
                            log_activity("usb", {
                                "action": "device_connected",
                                "device_info": device_info,
                                "files": files_info[:100]  # Limit to first 100 files
                            })
                        else:
                            previous_snapshot = prev_file_snapshots.get(device_key, {})
                            for rel_path, meta in current_snapshot.items():
                                old = previous_snapshot.get(rel_path)
                                if old and old.get("size") == meta.get("size") and old.get("mtime") == meta.get("mtime"):
                                    continue
                                if float(meta.get("size", 0) or 0) < large_file_threshold:
                                    continue
                                event = {
                                    "event_type": "usb",
                                    "action": "large_file_transfer",
                                    "drive": part.device,
                                    "mountpoint": part.mountpoint,
                                    "path": meta.get("full_path"),
                                    "file_name": meta.get("name"),
                                    "relative_path": rel_path,
                                    "file_size": meta.get("size", 0),
                                    "file_size_mb": round(float(meta.get("size", 0) or 0) / (1024 * 1024), 2),
                                    "timestamp": now_ts(),
                                    "hour_of_day": datetime.now().hour,
                                    "details": f"Large file transferred to USB: {rel_path}",
                                }
                                enrich_event(event)
                                event["risk_score"] = compute_risk_score(event)
                                immediate_send_event(event)
                                store_local_encrypted(event)
                                print(f"Large USB transfer detected: {rel_path} ({event['file_size_mb']} MB)")

                        prev_file_snapshots[device_key] = current_snapshot
                except:
                    continue
            
            # Check for removed devices
            for device in prev_devices:
                if device not in current_devices:
                    dev, mnt = device.split(":", 1)
                    log_activity("usb", {
                        "action": "device_removed",
                        "device_info": {
                            "device": dev,
                            "mountpoint": mnt
                        }
                    })
                    prev_file_snapshots.pop(device, None)
            
            prev_devices = current_devices
        except:
            pass
        time.sleep(3)

# Enhance clipboard monitoring
def enhanced_clipboard_monitor():
    if not pyperclip:
        return
    last_content = None
    while True:
        try:
            current_content = pyperclip.paste()
            if current_content and current_content != last_content:
                # Prepare clipboard event data
                clipboard_data = {
                    "action": "content_copied",
                    "content_length": len(current_content),
                    "content_preview": current_content[:100] + "..." if len(current_content) > 100 else current_content,
                    "content_type": "text",
                    "sensitive_keywords": []
                }
                
                # Check for sensitive information
                for keyword in SENSITIVE_KEYWORDS:
                    if keyword in current_content.lower():
                        clipboard_data["sensitive_keywords"].append(keyword)
                
                # Try to determine content type
                if current_content.startswith('{') and current_content.endswith('}'):
                    try:
                        json.loads(current_content)
                        clipboard_data["content_type"] = "json"
                    except:
                        pass
                elif '<html' in current_content.lower():
                    clipboard_data["content_type"] = "html"
                elif current_content.startswith('http://') or current_content.startswith('https://'):
                    clipboard_data["content_type"] = "url"
                
                # Log the clipboard event (activity stream)
                log_activity("CLIPBOARD", clipboard_data)
                
                # Sensitive copy: same path as legacy clipboard_monitor — alert + optional screenshot
                if clipboard_data["sensitive_keywords"]:
                    sec_ev = {
                        "event_type": "clipboard",
                        "action": "sensitive_clipboard_copy",
                        "timestamp": now_ts(),
                        "content_snippet": current_content[:200],
                        "hour_of_day": datetime.now().hour,
                        "keywords_found": clipboard_data["sensitive_keywords"],
                        "content_type": clipboard_data["content_type"],
                    }
                    enrich_event(sec_ev)
                    sec_ev["risk_score"] = 0.75
                    if cfg.get("take_screenshot_on_alert", True):
                        sev = "CRITICAL" if len(clipboard_data["sensitive_keywords"]) >= 3 else "HIGH"
                        _attach_screenshot_b64(sec_ev, severity=sev)
                    ALERT_QUEUE.put(sec_ev)
                    print("⚠️ Sensitive clipboard content detected (alert queued)")
                
                last_content = current_content
        except:
            pass
        time.sleep(1)

# ---------------------------
# Poll admin commands (screenshot burst / screen recording frames)
# ---------------------------
def agent_command_poller():
    base = server_base_url()
    while True:
        try:
            r = requests.get(f"{base}/get_commands/{AGENT_ID}", timeout=15)
            if r.status_code != 200:
                time.sleep(8)
                continue
            payload = r.json() or {}
            for cmd in payload.get("commands") or []:
                name = (cmd.get("command") or "").strip()
                if name == "screenshot":
                    ev = {
                        "event_type": "admin",
                        "action": "remote_screenshot",
                        "timestamp": now_ts(),
                        "hour_of_day": datetime.now().hour,
                        "admin_reason": cmd.get("reason", ""),
                    }
                    enrich_event(ev)
                    ev["risk_score"] = 0.5
                    if cfg.get("take_screenshot_on_alert", True):
                        _attach_screenshot_b64(ev, severity="HIGH")
                    immediate_send_event(ev)
                elif name == "screen_record":
                    duration = int(cmd.get("duration_sec") or 15)
                    duration = max(6, min(duration, 120))
                    # Frame every ~3s; lightweight substitute for full video until ffmpeg is wired
                    frames = max(2, min(duration // 3, 20))
                    for i in range(frames):
                        ev = {
                            "event_type": "recording",
                            "action": "screen_record_frame",
                            "timestamp": now_ts(),
                            "hour_of_day": datetime.now().hour,
                            "recording_frame": i + 1,
                            "recording_frame_total": frames,
                            "admin_reason": cmd.get("reason", ""),
                        }
                        enrich_event(ev)
                        ev["risk_score"] = 0.85
                        if cfg.get("take_screenshot_on_alert", True):
                            _attach_screenshot_b64(ev, severity="HIGH")
                        immediate_send_event(ev)
                        time.sleep(3)
        except Exception:
            pass
        time.sleep(8)


# ---------------------------
# Main
# ---------------------------
if __name__ == "__main__":
    print("="*60)
    print("🚀 Advanced Insider-Threat Agent - Starting (fixed safe mode)")
    print("="*60)
    
    log_activity("SYSTEM", "Security monitoring agent started")
    log_activity("SYSTEM", f"Monitoring user: {safe_get_username()}")
    
    threading.Thread(target=agent_command_poller, daemon=True).start()
    # Start enhanced monitoring threads
    if cfg.get("enable_process_monitor", True):
        threading.Thread(target=update_process_monitor, daemon=True).start()
    else:
        print("Process monitor disabled by config.")
    threading.Thread(target=enhanced_usb_monitor, daemon=True).start()
    threading.Thread(target=enhanced_clipboard_monitor, daemon=True).start()

    try:
        start_watchers()
    except Exception as e:
        log_activity("ERROR", f"Error starting watchers: {e}")
        print("Error starting watchers:", e)
