# =============================================================================
# DeepSentinel — honeypot.py
# Plants fake bait files on the monitored machine.
# Any access = INSTANT CRITICAL alert. Zero false positives.
#
# RUN ON OLD MACHINE:
#   python honeypot.py setup    → plants bait files
#   python honeypot.py watch    → monitors for access
#   python honeypot.py clean    → removes bait files
# =============================================================================

import sys, os, time, json, logging, requests, base64, io
from datetime import datetime
from pathlib import Path

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import config

os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [HONEYPOT] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(
            os.path.join(ROOT,"logs","honeypot.log"), encoding="utf-8"),
    ]
)
log = logging.getLogger("honeypot")

try:
    from watchdog.observers import Observer
    from watchdog.events    import FileSystemEventHandler
    WATCHDOG_OK = True
except ImportError:
    WATCHDOG_OK = False
    print("❌ pip install watchdog")
    sys.exit(1)

try:
    import pyautogui
    from PIL import Image
    SCREENSHOT_OK = True
except ImportError:
    SCREENSHOT_OK = False

# =============================================================================
# BAIT FILES — realistic names that no legitimate user should open
# =============================================================================

BAIT_FILES = [
    {
        "filename": "salary_master_2026.xlsx",
        "content":  "DEEPSENTINEL_HONEYPOT - DO NOT DISTRIBUTE\nEmployee Salary Data\nThis file is monitored.",
        "folder":   "Documents",
        "reason":   "Employee salary database accessed",
    },
    {
        "filename": "client_passwords_backup.txt",
        "content":  "DEEPSENTINEL_HONEYPOT\nClient Portal Credentials\nAccess to this file triggers security alert.",
        "folder":   "Documents",
        "reason":   "Client password file accessed",
    },
    {
        "filename": "acquisition_plan_confidential.pdf",
        "content":  "DEEPSENTINEL_HONEYPOT\nM&A Strategy Document\nClassified — Security monitored.",
        "folder":   "Desktop",
        "reason":   "Confidential acquisition plan accessed",
    },
    {
        "filename": "employee_ssn_records.csv",
        "content":  "DEEPSENTINEL_HONEYPOT\nEmployee ID,Name,SSN\n001,Test User,MONITORED",
        "folder":   "Documents",
        "reason":   "Employee PII database accessed",
    },
    {
        "filename": "admin_credentials_backup.txt",
        "content":  "DEEPSENTINEL_HONEYPOT\nSystem Administrator Credentials\nThis access has been logged and reported.",
        "folder":   "Desktop",
        "reason":   "Admin credentials file accessed",
    },
]


def get_bait_path(bait):
    """Get full path for a bait file."""
    folder = bait["folder"]
    if folder == "Documents":
        base = os.path.join(os.path.expanduser("~"), "Documents")
    elif folder == "Desktop":
        base = os.path.join(os.path.expanduser("~"), "Desktop")
    else:
        base = os.path.expanduser("~")
    return os.path.join(base, bait["filename"])


# =============================================================================
# SETUP — plant bait files
# =============================================================================

def setup():
    print("🪤  Planting honeypot files...")
    planted = []
    for bait in BAIT_FILES:
        path = get_bait_path(bait)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(bait["content"])
            print(f"  ✅ {bait['folder']}/{bait['filename']}")
            planted.append(path)
        except Exception as e:
            print(f"  ❌ {bait['filename']}: {e}")

    # Save list of planted files
    with open(os.path.join(ROOT,"logs","honeypot_files.json"),"w") as f:
        json.dump(planted, f, indent=2)

    print(f"\n  {len(planted)} bait files planted.")
    print("  Run: python honeypot.py watch")
    return planted


# =============================================================================
# CLEAN — remove bait files
# =============================================================================

def clean():
    print("🧹  Removing honeypot files...")
    for bait in BAIT_FILES:
        path = get_bait_path(bait)
        try:
            if os.path.exists(path):
                os.remove(path)
                print(f"  ✅ Removed: {bait['filename']}")
        except Exception as e:
            print(f"  ❌ {bait['filename']}: {e}")
    print("  Done.")


# =============================================================================
# SCREENSHOT
# =============================================================================

def _screenshot_b64():
    if not SCREENSHOT_OK: return None
    try:
        img = pyautogui.screenshot()
        buf = io.BytesIO()
        img.save(buf, format="PNG", optimize=True)
        return base64.b64encode(buf.getvalue()).decode()
    except Exception as e:
        log.error(f"Screenshot: {e}")
        return None


# =============================================================================
# ALERT — fires when bait file is accessed
# =============================================================================

def fire_alert(bait_file, event_type, path):
    """
    INSTANT CRITICAL alert when any bait file is accessed.
    Zero false positives — nobody should ever touch these files.
    """
    reason  = bait_file["reason"]
    fname   = bait_file["filename"]
    uid     = getattr(config, 'AGENT_ID', 'DESKTOP-OUTLOOK-01')
    score   = 1.0    # ALWAYS maximum score — honeypot = 100% confidence
    ts      = datetime.now().strftime("%H:%M:%S")

    print(f"\n{'='*60}")
    print(f"  💀 HONEYPOT TRIGGERED  [{ts}]")
    print(f"  File    : {fname}")
    print(f"  Action  : {event_type.upper()}")
    print(f"  Reason  : {reason}")
    print(f"  Score   : 1.000 (CRITICAL — 100% confidence)")
    print(f"{'='*60}\n")

    log.critical(f"🪤 HONEYPOT: {event_type} | {fname} | {reason}")

    # Screenshot immediately
    shot = _screenshot_b64()
    if shot:
        log.info("📸 Screenshot captured")

    # Notify server
    try:
        evt = {
            "agent_id":          uid,
            "event_type":        "honeypot",
            "action":            f"honeypot_{event_type}",
            "user":              uid,
            "timestamp":         datetime.now().isoformat(),
            "hour_of_day":       datetime.now().hour,
            "risk_score":        1.0,
            "details":           f"HONEYPOT: {reason}",
            "honeypot_file":     fname,
            "honeypot_reason":   reason,
            "file_path":         path,
            "event_type_detail": event_type,
            "screenshot_severity": "CRITICAL",
            "has_screenshot":    shot is not None,
            "screenshot_b64":    shot,
            "source":            "honeypot_monitor",
            # ML features
            "num_file":          1,
            "in_sensitive_path": True,
            "is_document":       True,
        }
        r = requests.post(
            config.SERVER_URL,
            json={"agent_id": uid, "events": [evt]},
            timeout=5,
        )
        if r.status_code == 200:
            log.info("📤 Server alerted")
    except Exception as e:
        log.error(f"Server notify failed: {e}")

    # Save local record
    record = {
        "timestamp":   datetime.now().isoformat(),
        "file":        fname,
        "path":        path,
        "event_type":  event_type,
        "reason":      reason,
        "score":       1.0,
        "severity":    "CRITICAL",
    }
    with open(os.path.join(ROOT,"logs","honeypot_triggers.jsonl"),
              "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


# =============================================================================
# WATCHER
# =============================================================================

# Build lookup map: filepath → bait info
_BAIT_MAP = {}

class HoneypotHandler(FileSystemEventHandler):

    def _check(self, event_type, src_path):
        norm = os.path.normpath(src_path).lower()
        for path_key, bait in _BAIT_MAP.items():
            if norm == path_key:
                fire_alert(bait, event_type, src_path)
                return

    def on_opened(self, event):
        if not event.is_directory:
            self._check("opened", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._check("modified", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._check("moved", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._check("deleted", event.src_path)


def watch():
    global _BAIT_MAP

    # Build bait map
    _BAIT_MAP = {}
    for bait in BAIT_FILES:
        path = get_bait_path(bait)
        _BAIT_MAP[os.path.normpath(path).lower()] = bait

    # Get unique folders to watch
    watch_folders = set()
    for bait in BAIT_FILES:
        path = get_bait_path(bait)
        watch_folders.add(os.path.dirname(path))

    print("🪤  Honeypot Monitor Active")
    print(f"   Monitoring {len(_BAIT_MAP)} bait files")
    print()
    for bait in BAIT_FILES:
        path = get_bait_path(bait)
        exists = "✅" if os.path.exists(path) else "⚠️  NOT PLANTED"
        print(f"   {exists}  {bait['folder']}/{bait['filename']}")
    print()
    print("   Any access = INSTANT CRITICAL alert")
    print("   Press Ctrl+C to stop\n")

    observer = Observer()
    handler  = HoneypotHandler()

    for folder in watch_folders:
        if os.path.exists(folder):
            observer.schedule(handler, folder, recursive=False)
            log.info(f"Watching: {folder}")

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n\n  Honeypot monitor stopped.")
    observer.join()


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"

    if cmd == "setup":
        setup()
    elif cmd == "watch":
        watch()
    elif cmd == "both":
        setup()
        print()
        watch()
    elif cmd == "clean":
        clean()
    else:
        print("DeepSentinel Honeypot")
        print()
        print("  python honeypot.py setup   → plant bait files")
        print("  python honeypot.py watch   → monitor for access")
        print("  python honeypot.py both    → setup + watch together")
        print("  python honeypot.py clean   → remove bait files")
