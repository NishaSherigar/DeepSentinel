# =============================================================================
# DeepSentinel — run_agent.py
# Run on the OLD MACHINE (Outlook 2013):
#   python run_agent.py
# Make sure Outlook 2013 is OPEN before running.
# =============================================================================

import sys, os, json, time, hashlib, logging, requests, random, uuid, base64, io, tempfile
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import config

os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [AGENT] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(ROOT, "logs", "agent.log"), encoding="utf-8"),
    ]
)
log = logging.getLogger("agent")

# Payload limits for body + attachment content extraction.
MAX_EMAIL_BODY_CHARS = int(getattr(config, "MAX_EMAIL_BODY_CHARS", 4000))
MAX_ATTACHMENT_SIZE_MB_FOR_TEXT = float(
    getattr(config, "MAX_ATTACHMENT_SIZE_MB_FOR_TEXT", 2.0)
)
MAX_ATTACHMENT_TEXT_BYTES = int(getattr(config, "MAX_ATTACHMENT_TEXT_BYTES", 8192))
MAX_ATTACHMENT_TEXT_CHARS = int(getattr(config, "MAX_ATTACHMENT_TEXT_CHARS", 2000))
TEXT_PREVIEW_EXTENSIONS = {
    ".txt", ".csv", ".log", ".json", ".xml", ".md", ".ini", ".cfg", ".sql"
}
DOC_PREVIEW_EXTENSIONS = {".docx"}
PDF_PREVIEW_EXTENSIONS = {".pdf"}

try:
    import docx
    DOCX_OK = True
except ImportError:
    DOCX_OK = False

try:
    import PyPDF2
    PDF_OK = True
except ImportError:
    PDF_OK = False

try:
    import win32com.client
    import pythoncom
    MAPI_OK = True
except ImportError:
    MAPI_OK = False

# ── Screenshot (runs on THIS machine — the agent/old machine) ─────────────────
try:
    import pyautogui
    from PIL import Image
    SCREENSHOT_OK = True
except ImportError:
    SCREENSHOT_OK = False
    log.warning("pip install pyautogui pillow  — screenshots disabled")

def _take_agent_screenshot(user_id, subject, severity):
    """
    Take a screenshot on the AGENT machine (old PC).
    Returns base64-encoded PNG string, or None.
    """
    if not SCREENSHOT_OK:
        return None
    try:
        img = pyautogui.screenshot()
        buf = io.BytesIO()
        img.save(buf, format="PNG", optimize=True)
        b64 = base64.b64encode(buf.getvalue()).decode()
        ts  = __import__('datetime').datetime.now().strftime("%H:%M:%S")
        log.info(f"📸 Screenshot taken on agent [{ts}] — {severity} | {subject[:40]}")
        return b64
    except Exception as e:
        log.error(f"Agent screenshot failed: {e}")
        return None

# =============================================================================
# SIMULATION MODE
# =============================================================================
DEMO_SUBJECTS = [
    "Confidential: Q4 financial forecast", "Client database export",
    "FYI: internal salary spreadsheet",    "Project roadmap - DO NOT SHARE",
    "Please find credentials attached",    "Team lunch next Friday",
    "Re: meeting notes",                   "API keys for production",
    "Urgent: client list update",          "Vendor contract renewal",
]
DEMO_USERS = [
    "alice@demoorg.com",   "bob@demoorg.com",   "charlie@demoorg.com",
    "diana@demoorg.com",   "eve@demoorg.com",   "frank@demoorg.com",
    "grace@demoorg.com",   "henry@demoorg.com", "iris@demoorg.com",
    "jack@demoorg.com",
]

def make_sim_email(user_id, force_suspicious=False):
    is_sus = force_suspicious or random.random() > 0.65
    ext    = random.random() > 0.4 if is_sus else False
    recips = ([f"leak{random.randint(1,5)}@external{random.randint(1,3)}.com"]
              if ext else [f"colleague{random.randint(1,5)}@demoorg.com"])
    domain = recips[0].split("@")[1]
    atts   = []
    if is_sus and random.random() > 0.5:
        atts = [{"name":    random.choice(["clients.zip","salary.xlsx","passwords.txt","database.sql"]),
                 "size_mb": round(random.uniform(1.5, 14), 1),
                 "type":    random.choice([".zip",".xlsx",".txt",".sql"])}]
    return {
        "email_uid":         str(uuid.uuid4())[:32],
        "user_id":           user_id,
        "sender":            user_id,
        "recipients":        recips,
        "subject":           random.choice(DEMO_SUBJECTS),
        "body":              "Attached is the confidential data." if is_sus else "Hi, see below.",
        "timestamp":         datetime.utcnow().isoformat(),
        "body_length":       random.randint(80, 600),
        "attachment_count":  len(atts),
        "attachments":       atts,
        "recipient_domains": [domain],
        "has_external":      ext,
        "is_sent":           True,
        "folder":            "Sent Mail",
        "raw_metadata":      {"simulated": True},
    }

# =============================================================================
# HTTP SENDER  ← CHANGED: now sends to server.py /receive_log
# =============================================================================
class Sender:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        # SERVER_URL already points to /receive_log from config.py
        self.url  = config.SERVER_URL
        self.base = config.SERVER_URL.replace("/receive_log", "")

    # ── CHANGE 1: ping uses /dashboard (server.py has no /health) ────────────
    def ping(self):
        try:
            r = self.session.get(f"{self.base}/dashboard", timeout=5)
            return r.status_code in (200, 302)
        except Exception as e:
            log.error(f"Server unreachable: {e}")
            return False

    # ── CHANGE 2: send converts emails → SIEM format → /receive_log ──────────
    def send(self, emails):
        if not emails: return True
        try:
            events  = [self._to_siem(e) for e in emails]
            payload = {
                "agent_id": getattr(config, 'AGENT_ID', 'DESKTOP-OUTLOOK-01'),
                "events":   events,
            }
            r = self.session.post(
                self.url,
                data=json.dumps(payload, default=str),
                timeout=15,
            )
            if r.status_code == 200:
                d = r.json()
                log.info(f"📤 Sent {len(events)} email(s) → "
                         f"server status={d.get('status')}")
                return True
            log.error(f"Server {r.status_code}: {r.text[:100]}")
        except Exception as e:
            log.error(f"Send failed: {e}")
        return False

    # ── CHANGE 3: convert raw email dict → server.py SIEM event format ───────
    def _to_siem(self, e):
        subject  = e.get("subject", "")
        ext      = e.get("has_external", False)
        atts     = e.get("attachments", [])
        is_sent  = e.get("is_sent", False)
        user_id  = e.get("user_id", "unknown")
        att_cnt  = e.get("attachment_count", 0)
        body_text = e.get("body", "")

        # Quick inline risk score (server.py will re-score with ML model)
        score = 0.0
        text  = subject.lower()
        HIGH_KW = ["confidential","credentials","password","salary",
                   "client list","secret","internal","api key","token"]
        MED_KW  = ["financial","budget","nda","acquisition","merger","forecast"]
        for k in HIGH_KW:
            if k in text: score += 0.25; break
        for k in MED_KW:
            if k in text: score += 0.15; break
        if ext: score += 0.20
        for a in atts:
            if a.get("size_mb", 0) > 5:                            score += 0.15
            if a.get("type","").lower() in [".zip",".rar",".exe",
                                            ".sql",".bak"]:        score += 0.20

        # ── Determine severity + take screenshot on THIS machine ────────────
        final_score = round(min(score, 1.0), 3)
        if final_score >= 0.9:   severity = "CRITICAL"
        elif final_score >= 0.7: severity = "HIGH"
        elif final_score >= 0.5: severity = "MEDIUM"
        else:                    severity = "LOW"

        # Take screenshot on OLD MACHINE if suspicious
        screenshot_b64 = None
        if severity in ("HIGH", "CRITICAL", "MEDIUM"):
            screenshot_b64 = _take_agent_screenshot(user_id, subject, severity)

        return {
            # ── Fields server.py reads ────────────────────────────────────────
            "agent_id":            getattr(config, 'AGENT_ID', 'DESKTOP-OUTLOOK-01'),
            "event_type":          "outlook",
            "action":              "email_sent" if is_sent else "email_received",
            "user":                user_id,
            "timestamp":           e.get("timestamp", datetime.now().isoformat()),
            "hour_of_day":         datetime.now().hour,
            "risk_score":          final_score,

            # ── Email fields (rendered in dashboard) ──────────────────────────
            "email_subject":       subject,
            "email_body":          body_text,
            "email_body_truncated": bool(e.get("body_truncated", False)),
            "email_recipients":    e.get("recipients", [])[:5],
            "email_sender":        e.get("sender", user_id),
            "recipient_domains":   e.get("recipient_domains", []),
            "has_external":        ext,
            "attachment_count":    att_cnt,
            "attachments":         [{"name": a.get("name"),
                                     "size_mb": a.get("size_mb"),
                                     "type": a.get("type"),
                                     "content_preview": a.get("content_preview")}
                                    for a in atts[:5]],
            "body_length":         e.get("body_length", 0),
            "folder":              e.get("folder", ""),

            # ── ML model feature hints ────────────────────────────────────────
            "num_emails":          1,
            "num_external_emails": 1 if ext else 0,
            "total_attachments":   att_cnt,
            "is_remote":           ext,
            "is_document":         any(
                a.get("type","") in [".pdf",".docx",".xlsx",".csv"]
                for a in atts
            ),

            # ── Source tag ────────────────────────────────────────────────────
            "source":              "deepsentinel_email_agent",
            "email_uid":           e.get("email_uid", ""),

            # ── Screenshot from AGENT machine ────────────────────────────────
            "has_screenshot":      screenshot_b64 is not None,
            "screenshot_b64":      screenshot_b64,   # base64 PNG or None
            "screenshot_severity": severity,
        }


# =============================================================================
# OUTLOOK MAPI READER — unchanged, Gmail-aware
# =============================================================================
class MAPIReader:

    SENT_FOLDERS  = ["Sent Mail", "Sent Items", "Sent", "[Gmail]/Sent Mail"]
    INBOX_FOLDERS = ["Inbox"]

    def connect(self):
        try:
            pythoncom.CoInitialize()
            self.app = win32com.client.Dispatch("Outlook.Application")
            self.ns  = self.app.GetNamespace("MAPI")
            log.info("✅ Connected to Outlook MAPI")
            return True
        except Exception as e:
            log.error(f"MAPI connect failed: {e}")
            return False

    def accounts(self):
        out = []
        for i in range(1, self.ns.Accounts.Count + 1):
            a = self.ns.Accounts.Item(i)
            out.append({"name": a.DisplayName, "address": a.SmtpAddress})
        return out

    def _find_store(self, account_addr):
        for i in range(1, self.ns.Stores.Count + 1):
            s = self.ns.Stores.Item(i)
            name = (s.DisplayName or "").lower()
            if account_addr.lower() in name and "outlook data file" not in name:
                return s
        return None

    def _find_folder(self, root, name):
        try:
            for i in range(1, root.Folders.Count + 1):
                f = root.Folders.Item(i)
                if f.Name.lower() == name.lower():
                    return f
                sub = self._find_folder(f, name)
                if sub:
                    return sub
        except:
            pass
        return None

    def _uid(self, item):
        try:    return hashlib.sha256(item.EntryID.encode()).hexdigest()[:32]
        except: return hashlib.sha256(
            f"{item.SenderEmailAddress}{item.ReceivedTime}{item.Subject}".encode()
        ).hexdigest()[:32]

    def _recipients(self, item):
        recips, domains, external = [], set(), False
        try:
            for i in range(1, item.Recipients.Count + 1):
                addr = (item.Recipients.Item(i).Address or "").lower()
                recips.append(addr)
                if "@" in addr:
                    d = addr.split("@")[1]
                    domains.add(d)
                    if d not in [x.lower() for x in config.INTERNAL_DOMAINS]:
                        external = True
        except: pass
        return recips, list(domains), external

    def _attachments(self, item):
        out = []
        try:
            for i in range(1, item.Attachments.Count + 1):
                a = item.Attachments.Item(i)
                preview = self._extract_attachment_text_preview(a)
                out.append({
                    "name":    a.FileName,
                    "size_mb": round(a.Size / 1048576, 3),
                    "type":    os.path.splitext(a.FileName)[1].lower(),
                    "content_preview": preview,
                })
        except: pass
        return out

    def _extract_attachment_text_preview(self, attachment):
        """
        Extract a short text preview from supported attachments.
        Supports plain text files plus lightweight PDF/DOCX extraction.
        """
        tmp_path = None
        try:
            ext = os.path.splitext(attachment.FileName or "")[1].lower()
            size_mb = float(attachment.Size or 0) / 1048576.0
            if size_mb > MAX_ATTACHMENT_SIZE_MB_FOR_TEXT:
                return None
            if ext not in (TEXT_PREVIEW_EXTENSIONS | DOC_PREVIEW_EXTENSIONS | PDF_PREVIEW_EXTENSIONS):
                return None

            with tempfile.NamedTemporaryFile(
                prefix="deepsentinel_att_",
                suffix=ext,
                delete=False
            ) as tmp:
                tmp_path = tmp.name

            attachment.SaveAsFile(tmp_path)

            text = ""
            if ext in TEXT_PREVIEW_EXTENSIONS:
                with open(tmp_path, "rb") as f:
                    raw = f.read(MAX_ATTACHMENT_TEXT_BYTES)
                text = raw.decode("utf-8", errors="ignore").strip()
                if not text:
                    text = raw.decode("utf-16", errors="ignore").strip()
            elif ext in DOC_PREVIEW_EXTENSIONS and DOCX_OK:
                document = docx.Document(tmp_path)
                text = "\n".join(
                    para.text.strip() for para in document.paragraphs if para.text.strip()
                )
            elif ext in PDF_PREVIEW_EXTENSIONS and PDF_OK:
                pages = []
                with open(tmp_path, "rb") as f:
                    reader = PyPDF2.PdfReader(f)
                    for page in reader.pages[:3]:
                        try:
                            pages.append(page.extract_text() or "")
                        except Exception:
                            continue
                text = "\n".join(pages).strip()
            else:
                return None

            text = text.replace("\x00", "")
            if not text:
                return None
            return text[:MAX_ATTACHMENT_TEXT_CHARS]
        except Exception as e:
            log.debug(f"Attachment preview failed for '{attachment.FileName}': {e}")
            return None
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

    def read_all_folders(self, account_addr, since):
        store = self._find_store(account_addr)
        if not store:
            log.error(f"Could not find store for {account_addr}")
            return []

        root   = store.GetRootFolder()
        emails = []

        sent_folder = None
        for name in self.SENT_FOLDERS:
            sent_folder = self._find_folder(root, name)
            if sent_folder:
                log.info(f"Found sent folder: '{sent_folder.Name}'")
                break

        inbox_folder = None
        for name in self.INBOX_FOLDERS:
            inbox_folder = self._find_folder(root, name)
            if inbox_folder:
                log.info(f"Found inbox folder: '{inbox_folder.Name}'")
                break

        for folder, is_sent in [(sent_folder, True), (inbox_folder, False)]:
            if not folder:
                continue
            try:
                count = 0
                for item in folder.Items:
                    try:
                        if item.Class != 43: continue

                        item_time = None
                        for attr in ["SentOn", "ReceivedTime"]:
                            try:
                                item_time = getattr(item, attr)
                                if item_time: break
                            except: pass

                        if item_time is None: continue

                        try:
                            item_dt = item_time.replace(tzinfo=None)
                        except: continue

                        if item_dt < since: continue

                        recips, domains, ext = self._recipients(item)
                        atts  = self._attachments(item)
                        ts    = item_time.strftime("%Y-%m-%dT%H:%M:%S")
                        full_body = item.Body or ""
                        body_excerpt = full_body[:MAX_EMAIL_BODY_CHARS]
                        count += 1

                        emails.append({
                            "email_uid":         self._uid(item),
                            "user_id":           account_addr.lower(),
                            "sender":            (item.SenderEmailAddress or account_addr).lower(),
                            "recipients":        recips,
                            "subject":           item.Subject or "(no subject)",
                            "body":              body_excerpt,
                            "body_truncated":    len(full_body) > MAX_EMAIL_BODY_CHARS,
                            "timestamp":         ts,
                            "body_length":       len(full_body),
                            "attachment_count":  len(atts),
                            "attachments":       atts,
                            "recipient_domains": domains,
                            "has_external":      ext,
                            "is_sent":           is_sent,
                            "folder":            folder.Name,
                            "raw_metadata":      {"account": account_addr,
                                                  "folder":  folder.Name},
                        })
                    except Exception as e:
                        log.debug(f"Skip item: {e}")
                        continue

                if count > 0:
                    log.info(f"Read {count} email(s) from '{folder.Name}'")

            except Exception as e:
                log.error(f"Error reading {folder.Name}: {e}")

        return emails


# =============================================================================
# MAIN — unchanged
# =============================================================================
def run():
    print("=" * 60)
    print("  🛡️  DeepSentinel — Email Agent")
    print(f"  Server : {config.SERVER_URL}")
    print("=" * 60)

    sender = Sender()

    print("\n[1/3] Checking server connection...")
    if not sender.ping():
        print(f"\n  ❌ Cannot reach server at {sender.base}")
        print("  ► Is server.py running on the Dell machine?")
        print(f"  ► Check config.py → SERVER_IP = {getattr(config,'SERVER_IP','?')}")
        sys.exit(1)
    print("  ✅ Server reachable!\n")

    print("[2/3] Connecting to Outlook...")
    SIM_MODE = False
    reader   = None
    accounts = []

    if MAPI_OK:
        reader = MAPIReader()
        if reader.connect():
            accounts = reader.accounts()
            if accounts:
                print(f"  ✅ Outlook connected — {len(accounts)} account(s):")
                for a in accounts:
                    print(f"       • {a['name']} <{a['address']}>")
            else:
                SIM_MODE = True
        else:
            SIM_MODE = True
    else:
        SIM_MODE = True

    if SIM_MODE:
        print("  ⚠️  SIMULATION MODE — Outlook unavailable\n")

    print("[3/3] Starting email collection...\n")

    if not SIM_MODE:
        since = datetime.now() - timedelta(minutes=config.AGENT_LOOKBACK_MINUTES)
        log.info(f"Backfill since {since.strftime('%Y-%m-%d %H:%M')}")
        batch = []
        for acc in accounts:
            found = reader.read_all_folders(acc["address"], since)
            log.info(f"Backfill: {len(found)} emails from {acc['address']}")
            batch += found
        if batch:
            sender.send(batch)
        else:
            log.info("No emails in backfill window")

    # ── Start command listener (polls server for admin commands) ─────────────
    try:
        from command_receiver import start_command_listener
        start_command_listener()
        log.info("⚡ Admin command listener started")
    except Exception as e:
        log.warning(f"Command listener not available: {e}")

    print(f"  Polling every {config.AGENT_POLL_INTERVAL_SECONDS}s — Ctrl+C to stop\n")
    last_check = datetime.now()
    cycle = 0

    while True:
        try:
            time.sleep(config.AGENT_POLL_INTERVAL_SECONDS)
            cycle += 1

            if SIM_MODE:
                batch = []
                for _ in range(random.randint(2, 4)):
                    batch.append(make_sim_email(
                        random.choice(DEMO_USERS),
                        force_suspicious=(cycle % 5 == 0)
                    ))
                log.info(f"Cycle {cycle} — simulating {len(batch)} emails")
                sender.send(batch)
            else:
                batch = []
                for acc in accounts:
                    batch += reader.read_all_folders(acc["address"], last_check)
                last_check = datetime.now()
                if batch:
                    log.info(f"Cycle {cycle} — {len(batch)} new email(s)")
                    sender.send(batch)
                else:
                    log.info(f"Cycle {cycle} — no new emails")

        except KeyboardInterrupt:
            print("\n\n[AGENT] Stopped.")
            break
        except Exception as e:
            log.error(f"Cycle error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    run()
