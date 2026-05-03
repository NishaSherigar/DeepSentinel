import base64
import ctypes
import io
import json
import logging
import os
import shutil
import sys
import threading
import time
import uuid
from datetime import datetime

import pythoncom
import requests
import win32com.client

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import config

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
    import pyautogui
    SCREENSHOT_OK = True
except ImportError:
    SCREENSHOT_OK = False

os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
os.makedirs(os.path.join(ROOT, "data"), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [HOOK] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(ROOT, "logs", "hook.log"), encoding="utf-8"),
    ],
)
log = logging.getLogger("hook")

PENDING_EMAILS_PATH = os.path.join(ROOT, "data", "pending_outgoing_emails.json")
PENDING_ATTACHMENTS_DIR = os.path.join(ROOT, "data", "pending_email_attachments")
SERVER_BASE = config.SERVER_URL.replace("/receive_log", "")
CLASSIFY_URL = SERVER_BASE + "/api/email/classify"
COMMAND_POLL_URL = SERVER_BASE + f"/get_commands/{getattr(config, 'AGENT_ID', 'DESKTOP-OUTLOOK-01')}"
POLL_INTERVAL = 10
APPROVED_CATEGORY = "DeepSentinelApproved"
MAX_EMAIL_BODY_CHARS = int(getattr(config, "MAX_EMAIL_BODY_CHARS", 4000))
MAX_ATTACHMENT_SIZE_MB_FOR_TEXT = float(getattr(config, "MAX_ATTACHMENT_SIZE_MB_FOR_TEXT", 2.0))
MAX_ATTACHMENT_TEXT_BYTES = int(getattr(config, "MAX_ATTACHMENT_TEXT_BYTES", 8192))
MAX_ATTACHMENT_TEXT_CHARS = int(getattr(config, "MAX_ATTACHMENT_TEXT_CHARS", 2000))

TEXT_PREVIEW_EXTENSIONS = {
    ".txt", ".csv", ".log", ".json", ".xml", ".md", ".ini", ".cfg", ".sql",
}
DOC_PREVIEW_EXTENSIONS = {".docx"}
PDF_PREVIEW_EXTENSIONS = {".pdf"}


def quick_scan(subject, body, recipients, attachments):
    score, reasons = 0.0, []
    text = f"{subject} {body[:500]}".lower()

    critical = ["password", "credential", "secret", "api key", "token", "private key", "access code"]
    high = ["confidential", "top secret", "classified", "do not share", "internal only", "proprietary"]
    medium = ["salary", "client list", "financial", "nda", "budget", "acquisition", "merger", "forecast"]

    for k in critical:
        if k in text:
            score += 0.40
            reasons.append(f"Critical keyword: '{k}'")
            break
    for k in high:
        if k in text:
            score += 0.30
            reasons.append(f"High-risk keyword: '{k}'")
            break
    for k in medium:
        if k in text:
            score += 0.15
            reasons.append(f"Sensitive keyword: '{k}'")
            break

    ext_recips = [
        r for r in recipients
        if "@" in r and r.split("@")[1].lower() not in [d.lower() for d in config.INTERNAL_DOMAINS]
    ]
    if ext_recips:
        score += 0.25
        reasons.append(f"External recipient: {', '.join(ext_recips[:2])}")

    risky_exts = set(getattr(config, "RISKY_ATTACHMENT_EXTENSIONS", [".zip", ".rar", ".exe", ".sql", ".bak", ".ps1"]))
    size_limit = getattr(config, "ATTACHMENT_SIZE_THRESHOLD_MB", 5)
    for att in attachments:
        ext = os.path.splitext(att.get("name", ""))[1].lower()
        size = att.get("size_mb", 0)
        if ext in risky_exts:
            score += 0.30
            reasons.append(f"Risky file: {att.get('name', '')}")
        if size > size_limit:
            score += 0.15
            reasons.append(f"Large file: {att.get('name', '')} ({size:.1f}MB)")

    score = min(1.0, score)
    if score >= 0.90:
        sev = "CRITICAL"
    elif score >= 0.70:
        sev = "HIGH"
    elif score >= 0.50:
        sev = "MEDIUM"
    elif score >= 0.30:
        sev = "LOW"
    else:
        sev = "NORMAL"
    return round(score, 3), sev, reasons


def ext_recips_exist(recipients):
    return any(
        "@" in r and r.split("@")[1].lower() not in [d.lower() for d in config.INTERNAL_DOMAINS]
        for r in recipients
    )


def _screenshot():
    if not SCREENSHOT_OK:
        return None
    try:
        img = pyautogui.screenshot()
        buf = io.BytesIO()
        img.save(buf, format="PNG", optimize=True)
        return base64.b64encode(buf.getvalue()).decode()
    except Exception as e:
        log.error(f"Screenshot failed: {e}")
        return None


def _load_pending_emails():
    if not os.path.exists(PENDING_EMAILS_PATH):
        return {}
    try:
        with open(PENDING_EMAILS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_pending_emails(pending):
    try:
        with open(PENDING_EMAILS_PATH, "w", encoding="utf-8") as f:
            json.dump(pending, f, indent=2)
    except Exception as e:
        log.error(f"Save pending emails failed: {e}")


def _extract_text_from_saved_attachment(path):
    ext = os.path.splitext(path or "")[1].lower()
    size_mb = (os.path.getsize(path) / 1048576.0) if os.path.exists(path) else 0.0
    if size_mb > MAX_ATTACHMENT_SIZE_MB_FOR_TEXT:
        return None

    try:
        if ext in TEXT_PREVIEW_EXTENSIONS:
            with open(path, "rb") as f:
                raw = f.read(MAX_ATTACHMENT_TEXT_BYTES)
            text = raw.decode("utf-8", errors="ignore").strip()
            if not text:
                text = raw.decode("utf-16", errors="ignore").strip()
            text = text.replace("\x00", "")
            return text[:MAX_ATTACHMENT_TEXT_CHARS] if text else None
        if ext in DOC_PREVIEW_EXTENSIONS and DOCX_OK:
            document = docx.Document(path)
            text = "\n".join(para.text.strip() for para in document.paragraphs if para.text.strip())
            return text[:MAX_ATTACHMENT_TEXT_CHARS] if text else None
        if ext in PDF_PREVIEW_EXTENSIONS and PDF_OK:
            pages = []
            with open(path, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                for page in reader.pages[:3]:
                    try:
                        pages.append(page.extract_text() or "")
                    except Exception:
                        continue
            text = "\n".join(pages).strip()
            return text[:MAX_ATTACHMENT_TEXT_CHARS] if text else None
    except Exception as e:
        log.debug(f"Attachment preview failed for {path}: {e}")
    return None


def _capture_outgoing_attachments(item, email_id):
    attachments = []
    pending_dir = os.path.join(PENDING_ATTACHMENTS_DIR, email_id)
    os.makedirs(pending_dir, exist_ok=True)
    try:
        for i in range(1, item.Attachments.Count + 1):
            attachment = item.Attachments.Item(i)
            filename = attachment.FileName or f"attachment_{i}"
            dest_path = os.path.join(pending_dir, filename)
            attachment.SaveAsFile(dest_path)
            attachments.append({
                "name": filename,
                "size_mb": round((attachment.Size or 0) / 1048576.0, 3),
                "type": os.path.splitext(filename)[1].lower(),
                "content_preview": _extract_text_from_saved_attachment(dest_path),
                "local_path": dest_path,
            })
    except Exception as e:
        log.error(f"Capture attachments failed: {e}")
    return attachments


def _delete_pending_email(email_id):
    pending = _load_pending_emails()
    record = pending.pop(email_id, None)
    _save_pending_emails(pending)
    folder = os.path.join(PENDING_ATTACHMENTS_DIR, email_id)
    if os.path.isdir(folder):
        try:
            shutil.rmtree(folder, ignore_errors=True)
        except Exception:
            pass
    return record


def _show_hold_popup(subject, risk_score, classification):
    ctypes.windll.user32.MessageBoxW(
        0,
        (
            "Email held for admin approval.\n\n"
            f"Subject: {subject[:60] or '(no subject)'}\n"
            f"Risk Score: {risk_score:.2f}\n"
            f"Classification: {classification}\n\n"
            "Your message has not been sent yet. An administrator must approve or reject it."
        ),
        "DeepSentinel - Email Waiting for Approval",
        0x40 | 0x1000,
    )


def _show_reject_popup(subject, reason):
    ctypes.windll.user32.MessageBoxW(
        0,
        (
            "Your email was rejected by an administrator.\n\n"
            f"Subject: {subject[:60] or '(no subject)'}\n"
            f"Reason: {reason or 'Admin rejected'}"
        ),
        "DeepSentinel - Email Rejected",
        0x30 | 0x1000,
    )


def _notify_server(
    subject,
    body,
    recipients,
    attachments,
    score,
    severity,
    reasons,
    action,
    screenshot_b64,
    email_uid=None,
    skip_approval_queue=False,
    approval_state=None,
):
    try:
        uid = getattr(config, "AGENT_ID", "DESKTOP-OUTLOOK-01")
        evt = {
            "agent_id": uid,
            "event_type": "outlook",
            "action": f"email_{action}",
            "user": uid,
            "timestamp": datetime.now().isoformat(),
            "hour_of_day": datetime.now().hour,
            "risk_score": score,
            "email_uid": email_uid or str(uuid.uuid4())[:32],
            "email_subject": subject,
            "email_body": body,
            "body_length": len(body or ""),
            "email_recipients": recipients[:5],
            "email_sender": uid,
            "has_external": ext_recips_exist(recipients),
            "attachment_count": len(attachments),
            "attachments": attachments[:5],
            "reasons": reasons,
            "action_taken": action,
            "screenshot_severity": severity,
            "has_screenshot": screenshot_b64 is not None,
            "screenshot_b64": screenshot_b64,
            "source": "outlook_send_hook",
            "num_emails": 1,
            "num_external_emails": 1 if ext_recips_exist(recipients) else 0,
            "total_attachments": len(attachments),
            "skip_approval_queue": bool(skip_approval_queue),
            "approval_state": approval_state or "",
        }
        requests.post(config.SERVER_URL, json={"agent_id": uid, "events": [evt]}, timeout=5)
        log.info(f"Server notified - {action} | {severity}")
    except Exception as e:
        log.error(f"Notify failed: {e}")


def _log_local(subject, recipients, attachments, score, severity, reasons, blocked):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "subject": subject[:100],
        "recipients": recipients[:5],
        "attachments": [a.get("name") for a in attachments],
        "score": score,
        "severity": severity,
        "reasons": reasons,
        "blocked": blocked,
    }
    with open(os.path.join(ROOT, "logs", "intercepts.jsonl"), "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _classify_with_server(email_data):
    try:
        response = requests.post(CLASSIFY_URL, json=email_data, timeout=15)
        if response.status_code == 200:
            return response.json()
        log.error(f"Classify failed: {response.status_code} {response.text[:200]}")
    except Exception as e:
        log.error(f"Classify request failed: {e}")
    return None


def _store_pending_email(email_id, email_data):
    pending = _load_pending_emails()
    pending[email_id] = email_data
    _save_pending_emails(pending)


def _send_pending_email(email_id):
    pending = _load_pending_emails()
    email_data = pending.get(email_id)
    if not email_data:
        log.warning(f"Pending email not found: {email_id}")
        return False

    pythoncom.CoInitialize()
    try:
        outlook = win32com.client.Dispatch("Outlook.Application")
        mail = outlook.CreateItem(0)
        mail.Subject = email_data.get("subject") or ""
        mail.Body = email_data.get("body") or ""
        mail.Categories = APPROVED_CATEGORY

        for recip in email_data.get("recipients", []):
            if recip:
                mail.Recipients.Add(str(recip))
        mail.Recipients.ResolveAll()

        for att in email_data.get("attachments", []):
            path = att.get("local_path")
            if path and os.path.exists(path):
                mail.Attachments.Add(path)

        mail.Send()
        _delete_pending_email(email_id)
        log.info(f"Approved email sent: {email_id}")
        return True
    except Exception as e:
        log.error(f"Send pending email failed: {e}")
        return False


def _reject_pending_email(email_id, reason):
    record = _delete_pending_email(email_id) or {}
    _show_reject_popup(record.get("subject", ""), reason)
    log.info(f"Pending email rejected: {email_id} | {reason}")
    return True


def _start_email_command_listener():
    def _poll():
        session = requests.Session()
        log.info(f"Email approval listener started - polling every {POLL_INTERVAL}s")
        while True:
            try:
                response = session.get(COMMAND_POLL_URL, timeout=5)
                if response.status_code == 200:
                    commands = (response.json() or {}).get("commands", [])
                    for cmd in commands:
                        command = str(cmd.get("command") or "").strip()
                        email_id = str(cmd.get("email_id") or "").strip()
                        if command == "send_pending_email" and email_id:
                            _send_pending_email(email_id)
                        elif command == "reject_pending_email" and email_id:
                            _reject_pending_email(email_id, cmd.get("reason", "Admin rejected"))
            except Exception as e:
                log.debug(f"Email approval poll error: {e}")
            time.sleep(POLL_INTERVAL)

    threading.Thread(target=_poll, daemon=True).start()


class OutlookEventSink:
    def OnItemSend(self, item, cancel):
        try:
            subject = item.Subject or ""
            body = (item.Body or "")[:MAX_EMAIL_BODY_CHARS]

            categories = ""
            try:
                categories = (item.Categories or "").strip()
            except Exception:
                categories = ""

            recipients = []
            try:
                for i in range(1, item.Recipients.Count + 1):
                    addr = (item.Recipients.Item(i).Address or "").strip().lower()
                    if addr:
                        recipients.append(addr)
            except Exception:
                pass

            if APPROVED_CATEGORY.lower() in categories.lower():
                score, severity, reasons = quick_scan(subject, body, recipients, [])
                _notify_server(
                    subject,
                    body,
                    recipients,
                    [],
                    score,
                    severity,
                    reasons,
                    "sent_approved",
                    None,
                    skip_approval_queue=True,
                    approval_state="approved",
                )
                _log_local(subject, recipients, [], score, severity, reasons, False)
                return cancel

            local_email_id = str(uuid.uuid4())[:32]
            attachments = _capture_outgoing_attachments(item, local_email_id)

            score, severity, reasons = quick_scan(subject, body, recipients, attachments)
            log.info(f"SEND | '{subject[:40]}' | {severity} | {score}")

            email_data = {
                "email_id": local_email_id,
                "agent_id": getattr(config, "AGENT_ID", "DESKTOP-OUTLOOK-01"),
                "originating_agent_id": getattr(config, "AGENT_ID", "DESKTOP-OUTLOOK-01"),
                "release_via_agent": True,
                "source": "outlook_hook_pre_send",
                "sender": getattr(config, "AGENT_ID", "DESKTOP-OUTLOOK-01"),
                "recipient": recipients[0] if recipients else "",
                "recipients": recipients,
                "subject": subject,
                "body": body,
                "email_subject": subject,
                "email_body": body,
                "email_recipients": recipients,
                "email_sender": getattr(config, "AGENT_ID", "DESKTOP-OUTLOOK-01"),
                "attachments": attachments,
                "attachment_count": len(attachments),
                "has_external": ext_recips_exist(recipients),
                "body_length": len(body or ""),
                "num_emails": 1,
                "num_external_emails": 1 if ext_recips_exist(recipients) else 0,
                "total_attachments": len(attachments),
            }

            classification_result = _classify_with_server(email_data)
            if classification_result and "classification" in classification_result:
                cls = classification_result.get("classification") or {}
                score = float(cls.get("risk_score", score) or score)
                severity = str(cls.get("classification", severity) or severity).upper()
                reasons = cls.get("reasons") or reasons
                queued_email_id = classification_result.get("email_id") or local_email_id
            else:
                queued_email_id = local_email_id

            email_data["email_id"] = queued_email_id
            _store_pending_email(queued_email_id, email_data)

            if severity in ("MEDIUM", "HIGH", "CRITICAL"):
                cancel = True
                shot = _screenshot()
                _notify_server(
                    subject,
                    body,
                    recipients,
                    attachments,
                    score,
                    severity,
                    reasons,
                    "pending_approval",
                    shot,
                    email_uid=queued_email_id,
                    skip_approval_queue=True,
                    approval_state="pending",
                )
                _log_local(subject, recipients, attachments, score, severity, reasons, True)
                _show_hold_popup(subject, score, severity)
            else:
                _delete_pending_email(queued_email_id)
                _notify_server(
                    subject,
                    body,
                    recipients,
                    attachments,
                    score,
                    severity,
                    reasons,
                    "sent_low",
                    None,
                    email_uid=queued_email_id,
                    skip_approval_queue=True,
                    approval_state="allowed",
                )
                _log_local(subject, recipients, attachments, score, severity, reasons, False)

        except Exception as e:
            log.error(f"OnItemSend error: {e}")

        return cancel


def run():
    print("=" * 60)
    print("  DeepSentinel - Outlook Send Hook")
    print(f"  Server : {config.SERVER_URL}")
    print("=" * 60)
    print()
    print("  LOW      -> allow send")
    print("  MEDIUM   -> hold for admin approval")
    print("  HIGH     -> hold for admin approval")
    print("  CRITICAL -> hold for admin approval")
    print()
    print("  Keep Outlook OPEN")
    print("  Press Ctrl+C to stop\n")

    pythoncom.CoInitialize()

    try:
        win32com.client.DispatchWithEvents("Outlook.Application", OutlookEventSink)
        log.info("Hook attached to Outlook - monitoring all outbound emails")
    except Exception as e:
        log.error(f"Cannot attach: {e}")
        log.error("Open Outlook first")
        sys.exit(1)

    _start_email_command_listener()

    print("  Hook is LIVE - send a test email\n")
    try:
        while True:
            pythoncom.PumpWaitingMessages()
            time.sleep(0.05)
    except KeyboardInterrupt:
        print("\n\n  Hook stopped.")


if __name__ == "__main__":
    run()
