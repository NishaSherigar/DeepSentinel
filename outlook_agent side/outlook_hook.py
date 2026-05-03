# =============================================================================
# DeepSentinel — outlook_hook.py
# Intercepts Outlook emails BEFORE they are sent.
# Run on OLD MACHINE alongside Outlook 2013.
#
# CRITICAL → EMAIL BLOCKED + popup warning to user
# HIGH     → allowed + screenshot + admin alerted  
# MEDIUM   → allowed + screenshot + admin alerted
# LOW      → allowed + silent log
#
# RUN: python outlook_hook.py
# =============================================================================

import sys, os, time, json, logging, requests, base64, io
from datetime import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import config

os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [HOOK] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(
            os.path.join(ROOT, "logs", "hook.log"), encoding="utf-8"),
    ]
)
log = logging.getLogger("hook")

import win32com.client
import pythoncom
import ctypes

try:
    import pyautogui
    from PIL import Image
    SCREENSHOT_OK = True
except ImportError:
    SCREENSHOT_OK = False

# =============================================================================
# RISK SCANNER
# =============================================================================

def quick_scan(subject, body, recipients, attachments):
    score, reasons = 0.0, []
    text = (subject + " " + body[:500]).lower()

    CRIT = ["password","credential","secret","api key","token","private key","access code"]
    HIGH = ["confidential","top secret","classified","do not share","internal only","proprietary"]
    MED  = ["salary","client list","financial","nda","budget","acquisition","merger","forecast"]

    for k in CRIT:
        if k in text: score += 0.40; reasons.append(f"Critical keyword: '{k}'"); break
    for k in HIGH:
        if k in text: score += 0.30; reasons.append(f"High-risk keyword: '{k}'"); break
    for k in MED:
        if k in text: score += 0.15; reasons.append(f"Sensitive keyword: '{k}'"); break

    ext_recips = [r for r in recipients
                  if "@" in r and r.split("@")[1].lower()
                  not in [d.lower() for d in config.INTERNAL_DOMAINS]]
    if ext_recips:
        score += 0.25
        reasons.append(f"External recipient: {', '.join(ext_recips[:2])}")

    RISKY = set(getattr(config,'RISKY_ATTACHMENT_EXTENSIONS',
                        [".zip",".rar",".exe",".sql",".bak",".ps1"]))
    LIMIT = getattr(config,'ATTACHMENT_SIZE_THRESHOLD_MB', 5)
    for att in attachments:
        ext  = os.path.splitext(att.get("name",""))[1].lower()
        size = att.get("size_mb", 0)
        if ext in RISKY:  score += 0.30; reasons.append(f"Risky file: {att.get('name','')}")
        if size > LIMIT:  score += 0.15; reasons.append(f"Large file: {att.get('name','')} ({size:.1f}MB)")

    score = min(1.0, score)
    if   score >= 0.90: sev = "CRITICAL"
    elif score >= 0.70: sev = "HIGH"
    elif score >= 0.50: sev = "MEDIUM"
    elif score >= 0.30: sev = "LOW"
    else:               sev = "NORMAL"

    return round(score, 3), sev, reasons


# =============================================================================
# HELPERS
# =============================================================================

def _screenshot():
    if not SCREENSHOT_OK: return None
    try:
        img = pyautogui.screenshot()
        buf = io.BytesIO()
        img.save(buf, format="PNG", optimize=True)
        return base64.b64encode(buf.getvalue()).decode()
    except Exception as e:
        log.error(f"Screenshot: {e}")
        return None


def _notify_server(subject, recipients, attachments,
                   score, severity, reasons, action, screenshot_b64):
    try:
        uid = getattr(config, 'AGENT_ID', 'DESKTOP-OUTLOOK-01')
        evt = {
            "agent_id":          uid,
            "event_type":        "outlook",
            "action":            f"email_{action}",
            "user":              uid,
            "timestamp":         datetime.now().isoformat(),
            "hour_of_day":       datetime.now().hour,
            "risk_score":        score,
            "email_subject":     subject,
            "email_recipients":  recipients[:5],
            "has_external":      bool([r for r in recipients
                                       if "@" in r and r.split("@")[1].lower()
                                       not in [d.lower() for d in config.INTERNAL_DOMAINS]]),
            "attachment_count":  len(attachments),
            "attachments":       attachments[:5],
            "reasons":           reasons,
            "action_taken":      action,
            "screenshot_severity": severity,
            "has_screenshot":    screenshot_b64 is not None,
            "screenshot_b64":    screenshot_b64,
            "source":            "outlook_send_hook",
            "num_emails":        1,
            "num_external_emails": 1 if ext_recips_exist(recipients) else 0,
            "total_attachments": len(attachments),
        }
        requests.post(
            config.SERVER_URL,
            json={"agent_id": uid, "events": [evt]},
            timeout=5,
        )
        log.info(f"📤 Server notified — {action} | {severity}")
    except Exception as e:
        log.error(f"Notify failed: {e}")


def ext_recips_exist(recipients):
    return any("@" in r and r.split("@")[1].lower()
               not in [d.lower() for d in config.INTERNAL_DOMAINS]
               for r in recipients)


def _block_popup(subject, score, reasons):
    reason_text = "\n".join(f"  • {r}" for r in reasons[:4])
    ctypes.windll.user32.MessageBoxW(
        0,
        f"🚫  EMAIL BLOCKED by DeepSentinel\n\n"
        f"Subject: {subject[:60]}\n"
        f"Risk Score: {score:.2f}  (CRITICAL)\n\n"
        f"Reasons:\n{reason_text}\n\n"
        f"This incident has been reported to your administrator.\n"
        f"Contact IT Security if you believe this is an error.",
        "DeepSentinel — Email Blocked",
        0x10 | 0x1000
    )


def _log_local(subject, recipients, attachments, score, severity, reasons, blocked):
    entry = {
        "timestamp":   datetime.now().isoformat(),
        "subject":     subject[:100],
        "recipients":  recipients[:5],
        "attachments": [a["name"] for a in attachments],
        "score":       score,
        "severity":    severity,
        "reasons":     reasons,
        "blocked":     blocked,
    }
    with open(os.path.join(ROOT,"logs","intercepts.jsonl"),
              "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


# =============================================================================
# COM EVENT SINK
# =============================================================================

class OutlookEventSink:

    def OnItemSend(self, item, cancel):
        try:
            subject = item.Subject or ""
            body    = (item.Body or "")[:1000]

            recipients = []
            try:
                for i in range(1, item.Recipients.Count + 1):
                    addr = (item.Recipients.Item(i).Address or "").lower()
                    if addr: recipients.append(addr)
            except: pass

            attachments = []
            try:
                for i in range(1, item.Attachments.Count + 1):
                    a = item.Attachments.Item(i)
                    attachments.append({
                        "name":    a.FileName,
                        "size_mb": round(a.Size / 1048576, 2),
                        "type":    os.path.splitext(a.FileName)[1].lower(),
                    })
            except: pass

            score, severity, reasons = quick_scan(
                subject, body, recipients, attachments)

            log.info(f"SEND | '{subject[:40]}' | {severity} | {score}")

            if severity == "NORMAL":
                return cancel

            # Screenshot on THIS machine
            shot = _screenshot() if severity in ("MEDIUM","HIGH","CRITICAL") else None

            if severity == "CRITICAL":
                cancel = True
                log.warning(f"🚫 BLOCKED: '{subject[:50]}'")
                _notify_server(subject, recipients, attachments,
                               score, severity, reasons, "blocked", shot)
                _block_popup(subject, score, reasons)

            elif severity in ("HIGH", "MEDIUM"):
                log.warning(f"⚠️  RISKY SENT: '{subject[:50]}'")
                _notify_server(subject, recipients, attachments,
                               score, severity, reasons, "sent_risky", shot)

            else:
                _notify_server(subject, recipients, attachments,
                               score, severity, reasons, "sent_low", None)

            _log_local(subject, recipients, attachments,
                       score, severity, reasons, bool(cancel))

        except Exception as e:
            log.error(f"OnItemSend error: {e}")

        return cancel


# =============================================================================
# MAIN
# =============================================================================

def run():
    print("=" * 60)
    print("  🛡️  DeepSentinel — Outlook Send Hook")
    print(f"  Server : {config.SERVER_URL}")
    print("=" * 60)
    print()
    print("  NORMAL   → silent")
    print("  LOW      → logged")
    print("  MEDIUM   → screenshot + admin alert")
    print("  HIGH     → screenshot + admin alert")
    print("  CRITICAL → EMAIL BLOCKED + popup")
    print()
    print("  ⚠️  Keep Outlook 2013 OPEN")
    print("  Press Ctrl+C to stop\n")

    pythoncom.CoInitialize()

    try:
        outlook = win32com.client.DispatchWithEvents(
            "Outlook.Application", OutlookEventSink)
        log.info("✅ Hook attached to Outlook — monitoring all outbound emails")
    except Exception as e:
        log.error(f"❌ Cannot attach: {e}")
        log.error("   Open Outlook 2013 first")
        sys.exit(1)

    print("  ✅ Hook is LIVE — send a test email\n")

    try:
        while True:
            pythoncom.PumpWaitingMessages()
            time.sleep(0.05)
    except KeyboardInterrupt:
        print("\n\n  Hook stopped.")


if __name__ == "__main__":
    run()
