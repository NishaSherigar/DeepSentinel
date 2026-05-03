# =============================================================================
# DeepSentinel — action_engine.py
# Automated response actions triggered by threat severity.
# Runs on SERVER (Dell) machine.
#
# Add to server.py before if __name__ == '__main__':
#   from action_engine import ActionEngine
#   action_engine = ActionEngine()
#   action_engine.wire(app)
#
# ACTIONS BY SEVERITY:
#   LOW      → log only
#   MEDIUM   → desktop notification + log
#   HIGH     → notification + sound + log + email alert to admin
#   CRITICAL → all above + network isolation + quarantine record
# =============================================================================

import os, sys, json, logging, threading, subprocess, smtplib, socket
from datetime import datetime
from email.mime.text      import MIMEText
from email.mime.multipart import MIMEMultipart

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

os.makedirs(os.path.join(ROOT, "quarantine"), exist_ok=True)
os.makedirs(os.path.join(ROOT, "logs"),       exist_ok=True)

log = logging.getLogger("action_engine")

# ── Optional imports ──────────────────────────────────────────────────────────
try:
    from plyer import notification as plyer_notif
    PLYER_OK = True
except ImportError:
    PLYER_OK = False

try:
    import winsound
    SOUND_OK = True
except ImportError:
    SOUND_OK = False

# =============================================================================
# ADMIN EMAIL CONFIG — edit these
# =============================================================================
ADMIN_EMAIL_CONFIG = {
    "enabled":   False,          # Set True + fill details to get email alerts
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "sender":    "your_alert_email@gmail.com",
    "password":  "your_app_password",
    "recipient": "admin@yourcompany.com",
}

# =============================================================================
# ALERT THROTTLING — prevent notification spam
# =============================================================================
from datetime import timedelta

_alert_throttle = {}  # {user: timestamp} - track last notification per user

def _should_send_notification(user, severity):
    """Check if we should send a notification for this user (throttle to max 1 per minute per severity)"""
    global _alert_throttle
    key = f"{user}_{severity}"
    now = datetime.now()
    
    if key in _alert_throttle:
        last_time = _alert_throttle[key]
        # Only allow 1 notification per minute per user per severity
        if (now - last_time) < timedelta(seconds=60):
            return False
    
    _alert_throttle[key] = now
    return True

# =============================================================================
# SEVERITY HELPERS
# =============================================================================

SEV_ICONS  = {"LOW":"🟢","MEDIUM":"🟡","HIGH":"🔴","CRITICAL":"💀"}
SEV_SOUNDS = {"HIGH": (800,500), "CRITICAL": (1000,800)}

def _score_to_sev(score):
    try:
        s = float(score)
        if s >= 0.90: return "CRITICAL"
        if s >= 0.70: return "HIGH"
        if s >= 0.50: return "MEDIUM"
        if s >= 0.30: return "LOW"
    except: pass
    return "LOW"

# =============================================================================
# INDIVIDUAL ACTIONS
# =============================================================================

def action_log(severity, user, event_type, detail, score, event):
    """Always runs — structured JSON action log."""
    entry = {
        "timestamp":  datetime.now().isoformat(),
        "severity":   severity,
        "user":       user,
        "event_type": event_type,
        "detail":     detail[:200],
        "risk_score": score,
        "actions":    [],
    }
    path = os.path.join(ROOT, "logs", "actions.jsonl")
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def action_notify(severity, user, title, message):
    """Desktop toast notification on admin machine."""
    icons = {"MEDIUM":"⚠️","HIGH":"🚨","CRITICAL":"💀"}
    full_title = f"{icons.get(severity,'🛡️')} DeepSentinel — {severity}"

    if PLYER_OK:
        try:
            plyer_notif.notify(
                title   = full_title,
                message = f"User: {user}\n{message[:100]}",
                app_name= "DeepSentinel",
                timeout = 10 if severity == "CRITICAL" else 5,
            )
            return True
        except Exception as e:
            log.debug(f"plyer: {e}")

    # Fallback — Windows MessageBox for CRITICAL (DISABLED)
    # if severity == "CRITICAL":
    #     try:
    #         import ctypes
    #         def _show():
    #             ctypes.windll.user32.MessageBoxW(
    #                 0,
    #                 f"💀 CRITICAL THREAT\n\n"
    #                 f"User  : {user}\n"
    #                 f"Detail: {message[:150]}\n\n"
    #                 f"Immediate action required.",
    #                 "DeepSentinel — CRITICAL ALERT",
    #                 0x10 | 0x1000
    #             )
    #         threading.Thread(target=_show, daemon=True).start()
    #         return True
    #     except Exception as e:
    #         log.debug(f"MessageBox: {e}")
    return False


def action_sound(severity):
    """Alert beep on admin machine."""
    if not SOUND_OK: return
    try:
        freq, dur = SEV_SOUNDS.get(severity, (750, 300))
        if severity == "CRITICAL":
            for _ in range(3):
                winsound.Beep(freq, dur)
                winsound.Beep(600, 200)
        else:
            winsound.Beep(freq, dur)
    except Exception as e:
        log.debug(f"Sound: {e}")


def action_quarantine(user, event_type, detail, score, event):
    """
    Save full event to quarantine folder as forensic record.
    Includes timestamp, risk score, all event details.
    """
    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe  = user.replace("@","_").replace(".","_")[:20]
    fname = f"quarantine_{ts}_{safe}.json"
    fpath = os.path.join(ROOT, "quarantine", fname)

    record = {
        "quarantine_id": fname,
        "timestamp":     datetime.now().isoformat(),
        "user":          user,
        "event_type":    event_type,
        "detail":        detail,
        "risk_score":    score,
        "severity":      "CRITICAL",
        "event_data":    event,
        "status":        "QUARANTINED",
        "reviewed":      False,
        "machine":       socket.gethostname(),
    }

    with open(fpath, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, default=str)

    log.info(f"📁 Quarantine saved → {fname}")
    return fname


def action_network_isolate(agent_id, reason):
    """
    Block internet access for the suspicious agent machine.
    Uses Windows Firewall to block outbound traffic by hostname/IP.
    Run on ADMIN machine — requires admin rights.

    NOTE: This blocks the AGENT machine's IP from the server side.
    For full isolation, run netsh on the agent machine itself.
    """
    try:
        # Get agent IP from request context if available
        agent_ip = _resolve_agent_ip(agent_id)
        if not agent_ip:
            log.warning(f"Cannot isolate {agent_id} — IP unknown")
            return False

        rule_name = f"DeepSentinel_ISOLATE_{agent_id}"

        # Add Windows Firewall rule to block agent outbound
        cmd = [
            "netsh","advfirewall","firewall","add","rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            f"remoteip={agent_ip}",
            "enable=yes",
            f"description=DeepSentinel auto-isolation: {reason[:100]}",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            log.warning(f"🔒 ISOLATED: {agent_id} ({agent_ip}) — {reason}")
            _log_isolation(agent_id, agent_ip, reason)
            return True
        else:
            log.error(f"Isolation failed: {result.stderr}")
            return False

    except Exception as e:
        log.error(f"Network isolation error: {e}")
        return False


def action_unblock(agent_id):
    """Remove network isolation for an agent."""
    try:
        rule_name = f"DeepSentinel_ISOLATE_{agent_id}"
        cmd = [
            "netsh","advfirewall","firewall","delete","rule",
            f"name={rule_name}",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            log.info(f"🔓 UNBLOCKED: {agent_id}")
            return True
        return False
    except Exception as e:
        log.error(f"Unblock error: {e}")
        return False


def action_email_alert(severity, user, event_type, detail, score):
    """Send email alert to admin. Configure ADMIN_EMAIL_CONFIG above."""
    if not ADMIN_EMAIL_CONFIG.get("enabled"):
        return False
    try:
        msg            = MIMEMultipart()
        msg['From']    = ADMIN_EMAIL_CONFIG["sender"]
        msg['To']      = ADMIN_EMAIL_CONFIG["recipient"]
        msg['Subject'] = f"[DeepSentinel] {severity} Alert — {user}"

        body = f"""
DeepSentinel Security Alert
{'='*40}
Severity  : {severity}
User      : {user}
Event     : {event_type}
Detail    : {detail}
Risk Score: {score:.3f}
Time      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*40}
Login to dashboard: http://192.168.0.107:5000/dashboard
        """
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(ADMIN_EMAIL_CONFIG["smtp_host"],
                          ADMIN_EMAIL_CONFIG["smtp_port"]) as s:
            s.starttls()
            s.login(ADMIN_EMAIL_CONFIG["sender"],
                    ADMIN_EMAIL_CONFIG["password"])
            s.send_message(msg)

        log.info(f"📧 Email alert sent to {ADMIN_EMAIL_CONFIG['recipient']}")
        return True
    except Exception as e:
        log.error(f"Email alert: {e}")
        return False


# =============================================================================
# MAIN DISPATCHER
# =============================================================================

def dispatch(event):
    """
    Main action dispatcher. Called for every incoming event.
    Runs all appropriate actions based on severity.
    Returns list of actions taken.
    """
    score      = float(event.get("risk_score", 0))
    severity   = _score_to_sev(score)
    user       = str(event.get("user") or event.get("agent_id") or "unknown")
    event_type = str(event.get("event_type", "event"))
    action     = str(event.get("action", ""))
    detail     = str(
        event.get("email_subject") or
        event.get("details") or
        event.get("path") or
        action or "event"
    )[:100]

    if severity == "LOW" and score < 0.30:
        return []   # Too low — ignore

    taken = []
    icon  = SEV_ICONS.get(severity, "⚪")

    # Print to server console
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\n[{ts}] {icon} {severity:<8} | {user:<30} | {detail[:50]}")

    # ── ALWAYS: structured log ─────────────────────────────────────────────
    log_entry = action_log(severity, user, event_type, detail, score, event)
    taken.append("logged")

    # ── MEDIUM+ : desktop notification ────────────────────────────────────
    # ONLY show notification if throttle allows (max 1 per minute per user per severity)
    if severity in ("MEDIUM","HIGH","CRITICAL") and _should_send_notification(user, severity):
        ok = action_notify(severity, user, f"{event_type} alert", detail)
        if ok: taken.append("notified")

    # ── CRITICAL : sound ───────────────────────────────────────────────────
    # Keep the dashboard usable: HIGH can be noisy in real environments.
    if severity in ("CRITICAL",):
        threading.Thread(
            target=action_sound, args=(severity,), daemon=True).start()
        taken.append("sound")

    # ── HIGH+ : email to admin ─────────────────────────────────────────────
    if severity in ("HIGH","CRITICAL"):
        threading.Thread(
            target=action_email_alert,
            args=(severity, user, event_type, detail, score),
            daemon=True
        ).start()
        if ADMIN_EMAIL_CONFIG.get("enabled"):
            taken.append("email_alert")

    # ── CRITICAL : quarantine ─────────────────────────────────────────────
    if severity == "CRITICAL":
        fname = action_quarantine(user, event_type, detail, score, event)
        taken.append(f"quarantine:{fname}")

    # ── CRITICAL : network isolation ──────────────────────────────────────
    if severity == "CRITICAL":
        agent_id = event.get("agent_id","")
        if agent_id:
            threading.Thread(
                target=action_network_isolate,
                args=(agent_id, detail),
                daemon=True
            ).start()
            taken.append(f"isolating:{agent_id}")

    log.info(f"Actions taken: {taken}")
    return taken


# =============================================================================
# WIRE INTO server.py
# =============================================================================

def wire(app):
    """Patches /receive_log to trigger actions on every event."""
    try:
        original = app.view_functions['receive_log']
    except KeyError:
        print("⚠️  receive_log not found — cannot wire actions")
        return

    def patched():
        from flask import request
        response = original()
        try:
            data   = request.get_json(force=True, silent=True) or {}
            events = data.get('events', [])
            if not events and 'event_type' in data:
                events = [data]
            for evt in events:
                score = float(evt.get('risk_score', 0))
                if score >= 0.30:
                    threading.Thread(
                        target=dispatch, args=(evt,), daemon=True).start()
        except Exception as e:
            log.error(f"Action wire error: {e}")
        return response

    app.view_functions['receive_log'] = patched
    print("✅ Action engine wired into /receive_log")
    print("   LOW      → log")
    print("   MEDIUM   → log + notification")
    print("   HIGH     → log + notification + sound + email")
    print("   CRITICAL → all above + quarantine + network isolation")


# =============================================================================
# HELPERS
# =============================================================================

_agent_ip_cache = {}

def _resolve_agent_ip(agent_id):
    """Try to resolve agent machine IP."""
    if agent_id in _agent_ip_cache:
        return _agent_ip_cache[agent_id]
    try:
        ip = socket.gethostbyname(agent_id)
        _agent_ip_cache[agent_id] = ip
        return ip
    except:
        return None


def _log_isolation(agent_id, ip, reason):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "action":    "network_isolation",
        "agent_id":  agent_id,
        "ip":        ip,
        "reason":    reason,
        "status":    "ISOLATED",
    }
    path = os.path.join(ROOT, "logs", "isolations.jsonl")
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


# =============================================================================
# ADD TO server.py
# =============================================================================

class ActionEngine:
    """Simple wrapper — use: action_engine = ActionEngine(); action_engine.wire(app)"""
    def wire(self, app):
        wire(app)
