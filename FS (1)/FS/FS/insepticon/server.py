from flask import Flask, request, jsonify, render_template_string, render_template, send_file, redirect, Response, session
import json
import os
import re
import hashlib
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import sys as _sys

def local_now():
    return datetime.now()


def local_iso():
    return local_now().isoformat()


def is_after_office_hours(hour):
    try:
        hour = int(hour)
    except Exception:
        hour = local_now().hour
    return hour < 9 or hour >= 17

# Ensure stdout/stderr use UTF-8 on Windows consoles to avoid
# UnicodeEncodeError when printing emoji or other non-encodable chars.
try:
    if hasattr(_sys.stdout, 'reconfigure'):
        _sys.stdout.reconfigure(encoding='utf-8')
    else:
        # Fallback for older Python: wrap streams (best-effort)
        import io as _io
        _sys.stdout = _io.TextIOWrapper(_sys.stdout.buffer, encoding='utf-8', errors='replace')
        _sys.stderr = _io.TextIOWrapper(_sys.stderr.buffer, encoding='utf-8', errors='replace')
except Exception:
    # If reconfiguration fails, continue without crashing; prints may still raise elsewhere.
    pass

# Import model
try:
    import sys
    # add the project directory (this file's parent) to path so relative imports work
    proj_dir = os.path.dirname(__file__)
    if proj_dir not in sys.path:
        sys.path.append(proj_dir)
    from connect_models import threat_model
    print("✅ Using trained models")
except:
    class SimpleThreatModel:
        def predict_with_explanation(self, event):
            risk = 0.0
            reasons = []
            if event.get('is_executable'): risk += 0.4; reasons.append("Application launch")
            if event.get('is_document') and event.get('action') == 'file_deleted': risk += 0.6; reasons.append("Document deletion")
            if event.get('event_type') == 'usb': risk += 0.7; reasons.append("USB activity")
            if event.get('is_remote'): risk += 0.5; reasons.append("Remote access")
            hour = event.get('hour_of_day', 12)
            if hour < 7 or hour > 20: risk += 0.3; reasons.append("After hours")
            return min(risk, 1.0), {"top_factors": reasons[:2]}
    threat_model = SimpleThreatModel()

# Import critical systems
try:
    from incident_manager import IncidentManager
    incident_mgr = IncidentManager()
except Exception as e:
    print(f"⚠️  Incident manager not available: {e}")
    incident_mgr = None

# Import LLM Report Generator
try:
    from incident_report_generator_v2 import IncidentReportGeneratorV2 as IncidentReportGenerator, UserBehaviorReportGenerator
    print("✅ LLM Report Generator v2 loaded (with automatic risk scoring)")
    print("✅ Incident management system initialized")
except Exception as e:
    incident_mgr = None
    print(f"⚠️ Failed to load incident manager: {e}")

try:
    from audit_trail import AuditTrail
    audit_trail = AuditTrail()
    print("✅ Audit trail system initialized")
except Exception as e:
    audit_trail = None
    print(f"⚠️ Failed to load audit trail: {e}")

try:
    from user_risk_scoring import UserRiskScorer
    risk_scorer = UserRiskScorer()
    print("✅ User risk scoring system initialized")
except Exception as e:
    risk_scorer = None
    print(f"⚠️ Failed to load risk scorer: {e}")

try:
    from realtime_notifications import NotificationManager
    notif_mgr = NotificationManager()
    print("✅ Real-time notification system initialized")
except Exception as e:
    notif_mgr = None
    print(f"⚠️ Failed to load notification manager: {e}")

try:
    from screen_recording_addon import ScreenRecordingManager
    recording_mgr = ScreenRecordingManager()
    print("✅ Screen recording system initialized")
except Exception as e:
    recording_mgr = None
    print(f"⚠️ Failed to load screen recording manager: {e}")

try:
    from clipboard_monitor import ClipboardMonitor
    clipboard_monitor = ClipboardMonitor()
    print("✅ Clipboard monitoring system initialized")
except Exception as e:
    clipboard_monitor = None
    print(f"⚠️ Failed to load clipboard monitor: {e}")

try:
    from malicious_file_detector import MaliciousFileDetector
    file_detector = MaliciousFileDetector()
    print("✅ Malicious file detection system initialized")
except Exception as e:
    file_detector = None
    print(f"⚠️ Failed to load malicious file detector: {e}")

try:
    from high_risk_alerts_manager import HighRiskAlertManager
    high_risk_alerts = HighRiskAlertManager()
    print("✅ High-risk alert management system initialized")
except Exception as e:
    high_risk_alerts = None
    print(f"⚠️ Failed to load high-risk alert manager: {e}")

try:
    from outlook_integration import OutlookIntegration
    outlook_notifier = OutlookIntegration()
    print("✅ Outlook integration system initialized")
except Exception as e:
    outlook_notifier = None
    print(f"⚠️ Failed to load outlook integration: {e}")

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'deepsentinel-default-key-change-in-production')

# Session configuration
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

events_log = []
event_counter = Counter()

# Threshold/config persistence
CONFIG_PATH = "config.json"
ALERTS_PATH = os.path.join("data", "alerts.jsonl")
EVENTS_PATH = os.path.join("data", "user_activity.jsonl")
os.makedirs('data', exist_ok=True)

# Default config (will be created if missing)
DEFAULT_CONFIG = {
    "thresholds": {
        "files_created_today": 12,
        "http_requests_today": 500,
        "bytes_downloaded_today": 104857600,  # 100 MB
        "large_usb_transfer_bytes": 52428800  # 50 MB
    },
    # risk threshold for marking "critical" on dashboard
    "risk_display_threshold": 0.7
}

def load_config():
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        return DEFAULT_CONFIG.copy()
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        # merge missing keys
        for k, v in DEFAULT_CONFIG.items():
            if k not in cfg:
                cfg[k] = v
        return cfg
    except Exception:
        return DEFAULT_CONFIG.copy()

def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

config = load_config()
RISK_THRESHOLD = config.get("risk_display_threshold", 0.7)

# Per-user daily counters and alerts store
user_counters = defaultdict(lambda: defaultdict(int))
user_last_reset = defaultdict(lambda: local_now())
alerts = []  # in-memory, also appended to file for persistence

# Session tracking for logon/logoff
user_sessions = defaultdict(list)  # {username: [{'login': datetime, 'logout': datetime, ...}]}
active_sessions = {}  # {username: {'login_time': datetime, 'agent_id': str, ...}}

# User activity summary for risk scoring
user_activity_summary = defaultdict(lambda: defaultdict(int))  # {user: {event_type: count, ...}}
user_risk_cache = {}  # Cache of calculated risk scores

def generate_sample_data():
    """Generate sample events for demonstration if no events exist"""
    global events_log, event_counter
    
    if len(events_log) > 0:
        return  # Don't generate if data already exists
    
    sample_users = ['john_doe', 'alice_smith', 'bob_wilson', 'carol_nash']
    now = datetime.utcnow()
    
    sample_events = [
        {'event_type': 'file', 'action': 'created', 'path': 'C:\\Users\\john_doe\\Desktop\\sensitive.pdf', 'risk_score': 0.45},
        {'event_type': 'logon', 'action': 'login', 'user': 'alice_smith', 'logon_type_name': 'Interactive', 'risk_score': 0.1},
        {'event_type': 'usb', 'action': 'device_connected', 'drive': 'Kingston USB', 'total_size_gb': 64, 'risk_score': 0.6},
        {'event_type': 'file', 'action': 'modified', 'path': 'C:\\Users\\bob_wilson\\Documents\\report.xlsx', 'risk_score': 0.3},
        {'event_type': 'clipboard', 'action': 'copy', 'content_snippet': 'sensitive data from clipboard', 'risk_score': 0.65},
        {'event_type': 'process', 'action': 'started', 'process_name': 'powershell.exe', 'risk_score': 0.4},
        {'event_type': 'outlook', 'action': 'email_sent', 'email_subject': 'Test email', 'risk_score': 0.2},
        {'event_type': 'file', 'action': 'deleted', 'path': 'C:\\Users\\carol_nash\\Documents\\archived.zip', 'risk_score': 0.55},
    ]
    
    for i, sample in enumerate(sample_events):
        user = sample_users[i % len(sample_users)]
        event = {
            'timestamp': (now - timedelta(minutes=30-i*5)).isoformat(),
            'agent_id': user,
            'user': user if sample.get('event_type') != 'usb' else None,
            'username': user,
            'event_type': sample['event_type'],
            'action': sample['action'],
            'risk_score': sample['risk_score']
        }
        event.update({k: v for k, v in sample.items() if k not in ['event_type', 'action', 'risk_score']})
        events_log.append(event)
        event_counter[sample['event_type']] += 1
    
    print(f"📊 Generated {len(sample_events)} sample events for demonstration")

def persist_alert(alert):
    try:
        with open(ALERTS_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")
    except Exception as e:
        print("⚠️ Failed to persist alert:", e)

def track_logon_event(user, agent_id, event):
    """Track when user logs on"""
    global active_sessions
    login_time = local_now()
    try:
        login_time = datetime.fromisoformat(event.get('timestamp', login_time.isoformat()))
    except:
        pass
    
    active_sessions[user] = {
        'login_time': login_time,
        'agent_id': agent_id,
        'logon_type': event.get('logon_type', 'Interactive'),
        'session_id': event.get('session_id', 'N/A')
    }
    
    if user not in user_sessions:
        user_sessions[user] = []
    
    # If there's an active session, close it first
    if user_sessions[user] and not user_sessions[user][-1].get('logout_time'):
        user_sessions[user][-1]['logout_time'] = login_time - timedelta(seconds=1)
    
    user_sessions[user].append({
        'login_time': login_time,
        'logout_time': None,
        'agent_id': agent_id,
        'logon_type': event.get('logon_type', 'Interactive')
    })

def track_logoff_event(user, event):
    """Track when user logs off"""
    global active_sessions
    logout_time = local_now()
    try:
        logout_time = datetime.fromisoformat(event.get('timestamp', logout_time.isoformat()))
    except:
        pass
    
    if user in active_sessions:
        del active_sessions[user]
    
    if user in user_sessions and user_sessions[user]:
        for session in reversed(user_sessions[user]):
            if not session.get('logout_time'):
                session['logout_time'] = logout_time
                session['duration_seconds'] = int((logout_time - session['login_time']).total_seconds())
                break

def calculate_composite_user_risk(user):
    """Calculate composite risk score for a user based on their activities"""
    global user_risk_cache, user_activity_summary
    
    # Get all events for this user
    user_events = [e for e in events_log if (e.get('user') == user or e.get('username') == user or e.get('agent_id') == user)]
    
    if not user_events:
        return None
    
    # Calculate various risk factors
    risk_factors = {
        'email_risk': 0.0,
        'behavioral_deviation': 0.0,
        'peer_anomaly': 0.0,
        'threat_activity': 0.0,
        'login_risk': 0.0
    }
    
    # Email risk - check for phishing, malware in emails
    email_events = [e for e in user_events if e.get('event_type') in ['outlook', 'imap', 'email_sent']]
    suspicious_email_count = len([e for e in email_events if e.get('risk_score', 0) > 0.7])
    if email_events:
        risk_factors['email_risk'] = min(1.0, suspicious_email_count / max(1, len(email_events)))
    
    # Behavioral deviation - detect unusual hours
    logon_events = [e for e in user_events if e.get('event_type') in ['logon', 'session']]
    unusual_hour_logins = 0
    for evt in logon_events:
        hour = evt.get('hour_of_day', 12)
        if hour < 9 or hour > 17:
            unusual_hour_logins += 1
    if logon_events:
        risk_factors['behavioral_deviation'] = min(1.0, unusual_hour_logins / max(1, len(logon_events)))
    
    # Threat activity - high risk file operations, USB activity
    threat_events = [e for e in user_events if e.get('risk_score', 0) > 0.7]
    usb_events = [e for e in user_events if e.get('event_type') == 'usb']
    if user_events:
        risk_factors['threat_activity'] = min(1.0, (len(threat_events) + len(usb_events) * 0.5) / max(1, len(user_events)))
    
    # Login risk - failed logins or unusual patterns
    if len(logon_events) > 5:  # If user has many logins
        risk_factors['login_risk'] = min(1.0, len(logon_events) / 20.0)  # Scale by login frequency
    
    # Composite score (weighted average)
    weights = {
        'email_risk': 0.20,
        'behavioral_deviation': 0.25,
        'peer_anomaly': 0.20,
        'threat_activity': 0.20,
        'login_risk': 0.15
    }
    
    composite_score = sum(risk_factors[k] * weights[k] for k in weights)
    composite_score = min(1.0, max(0.0, composite_score))
    
    # Determine risk level
    if composite_score >= 0.80:
        risk_level = 'CRITICAL'
    elif composite_score >= 0.60:
        risk_level = 'HIGH'
    elif composite_score >= 0.40:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'
    
    risk_data = {
        'username': user,
        'risk_score': round(composite_score, 3),
        'risk_percentage': int(composite_score * 100),
        'risk_level': risk_level,
        'risk_factors': {k: round(v, 3) for k, v in risk_factors.items()},
        'event_count': len(user_events),
        'last_activity': user_events[-1].get('timestamp', 'N/A') if user_events else 'N/A',
        'timestamp': local_iso()
    }
    
    user_risk_cache[user] = risk_data
    return risk_data

def load_past_alerts(limit=200):
    out = []
    if not os.path.exists(ALERTS_PATH):
        return out
    try:
        with open(ALERTS_PATH, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    out.append(json.loads(line))
        return out[-limit:]
    except Exception:
        return out


def _fmt_audit_details(d):
    if d is None:
        return ""
    if isinstance(d, dict):
        try:
            return json.dumps(d, ensure_ascii=False)[:800]
        except Exception:
            return str(d)[:800]
    return str(d)[:800]


def normalize_audit_entries_for_ui(logs):
    """Map audit_trail records to dashboard field names (admin, action, target_user)."""
    out = []
    for entry in logs or []:
        if not isinstance(entry, dict):
            continue
        out.append({
            "timestamp": entry.get("timestamp", ""),
            "admin": entry.get("user_name") or entry.get("user_id") or "System",
            "action": entry.get("action_type") or entry.get("action") or "unknown",
            "target_user": entry.get("target") if entry.get("target") is not None else "N/A",
            "details": _fmt_audit_details(entry.get("details")),
        })
    return out


def normalize_leaderboard_row(row):
    """Unify risk_scorer + composite cache shapes for the dashboard."""
    if not isinstance(row, dict):
        return None
    uname = row.get("username") or row.get("user_name") or row.get("user_id")
    if not uname:
        return None
    try:
        rs = float(row.get("risk_score", 0) or 0)
    except (TypeError, ValueError):
        rs = 0.0
    rf = row.get("risk_factors") or row.get("factors") or {}
    return {
        "username": uname,
        "risk_score": rs,
        "risk_level": row.get("risk_level", "LOW"),
        "risk_factors": rf,
    }


def derived_incidents_from_events(limit=60):
    """Surface high-risk events as incident rows when no formal incidents exist."""
    out = []
    seen = set()
    thr = float(config.get("risk_display_threshold", RISK_THRESHOLD))
    # Scan the full in-memory timeline so we don't miss incidents
    # that occurred slightly earlier than the last sampling window.
    for e in reversed(events_log):
        try:
            rs = float(e.get("risk_score", 0) or 0)
        except (TypeError, ValueError):
            rs = 0.0
        if rs < thr:
            continue
        uid = e.get("user") or e.get("username") or e.get("agent_id") or "unknown"
        et = e.get("event_type") or "event"
        act = e.get("action") or ""
        ts = str(e.get("timestamp") or e.get("received_at") or "")
        key = (uid, et, act, ts[:19])
        if key in seen:
            continue
        seen.add(key)
        sev = "CRITICAL" if rs >= 0.9 else "HIGH" if rs >= 0.7 else "MEDIUM"
        title = f"{str(et).upper()}: {act}"[:140]
        out.append({
            "id": f"derived-{abs(hash(key)) & 0xFFFFFFFF:08x}",
            "title": title or "High-risk activity",
            "severity": sev,
            "status": "OPEN",
            "related_alerts": [],
            "affected_users": [uid],
            "timestamp": ts,
            "created_at": ts,
            "agent_id": e.get("agent_id"),
            "risk_score": rs,
            "source": "high_risk_event",
        })
        if len(out) >= limit:
            break
    return out


def reset_counters_if_needed(user):
    now = local_now()
    if (now - user_last_reset[user]) > timedelta(hours=24):
        user_counters[user] = defaultdict(int)
        user_last_reset[user] = now

# Throttle alert notifications to prevent spam
_alert_notification_throttle = {}  # {(user, metric): timestamp}

def check_and_generate_alerts(user, event=None):
    """
    Check thresholds for a user and generate alerts if violated.
    Also handles immediate alerts from specific events (like after-hours logins and USB transfers).
    Returns list of alerts generated (empty if none).
    
    Alert Throttling:
    - After-hours alerts: max 1 per 24 hours per user
    - USB transfer alerts: max 1 per 24 hours per user
    - Threshold alerts: max 1 per 24 hours per user per metric
    - Notification spam: max 1 notification per 5 minutes per user per metric
    """
    global _alert_notification_throttle
    generated = []
    
    # Handle immediate alerts from events (like after-hours logins and USB transfers)
    if event:
        today = local_now().date()
        event_type = str(event.get("event_type", "")).lower()
        action = str(event.get("action", "")).lower()
        
        # Check for after-hours login/logoff alerts
        is_session_event = event_type == "logon" or event_type in ("logoff", "logoff_session", "session_end")
        is_logoff = "logoff" in action or "logout" in action or event_type in ("logoff", "logoff_session", "session_end")
        hour = event.get("hour_of_day", local_now().hour)
        if is_session_event and (event.get("alert") or is_after_office_hours(hour)):
            metric = "after_hours_logoff" if is_logoff else "after_hours_login"
            last_after_hours = next((a for a in reversed(alerts) if 
                a['user']==user and a['metric']==metric and 
                datetime.fromisoformat(a['time']).date() == today), None)
            
            if not last_after_hours:  # Only alert once per day per user
                label = "Logoff" if is_logoff else "Login"
                alert = {
                    "time": local_iso(),
                    "user": user,
                    "agent_id": event.get("agent_id"),
                    "metric": metric,
                    "value": hour,
                    "limit": "9:00-17:00",
                    "note": event.get("alert_message", f"SECURITY ALERT: {label} at {int(hour):02d}:00 - Outside business hours (09:00-17:00)"),
                    "severity": "HIGH"
                }
                alerts.append(alert)
                persist_alert(alert)
                generated.append(alert)
        
        # Check for large USB file transfer alerts.
        if event_type == "usb" and action in ("large_file_transfer", "file_copied", "file_created", "file_modified"):
            file_size = float(event.get("file_size", 0) or 0)
            limit_bytes = float(config.get("thresholds", {}).get("large_usb_transfer_bytes", 50 * 1024 * 1024))
            if file_size >= limit_bytes:
                last_usb = next((a for a in reversed(alerts) if 
                    a['user']==user and a['metric']=='large_usb_transfer' and 
                    datetime.fromisoformat(a['time']).date() == today), None)
                
                if not last_usb:  # Only alert once per day per user
                    alert = {
                        "time": local_iso(),
                        "user": user,
                        "agent_id": event.get("agent_id"),
                        "metric": "large_usb_transfer",
                        "value": file_size,
                        "limit": limit_bytes,
                        "note": (
                            f"CRITICAL: Large file transferred to USB - "
                            f"{file_size / (1024 * 1024):.1f} MB "
                            f"({event.get('relative_path') or event.get('file_name') or event.get('path') or 'Unknown file'})"
                        ),
                        "severity": "CRITICAL"
                    }
                    alerts.append(alert)
                    persist_alert(alert)
                    generated.append(alert)
        
        return generated

    # Regular threshold checks - only generate alerts once per 24 hours per metric
    thresholds = config.get("thresholds", {})
    for metric, limit in thresholds.items():
        value = user_counters[user].get(metric, 0)
        if value > limit:
            # Check if we've already generated a same-day alert for this metric & user
            today = local_now().date()
            last_same = next((a for a in reversed(alerts) if 
                a['user']==user and a['metric']==metric and 
                datetime.fromisoformat(a['time']).date() == today), None)
            
            if last_same:
                continue  # skip duplicate alert (already alerted today)
            
            alert = {
                "time": local_iso(),
                "user": user,
                "agent_id": event.get("agent_id") if event else None,
                "metric": metric,
                "value": value,
                "limit": limit,
                "note": f"{metric} exceeded threshold ({value} > {limit})",
                "severity": "MEDIUM"
            }
            alerts.append(alert)
            persist_alert(alert)
            generated.append(alert)
    return generated

# Load persisted alerts into memory on start
alerts = load_past_alerts(limit=500)

EVENTS_FIXED = os.path.join('data', 'user_activity.jsonl.fixed')
CORRUPT_LOG_PATH = os.path.join('data', 'user_activity.jsonl.corrupt.log')


def _sanitize_str(v, max_len=128):
    """Sanitize a string to remove newlines/control characters and trim length."""
    if not isinstance(v, str):
        return v
    s = v.replace('\n', ' ').replace('\r', ' ').strip()
    s = re.sub(r'[\x00-\x1f\x7f]', '', s)
    if len(s) > max_len:
        s = s[:max_len]
    return s


def _derive_file_risk_features(evt):
    """
    Backfill file-event features expected by the hybrid scorer so the server can
    rescore file_agent events instead of relying only on the agent's local heuristic.
    """
    if not isinstance(evt, dict) or evt.get("event_type") != "file":
        return evt

    path = str(evt.get("path") or evt.get("file_path") or evt.get("dest") or "")
    path_low = path.lower()
    ext = str(evt.get("file_extension") or os.path.splitext(path)[1] or "").lower()
    keywords_found = evt.get("keywords_found") or []

    evt["path"] = path
    evt.setdefault("file_extension", ext)
    evt.setdefault("is_document", ext in {
        ".txt", ".csv", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
        ".ppt", ".pptx", ".md", ".json", ".xml", ".sql"
    })
    evt.setdefault("is_executable", ext in {
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".scr",
        ".msi", ".com", ".jar"
    })
    evt.setdefault(
        "in_sensitive_path",
        any(token in path_low for token in [
            "\\desktop", "\\documents", "\\downloads", "\\onedrive",
            "confidential", "finance", "hr", "payroll", "client", "secret"
        ])
    )
    evt.setdefault("has_special_chars", bool(keywords_found))
    return evt


def _should_use_hybrid_model_scoring(evt):
    """
    File-agent events already include a coarse local score for screenshots/console UX,
    but the server should recompute the final score using the hybrid ML path.
    """
    if not isinstance(evt, dict):
        return False
    return str(evt.get("event_type", "")).strip().lower() == "file"


def _is_email_event(evt):
    if not isinstance(evt, dict):
        return False
    evt_type = str(evt.get("event_type", "")).strip().lower()
    action = str(evt.get("action", "")).strip().lower()
    return evt_type in ("outlook", "imap", "email", "email_sent", "email_received") or action in ("email_sent", "email_received")


def _build_email_ml_payload(evt):
    """
    Normalize an Outlook/IMAP event into the structure expected by the email ML.
    This includes attachment preview text when the agent captured it.
    """
    subject = str(evt.get("email_subject") or evt.get("subject") or "").strip()
    body = str(evt.get("email_body") or evt.get("body") or "").strip()
    sender = str(evt.get("email_sender") or evt.get("sender") or "").strip()
    recipients = evt.get("email_recipients") or evt.get("recipients") or []
    if not isinstance(recipients, list):
        recipients = [str(recipients)] if recipients else []

    attachments = evt.get("attachments") or []
    attachment_snippets = []
    has_executable_attachment = False
    has_sensitive_files = False
    attachment_risk_score = 0.0

    for att in attachments[:5]:
        if not isinstance(att, dict):
            continue
        name = str(att.get("name") or "")
        ext = str(att.get("type") or os.path.splitext(name)[1] or "").lower()
        preview = str(att.get("content_preview") or "").strip()
        if preview:
            attachment_snippets.append(preview)

        if ext in {".exe", ".dll", ".bat", ".cmd", ".scr", ".vbs", ".js", ".jar", ".msi"}:
            has_executable_attachment = True
            attachment_risk_score = max(attachment_risk_score, 0.9)
        elif ext in {".zip", ".rar", ".7z", ".tar", ".sql", ".bak"}:
            attachment_risk_score = max(attachment_risk_score, 0.55)
        elif ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".ppt", ".pptx"}:
            has_sensitive_files = True
            attachment_risk_score = max(attachment_risk_score, 0.35)

    combined_text = "\n".join(part for part in [
        subject,
        body,
        "\n".join(attachment_snippets)
    ] if part).strip()
    text_lower = combined_text.lower()

    has_credential_keywords = any(
        kw in text_lower for kw in ["password", "credential", "secret", "api key", "token", "auth"]
    )
    has_urgency_keywords = any(
        kw in text_lower for kw in ["urgent", "immediate", "act now", "verify account", "confirm identity", "action required"]
    )
    has_confidential_content = any(
        kw in text_lower for kw in [
            "confidential", "top secret", "classified", "do not share",
            "internal use only", "trade secret", "proprietary",
            "salary", "client list", "account number", "credit card", "ssn"
        ]
    )

    return {
        "email_text": combined_text,
        "metadata": {
            "sender": sender,
            "recipients": recipients,
            "attachments": attachments,
            "body_length": int(evt.get("body_length", len(body)) or len(body)),
            "has_external": bool(evt.get("has_external", False)),
            "has_executable_attachment": has_executable_attachment,
            "has_credential_keywords": has_credential_keywords,
            "has_urgency_keywords": has_urgency_keywords,
            "attachment_risk_score": attachment_risk_score,
            "has_confidential_content": has_confidential_content,
            "has_sensitive_files": has_sensitive_files,
            "body_content_risk": 0.5 if has_confidential_content else 0.0,
        }
    }


def _format_email_event_details(evt):
    """
    Build a concise but useful dashboard summary for email events.
    Prefer subject, then body snippet, recipients, attachment names, and ML explanation.
    """
    if not isinstance(evt, dict):
        return "[Email event]"

    subject = str(evt.get("email_subject") or evt.get("subject") or "").strip()
    body = str(evt.get("email_body") or evt.get("body") or "").strip()
    recipients = evt.get("email_recipients") or evt.get("recipients") or []
    if not isinstance(recipients, list):
        recipients = [str(recipients)] if recipients else []
    attachments = evt.get("attachments") or []
    explanation = evt.get("explanation") or []
    if not isinstance(explanation, list):
        explanation = [str(explanation)]

    parts = []
    parts.append(f"Subject: {subject or '(no subject)'}")
    if body:
        snippet = body.replace("\r", " ").replace("\n", " ").strip()
        parts.append(f"Body: {snippet[:120]}")
    if recipients:
        parts.append(f"To: {', '.join(str(x) for x in recipients[:3])}")
    if attachments:
        attachment_names = [str(a.get("name", "")) for a in attachments[:3] if isinstance(a, dict)]
        if attachment_names:
            parts.append(f"Attachments: {', '.join(attachment_names)}")
    if explanation:
        parts.append(f"ML: {explanation[0]}")
    return " | ".join(parts)


def _derive_email_queue_classification(evt, approval_th, block_th):
    """
    Build queue classification from the already-computed ML email result.
    High-risk emails should also land in the approval queue so an admin can
    explicitly approve or reject them.
    """
    rs = float(evt.get('risk_score', 0.0) or 0.0)
    reasons = evt.get('explanation') or evt.get('reasons') or []
    if not isinstance(reasons, list):
        reasons = [str(reasons)]

    level = 'LOW'
    recommended_action = 'allow'
    if rs >= block_th:
        level = 'HIGH'
        recommended_action = 'block'
    elif rs >= approval_th:
        level = 'MEDIUM'
        recommended_action = 'approve'

    # Respect the ML explanation when it explicitly says HIGH / CRITICAL.
    joined = " ".join(str(x) for x in reasons).upper()
    if 'CRITICAL' in joined:
        level = 'HIGH'
        recommended_action = 'block'
    elif 'HIGH' in joined and level == 'MEDIUM':
        level = 'HIGH'
        recommended_action = 'block'

    return {
        'classification': level,
        'risk_score': round(rs, 3),
        'reasons': reasons,
        'action': recommended_action,
        'timestamp': datetime.now().isoformat(),
        'source': 'outlook_ml_queue',
    }


def _expand_possible_wrapper(raw_evt):
    """Given a persisted line (raw_evt), expand batch/legacy wrappers into a list of event dicts.
    This ensures old-style entries like { 'events': [ ... ] } or { 'event': {...}, 'risk_score': ... }
    don't appear as a single UNKNOWN row in the UI.
    """
    out = []
    try:
        # handle list input: if the raw input is already a list, iterate through it
        if isinstance(raw_evt, list):
            for item in raw_evt:
                out.extend(_expand_possible_wrapper(item))
            return out
        
        if isinstance(raw_evt, dict):
            # batch wrapper: { 'agent_id': '...', 'events': [ {...}, ... ] }
            if 'events' in raw_evt and isinstance(raw_evt['events'], list):
                for sub in raw_evt['events']:
                    if isinstance(sub, dict):
                        if 'agent_id' not in sub and isinstance(raw_evt.get('agent_id'), str):
                            sub['agent_id'] = raw_evt.get('agent_id')
                        out.append(sub)
                return out
            # legacy wrapper: { 'event': {...}, 'risk_score': ... }
            if 'event' in raw_evt and isinstance(raw_evt['event'], dict):
                ev = raw_evt['event']
                # prefer the wrapped risk_score/explanation if present
                if 'risk_score' not in ev and 'risk_score' in raw_evt:
                    ev['risk_score'] = raw_evt.get('risk_score', 0.0)
                if 'explanation' not in ev and 'explanation' in raw_evt:
                    ev['explanation'] = raw_evt.get('explanation', [])
                out.append(ev)
                return out
        # default: treat raw_evt as a single event (only if it's dict-like or a non-list object)
        if isinstance(raw_evt, dict):
            out.append(raw_evt)
        return out
    except Exception:
        # only append if it's a dict, otherwise skip malformed data
        if isinstance(raw_evt, dict):
            return [raw_evt]
        return []


def load_events_from_jsonl():
    """Robust loader for historical JSONL. Prefers a .fixed file when available.
    Quarantines unsalvageable lines to CORRUPT_LOG_PATH and continues loading.
    """
    source = EVENTS_FIXED if os.path.exists(EVENTS_FIXED) else EVENTS_PATH
    decoder = json.JSONDecoder()
    loaded = 0
    quarantined = 0
    try:
        with open(source, 'r', encoding='utf-8', errors='replace') as f, open(CORRUPT_LOG_PATH, 'a', encoding='utf-8') as corrupt_f:
            for lineno, raw in enumerate(f, start=1):
                line = raw.strip()
                if not line:
                    continue

                # try fast-path
                try:
                    obj = json.loads(line)
                    for ev in _expand_possible_wrapper(obj):
                        # sanitize top-level user/agent_id and common nested usernames
                        if isinstance(ev, dict):
                            if 'user' in ev:
                                ev['user'] = _sanitize_str(ev['user'])
                            if 'agent_id' in ev:
                                ev['agent_id'] = _sanitize_str(ev['agent_id'])
                            if isinstance(ev.get('details'), dict) and isinstance(ev['details'].get('process_info'), dict):
                                pi = ev['details']['process_info']
                                if 'username' in pi:
                                    pi['username'] = _sanitize_str(pi['username'])
                        events_log.append(ev)
                    loaded += 1
                    continue
                except json.JSONDecodeError:
                    pass

                # try to raw-decode possibly-concatenated objects
                idx = 0
                length = len(line)
                consumed_any = False
                success_full = True
                while idx < length:
                    while idx < length and line[idx].isspace():
                        idx += 1
                    if idx >= length:
                        break
                    try:
                        obj, end = decoder.raw_decode(line, idx)
                        consumed_any = True
                        for ev in _expand_possible_wrapper(obj):
                            if isinstance(ev, dict):
                                if 'user' in ev:
                                    ev['user'] = _sanitize_str(ev['user'])
                                if 'agent_id' in ev:
                                    ev['agent_id'] = _sanitize_str(ev['agent_id'])
                            events_log.append(ev)
                        idx = end
                    except json.JSONDecodeError:
                        success_full = False
                        break

                if success_full and consumed_any:
                    loaded += 1
                    continue

                # otherwise quarantine this line for manual inspection
                corrupt_f.write(f"# LINE {lineno} SOURCE {source}\n")
                corrupt_f.write(line + '\n\n')
                quarantined += 1

        if quarantined:
            print(f"Loaded {loaded} events; quarantined {quarantined} malformed lines (see {CORRUPT_LOG_PATH})")
        else:
            print(f"Loaded {loaded} events from {source}")
    except Exception as e:
        print('Could not load historical events:', e)


# Run robust loader at startup
load_events_from_jsonl()

# Rebuild event_counter from persisted events so dashboard stats reflect historical data
try:
    event_counter = Counter([e.get('event_type', 'unknown') for e in events_log])
except Exception:
    event_counter = Counter()

# Template helper functions
def event_summary(event):
    """Create a summary string for events"""
    if event.get('event_type') == 'file':
        return f"File {event.get('action', '')}: {event.get('path', '')}"
    elif event.get('event_type') == 'usb':
        return f"USB {event.get('action', '')}: {event.get('drive', '')}"
    elif event.get('event_type') == 'logon':
        return f"Logon: {event.get('user', '')} - {event.get('logon_type_name', '')}"
    else:
        return str(event.get('details', 'N/A'))

# Add template filters
@app.template_filter('tojson')
def to_json_filter(value):
    return json.dumps(value)

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Insider Threat SIEM</title>
    <meta charset="UTF-8">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Inter', -apple-system, sans-serif;
            background: #0B0F19;
            color: #E5E7EB;
            display: flex;
            height: 100vh;
            overflow: hidden;
        }
        
        /* Sidebar */
        .sidebar {
            width: 280px;
            background: linear-gradient(180deg, #1a1f2e 0%, #0f1419 100%);
            border-right: 1px solid #1F2937;
            display: flex;
            flex-direction: column;
            position: relative;
            box-shadow: 4px 0 24px rgba(0,0,0,0.3);
        }
        
        .sidebar-header {
            padding: 2rem 1.5rem;
            border-bottom: 1px solid #1F2937;
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 14px;
        }
        
        .logo-icon {
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, #60a5fa, #549af0);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            box-shadow: 0 8px 16px rgba(99, 102, 241, 0.3);
        }
        
        .logo-text h1 {
            font-size: 1.4rem;
            font-weight: 700;
            background: linear-gradient(135deg, #60a5fa, #2065ba);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -0.02em;
        }
        
        .logo-text p {
            font-size: 0.8rem;
            color: #6B7280;
            font-weight: 500;
            margin-top: 2px;
        }
        
        .nav-section {
            padding: 1.5rem 0;
        }
        
        .nav-title {
            padding: 0 1.5rem 0.75rem;
            font-size: 0.7rem;
            color: #6B7280;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.1em;
        }
        
        .nav-item {
            padding: 0.875rem 1.5rem;
            color: #9CA3AF;
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 14px;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            cursor: pointer;
            position: relative;
            font-weight: 500;
            font-size: 0.95rem;
        }
        
        .nav-item::before {
            content: '';
            position: absolute;
            left: 0;
            top: 50%;
            transform: translateY(-50%);
            width: 3px;
            height: 0;
            background: linear-gradient(180deg, #60a5fa, #549af0);
            border-radius: 0 2px 2px 0;
            transition: height 0.2s;
        }
        
        .nav-item:hover, .nav-item.active {
            background: rgba(99, 102, 241, 0.08);
            color: #2065ba;
        }
        
        .nav-item.active::before {
            height: 60%;
        }
        
        .nav-icon {
            font-size: 1.2rem;
            width: 24px;
            text-align: center;
        }
        
        .nav-badge {
            margin-left: auto;
            background: rgba(239, 68, 68, 0.2);
            color: #F87171;
            padding: 0.25rem 0.6rem;
            border-radius: 8px;
            font-size: 0.75rem;
            font-weight: 700;
        }
        
        /* Main Content */
        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }
        
        /* Header */
        .header {
            background: linear-gradient(90deg, #1a1f2e 0%, #0f1419 100%);
            border-bottom: 1px solid #1F2937;
            padding: 1.25rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
            position: relative;
            z-index: 10;
        }
        
        .header-left h2 {
            font-size: 1.75rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            margin-bottom: 0.25rem;
        }
        
        .header-subtitle {
            font-size: 0.9rem;
            color: #6B7280;
            font-weight: 500;
        }
        
        .header-right {
            display: flex;
            gap: 1rem;
            align-items: center;
        }
        
        .header-status {
            display: flex;
            align-items: center;
            gap: 10px;
            background: rgba(16, 185, 129, 0.1);
            padding: 0.6rem 1.2rem;
            border-radius: 12px;
            border: 1px solid rgba(16, 185, 129, 0.2);
        }

        .back-button {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem 1rem;
            border-radius: 9999px;
            border: 1px solid rgba(99, 102, 241, 0.35);
            color: #2065ba;
            background: rgba(15, 23, 42, 0.8);
            text-decoration: none;
            font-weight: 600;
            transition: background 0.2s ease, color 0.2s ease, border-color 0.2s ease;
        }

        .back-button:hover {
            background: rgba(99, 102, 241, 0.15);
            color: #E5E7EB;
            border-color: #60a5fa;
        }
        
        .status-dot {
            width: 10px;
            height: 10px;
            background: #10B981;
            border-radius: 50%;
            box-shadow: 0 0 12px rgba(16, 185, 129, 0.6);
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.7; transform: scale(1.1); }
        }
        
        /* Content Area */
        .content {
            flex: 1;
            padding: 2rem;
            overflow-y: auto;
            background: #0B0F19;
        }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
            animation: fadeInUp 0.5s ease;
        }
        
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .stat-card {
            background: linear-gradient(135deg, #1a1f2e 0%, #0f1419 100%);
            border: 1px solid #1F2937;
            border-radius: 16px;
            padding: 1.75rem;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #60a5fa, #549af0);
            transform: scaleX(0);
            transition: transform 0.3s;
        }
        
        .stat-card:hover::before {
            transform: scaleX(1);
        }
        
        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 12px 32px rgba(99, 102, 241, 0.15);
            border-color: #374151;
        }
        
        .stat-label {
            font-size: 0.875rem;
            color: #9CA3AF;
            font-weight: 600;
            margin-bottom: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .stat-value {
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, #60a5fa, #2065ba);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            line-height: 1;
        }
        
        /* Threshold Control */
        .threshold-box {
            background: linear-gradient(135deg, #1a1f2e, #0f1419);
            border: 1px solid #1F2937;
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
            animation: fadeInUp 0.6s ease;
        }
        
        .threshold-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }
        
        .threshold-title {
            font-size: 1.1rem;
            font-weight: 700;
            color: #E5E7EB;
        }
        
        .threshold-value {
            font-size: 2rem;
            font-weight: 700;
            color: #60a5fa;
        }
        
        .slider {
            width: 100%;
            height: 8px;
            background: #1F2937;
            border-radius: 4px;
            outline: none;
            -webkit-appearance: none;
            cursor: pointer;
        }
        
        .slider::-webkit-slider-thumb {
            -webkit-appearance: none;
            width: 24px;
            height: 24px;
            background: linear-gradient(135deg, #60a5fa, #549af0);
            border-radius: 50%;
            cursor: pointer;
            box-shadow: 0 4px 12px rgba(99, 102, 241, 0.4);
            transition: transform 0.2s;
        }
        
        .slider::-webkit-slider-thumb:hover {
            transform: scale(1.2);
        }
        
        .threshold-labels {
            display: flex;
            justify-content: space-between;
            font-size: 0.75rem;
            color: #6B7280;
            margin-top: 0.75rem;
        }
        
        /* Controls */
        .controls {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 0.875rem 1.75rem;
            border: none;
            border-radius: 12px;
            font-weight: 600;
            cursor: pointer;
            background: linear-gradient(135deg, #60a5fa, #549af0);
            color: white;
            transition: all 0.3s;
            font-size: 0.95rem;
            box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3);
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(99, 102, 241, 0.4);
        }
        
        .btn:active {
            transform: translateY(0);
        }
        
        /* Event Table */
        .event-section {
            background: linear-gradient(135deg, #1a1f2e, #0f1419);
            border: 1px solid #1F2937;
            border-radius: 16px;
            overflow: hidden;
            animation: fadeInUp 0.7s ease;
            box-shadow: 0 8px 24px rgba(0,0,0,0.2);
        }
        
        .section-header {
            padding: 1.75rem 2rem;
            border-bottom: 1px solid #1F2937;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(99, 102, 241, 0.03);
        }
        
        .section-title {
            font-size: 1.3rem;
            font-weight: 700;
            letter-spacing: -0.01em;
        }
        
        .section-subtitle {
            font-size: 0.875rem;
            color: #6B7280;
            font-weight: 500;
        }
        
        .table-container {
            overflow-x: auto;
            max-height: 600px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th {
            background: rgba(31, 41, 55, 0.5);
            padding: 1.25rem 1.5rem;
            text-align: left;
            font-size: 0.875rem;
            color: #9CA3AF;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            position: sticky;
            top: 0;
            z-index: 5;
        }
        
        td {
            padding: 1.25rem 1.5rem;
            border-bottom: 1px solid #1F2937;
            font-size: 0.9rem;
            transition: background 0.2s;
        }
        
        tr {
            transition: all 0.2s;
        }
        
        tr:hover {
            background: rgba(99, 102, 241, 0.05);
        }
        
        .badge {
            display: inline-flex;
            align-items: center;
            padding: 0.375rem 0.875rem;
            border-radius: 10px;
            font-size: 0.8rem;
            font-weight: 700;
            letter-spacing: 0.02em;
        }
        
        .badge-file {
            background: rgba(59, 130, 246, 0.15);
            color: #60A5FA;
            border: 1px solid rgba(59, 130, 246, 0.3);
        }
        
        .badge-usb {
            background: rgba(239, 68, 68, 0.15);
            color: #F87171;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        
        .badge-logon {
            background: rgba(251, 146, 60, 0.15);
            color: #FB923C;
            border: 1px solid rgba(251, 146, 60, 0.3);
        }
        
        .risk-critical {
            background: rgba(239, 68, 68, 0.2);
            color: #EF4444;
            border: 1px solid rgba(239, 68, 68, 0.4);
            font-weight: 700;
        }
        
        .risk-high {
            background: rgba(251, 146, 60, 0.2);
            color: #FB923C;
            border: 1px solid rgba(251, 146, 60, 0.4);
        }
        
        .risk-medium {
            background: rgba(251, 191, 36, 0.2);
            color: #FBBF24;
            border: 1px solid rgba(251, 191, 36, 0.4);
        }
        
        .risk-low {
            background: rgba(16, 185, 129, 0.2);
            color: #10B981;
            border: 1px solid rgba(16, 185, 129, 0.4);
        }
        
        .no-data {
            text-align: center;
            padding: 4rem 2rem;
            color: #6B7280;
        }
        
        .no-data-icon {
            font-size: 4rem;
            margin-bottom: 1rem;
            opacity: 0.5;
        }
        
        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: #1F2937;
        }
        
        ::-webkit-scrollbar-thumb {
            background: #374151;
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: #4B5563;
        }
        
        /* Alert Popup */
        .alert-popup {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 10000;
            animation: slideIn 0.3s ease;
        }
        
        @keyframes slideIn {
            from { transform: translateX(400px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(400px); opacity: 0; }
        }
        
        .alert-popup-content {
            background: linear-gradient(135deg, #1a1f2e, #0f1419);
            border: 2px solid #EF4444;
            border-radius: 16px;
            padding: 1.5rem;
            min-width: 350px;
            max-width: 400px;
            box-shadow: 0 20px 50px rgba(239, 68, 68, 0.4), 0 0 0 1px rgba(239, 68, 68, 0.1);
            animation: pulse-border 2s infinite;
        }
        
        @keyframes pulse-border {
            0%, 100% {
                box-shadow: 0 20px 50px rgba(239, 68, 68, 0.4), 0 0 0 1px rgba(239, 68, 68, 0.1);
            }
            50% {
                box-shadow: 0 20px 50px rgba(239, 68, 68, 0.6), 0 0 0 2px rgba(239, 68, 68, 0.3);
            }
        }
        
        .alert-popup-icon {
            font-size: 3rem;
            text-align: center;
            margin-bottom: 1rem;
            animation: shake 0.5s infinite;
        }
        
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-5px); }
            75% { transform: translateX(5px); }
        }
        
        .alert-popup-title {
            font-size: 1.25rem;
            font-weight: 700;
            color: #EF4444;
            text-align: center;
            margin-bottom: 0.5rem;
        }
        
        .alert-popup-message {
            font-size: 0.95rem;
            color: #D1D5DB;
            text-align: center;
            margin-bottom: 1.5rem;
            line-height: 1.5;
        }
        
        .alert-popup-actions {
            display: flex;
            gap: 0.75rem;
        }
        
        .alert-popup-btn {
            flex: 1;
            padding: 0.75rem 1rem;
            background: linear-gradient(135deg, #EF4444, #DC2626);
            color: white;
            border: none;
            border-radius: 10px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 0.9rem;
        }
        
        .alert-popup-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(239, 68, 68, 0.4);
        }
        
        .alert-popup-btn-secondary {
            flex: 1;
            padding: 0.75rem 1rem;
            background: rgba(75, 85, 99, 0.3);
            color: #D1D5DB;
            border: 1px solid #374151;
            border-radius: 10px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 0.9rem;
        }
        
        .alert-popup-btn-secondary:hover {
            background: rgba(75, 85, 99, 0.5);
            border-color: #4B5563;
        }
        
        /* Event Modal */
        .event-modal-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
        }

        .event-modal {
            background: #1a1f2e;
            border: 1px solid #374151;
            border-radius: 16px;
            padding: 2rem;
            max-width: 600px;
            max-height: 80vh;
            overflow-y: auto;
            color: #E5E7EB;
        }

        .event-modal h2 {
            margin-bottom: 1rem;
            color: #60a5fa;
        }

        .event-modal button {
            margin-top: 1rem;
            padding: 0.5rem 1rem;
            background: #60a5fa;
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
        }

        /* User Modal */
        .user-modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.85);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 2000;
            animation: fadeIn 0.3s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        .user-modal-content {
            background: linear-gradient(135deg, #1a1f2e, #0f1419);
            border: 1px solid #374151;
            border-radius: 16px;
            max-width: 900px;
            width: 90%;
            max-height: 85vh;
            overflow-y: auto;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.6);
        }

        .user-modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1.5rem;
            border-bottom: 1px solid #374151;
            background: rgba(0, 0, 0, 0.3);
        }

        .user-modal-header h3 {
            margin: 0;
            color: #E5E7EB;
            font-size: 1.5rem;
        }

        .user-modal-close {
            background: none;
            border: none;
            color: #9CA3AF;
            font-size: 2rem;
            cursor: pointer;
            transition: color 0.2s;
            padding: 0;
            width: 40px;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .user-modal-close:hover {
            color: #EF4444;
        }

        .user-modal-body {
            padding: 2rem;
            color: #D1D5DB;
        }

        .risk-factor-item {
            display: flex;
            justify-content: space-between;
            padding: 0.75rem 0.5rem;
            border-bottom: 1px solid #1F2937;
        }

        .risk-factor-label {
            color: #9CA3AF;
        }

        .risk-factor-value {
            font-weight: 600;
            color: #E5E7EB;
        }

        .risk-meter {
            width: 100%;
            height: 8px;
            background: #1F2937;
            border-radius: 4px;
            margin-top: 0.5rem;
            overflow: hidden;
        }

        .risk-meter-fill {
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s ease, background-color 0.3s ease;
        }

        .user-event-list {
            margin-top: 1rem;
            max-height: 300px;
            overflow-y: auto;
        }

        .user-event-item {
            padding: 0.75rem;
            margin: 0.5rem 0;
            background: rgba(99, 102, 241, 0.05);
            border-left: 3px solid #60a5fa;
            border-radius: 4px;
            font-size: 0.9rem;
            color: #D1D5DB;
        }

        .user-event-time {
            color: #9CA3AF;
            font-size: 0.8rem;
        }

        .section-tabs {
            display: flex;
            gap: 1rem;
            border-bottom: 1px solid #374151;
            padding: 0 2rem;
        }

        .section-tab {
            padding: 1rem;
            background: none;
            border: none;
            color: #9CA3AF;
            cursor: pointer;
            transition: all 0.2s;
            border-bottom: 3px solid transparent;
            font-weight: 600;
        }

        .section-tab.active {
            color: #60a5fa;
            border-bottom-color: #60a5fa;
        }

        .section-tab:hover {
            color: #E5E7EB;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        /* Clickable user row */
        .user-row:hover {
            cursor: pointer;
            background: rgba(99, 102, 241, 0.1) !important;
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-header">
            <div class="logo">
                <div class="logo-icon">🛡️</div>
                <div class="logo-text">
                    <h1>DeepSentinel</h1>
                    <p>AI-Powered SIEM</p>
                </div>
            </div>
        </div>
        
        <div class="nav-section">
            <div class="nav-title">Main</div>
            <div class="nav-item active">
                <span class="nav-icon">📊</span>
                <span>Dashboard</span>
            </div>
            <div class="nav-item">
                <span class="nav-icon">⚠️</span>
                <span>Alerts</span>
                {% if stats.high_risk > 0 %}
                <span class="nav-badge">{{ stats.high_risk }}</span>
                {% endif %}
            </div>
            <div class="nav-item" onclick="showPage('analytics')">
                <span class="nav-icon">📈</span>
                <span>Analytics</span>
            </div>
            <div class="nav-item" onclick="showPage('reports')">
                <span class="nav-icon">📑</span>
                <span>Reports</span>
            </div>
        </div>
        
        <div class="nav-section">
            <div class="nav-title">Multi-LAN scope</div>
            <div style="padding: 0.8rem; display: flex; flex-direction: column; gap: 0.5rem;">
                <label style="font-size: 0.7rem; color: #6B7280;">Endpoint (agent)</label>
                <select id="agentFilter" style="width: 100%; padding: 0.5rem; background: #1F2937; color: #E5E7EB; border: 1px solid #3F4655; border-radius: 4px; cursor: pointer; font-size: 0.85rem;">
                    <option value="">🌐 All endpoints</option>
                </select>
                <label style="font-size: 0.7rem; color: #6B7280;">User on endpoint</label>
                <select id="userFilter" style="width: 100%; padding: 0.5rem; background: #1F2937; color: #E5E7EB; border: 1px solid #3F4655; border-radius: 4px; cursor: pointer; font-size: 0.85rem;">
                    <option value="">👥 All users</option>
                </select>
                <div id="machineUserMap" style="font-size: 0.72rem; color: #9CA3AF; line-height: 1.4; margin-top: 0.35rem; padding: 0.55rem; background: #111827; border-radius: 6px; border: 1px solid #374151;">Loading endpoint ↔ user map…</div>
                <a href="/agents" style="font-size: 0.8rem; color: #818CF8; text-decoration: none;">→ Connected agents overview</a>
            </div>
        </div>
        
        <div class="nav-section">
            <div class="nav-title">Events</div>
            <div class="nav-item event-filter-btn active" data-filter="all">
                <span class="nav-icon">📊</span>
                <span>All</span>
            </div>
            <div class="nav-item event-filter-btn" data-filter="file">
                <span class="nav-icon">📁</span>
                <span>Files</span>
                <span style="margin-left: auto; color: #6B7280; font-size: 0.85rem;">{{ stats.file_events }}</span>
            </div>
            <div class="nav-item event-filter-btn" data-filter="usb">
                <span class="nav-icon">💾</span>
                <span>USB Devices</span>
                <span style="margin-left: auto; color: #6B7280; font-size: 0.85rem;">{{ stats.usb_events }}</span>
            </div>
            <div class="nav-item event-filter-btn" data-filter="logon">
                <span class="nav-icon">🔑</span>
                <span>Logons</span>
                <span style="margin-left: auto; color: #6B7280; font-size: 0.85rem;">{{ stats.logon_events }}</span>
            </div>
            <div class="nav-item event-filter-btn" data-filter="clipboard">
                <span class="nav-icon">📋</span>
                <span>Clipboard</span>
                <span style="margin-left: auto; color: #6B7280; font-size: 0.85rem;">{{ stats.clipboard_events }}</span>
            </div>
            <div class="nav-item event-filter-btn" data-filter="process">
                <span class="nav-icon">⚙️</span>
                <span>Processes</span>
                <span style="margin-left: auto; color: #6B7280; font-size: 0.85rem;">{{ stats.process_events }}</span>
            </div>
            <div class="nav-item event-filter-btn" data-filter="outlook">
                <span class="nav-icon">📧</span>
                <span>Outlook</span>
                <span style="margin-left: auto; color: #6B7280; font-size: 0.85rem;">{{ stats.outlook_events }}</span>
            </div>
            <div class="nav-item event-filter-btn" data-filter="imap">
                <span class="nav-icon">✉️</span>
                <span>IMAP</span>
                <span style="margin-left: auto; color: #6B7280; font-size: 0.85rem;">{{ stats.imap_events }}</span>
            </div>
        </div>
        
        <div class="nav-section">
            <div class="nav-title">Analysis</div>
            <div class="nav-item">
                <span class="nav-icon">🤖</span>
                <span>ML Models</span>
            </div>
            <div class="nav-item">
                <span class="nav-icon">👥</span>
                <span>User Behavior</span>
            </div>
            <div class="nav-item">
                <span class="nav-icon">🔍</span>
                <span>Threat Hunt</span>
            </div>
        </div>
        
        <div class="nav-section">
            <div class="nav-title">System</div>
            <div class="nav-item">
                <span class="nav-icon">⚙️</span>
                <span>Settings</span>
            </div>
            <div class="nav-item">
                <span class="nav-icon">📥</span>
                <span>Export</span>
            </div>
        </div>
    </div>
    
    <!-- Main Content -->
    <div class="main-content">
        <!-- Header -->
        <div class="header">
            <div class="header-left">
                <h2>Security Dashboard</h2>
                <div class="header-subtitle">Real-time user activity monitoring</div>
            </div>
            <div class="header-right">
                <a href="http://localhost:5173" class="back-button">← Back to Home</a>
                <div class="header-status">
                    <span class="status-dot"></span>
                    <span style="font-size: 0.9rem; font-weight: 600;">System Active</span>
                </div>
            </div>
        </div>
        
        <!-- Content -->
        <div class="content">
            <!-- Stats Grid -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Total Events</div>
                    <div class="stat-value" id="stat-total-events">{{ stats.total_events }}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">File Actions</div>
                    <div class="stat-value" id="stat-file-events">{{ stats.file_events }}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">USB Events</div>
                    <div class="stat-value" id="stat-usb-events">{{ stats.usb_events }}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">User Logons</div>
                    <div class="stat-value" id="stat-logon-events">{{ stats.logon_events }}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Critical Alerts</div>
                    <div class="stat-value" id="stat-high-risk" style="background: linear-gradient(135deg, #EF4444, #F87171); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">{{ stats.high_risk }}</div>
                </div>
                <a href="/activity_logs" class="stat-card activity-logs-btn" style="text-decoration: none;">
                    <div class="stat-label">User Activity Logs</div>
                    <div class="stat-value" style="font-size: 2rem;">📋</div>
                    <div class="stat-hint">Click to view logs</div>
                </a>
                <style>
                    .activity-logs-btn {
                        cursor: pointer;
                        transition: all 0.3s ease;
                        position: relative;
                        overflow: hidden;
                    }
                    .activity-logs-btn:hover {
                        transform: translateY(-5px);
                        box-shadow: 0 10px 20px rgba(99, 102, 241, 0.3);
                    }
                    .activity-logs-btn:active {
                        transform: translateY(-2px);
                    }
                    .stat-hint {
                        font-size: 0.8rem;
                        color: #60a5fa;
                        margin-top: 0.5rem;
                    }
                </style>
                <script>
                    // Safe-bind: element may not exist depending on template version
                    const _activityBtn = document.getElementById('activityLogsBtn');
                    if (_activityBtn) {
                        _activityBtn.addEventListener('click', function() {
                            console.log('Activity Logs button clicked');
                            showActivityLogs();
                        });
                    }
                </script>
                <div class="stat-card">
                    <div class="stat-label">Clipboard Events</div>
                    <div class="stat-value" id="stat-clipboard-events">{{ stats.clipboard_events }}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Process Events</div>
                    <div class="stat-value" id="stat-process-events">{{ stats.process_events }}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Outlook Events</div>
                    <div class="stat-value" id="stat-outlook-events">{{ stats.outlook_events }}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">IMAP Events</div>
                    <div class="stat-value" id="stat-imap-events">{{ stats.imap_events }}</div>
                </div>
            </div>
            
            <!-- Threshold Control -->
            <div class="threshold-box">
                <div class="threshold-header">
                    <div>
                        <div class="threshold-title">🎯 Risk Threshold</div>
                        <div style="font-size: 0.875rem; color: #6B7280; margin-top: 0.5rem;">
                            Events above this threshold trigger critical alerts
                        </div>
                    </div>
                    <div class="threshold-value" id="thresholdValue">{{ threshold }}</div>
                </div>
                <input type="range" min="0" max="100" value="{{ (threshold * 100)|int }}" 
                       class="slider" id="thresholdSlider" 
                       oninput="updateThreshold(this.value)">
                <div class="threshold-labels">
                    <span>0.0 - Low</span>
                    <span>0.5 - Medium</span>
                    <span>1.0 - High</span>
                </div>
            </div>
            
            <!-- Controls -->
            <div class="controls">
                <button class="btn" onclick="refreshNow()">🔄 Refresh Now</button>
                <button class="btn" onclick="exportData()">📥 Export CSV</button>
                <button class="btn" onclick="clearData()">🗑️ Clear All</button>
            </div>
            
            <!-- Alerts for current scope (multi-LAN / per-user) -->
            <div class="event-section" style="margin-top: 1rem;">
                <div class="section-header">
                    <div>
                        <div class="section-title">Alerts &amp; high-risk activity</div>
                        <div class="section-subtitle">Threshold alerts + events above risk threshold • Uses endpoint / user picks in sidebar</div>
                    </div>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Endpoint</th>
                                <th>User</th>
                                <th>Type</th>
                                <th>Detail</th>
                                <th>Severity</th>
                            </tr>
                        </thead>
                        <tbody id="dashboard-alerts-tbody">
                            <tr>
                                <td colspan="6" class="no-data">
                                    <div class="no-data-icon">🔔</div>
                                    <div style="font-size: 1rem;">No alerts for this scope</div>
                                    <div style="color: #6B7280; font-size: 0.85rem;">Choose an endpoint or user in the sidebar, or wait for activity.</div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <div style="margin-top: 1rem; display:flex; justify-content:flex-end;">
                <button class="btn" onclick="openScreenshotsModal()">📸 View screenshots</button>
            </div>

            <!-- Event Table -->
            <div class="event-section">
                <div class="section-header">
                    <div>
                        <div class="section-title">Recent User Activity</div>
                        <div class="section-subtitle">Live monitoring • Auto-refresh: 60s • Filtered by sidebar scope</div>
                    </div>
                </div>
                
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Agent</th>
                                <th>Type</th>
                                <th>Action</th>
                                <th>Details</th>
                                <th>Risk Score</th>
                            </tr>
                        </thead>
                        <tbody id="events-tbody">
                            {% if events %}
                                {% for event in events %}
                                <tr data-event-type="{{ event.event_type }}" data-detail="{{ event.details|e }}" data-summary="{{ event_summary(event) }}">
                                    <td style="font-family: 'Courier New', monospace; color: #9CA3AF;">{{ event.timestamp }}</td>
                                    <td style="font-weight: 600;">{{ event.agent_id }}</td>
                                    <td>
                                        <span class="badge badge-{{ event.event_type }}">
                                            {{ event.event_type.upper() }}
                                        </span>
                                    </td>
                                    <td>{{ event.action|replace('_',' ') }}</td>
                                    <td style="max-width: 400px; color: #9CA3AF; font-size: 0.85rem;">{{ event.details }}</td>
                                    <td>
                                        <span class="badge {{ event.risk_class }}">
                                            {{ "%.3f"|format(event.risk_score) }}
                                        </span>
                                    </td>
                                </tr>
                                {% endfor %}
                            {% else %}
                                <tr>
                                    <td colspan="6" class="no-data">
                                        <div class="no-data-icon">📊</div>
                                        <div style="font-size: 1.2rem; font-weight: 600; margin-bottom: 0.5rem;">No Events Detected</div>
                                        <div style="color: #6B7280;">Waiting for user activity...</div>
                                    </td>
                                </tr>
                            {% endif %}
                            </tbody>
                    </table>
                </div>
            </div>
            
            <!-- User Risk Leaderboard -->
            <div class="event-section" style="margin-top: 2rem;">
                <div class="section-header">
                    <div>
                        <div class="section-title">User Risk Leaderboard</div>
                        <div class="section-subtitle">Top users by composite risk score</div>
                    </div>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Risk Score</th>
                                <th>Risk Level</th>
                                <th>Risk Factors</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody id="leaderboard-tbody">
                            <tr>
                                <td colspan="5" class="no-data">
                                    <div class="no-data-icon">👥</div>
                                    <div style="font-size: 1.2rem; font-weight: 600; margin-bottom: 0.5rem;">No User Risk Data</div>
                                    <div style="color: #6B7280;">Waiting for activity analysis...</div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Incidents Management -->
            <div class="event-section" style="margin-top: 2rem;">
                <div class="section-header">
                    <div>
                        <div class="section-title">Security Incidents</div>
                        <div class="section-subtitle">Auto-grouped threat events</div>
                    </div>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Incident Title</th>
                                <th>Severity</th>
                                <th>Status</th>
                                <th>Affected Users</th>
                                <th>Created</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody id="incidents-tbody">
                            <tr>
                                <td colspan="6" class="no-data">
                                    <div class="no-data-icon">🔐</div>
                                    <div style="font-size: 1.2rem; font-weight: 600; margin-bottom: 0.5rem;">No Incidents</div>
                                    <div style="color: #6B7280;">All systems normal</div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Audit Trail -->
            <div class="event-section" style="margin-top: 2rem;">
                <div class="section-header">
                    <div>
                        <div class="section-title">Audit Trail</div>
                        <div class="section-subtitle">Admin actions and system events</div>
                    </div>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Admin</th>
                                <th>Action</th>
                                <th>Target User</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody id="audit-tbody">
                            <tr>
                                <td colspan="5" class="no-data">
                                    <div class="no-data-icon">📋</div>
                                    <div style="font-size: 1.2rem; font-weight: 600; margin-bottom: 0.5rem;">No Audit Records</div>
                                    <div style="color: #6B7280;">No admin actions yet</div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Email approvals (ML medium-risk queue) -->
            <div class="event-section" style="margin-top: 2rem;">
                <div class="section-header">
                    <div>
                        <div class="section-title">Email approvals</div>
                        <div class="section-subtitle">Messages queued for review (MEDIUM risk from classifier)</div>
                    </div>
                    <button type="button" class="btn" style="padding: 0.4rem 0.9rem; font-size: 0.85rem;" onclick="loadEmailApprovals()">Refresh</button>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Queued</th>
                                <th>Subject</th>
                                <th>Class</th>
                                <th>Risk</th>
                                <th>Message</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="email-approvals-tbody">
                            <tr>
                                <td colspan="6" class="no-data">
                                    <div class="no-data-icon">✉️</div>
                                    <div style="font-size: 1rem;">No pending emails</div>
                                    <div style="color: #6B7280; font-size: 0.85rem;">POST to /api/email/classify or enable the email filter module.</div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <!-- User Detail Modal -->
    <div id="userModal" class="user-modal" style="display: none;">
        <div class="user-modal-content">
            <div class="user-modal-header">
                <h3 id="userModalTitle">User Details</h3>
                <button class="user-modal-close" onclick="closeUserModal()">&times;</button>
            </div>
            <div class="user-modal-body">
                <div id="userModalBody">Loading...</div>
            </div>
        </div>
    </div>

    <!-- Screenshots Modal -->
    <div id="screenshotsModal" class="user-modal" style="display: none;">
        <div class="user-modal-content" style="width: min(1200px, 95vw);">
            <div class="user-modal-header">
                <h3>Agent Screenshots</h3>
                <button class="user-modal-close" onclick="closeScreenshotsModal()">&times;</button>
            </div>
            <div class="user-modal-body">
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>User</th>
                                <th>Severity</th>
                                <th>Preview</th>
                                <th>Open</th>
                            </tr>
                        </thead>
                        <tbody id="screenshots-modal-tbody">
                            <tr><td colspan="5" class="no-data">No screenshots yet.</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <!-- Analytics Page -->
    <div id="analytics-page" style="display: none; position: fixed; top: 0; left: 280px; right: 0; height: 100vh; background: #0B0F19; color: #E5E7EB; overflow-y: auto; z-index: 100;">
        <div style="padding: 2rem;">
            <h2 style="font-size: 1.75rem; margin-bottom: 0.5rem;">📊 Analytics Dashboard</h2>
            <p style="color: #6B7280; margin-bottom: 2rem;">Real-time security metrics and insights</p>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 2rem; margin-bottom: 2rem;">
                <div style="background: linear-gradient(135deg, #1a1f2e 0%, #0f1419 100%); border: 1px solid #1F2937; border-radius: 16px; padding: 2rem; height: 400px; display: flex; flex-direction: column;">
                    <h3 style="font-size: 1.1rem; margin-bottom: 0.5rem;">Live Event Counter</h3>
                    <p style="color: #6B7280; margin-bottom: 1.5rem; font-size: 0.85rem;">Last 60 seconds</p>
                    <div style="flex: 1; position: relative; min-height: 0;">
                        <canvas id="canvas-live-counter" style="width: 100% !important; height: 100% !important;"></canvas>
                    </div>
                </div>
                
                <div style="background: linear-gradient(135deg, #1a1f2e 0%, #0f1419 100%); border: 1px solid #1F2937; border-radius: 16px; padding: 2rem; height: 400px; display: flex; flex-direction: column;">
                    <h3 style="font-size: 1.1rem; margin-bottom: 0.5rem;">Event Type Breakdown</h3>
                    <p style="color: #6B7280; margin-bottom: 1.5rem; font-size: 0.85rem;">Last 5 minutes</p>
                    <div style="flex: 1; position: relative; min-height: 0;">
                        <canvas id="canvas-event-types" style="width: 100% !important; height: 100% !important;"></canvas>
                    </div>
                </div>
                
                <div style="background: linear-gradient(135deg, #1a1f2e 0%, #0f1419 100%); border: 1px solid #1F2937; border-radius: 16px; padding: 2rem; height: 400px; display: flex; flex-direction: column;">
                    <h3 style="font-size: 1.1rem; margin-bottom: 0.5rem;">Top Active Users</h3>
                    <p style="color: #6B7280; margin-bottom: 1.5rem; font-size: 0.85rem;">Last 15 minutes</p>
                    <div style="flex: 1; position: relative; min-height: 0;">
                        <canvas id="canvas-top-users" style="width: 100% !important; height: 100% !important;"></canvas>
                    </div>
                </div>
                
                <div style="background: linear-gradient(135deg, #1a1f2e 0%, #0f1419 100%); border: 1px solid #1F2937; border-radius: 16px; padding: 2rem; height: 400px; display: flex; flex-direction: column;">
                    <h3 style="font-size: 1.1rem; margin-bottom: 0.5rem;">Events Per Minute</h3>
                    <p style="color: #6B7280; margin-bottom: 1.5rem; font-size: 0.85rem;">Last 10 minutes</p>
                    <div style="flex: 1; position: relative; min-height: 0;">
                        <canvas id="canvas-events-per-minute" style="width: 100% !important; height: 100% !important;"></canvas>
                    </div>
                </div>
                
                <div style="background: linear-gradient(135deg, #1a1f2e 0%, #0f1419 100%); border: 1px solid #1F2937; border-radius: 16px; padding: 2rem; height: 400px; display: flex; flex-direction: column;">
                    <h3 style="font-size: 1.1rem; margin-bottom: 0.5rem;">Alert Risk Meter</h3>
                    <p style="color: #6B7280; margin-bottom: 1.5rem; font-size: 0.85rem;">Threat score (last 10 min)</p>
                    <div style="flex: 1; position: relative; min-height: 0;">
                        <canvas id="canvas-risk-meter" style="width: 100% !important; height: 100% !important;"></canvas>
                    </div>
                </div>
                
                <div style="background: linear-gradient(135deg, #1a1f2e 0%, #0f1419 100%); border: 1px solid #1F2937; border-radius: 16px; padding: 2rem; height: 400px; display: flex; flex-direction: column;">
                    <h3 style="font-size: 1.1rem; margin-bottom: 0.5rem;">Data Transfer Activity</h3>
                    <p style="color: #6B7280; margin-bottom: 1.5rem; font-size: 0.85rem;">Last 1 hour</p>
                    <div style="flex: 1; position: relative; min-height: 0;">
                        <canvas id="canvas-data-transfer" style="width: 100% !important; height: 100% !important;"></canvas>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Reports Page -->
    <div id="reports-page" style="display: none; position: fixed; top: 0; left: 280px; right: 0; height: 100vh; background: #0B0F19; color: #E5E7EB; overflow-y: auto; z-index: 100;">
        <div style="max-width: 1200px; margin: 0 auto; padding: 2rem;">
            <h2 style="font-size: 1.75rem; margin-bottom: 0.5rem;">📑 LLM-Generated Security Reports</h2>
            <p style="color: #9CA3AF; margin-bottom: 2rem;">AI-powered incident investigations and behavior analysis</p>

            <!-- Report Generation Controls -->
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin-bottom: 3rem;">
                <!-- Incident Report Generator -->
                <div style="background: linear-gradient(135deg, #1a1f2e 0%, #0f1419 100%); border: 1px solid #1F2937; border-radius: 12px; padding: 1.5rem;">
                    <h3 style="font-size: 1.2rem; margin-bottom: 1rem; color: #60a5fa;">⚡ Generate Incident Report</h3>
                    <p style="color: #9CA3AF; margin-bottom: 1rem; font-size: 0.9rem;">AI analyzes user's 24-hour events and automatically calculates risk score based on:<br/>• Off-hours access • USB transfers • External emails • Sensitive file access</p>
                    <input type="text" id="incident-username" placeholder="Enter username to investigate" style="width: 100%; padding: 0.5rem; margin-bottom: 1rem; background: #1F2937; border: 1px solid #374151; border-radius: 6px; color: #E5E7EB;">
                    <button onclick="generateIncidentReport()" style="width: 100%; padding: 0.75rem; background: #60a5fa; border: none; border-radius: 6px; color: white; cursor: pointer; font-weight: 600;">🔍 Analyze & Generate Report</button>
                    <div id="incident-status" style="margin-top: 1rem; font-size: 0.85rem; color: #9CA3AF;"></div>
                </div>

                <!-- Behavior Report Generator -->
                <div style="background: linear-gradient(135deg, #1a1f2e 0%, #0f1419 100%); border: 1px solid #1F2937; border-radius: 12px; padding: 1.5rem;">
                    <h3 style="font-size: 1.2rem; margin-bottom: 1rem; color: #549af0;">👥 Generate Behavior Report</h3>
                    <p style="color: #9CA3AF; margin-bottom: 1rem; font-size: 0.9rem;">Analyzes 30-day user behavior patterns and detects anomalies in working hours, file access, and risk indicators</p>
                    <input type="text" id="behavior-username" placeholder="Enter username to analyze" style="width: 100%; padding: 0.5rem; margin-bottom: 1rem; background: #1F2937; border: 1px solid #374151; border-radius: 6px; color: #E5E7EB;">
                    <button onclick="generateBehaviorReport()" style="width: 100%; padding: 0.75rem; background: #549af0; border: none; border-radius: 6px; color: white; cursor: pointer; font-weight: 600;">📊 Analyze Behavior</button>
                    <div id="behavior-status" style="margin-top: 1rem; font-size: 0.85rem; color: #9CA3AF;"></div>
                </div>
            </div>

            <!-- Generated Reports List -->
            <div style="background: linear-gradient(135deg, #1a1f2e 0%, #0f1419 100%); border: 1px solid #1F2937; border-radius: 12px; padding: 1.5rem;">
                <h3 style="font-size: 1.2rem; margin-bottom: 1rem;">📄 Generated Reports</h3>
                <div id="reports-list" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1rem;">
                    <div style="text-align: center; padding: 2rem; color: #6B7280;">
                        <div style="font-size: 2rem; margin-bottom: 0.5rem;">📋</div>
                        <div>Loading reports...</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Track last known alert count
        let lastAlertCount = {{ stats.high_risk }};
        
        // Auto-refresh every 60 seconds
        setTimeout(() => location.reload(), 60000);
        
        // Check for new critical alerts every 10 seconds
        setInterval(checkForNewAlerts, 10000);
        
        function checkForNewAlerts() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    if (data.high_risk > lastAlertCount) {
                        showAlertPopup(data.high_risk - lastAlertCount);
                        lastAlertCount = data.high_risk;
                    }
                })
                .catch(err => console.error('Failed to check alerts:', err));
        }

        // Page Navigation Function
        function showPage(pageName) {
            const mainContent = document.querySelector('.main-content');
            const analyticsPage = document.getElementById('analytics-page');
            const reportsPage = document.getElementById('reports-page');
            const content = document.querySelector('.content');
            
            if (pageName === 'analytics') {
                if (content) content.style.display = 'none';
                if (reportsPage) reportsPage.style.display = 'none';
                if (analyticsPage) {
                    analyticsPage.style.display = 'block';
                    setTimeout(initializeAnalyticsCharts, 100);
                }
            } else if (pageName === 'reports') {
                if (content) content.style.display = 'none';
                if (analyticsPage) analyticsPage.style.display = 'none';
                if (reportsPage) {
                    reportsPage.style.display = 'block';
                    setTimeout(loadGeneratedReports, 100);
                }
            } else {
                if (content) content.style.display = 'block';
                if (analyticsPage) analyticsPage.style.display = 'none';
                if (reportsPage) reportsPage.style.display = 'none';
            }
        }

        // Analytics Charts
        let analyticsCharts = {};
        
        function initializeAnalyticsCharts() {
            createLiveCounterChart();
            createEventTypesChart();
            createTopUsersChart();
            createEventsPerMinuteChart();
            createRiskMeterChart();
            createDataTransferChart();
            
            setInterval(updateLiveCounterChart, 5000);
            setInterval(updateEventTypesChart, 10000);
            setInterval(updateTopUsersChart, 10000);
            setInterval(updateEventsPerMinuteChart, 10000);
            setInterval(updateRiskMeterChart, 5000);
            setInterval(updateDataTransferChart, 30000);
        }

        function createLiveCounterChart() {
            fetch('/api/analytics/live-stats')
                .then(r => r.json())
                .then(data => {
                    const ctx = document.getElementById('canvas-live-counter');
                    if (!ctx) return;
                    if (analyticsCharts.liveCounter) analyticsCharts.liveCounter.destroy();
                    analyticsCharts.liveCounter = new Chart(ctx, {
                        type: 'doughnut',
                        data: {
                            labels: ['Events', 'Remaining'],
                            datasets: [{
                                data: [data.count, Math.max(0, 100 - data.count)],
                                backgroundColor: ['#60a5fa', '#1F2937'],
                                borderColor: '#0B0F19',
                                borderWidth: 2
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: { legend: { labels: { color: '#9CA3AF' } } }
                        },
                        plugins: [{
                            id: 'textCenter',
                            afterDatasetsDraw(chart) {
                                const {width, height, ctx} = chart;
                                ctx.restore();
                                ctx.font = '2rem sans-serif';
                                ctx.fillStyle = '#60a5fa';
                                ctx.textAlign = 'center';
                                ctx.fillText(data.count, width / 2, height / 2);
                            }
                        }]
                    });
                });
        }

        function updateLiveCounterChart() {
            createLiveCounterChart();
        }

        function createEventTypesChart() {
            fetch('/api/analytics/event-types')
                .then(r => r.json())
                .then(data => {
                    const ctx = document.getElementById('canvas-event-types');
                    if (!ctx) return;
                    if (analyticsCharts.eventTypes) analyticsCharts.eventTypes.destroy();
                    const types = Object.keys(data.types);
                    const colors = ['#3B82F6', '#EF4444', '#10B981', '#FCD34D', '#549af0'];
                    analyticsCharts.eventTypes = new Chart(ctx, {
                        type: 'pie',
                        data: {
                            labels: types,
                            datasets: [{
                                data: types.map(t => data.types[t]),
                                backgroundColor: colors.slice(0, types.length),
                                borderColor: '#0B0F19',
                                borderWidth: 2
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: { legend: { labels: { color: '#9CA3AF' } } }
                        }
                    });
                });
        }

        function updateEventTypesChart() {
            createEventTypesChart();
        }

        function createTopUsersChart() {
            fetch('/api/analytics/top-users')
                .then(r => r.json())
                .then(data => {
                    const ctx = document.getElementById('canvas-top-users');
                    if (!ctx) return;
                    if (analyticsCharts.topUsers) analyticsCharts.topUsers.destroy();
                    analyticsCharts.topUsers = new Chart(ctx, {
                        type: 'bar',
                        data: {
                            labels: data.users.map(u => u.username),
                            datasets: [{
                                label: 'Events',
                                data: data.users.map(u => u.count),
                                backgroundColor: '#549af0',
                                borderRadius: 8
                            }]
                        },
                        options: {
                            indexAxis: 'y',
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: { x: { ticks: { color: '#9CA3AF' } }, y: { ticks: { color: '#9CA3AF' } } }
                        }
                    });
                });
        }

        function updateTopUsersChart() {
            createTopUsersChart();
        }

        function createEventsPerMinuteChart() {
            fetch('/api/analytics/events-per-minute')
                .then(r => r.json())
                .then(data => {
                    const ctx = document.getElementById('canvas-events-per-minute');
                    if (!ctx) return;
                    if (analyticsCharts.eventsPerMinute) analyticsCharts.eventsPerMinute.destroy();
                    const labels = data.data.map(d => d.minute.split('T')[1].substring(0, 5));
                    analyticsCharts.eventsPerMinute = new Chart(ctx, {
                        type: 'line',
                        data: {
                            labels: labels,
                            datasets: [{
                                label: 'Events',
                                data: data.data.map(d => d.count),
                                borderColor: '#10B981',
                                backgroundColor: 'rgba(16, 185, 129, 0.1)',
                                borderWidth: 2,
                                fill: true,
                                tension: 0.4
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: { x: { ticks: { color: '#9CA3AF' } }, y: { ticks: { color: '#9CA3AF' } } }
                        }
                    });
                });
        }

        function updateEventsPerMinuteChart() {
            createEventsPerMinuteChart();
        }

        function createRiskMeterChart() {
            fetch('/api/analytics/risk-meter')
                .then(r => r.json())
                .then(data => {
                    const ctx = document.getElementById('canvas-risk-meter');
                    if (!ctx) return;
                    if (analyticsCharts.riskMeter) analyticsCharts.riskMeter.destroy();
                    analyticsCharts.riskMeter = new Chart(ctx, {
                        type: 'doughnut',
                        data: {
                            labels: [data.risk_level, 'Safe'],
                            datasets: [{
                                data: [data.score, 100 - data.score],
                                backgroundColor: [data.color, '#1F2937'],
                                borderColor: '#0B0F19',
                                borderWidth: 2
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: { legend: { labels: { color: '#9CA3AF' } } }
                        }
                    });
                });
        }

        function updateRiskMeterChart() {
            createRiskMeterChart();
        }

        function createDataTransferChart() {
            fetch('/api/analytics/data-transfer')
                .then(r => r.json())
                .then(data => {
                    const ctx = document.getElementById('canvas-data-transfer');
                    if (!ctx) return;
                    if (analyticsCharts.dataTransfer) analyticsCharts.dataTransfer.destroy();
                    analyticsCharts.dataTransfer = new Chart(ctx, {
                        type: 'bar',
                        data: {
                            labels: data.data.map(d => d.type.replace(/_/g, ' ')),
                            datasets: [{
                                label: 'Events',
                                data: data.data.map(d => d.count),
                                backgroundColor: data.data.map(d => d.color),
                                borderRadius: 8
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: { y: { ticks: { color: '#9CA3AF' } }, x: { ticks: { color: '#9CA3AF' } } }
                        }
                    });
                });
        }

        function updateDataTransferChart() {
            createDataTransferChart();
        }
        
        function showAlertPopup(newAlertCount) {
            playAlertSound();
            
            const popup = document.createElement('div');
            popup.className = 'alert-popup';
            popup.innerHTML = `
                <div class="alert-popup-content">
                    <div class="alert-popup-icon">🚨</div>
                    <div class="alert-popup-title">Critical Alert Detected!</div>
                    <div class="alert-popup-message">
                        ${newAlertCount} new high-risk ${newAlertCount === 1 ? 'event' : 'events'} detected
                    </div>
                    <div class="alert-popup-actions">
                        <button class="alert-popup-btn" onclick="location.reload()">View Details</button>
                        <button class="alert-popup-btn-secondary" onclick="closeAlertPopup(this)">Dismiss</button>
                    </div>
                </div>
            `;
            
            document.body.appendChild(popup);
            
            setTimeout(() => {
                if (popup.parentElement) {
                    closeAlertPopup(popup);
                }
            }, 15000);
        }
        
        function closeAlertPopup(element) {
            const popup = element.closest ? element.closest('.alert-popup') : element;
            if (popup) {
                popup.style.animation = 'slideOut 0.3s ease';
                setTimeout(() => popup.remove(), 300);
            }
        }
        
        function playAlertSound() {
            try {
                const audioContext = new (window.AudioContext || window.webkitAudioContext)();
                const oscillator = audioContext.createOscillator();
                const gainNode = audioContext.createGain();
                
                oscillator.connect(gainNode);
                gainNode.connect(audioContext.destination);
                
                oscillator.frequency.value = 800;
                oscillator.type = 'sine';
                
                gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
                gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.5);
                
                oscillator.start(audioContext.currentTime);
                oscillator.stop(audioContext.currentTime + 0.5);
            } catch (e) {
                console.log('Audio not supported');
            }
        }
        
        function updateThreshold(value) {
            const threshold = (value / 100).toFixed(2);
            document.getElementById('thresholdValue').textContent = threshold;
            
            fetch('/update_threshold', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({threshold: parseFloat(threshold)})
            });
        }
        
        function exportData() {
            window.location.href = '/export_csv';
        }
        
        function clearData() {
            if(confirm('Clear all events? This cannot be undone.')) {
                fetch('/clear_all', {method: 'POST'})
                    .then(() => {
                        // update UI dynamically instead of full reload
                        updateStatsAndEvents();
                    });
            }
        }

        // Report Generation Functions
        function generateIncidentReport() {
            const username = document.getElementById('incident-username').value.trim();
            const statusDiv = document.getElementById('incident-status');

            if (!username) {
                statusDiv.textContent = '❌ Please enter a username';
                statusDiv.style.color = '#EF4444';
                return;
            }

            statusDiv.textContent = '⏳ Analyzing 24-hour events and calculating risk score...';
            statusDiv.style.color = '#F59E0B';

            fetch('/api/reports/generate-incident', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username})
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    const riskLabel = data.risk_score >= 7 ? '🔴 CRITICAL' : data.risk_score >= 5 ? '🟠 HIGH' : data.risk_score >= 3 ? '🟡 MEDIUM' : '🟢 LOW';
                    statusDiv.innerHTML = `✅ Report Generated! Risk: ${riskLabel} (${data.risk_score.toFixed(1)}/10) | <a href="${data.pdf_url}" target="_blank" style="color: #60a5fa; text-decoration: underline;">📥 Download PDF</a>`;
                    statusDiv.style.color = '#10B981';
                    setTimeout(() => loadGeneratedReports(), 1000);
                } else {
                    statusDiv.textContent = '❌ ' + (data.error || 'Failed to generate report');
                    statusDiv.style.color = '#EF4444';
                }
            })
            .catch(err => {
                statusDiv.textContent = '❌ Error: ' + err.message;
                statusDiv.style.color = '#EF4444';
                console.error('Report generation error:', err);
            });
        }

        function generateBehaviorReport() {
            const username = document.getElementById('behavior-username').value.trim();
            const statusDiv = document.getElementById('behavior-status');

            if (!username) {
                statusDiv.textContent = '❌ Please enter a username';
                statusDiv.style.color = '#EF4444';
                return;
            }

            statusDiv.textContent = '⏳ Analyzing 30-day behavior patterns...';
            statusDiv.style.color = '#F59E0B';

            fetch('/api/reports/generate-behavior', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username})
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    statusDiv.innerHTML = `✅ Report Generated! | <a href="${data.pdf_url}" target="_blank" style="color: #549af0; text-decoration: underline;">📥 Download PDF</a>`;
                    statusDiv.style.color = '#10B981';
                    setTimeout(() => loadGeneratedReports(), 1000);
                } else {
                    statusDiv.textContent = '❌ ' + (data.error || 'Failed to generate report');
                    statusDiv.style.color = '#EF4444';
                }
            })
            .catch(err => {
                statusDiv.textContent = '❌ Error: ' + err.message;
                statusDiv.style.color = '#EF4444';
                console.error('Report generation error:', err);
            });
        }

        function loadGeneratedReports() {
            fetch('/api/reports/list')
            .then(r => r.json())
            .then(data => {
                const reportsList = document.getElementById('reports-list');
                if (!reportsList) return;

                const reports = data.reports || [];
                if (reports.length === 0) {
                    reportsList.innerHTML = `
                        <div style="grid-column: 1/-1; text-align: center; padding: 2rem; color: #6B7280;">
                            <div style="font-size: 2rem; margin-bottom: 0.5rem;">📋</div>
                            <div>No reports generated yet. Create one above!</div>
                        </div>
                    `;
                    return;
                }

                reportsList.innerHTML = reports.map(report => `
                    <div style="background: #0F1419; border: 1px solid #1F2937; border-radius: 8px; padding: 1rem;">
                        <div style="font-weight: 600; margin-bottom: 0.5rem; color: #60a5fa;">
                            ${report.type === 'incident' ? '⚡' : '👥'} ${report.filename}
                        </div>
                        <div style="font-size: 0.85rem; color: #9CA3AF; margin-bottom: 0.75rem;">
                            User: <strong>${report.username}</strong><br/>
                            Generated: ${new Date(report.created).toLocaleString()}
                        </div>
                        <a href="/download-report/${report.filename}" target="_blank" style="display: inline-block; padding: 0.5rem 1rem; background: #60a5fa; color: white; border-radius: 6px; text-decoration: none; font-size: 0.85rem;">📄 Download PDF</a>
                    </div>
                `).join('');
            })
            .catch(err => {
                console.error('Failed to load reports:', err);
                const reportsList = document.getElementById('reports-list');
                if (reportsList) {
                    reportsList.innerHTML = '<div style="grid-column: 1/-1; text-align: center; padding: 2rem; color: #EF4444;">Failed to load reports</div>';
                }
            });
        }

        // New dynamic refresh function
        function refreshNow() {
            applyDashboardScope();
        }

        function scopeQuery() {
            const uf = (document.getElementById('userFilter') && document.getElementById('userFilter').value) || '';
            const af = (document.getElementById('agentFilter') && document.getElementById('agentFilter').value) || '';
            const q = [];
            if (uf) q.push('user=' + encodeURIComponent(uf));
            if (af) q.push('agent=' + encodeURIComponent(af));
            return q.length ? ('?' + q.join('&')) : '';
        }

        // Fetch stats and events and update the DOM
        function updateStatsAndEvents() {
            const qs = scopeQuery();
            Promise.all([
                fetch('/api/stats').then(r => r.json()),
                fetch('/api/events' + qs).then(r => r.json())
            ]).then(([stats, events]) => {
                // Update stat elements
                const setText = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
                setText('stat-total-events', stats.total_events);
                setText('stat-file-events', stats.file_events);
                setText('stat-usb-events', stats.usb_events);
                setText('stat-logon-events', stats.logon_events);
                setText('stat-clipboard-events', stats.clipboard_events);
                setText('stat-process-events', stats.process_events);
                setText('stat-outlook-events', stats.outlook_events);
                setText('stat-imap-events', stats.imap_events);
                setText('stat-high-risk', stats.high_risk);
                setText('stat-avg-risk', (stats.total_events>0? (stats.avg_risk||0).toFixed(2): '0.00'));

                // Rebuild events table body
                const tbody = document.getElementById('events-tbody');
                if (tbody) {
                    if (!events || events.length === 0) {
                        tbody.innerHTML = `<tr><td colspan="6" class="no-data"><div class="no-data-icon">📊</div><div style="font-size: 1.2rem; font-weight: 600; margin-bottom: 0.5rem;">No Events Detected</div><div style="color: #6B7280;">Waiting for user activity...</div></td></tr>`;
                    } else {
                        tbody.innerHTML = events.map(ev => {
                            const badgeClass = ev.event_type || 'unknown';
                            return `
                                <tr data-event-type="${ev.event_type}" data-detail="${(ev.details||'').replace(/"/g,'&quot;')}" data-summary="${(ev.details||'').replace(/"/g,'&quot;')}">
                                    <td style="font-family: 'Courier New', monospace; color: #9CA3AF;">${ev.timestamp}</td>
                                    <td style="font-weight: 600;">${ev.agent_id}</td>
                                    <td><span class="badge badge-${badgeClass}">${(ev.event_type||'').toUpperCase()}</span></td>
                                    <td>${(ev.action||'').replace(/_/g,' ')}</td>
                                    <td style="max-width: 400px; color: #9CA3AF; font-size: 0.85rem;">${ev.details}</td>
                                    <td><span class="badge ${ev.risk_class}">${(ev.risk_score||0).toFixed(3)}</span></td>
                                </tr>`;
                        }).join('\\n');
                    }
                }
            }).catch(err => console.error('Failed to refresh stats/events:', err));
        }

        function loadDashboardAlerts() {
            fetch('/api/dashboard/alerts' + scopeQuery())
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById('dashboard-alerts-tbody');
                    if (!tbody) return;
                    const rows = data.alerts || [];
                    if (rows.length === 0) {
                        tbody.innerHTML = `<tr><td colspan="6" class="no-data"><div class="no-data-icon">🔔</div><div style="font-size: 1rem;">No alerts for this scope</div><div style="color: #6B7280; font-size: 0.85rem;">Pick another user/endpoint or lower the risk threshold.</div></td></tr>`;
                        return;
                    }
                    tbody.innerHTML = rows.map(a => {
                        const sev = (a.severity || 'MEDIUM');
                        let cls = 'risk-medium';
                        if (sev === 'CRITICAL' || sev === 'HIGH') cls = 'risk-critical';
                        else if (sev === 'LOW') cls = 'risk-low';
                        return `<tr>
                            <td style="font-family: monospace; font-size: 0.8rem; color: #9CA3AF;">${(a.time || '').toString().slice(0, 24)}</td>
                            <td>${(a.agent_id || '—')}</td>
                            <td style="font-weight: 600;">${a.user || '—'}</td>
                            <td><span class="badge badge-unknown">${(a.metric || '').replace(/_/g, ' ')}</span></td>
                            <td style="max-width: 360px; color: #9CA3AF; font-size: 0.85rem;">${(a.note || '').replace(/</g, '&lt;')}</td>
                            <td><span class="badge ${cls}">${sev}</span></td>
                        </tr>`;
                    }).join('');
                })
                .catch(err => console.error('Failed to load dashboard alerts:', err));
        }

        function loadScreenshotsIntoModal() {
            fetch('/api/screenshots')
                .then(r => r.json())
                .then(items => {
                    const tbody = document.getElementById('screenshots-modal-tbody');
                    if (!tbody) return;
                    const uf = (document.getElementById('userFilter') && document.getElementById('userFilter').value) || '';
                    const af = (document.getElementById('agentFilter') && document.getElementById('agentFilter').value) || '';

                    let rows = Array.isArray(items) ? items : [];
                    if (uf) {
                        rows = rows.filter(x => (x.user || '').toString() === uf);
                    }
                    // screenshots API doesn't store agent_id separately; fall back to filename match
                    if (af) {
                        rows = rows.filter(x => (x.filename || '').toString().includes(af));
                    }

                    if (!rows.length) {
                        tbody.innerHTML = `<tr><td colspan="5" class="no-data"><div class="no-data-icon">📸</div><div style="font-size: 1rem;">No screenshots for this scope</div><div style="color: #6B7280; font-size: 0.85rem;">Trigger a sensitive clipboard/file event on the endpoint.</div></td></tr>`;
                        return;
                    }

                    tbody.innerHTML = rows.slice(0, 20).map(s => {
                        const ts = (s.timestamp || '').toString();
                        const u = s.user || 'unknown';
                        const sev = s.severity || 'LOW';
                        const url = s.url || (`/screenshot/${encodeURIComponent(s.filename)}`);
                        return `<tr>
                            <td style="font-family: monospace; font-size: 0.8rem; color: #9CA3AF;">${ts.slice(0, 24)}</td>
                            <td style="font-weight: 600;">${u}</td>
                            <td><span class="badge ${sev==='CRITICAL'?'risk-critical':sev==='HIGH'?'risk-high':sev==='MEDIUM'?'risk-medium':'risk-low'}">${sev}</span></td>
                            <td><img src="${url}" style="height:36px;border-radius:6px;border:1px solid #374151" /></td>
                            <td><a class="btn" style="display:inline-block; padding: 0.3rem 0.8rem; font-size: 0.85rem; text-decoration:none;" href="${url}" target="_blank">Open</a></td>
                        </tr>`;
                    }).join('');
                })
                .catch(err => console.error('Failed to load screenshots:', err));
        }

        function openScreenshotsModal() {
            const modal = document.getElementById('screenshotsModal');
            if (!modal) return;
            loadScreenshotsIntoModal();
            modal.style.display = 'flex';
        }

        function closeScreenshotsModal() {
            const modal = document.getElementById('screenshotsModal');
            if (modal) modal.style.display = 'none';
        }

        function applyDashboardScope() {
            updateStatsAndEvents();
            loadDashboardAlerts();
            loadIncidents();
            loadLeaderboard();
            loadAuditTrail();
            loadEmailApprovals();
        }

        function loadEmailApprovals() {
            fetch('/api/email/pending_approvals')
                .then(r => r.json())
                .then(rows => {
                    const tbody = document.getElementById('email-approvals-tbody');
                    if (!tbody) return;
                    if (!Array.isArray(rows) || rows.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="6" class="no-data"><div class="no-data-icon">✉️</div><div style="font-size: 1rem;">No pending emails</div><div style="color: #6B7280;">Classifier queue is empty.</div></td></tr>';
                        return;
                    }
                    tbody.innerHTML = rows.map(function(p) {
                        const d = p.data || {};
                        const subj = String(d.subject || '(no subject)').replace(/</g, '&lt;');
                        const cls = (p.classification && p.classification.classification) ? String(p.classification.classification) : '';
                        const rs = (p.classification && (p.classification.risk_score !== undefined)) ? String(p.classification.risk_score) : '';
                        const q = (p.queued_at || '').toString().slice(0, 19);
                        const eid = p.email_id || '';
                        const sender = String(d.sender || '').trim();
                        const recipient = String(d.recipient || '').trim();
                        const bodyRaw = String(d.body || '').trim();
                        const bodyEsc = bodyRaw
                            .replace(/&/g, '&amp;')
                            .replace(/</g, '&lt;')
                            .replace(/>/g, '&gt;');
                        const meta = (sender || recipient) ? ('From: ' + sender + '<br/>To: ' + recipient + '<br/>') : '';
                        const preview = (bodyEsc ? bodyEsc : 'No message body provided');
                        const previewShort = preview.slice(0, 220) + (preview.length > 220 ? '...' : '');
                        return '<tr><td style="font-family: monospace; font-size: 0.8rem; color: #9CA3AF;">' + q + '</td><td>' + subj + '</td><td>' + cls + '</td><td>' + rs + '</td><td style="max-width:420px; color:#9CA3AF; font-size:0.85rem;"><div style="white-space: pre-wrap;">' + (meta + previewShort) + '</div></td><td><button type="button" class="btn" style="padding:0.25rem 0.6rem; font-size:0.8rem; margin-right:0.35rem;" onclick="approveEmail(' + JSON.stringify(eid) + ')">Approve</button><button type="button" class="btn" style="padding:0.25rem 0.6rem; font-size:0.8rem; background:#7f1d1d;border-color:#991b1b;" onclick="rejectEmail(' + JSON.stringify(eid) + ')">Reject</button></td></tr>';
                    }).join('\\n');
                })
                .catch(function(err) {
                    console.error('Failed to load email approvals:', err);
                    const tbody = document.getElementById('email-approvals-tbody');
                    if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="no-data">Could not load approvals (is the server running?).</td></tr>';
                });
        }

        function approveEmail(emailId) {
            fetch('/api/email/approve/' + encodeURIComponent(emailId), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
                .then(function(r) { return r.json().catch(function() { return {}; }); })
                .then(function(res) {
                    if (res && res.success && res.sent === false && res.message) {
                        alert(res.message);
                    }
                    loadEmailApprovals();
                })
                .catch(function(e) { console.error(e); });
        }

        function rejectEmail(emailId) {
            var reason = window.prompt('Rejection reason (optional):', 'Admin rejected') || 'Admin rejected';
            fetch('/api/email/reject/' + encodeURIComponent(emailId), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ reason: reason })
            }).then(function(r) { return r.json().catch(function() { return {}; }); })
              .then(function(res) {
                  if (res && res.success === false && res.message) alert(res.message);
                  loadEmailApprovals();
              })
              .catch(function(e) { console.error(e); });
        }

        // Event filter logic — only the main activity table (#events-tbody)
        const filterButtons = document.querySelectorAll('.event-filter-btn');

        filterButtons.forEach(btn => {
            btn.addEventListener('click', () => {
                filterButtons.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                const filter = btn.getAttribute('data-filter');
                const eventRows = document.querySelectorAll('#events-tbody tr');
                eventRows.forEach(row => {
                    if (filter === 'all' || row.getAttribute('data-event-type') === filter) {
                        row.style.display = '';
                    } else {
                        row.style.display = 'none';
                    }
                });
            });
        });

        // Event details modal logic
        const eventTable = document.querySelector('.event-section tbody');
        if (eventTable) {
            eventTable.addEventListener('click', function(evt) {
                let tr = evt.target.closest('tr');
                if (tr && tr.getAttribute('data-summary')) {
                    const summary = tr.getAttribute('data-summary');
                    const modal = document.createElement('div');
                    modal.className = 'event-modal-bg';
                    modal.innerHTML = `
                        <div class='event-modal'>
                            <h2>Event Details</h2>
                            <div style="white-space: pre-wrap; font-family: monospace; background: #0B0F19; padding: 1rem; border-radius: 8px; margin: 1rem 0;">${summary}</div>
                            <button onclick='this.parentElement.parentElement.remove()'>Close</button>
                        </div>
                    `;
                    document.body.appendChild(modal);
                }
            });
        }
        // Activity Log Modal
        function showActivityLogs() {
            console.log('Showing activity logs...');
            // Create and show loading indicator
            const loadingModal = document.createElement('div');
            loadingModal.className = 'activity-log-modal';
            loadingModal.innerHTML = `
                <div class="activity-log-content" style="text-align: center; padding: 2rem;">
                    <div style="font-size: 2rem; margin-bottom: 1rem;">📋</div>
                    <div>Loading activity logs...</div>
                </div>
            `;
            document.body.appendChild(loadingModal);

            // Fetch the logs
            fetch('/api/activity_logs')
                .then(response => {
                    console.log('Response received:', response);
                    return response.json();
                })
                .then(logs => {
                    console.log('Logs received:', logs);
                    // Remove loading indicator
                    loadingModal.remove();
                    
                    // Create the actual logs modal
                    const modal = document.createElement('div');
                    modal.className = 'activity-log-modal';
                    modal.innerHTML = `
                        <div class="activity-log-content">
                            <div class="activity-log-header">
                                <h2>📋 User Activity Logs</h2>
                                <div class="activity-log-controls">
                                    <button class="refresh-btn" onclick="refreshActivityLogs()">🔄 Refresh</button>
                                    <button class="close-btn" onclick="closeActivityModal(this)">×</button>
                                </div>
                            </div>
                            <div class="activity-log-body">
                                ${logs.length > 0 ? logs.map(log => `
                                    <div class="log-entry ${log.event_type.toLowerCase()}">
                                        <div class="log-time">${log.timestamp}</div>
                                        <div class="log-type">${log.event_type}</div>
                                        <div class="log-details">${formatLogDetails(log)}</div>
                                    </div>
                                `).join('') : '<div class="no-logs">No activity logs found</div>'}
                            </div>
                        </div>
                    `;
                    document.body.appendChild(modal);

                    // Add click handler to close modal when clicking outside
                    modal.addEventListener('click', function(e) {
                        if (e.target === modal) {
                            modal.remove();
                        }
                    });
                })
                .catch(error => {
                    console.error('Error fetching logs:', error);
                    loadingModal.innerHTML = `
                        <div class="activity-log-content" style="text-align: center; padding: 2rem;">
                            <div style="font-size: 2rem; margin-bottom: 1rem;">⚠️</div>
                            <div>Error loading activity logs</div>
                            <button onclick="this.closest('.activity-log-modal').remove()" style="margin-top: 1rem;">Close</button>
                        </div>
                    `;
                });
        }

        function formatLogDetails(log) {
            if (typeof log.details === 'object') {
                return Object.entries(log.details)
                    .map(([key, value]) => `<strong>${key}:</strong> ${value}`)
                    .join('<br>');
            }
            return log.details;
        }

        function closeActivityModal(button) {
            const modal = button.closest('.activity-log-modal');
            if (modal) {
                modal.style.opacity = '0';
                setTimeout(() => modal.remove(), 300);
            }
        }

        function refreshActivityLogs() {
            const currentModal = document.querySelector('.activity-log-modal');
            if (currentModal) {
                currentModal.remove();
            }
            showActivityLogs();
        }

        // Load user risk leaderboard
        function loadLeaderboard() {
            fetch('/api/users/risk_leaderboard')
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById('leaderboard-tbody');
                    if (!tbody) return;
                    
                    const users = data.leaderboard || [];
                    if (users.length === 0) {
                        tbody.innerHTML = `<tr><td colspan="5" class="no-data"><div class="no-data-icon">👥</div><div style="font-size: 1.2rem; font-weight: 600;">No User Risk Data</div><div style="color: #6B7280;">Waiting for activity analysis...</div></td></tr>`;
                        return;
                    }
                    
                    tbody.innerHTML = users.slice(0, 20).map(user => {
                        const riskPct = (user.risk_score * 100).toFixed(1);
                        let riskLevel = 'LOW', riskClass = 'risk-low';
                        if (user.risk_score >= 0.8) {
                            riskLevel = 'CRITICAL';
                            riskClass = 'risk-critical';
                        } else if (user.risk_score >= 0.6) {
                            riskLevel = 'HIGH';
                            riskClass = 'risk-high';
                        } else if (user.risk_score >= 0.4) {
                            riskLevel = 'MEDIUM';
                            riskClass = 'risk-medium';
                        }
                        
                        const factors = user.risk_factors || {};
                        const factorsList = Object.entries(factors)
                            .map(([key, val]) => `${key}: ${(val * 100).toFixed(0)}%`)
                            .join(', ');
                        
                        return `
                            <tr class="user-row" onclick="selectUserForScope('${user.username}', ${JSON.stringify(user).replace(/'/g, '&#39;')})">
                                <td style="font-weight: 600; cursor: pointer; transition: color 0.2s;" onmouseover="this.style.color='#60a5fa'" onmouseout="this.style.color='#E5E7EB'">${user.username}</td>
                                <td><span class="badge ${riskClass}">${riskPct}%</span></td>
                                <td><span class="badge ${riskClass}">${riskLevel}</span></td>
                                <td style="font-size: 0.85rem; color: #9CA3AF;">${factorsList || 'N/A'}</td>
                                <td><button class="btn" style="padding: 0.3rem 0.8rem; font-size: 0.85rem;" onclick="event.stopPropagation(); selectUserForScope('${user.username}', ${JSON.stringify(user).replace(/'/g, '&#39;')})">👤 View</button></td>
                            </tr>
                        `;
                    }).join('\\n');
                })
                .catch(err => console.error('Failed to load leaderboard:', err));
        }

        // Load incidents (includes high-risk rows derived from events)
        function loadIncidents() {
            fetch('/incidents' + scopeQuery())
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById('incidents-tbody');
                    if (!tbody) return;
                    
                    const incidents = (data.incidents || []);
                    if (incidents.length === 0) {
                        tbody.innerHTML = `<tr><td colspan="6" class="no-data"><div class="no-data-icon">🔐</div><div style="font-size: 1.2rem; font-weight: 600;">No incidents for this scope</div><div style="color: #6B7280;">Try &quot;All endpoints&quot; / &quot;All users&quot; or generate high-risk events.</div></td></tr>`;
                        return;
                    }
                    
                    tbody.innerHTML = incidents.slice(0, 50).map(incident => {
                        let severityClass = 'risk-low';
                        if (incident.severity === 'CRITICAL') severityClass = 'risk-critical';
                        else if (incident.severity === 'HIGH') severityClass = 'risk-high';
                        else if (incident.severity === 'MEDIUM') severityClass = 'risk-medium';
                        
                        let statusClass = 'badge';
                        const st = (incident.status || '').toString().toUpperCase();
                        if (st === 'OPEN') statusClass += ' risk-critical';
                        else if (st === 'IN_PROGRESS') statusClass += ' risk-high';
                        else statusClass += ' risk-low';
                        const when = incident.timestamp || incident.created_at || 'Unknown';
                        
                        return `
                            <tr>
                                <td style="font-weight: 600;">${incident.title || 'Untitled Incident'}</td>
                                <td><span class="badge ${severityClass}">${incident.severity || 'UNKNOWN'}</span></td>
                                <td><span class="${statusClass}">${st || 'UNKNOWN'}</span></td>
                                <td style="font-size: 0.85rem;">${(incident.affected_users || []).join(', ') || 'N/A'}</td>
                                <td style="font-size: 0.85rem; color: #9CA3AF;">${when}</td>
                                <td><button class="btn" style="padding: 0.3rem 0.8rem; font-size: 0.85rem;">📋</button></td>
                            </tr>
                        `;
                    }).join('\\n');
                })
                .catch(err => console.error('Failed to load incidents:', err));
        }

        // Load audit trail
        function loadAuditTrail() {
            const uf = (document.getElementById('userFilter') && document.getElementById('userFilter').value) ? document.getElementById('userFilter').value : '';
            const qs = uf ? ('?user_id=' + encodeURIComponent(uf)) : '';
            fetch('/api/audit_log' + qs)
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById('audit-tbody');
                    if (!tbody) return;
                    
                    const entries = (data.entries || []).slice(0, 100);
                    if (entries.length === 0) {
                        tbody.innerHTML = `<tr><td colspan="5" class="no-data"><div class="no-data-icon">📋</div><div style="font-size: 1.2rem; font-weight: 600;">No Audit Records</div><div style="color: #6B7280;">No admin actions yet</div></td></tr>`;
                        return;
                    }
                    
                    tbody.innerHTML = entries.map(entry => {
                        return `
                            <tr>
                                <td style="font-family: 'Courier New', monospace; color: #9CA3AF; font-size: 0.85rem;">${entry.timestamp || 'Unknown'}</td>
                                <td style="font-weight: 600;">${entry.admin || 'System'}</td>
                                <td>${entry.action || 'Unknown'}</td>
                                <td>${entry.target_user || 'N/A'}</td>
                                <td style="font-size: 0.85rem; color: #9CA3AF; max-width: 300px;">${entry.details || 'N/A'}</td>
                            </tr>
                        `;
                    }).join('\\n');
                })
                .catch(err => console.error('Failed to load audit trail:', err));
        }

        function selectUserForScope(username, userDataStr) {
            const uf = document.getElementById('userFilter');
            if (uf) uf.value = username;
            applyDashboardScope();
            showUserDetails(username, userDataStr);
        }

        // Show user detail modal
        function showUserDetails(username, userDataStr) {
            const userData = typeof userDataStr === 'string' ? JSON.parse(userDataStr) : userDataStr;
            const modal = document.getElementById('userModal');
            const title = document.getElementById('userModalTitle');
            const body = document.getElementById('userModalBody');
            
            if (!modal) return;
            
            title.textContent = `User Details: ${username}`;
            
            const riskScore = userData.risk_score || 0;
            const riskPct = (riskScore * 100).toFixed(1);
            const factors = userData.risk_factors || {};
            
            let riskLevel = 'LOW', riskColor = '#10B981';
            if (riskScore >= 0.8) {
                riskLevel = 'CRITICAL';
                riskColor = '#EF4444';
            } else if (riskScore >= 0.6) {
                riskLevel = 'HIGH';
                riskColor = '#FB923C';
            } else if (riskScore >= 0.4) {
                riskLevel = 'MEDIUM';
                riskColor = '#FBBF24';
            }
            
            const meterColor = riskColor;
            const meterWidth = (riskScore * 100).toFixed(1) + '%';
            
            body.innerHTML = `
                <div style="margin-bottom: 2rem;">
                    <div style="font-size: 1.5rem; font-weight: 700; margin-bottom: 0.5rem; color: #E5E7EB;">Risk Score: <span style="color: ${riskColor};">${riskPct}%</span></div>
                    <div style="font-size: 0.9rem; color: #9CA3AF; margin-bottom: 1rem;">Risk Level: <span style="color: ${riskColor}; font-weight: 600;">${riskLevel}</span></div>
                    <div class="risk-meter">
                        <div class="risk-meter-fill" style="width: ${meterWidth}; background-color: ${meterColor};"></div>
                    </div>
                </div>
                
                <div style="background: rgba(0, 0, 0, 0.3); border-radius: 8px; padding: 1rem; margin-bottom: 2rem;">
                    <div style="font-weight: 600; margin-bottom: 1rem; color: #E5E7EB;">Risk Factor Breakdown</div>
                    ${Object.entries(factors).map(([key, val]) => {
                        const factorPct = (val * 100).toFixed(1);
                        return `
                            <div class="risk-factor-item">
                                <span class="risk-factor-label">${key.replace(/_/g, ' ')}</span>
                                <span class="risk-factor-value">${factorPct}%</span>
                            </div>
                        `;
                    }).join('')}
                </div>
                
                <div style="text-align: center; color: #6B7280; font-size: 0.9rem;">
                    <p>Click "Close" to view this user's events, incidents, and audit actions.</p>
                </div>
            `;
            
            modal.style.display = 'flex';
        }

        function closeUserModal() {
            const modal = document.getElementById('userModal');
            if (modal) {
                modal.style.display = 'none';
            }
        }

        // Close user modal when clicking outside
        window.addEventListener('click', function(event) {
            const modal = document.getElementById('userModal');
            if (modal && event.target === modal) {
                modal.style.display = 'none';
            }
        });

        // Populate endpoint + user dropdowns from activity
        function loadScopeFilters() {
            fetch('/api/users')
                .then(r => r.json())
                .then(data => {
                    const userSel = document.getElementById('userFilter');
                    const agentSel = document.getElementById('agentFilter');
                    const mapEl = document.getElementById('machineUserMap');
                    if (!userSel || !agentSel) return;
                    
                    const users = data.users || [];
                    const agents = data.agents || [];
                    const machines = data.machines || [];
                    
                    while (userSel.options.length > 1) userSel.remove(1);
                    while (agentSel.options.length > 1) agentSel.remove(1);
                    
                    const byAgent = {};
                    machines.forEach(function(m) {
                        if (m && m.agent_id) byAgent[m.agent_id] = m;
                    });
                    
                    agents.forEach(aid => {
                        const o = document.createElement('option');
                        o.value = aid;
                        const m = byAgent[aid];
                        const hn = (m && m.hostname) ? m.hostname : '';
                        o.textContent = hn ? ('🖥 ' + hn + ' (' + aid + ')') : ('🖥 ' + aid);
                        agentSel.appendChild(o);
                    });
                    
                    users.forEach(user => {
                        const option = document.createElement('option');
                        option.value = user;
                        const label = (user || '').toString().includes('\\\\') ? (user.toString().split('\\\\').slice(-1)[0]) : user;
                        option.textContent = '👤 ' + label;
                        userSel.appendChild(option);
                    });

                    if (mapEl) {
                        if (!machines.length) {
                            mapEl.textContent = 'No endpoints seen in telemetry yet. Start agents to map PC → user.';
                        } else {
                            mapEl.innerHTML = machines.map(function(m) {
                                const hn = (m.hostname || m.agent_id || '').toString();
                                const uid = (m.agent_id || '').toString();
                                const ul = (m.users && m.users.length) ? m.users.join(', ') : '(no user in events yet)';
                                return '<div><strong style="color:#E5E7EB;">' + hn + '</strong> <span style="color:#6B7280;">→</span> ' + ul + ' <span style="color:#4B5563;font-size:0.65rem;">[' + uid + ']</span></div>';
                            }).join('');
                        }
                    }
                })
                .catch(err => console.error('Failed to load scope filters:', err));
        }

        function setupScopeHandlers() {
            const userFilter = document.getElementById('userFilter');
            const agentFilter = document.getElementById('agentFilter');
            const onChange = () => applyDashboardScope();
            if (userFilter) userFilter.addEventListener('change', onChange);
            if (agentFilter) agentFilter.addEventListener('change', onChange);
        }

        // Initialize - load data on page load
        window.addEventListener('load', function() {
            console.log('Page loaded, initializing dashboard...');
            loadScopeFilters();
            setupScopeHandlers();
            applyDashboardScope();
        });

        // Refresh scoped data every 30 seconds
        setInterval(function() {
            applyDashboardScope();
        }, 30000);
    </script>
    <style>
        /* Activity Log Modal Styles */
        .activity-log-modal {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.8);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 1000;
            opacity: 1;
            transition: opacity 0.3s ease;
        }

        .activity-log-content {
            background: linear-gradient(135deg, #1a1f2e, #0f1419);
            border: 1px solid #374151;
            border-radius: 16px;
            width: 90%;
            max-width: 1200px;
            max-height: 90vh;
            display: flex;
            flex-direction: column;
            box-shadow: 0 20px 50px rgba(0,0,0,0.3);
            animation: modalSlideIn 0.3s ease;
        }

        @keyframes modalSlideIn {
            from {
                transform: translateY(-20px);
                opacity: 0;
            }
            to {
                transform: translateY(0);
                opacity: 1;
            }
        }

        .activity-log-header {
            padding: 1.5rem;
            border-bottom: 1px solid #374151;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(26, 31, 46, 0.8);
            border-radius: 16px 16px 0 0;
        }

        .activity-log-header h2 {
            font-size: 1.5rem;
            color: #E5E7EB;
            margin: 0;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .activity-log-controls {
            display: flex;
            gap: 1rem;
            align-items: center;
        }

        .refresh-btn {
            background: linear-gradient(135deg, #60a5fa, #549af0);
            border: none;
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 5px;
            transition: all 0.2s;
        }

        .refresh-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3);
        }

        .close-btn {
            background: rgba(75, 85, 99, 0.3);
            border: 1px solid #374151;
            color: #D1D5DB;
            width: 32px;
            height: 32px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s;
        }

        .close-btn:hover {
            background: rgba(75, 85, 99, 0.5);
            transform: rotate(90deg);
        }

        .activity-log-body {
            padding: 1.5rem;
            overflow-y: auto;
            max-height: calc(80vh - 80px);
        }

        .log-entry {
            display: grid;
            grid-template-columns: 180px 100px 1fr;
            gap: 1rem;
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 0.5rem;
            background: rgba(255, 255, 255, 0.05);
        }

        .log-entry:hover {
            background: rgba(255, 255, 255, 0.1);
        }

        .log-time {
            font-family: 'Courier New', monospace;
            color: #9CA3AF;
        }

        .log-type {
            font-weight: 600;
        }

        .log-details {
            color: #D1D5DB;
        }

        /* Log type colors */
        .log-entry.file .log-type { color: #60A5FA; }
        .log-entry.process .log-type { color: #34D399; }
        .log-entry.usb .log-type { color: #F59E0B; }
        .log-entry.security .log-type { color: #EF4444; }
        .log-entry.clipboard .log-type { color: #549af0; }
    </style>
</body>
</html>
"""

# ----------------------------
# /receive_log endpoint (enhanced)
# ----------------------------
@app.route('/receive_log', methods=['POST'])
def receive_log():
    """Receive user activity logs - enhanced with threshold checks and alerting"""
    global RISK_THRESHOLD, events_log, event_counter
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"status": "error", "message": "invalid json"}), 400

    # Normalize any incoming risk_score values inside the cached request JSON.
    # This is important because addons (action_engine, screenshot_addon, multi_lan_addon)
    # re-read request.get_json() after the main handler returns.
    def _norm_score(v):
        try:
            s = float(v or 0)
        except Exception:
            return 0.0
        if s > 1.0:
            if s <= 10.0:
                s = s / 10.0
            else:
                s = 1.0
        if s < 0.0:
            s = 0.0
        return s

    try:
        if isinstance(data, dict) and isinstance(data.get("events"), list):
            for ev in data["events"]:
                if isinstance(ev, dict) and "risk_score" in ev:
                    ev["risk_score"] = _norm_score(ev.get("risk_score"))
        elif isinstance(data, dict) and "risk_score" in data:
            data["risk_score"] = _norm_score(data.get("risk_score"))
    except Exception:
        pass

    # Debug: persist a copy of the raw incoming payload for troubleshooting (append)
    try:
        with open(os.path.join('data', 'incoming_requests.log'), 'a', encoding='utf-8') as dbg:
            dbg.write(json.dumps({
                'time': local_iso(),
                'payload': data
            }, ensure_ascii=False) + '\n')
    except Exception:
        pass

    # Support two payload formats:
    # 1) single event dict -> { ... }
    # 2) batched events from agents -> { "agent_id": "DESKTOP-...", "events": [ {...}, {...} ] }

    def process_single_event(evt, default_agent=None):
        # ensure server-side metadata
        evt = dict(evt) if isinstance(evt, dict) else {}
        # sanitize common fields early to prevent embedded newlines/control characters from corrupting JSONL
        if 'user' in evt:
            evt['user'] = _sanitize_str(evt['user'])
        if 'agent_id' in evt:
            evt['agent_id'] = _sanitize_str(evt['agent_id'])
        if 'event_type' in evt:
            evt['event_type'] = str(evt.get('event_type') or 'unknown').strip().lower()
        if isinstance(evt.get('details'), dict) and isinstance(evt['details'].get('process_info'), dict):
            pi = evt['details']['process_info']
            if 'username' in pi:
                pi['username'] = _sanitize_str(pi['username'])
        if isinstance(evt.get('details'), dict):
            evt.setdefault('action', evt['details'].get('action'))
            device_info = evt['details'].get('device_info') or {}
            if isinstance(device_info, dict):
                evt.setdefault('drive', device_info.get('device'))
                evt.setdefault('mountpoint', device_info.get('mountpoint'))
                evt.setdefault('total_size', device_info.get('total_size'))
        evt.setdefault('received_at', local_iso())
        if default_agent and not evt.get('agent_id'):
            evt['agent_id'] = default_agent

        evt = _derive_file_risk_features(evt)
            
        # Force-check for after-hours logon/logoff events
        logon_action = str(evt.get('action', '')).lower()
        is_logoff_action = "logoff" in logon_action or "logout" in logon_action
        if evt.get('event_type') == 'logon' and not is_logoff_action:
            hour = evt.get('hour_of_day', local_now().hour)
            if is_after_office_hours(hour):
                evt['risk_score'] = 8.0  # Force high risk
                evt['alert'] = True
                alert_msg = f"⚠️ CRITICAL: Login at {hour:02d}:00 - Outside business hours (9:00-17:00)"
                evt['alert_message'] = alert_msg
                evt['details'] = alert_msg
                print(f"🚨 {alert_msg} | User: {evt.get('user', 'unknown')}")
            
            # Track logon session
            user = evt.get('user') or evt.get('username', 'unknown')
            track_logon_event(user, default_agent or evt.get('agent_id', 'unknown'), evt)
        
        elif evt.get('event_type') in ('logoff', 'logoff_session', 'session_end') or (evt.get('event_type') == 'logon' and is_logoff_action):
            hour = evt.get('hour_of_day', local_now().hour)
            if is_after_office_hours(hour):
                evt['risk_score'] = 8.0
                evt['alert'] = True
                alert_msg = f"CRITICAL: Logoff at {hour:02d}:00 - Outside business hours (9:00-17:00)"
                evt['alert_message'] = alert_msg
                evt['details'] = alert_msg
                print(f"{alert_msg} | User: {evt.get('user', 'unknown')}")
            # Track logoff session
            user = evt.get('user') or evt.get('username', 'unknown')
            track_logoff_event(user, evt)

        # Determine risk_score: prefer agent-provided score if present; otherwise run model
        try:
            if _is_email_event(evt):
                if 'risk_score' in evt and 'agent_risk_score' not in evt:
                    evt['agent_risk_score'] = evt.get('risk_score')
                try:
                    email_payload = _build_email_ml_payload(evt)
                    email_prediction = threat_model.predict_email_risk(
                        email_payload["email_text"],
                        metadata=email_payload["metadata"]
                    )
                    risk_score = float(email_prediction.get('risk_score', 0.0))
                    explanation = [email_prediction.get('reason', 'Email ML scoring')]
                except Exception as e:
                    print("⚠️ Email ML prediction failed:", e)
                    risk_score = float(evt.get('risk_score', 0.0))
                    explanation = evt.get('explanation', [])
            elif _should_use_hybrid_model_scoring(evt):
                if 'risk_score' in evt and 'agent_risk_score' not in evt:
                    evt['agent_risk_score'] = evt.get('risk_score')
                try:
                    risk_score, explanation = threat_model.predict_with_explanation(evt)
                except Exception as e:
                    print("⚠️ Model prediction failed:", e)
                    risk_score = float(evt.get('risk_score', 0.0))
                    explanation = evt.get('explanation', [])
                risk_score = float(risk_score)
                explanation = explanation.get('top_factors', []) if isinstance(explanation, dict) else explanation
            elif 'risk_score' in evt:
                risk_score = float(evt.get('risk_score', 0.0))
                explanation = evt.get('explanation', [])
            else:
                try:
                    risk_score, explanation = threat_model.predict_with_explanation(evt)
                except Exception as e:
                    print("⚠️ Model prediction failed:", e)
                    risk_score, explanation = 0.0, {"top_factors": []}
                risk_score = float(risk_score)
                explanation = explanation.get('top_factors', []) if isinstance(explanation, dict) else explanation

            # Normalize risk score to 0.0–1.0 for downstream systems (action engine, UI badges).
            # Some agents/modules produce 0–10 scores; without normalization everything looks CRITICAL
            # and causes constant sound notifications.
            if risk_score > 1.0:
                if risk_score <= 10.0:
                    risk_score = risk_score / 10.0
                else:
                    risk_score = 1.0
            if risk_score < 0.0:
                risk_score = 0.0

            evt['risk_score'] = risk_score
            evt['explanation'] = explanation

            # Auto-enqueue email approvals (dashboard "Email approvals" table)
            # The Outlook agent sends events directly to /receive_log, but the approvals
            # queue is populated only via email_filter.queue_for_approval.
            try:
                ef = ensure_email_filter()
                evt_type = str(evt.get('event_type', '')).strip().lower()
                action = str(evt.get('action', '')).strip().lower()

                if ef and not evt.get('skip_approval_queue') and (evt_type in ('outlook', 'imap', 'email_sent', 'email') or action in ('email_sent', 'email_pending_approval')):
                    rs = float(evt.get('risk_score', 0.0))
                    approval_th = float(getattr(ef, 'approval_threshold', 0.5))
                    block_th = float(getattr(ef, 'block_threshold', 0.75))

                    # Queue any email at or above the approval threshold.
                    # HIGH-risk emails are queued as pending admin decisions too,
                    # with a recommended action of "block".
                    if rs >= approval_th:
                        subject = (evt.get('email_subject') or evt.get('subject') or '').strip()
                        sender = (evt.get('email_sender') or evt.get('sender') or '').strip()

                        recips = evt.get('email_recipients') or evt.get('recipients') or []
                        if isinstance(recips, list):
                            recipient = (recips[0] if recips else '').strip()
                        else:
                            recipient = str(recips or '').strip()

                        email_uid = evt.get('email_uid') or evt.get('email_id')
                        if not email_uid:
                            key = f"{sender}|{subject}|{evt.get('timestamp') or evt.get('received_at') or ''}"
                            email_uid = hashlib.sha256(key.encode('utf-8', errors='ignore')).hexdigest()[:32]

                        body = evt.get('body') or evt.get('email_body') or ''
                        if not body and evt.get('body_length') is not None:
                            # Many agents only provide body_length; keep something visible for the admin UI.
                            body = f"(Body not provided by email agent. body_length={evt.get('body_length')})"

                        email_data = {
                            'email_id': email_uid,
                            'sender': sender,
                            'recipient': recipient,
                            'subject': subject,
                            'body': body,
                            # Stored as-is; queue visualization doesn't require feature extraction.
                            'attachments': evt.get('attachments') or [],
                            'recipients': recips if isinstance(recips, list) else ([recipient] if recipient else []),
                            'has_external': bool(evt.get('has_external', False)),
                            'body_length': evt.get('body_length', len(body) if body else 0),
                            'event_snapshot': {
                                'agent_id': evt.get('agent_id'),
                                'timestamp': evt.get('timestamp') or evt.get('received_at'),
                                'risk_score': round(rs, 3),
                                'details': _format_email_event_details(evt),
                            }
                        }

                        classification = _derive_email_queue_classification(evt, approval_th, block_th)

                        existing = ef.get_pending_record(email_uid) if hasattr(ef, 'get_pending_record') else None
                        if not existing:
                            ef.queue_for_approval(email_data, classification)
            except Exception:
                # Never block ingestion due to email approval queueing.
                pass
        except Exception:
            evt['risk_score'] = float(evt.get('risk_score', 0.0))
            evt['explanation'] = evt.get('explanation', [])

        # store and counters
        events_log.append(evt)
        event_type = evt.get('event_type', 'unknown')
        event_counter[event_type] += 1

        # persist event (append to jsonl)
        try:
            # Debug: write a lightweight pre/post persist trace to help troubleshooting
            dbg_path = os.path.join('data', 'persist_debug.log')
            try:
                with open(dbg_path, 'a', encoding='utf-8') as dbgf:
                    dbgf.write(json.dumps({'time': local_iso(), 'stage': 'before_persist', 'agent_id': evt.get('agent_id'), 'event_type': evt.get('event_type'), 'path': evt.get('path', None), 'raw': evt}, ensure_ascii=False) + '\n')
            except Exception:
                pass

            with open(EVENTS_PATH, 'a', encoding='utf-8') as f:
                f.write(json.dumps(evt, ensure_ascii=False) + '\n')

            try:
                with open(dbg_path, 'a', encoding='utf-8') as dbgf:
                    dbgf.write(json.dumps({'time': local_iso(), 'stage': 'after_persist', 'agent_id': evt.get('agent_id'), 'event_type': evt.get('event_type'), 'path': evt.get('path', None)}, ensure_ascii=False) + '\n')
            except Exception:
                pass
        except Exception as e:
            print("⚠️ Failed to persist event:", e)
            try:
                with open(os.path.join('data', 'persist_debug.log'), 'a', encoding='utf-8') as dbgf:
                    dbgf.write(json.dumps({'time': local_iso(), 'stage': 'persist_failed', 'error': str(e), 'agent_id': evt.get('agent_id'), 'event_type': evt.get('event_type'), 'path': evt.get('path', None)}, ensure_ascii=False) + '\n')
            except Exception:
                pass

        # Update per-user counters for thresholds
        user = evt.get('user') or evt.get('agent_id') or "unknown"
        reset_counters_if_needed(user)

        # Increment counters based on event type
        if event_type == 'file':
            if evt.get('action') in ['file_created', 'file_created_manual', 'created', 'file_added', 'file_moved']:
                user_counters[user]['files_created_today'] += 1
            user_counters[user]['file_actions_today'] += 1
        elif event_type == 'http':
            user_counters[user]['http_requests_today'] += 1
            try:
                if 'bytes' in evt and isinstance(evt['bytes'], (int, float)):
                    user_counters[user]['bytes_downloaded_today'] += int(evt['bytes'])
            except Exception:
                pass
        elif event_type == 'usb':
            user_counters[user]['usb_events_today'] += 1
        elif event_type in ('logon', 'session'):
            user_counters[user]['logon_events_today'] += 1
        elif event_type == 'clipboard':
            user_counters[user]['clipboard_events_today'] += 1
        elif event_type == 'process':
            user_counters[user]['process_events_today'] += 1
        elif event_type in ['outlook', 'imap', 'email_sent']:
            user_counters[user]['outlook_events_today'] += 1
            user_counters[user]['imap_events_today'] += 1

        # Check thresholds and create alerts if required
        new_alerts = []
        # ALERT SYSTEM ENABLED - generates real-time alerts for anomalies
        new_alerts = check_and_generate_alerts(user, evt)
        if new_alerts:
            for a in new_alerts:
                severity_emoji = "🔴" if a['severity'] == "CRITICAL" else "🟠" if a['severity'] == "HIGH" else "🟡"
                print(f"{severity_emoji} ALERT: {a['note']} | user: {a['user']} | metric: {a['metric']}")
                if a['metric'] == 'after_hours_login':
                    evt['details'] = a['note']
                if a['metric'] == 'large_usb_transfer':
                    evt['details'] = a['note']

        # Console logging with severity emoji
        try:
            rs = float(evt.get('risk_score', 0.0))
        except Exception:
            rs = 0.0
        if rs > RISK_THRESHOLD:
            emoji = "🔴"
        elif rs > 0.5:
            emoji = "🟡"
        else:
            emoji = "🟢"
        print(f"{emoji} [{event_type.upper()}] {evt.get('action','-')} | Risk: {rs:.3f} | user: {user}")

        return evt, new_alerts

    # handle batch or single
    generated_alerts = []
    if isinstance(data, dict) and 'events' in data and isinstance(data['events'], list):
        agent = data.get('agent_id') or data.get('agent')
        for ev in data['events']:
            processed, alerts_created = process_single_event(ev, default_agent=agent)
            generated_alerts.extend(alerts_created)
        return jsonify({"status": "received", "events_received": len(data['events']), "alerts": generated_alerts}), 200
    else:
        # assume single event dict
        processed, alerts_created = process_single_event(data, default_agent=None)
        return jsonify({"status": "received", "risk_score": processed.get('risk_score', 0.0), "alerts": alerts_created}), 200

# ----------------------------
# Dashboard & Helpers
# ----------------------------
@app.route('/activity_logs')
def activity_logs():
    logs = []
    try:
        # Read both fixed and live files so newly appended events are visible even when a .fixed exists
        sources = []
        if os.path.exists(EVENTS_FIXED):
            sources.append(EVENTS_FIXED)
        if os.path.exists(EVENTS_PATH):
            sources.append(EVENTS_PATH)

        seen = set()
        for source in sources:
            try:
                with open(source, 'r', encoding='utf-8') as f:
                    for lineno, line in enumerate(f, start=1):
                        if not line.strip():
                            continue
                        try:
                            evt = json.loads(line.strip())
                        except Exception:
                            # skip malformed lines (they should be quarantined by loader)
                            continue

                        # Use a simple dedupe key to avoid duplicates when same event exists in both files
                        try:
                            key = json.dumps({'timestamp': evt.get('timestamp'), 'agent_id': evt.get('agent_id'), 'event_type': evt.get('event_type'), 'path': evt.get('path')}, sort_keys=True)
                        except Exception:
                            key = None
                        if key and key in seen:
                            continue
                        if key:
                            seen.add(key)

                        risk_score = 0.0
                        try:
                            risk_score = float(evt.get('risk_score', 0))
                        except Exception:
                            pass

                        # Determine risk class
                        if risk_score > 0.8:
                            risk_class = 'risk-critical'
                        elif risk_score > 0.6:
                            risk_class = 'risk-high'
                        elif risk_score > 0.4:
                            risk_class = 'risk-medium'
                        else:
                            risk_class = 'risk-low'

                        # Format details and action (keep same logic as before)
                        if evt.get('event_type') == 'file':
                            path = evt.get('path', 'N/A')
                            file_name = os.path.basename(path)
                            details = f"File: {file_name}"
                            action = evt.get('action', '').replace('_', ' ').title()
                        elif evt.get('event_type') == 'usb':
                            details = f"Drive: {evt.get('drive', 'Unknown')} ({evt.get('total_size_gb', 0)} GB)"
                            action = evt.get('action', '').replace('_', ' ').title()
                        elif evt.get('event_type') == 'logon':
                            if evt.get('details') and isinstance(evt.get('details', ''), str) and evt['details'].startswith('⚠️ CRITICAL'):
                                details = evt['details']
                            else:
                                details = f"User: {evt.get('user', 'Unknown')}\nType: {evt.get('logon_type_name', 'Unknown')}"
                            action = "Login"
                        elif evt.get('event_type') == 'http':
                            details = f"URL: {evt.get('url', '')}"
                            action = evt.get('action', '').replace('_', ' ').title()
                        elif evt.get('event_type') == 'clipboard':
                            details = f"Content: {evt.get('content_snippet', '[Clipboard event]')}"
                            action = evt.get('action', '').replace('_', ' ').title()
                        elif evt.get('event_type') == 'process':
                            process_info = evt.get('process_info', {})
                            if isinstance(process_info, str):
                                try:
                                    process_info = json.loads(process_info)
                                except:
                                    process_info = {}

                            name = process_info.get('name', evt.get('process_name', ''))
                            username = process_info.get('username', evt.get('username', ''))
                            pid = process_info.get('pid', evt.get('pid', ''))
                            exe_path = process_info.get('exe_path', evt.get('exe_path', ''))
                            cmdline = process_info.get('cmdline', evt.get('cmdline', ''))

                            action_type = evt.get('action', '')
                            if 'process_started' in action_type.lower():
                                action = "Process Started"
                            elif 'process_ended' in action_type.lower():
                                action = "Process Ended"
                            else:
                                action = action_type.replace('_', ' ').title()

                            details_parts = []
                            if name:
                                details_parts.append(f"Program: {name}")
                            if pid:
                                details_parts.append(f"Process ID: {pid}")
                            if username:
                                details_parts.append(f"User: {username}")
                            if exe_path:
                                details_parts.append(f"Location: {exe_path}")
                            if cmdline:
                                details_parts.append(f"Command: {cmdline}")

                            details = "\n".join(details_parts)
                        elif evt.get('event_type') in ['outlook', 'imap']:
                            details = _format_email_event_details(evt)
                            action = evt.get('action', '').replace('_', ' ').title()
                        else:
                            raw_details = evt.get('details', {})
                            if isinstance(raw_details, dict):
                                details = '\n'.join(f"{k.replace('_', ' ').title()}: {v}" for k, v in raw_details.items())
                            else:
                                details = str(raw_details)
                            action = evt.get('action', '').replace('_', ' ').title()

                        if not action:
                            action = 'Started' if evt.get('action') == 'process_started' else 'Ended'

                        logs.append({
                            'timestamp': evt.get('timestamp', evt.get('received_at', 'N/A')),
                            'agent_id': evt.get('agent_id', 'N/A'),
                            'event_type': evt.get('event_type', 'unknown'),
                            'action': action,
                            'details': details,
                            'risk_score': risk_score,
                            'risk_class': risk_class
                        })
            except Exception as e:
                print(f"Error reading source {source}: {e}")

        # Sort logs by timestamp, most recent first
        try:
            logs.sort(key=lambda x: x['timestamp'], reverse=True)
        except Exception:
            pass
    except Exception as e:
        print(f"Error loading activity logs: {e}")

    return render_template('activity_logs.html', logs=logs)

@app.route('/dashboard')
def dashboard():
    """Modern dashboard - uses STATUS from runtime variables"""
    # Force immediate alert for any recent after-hours sessions
    current_hour = local_now().hour
    recent_sessions = [e for e in events_log[-10:] if e.get('event_type') == 'session']
    for session in recent_sessions:
        hour = session.get('hour_of_day', current_hour)
        if hour < 9 or hour >= 17:
            # risk_score is normalized 0.0–1.0 in the rest of the app
            session['risk_score'] = 0.8
            session['alert'] = True
            alert_msg = f"⚠️ CRITICAL: Login at {hour:02d}:00 - Outside business hours (9:00-17:00)"
            session['alert_message'] = alert_msg
            session['details'] = alert_msg

    total = len(events_log)
    file_count = event_counter.get('file', 0)
    usb_count = event_counter.get('usb', 0)
    logon_count = event_counter.get('logon', 0)
    clipboard_count = event_counter.get('clipboard', 0)
    process_count = event_counter.get('process', 0)
    outlook_count = event_counter.get('outlook', 0)
    imap_count = event_counter.get('imap', 0)

    high_risk = len([e for e in events_log if e.get('risk_score', 0) > RISK_THRESHOLD])
    avg_risk = sum(e.get('risk_score', 0) for e in events_log) / total if total > 0 else 0

    stats = {
        'total_events': total,
        'file_events': file_count,
        'usb_events': usb_count,
        'logon_events': logon_count,
        'clipboard_events': clipboard_count,
        'process_events': process_count,
        'outlook_events': outlook_count,
        'imap_events': imap_count,
        'high_risk': high_risk,
        'avg_risk': avg_risk
    }

    # Prepare events for display (most recent first)
    display_events = []
    # Expand any batch/legacy wrappers when building display list
    for raw_event in reversed(events_log[-50:]):  # Last 50 events
        for event in _expand_possible_wrapper(raw_event):
            risk_score = event.get('risk_score', 0)

            if risk_score > 0.8:
                risk_class = 'risk-critical'
            elif risk_score > 0.6:
                risk_class = 'risk-high'
            elif risk_score > 0.4:
                risk_class = 'risk-medium'
            else:
                risk_class = 'risk-low'

            # Format details
            if event.get('event_type') == 'file':
                path = event.get('path', 'N/A')
                file_name = os.path.basename(path)
                details = f"{file_name}"
            elif event.get('event_type') == 'usb':
                if event.get('action') == 'large_file_transfer':
                    details = f"{event.get('file_name') or event.get('relative_path') or 'USB file'} ({float(event.get('file_size', 0) or 0) / (1024 * 1024):.1f} MB)"
                else:
                    total_size = event.get('total_size_gb')
                    if total_size is None and event.get('total_size'):
                        total_size = round(float(event.get('total_size') or 0) / (1024 ** 3), 1)
                    details = f"{event.get('drive', 'Unknown')} ({total_size or 0} GB)"
            elif event.get('event_type') == 'logon':
                details = f"{event.get('user', 'Unknown')} - {event.get('logon_type_name', 'Unknown')}"
            elif event.get('event_type') == 'http':
                details = f"{event.get('url', '')}"
            elif event.get('event_type') == 'clipboard':
                details = event.get('content_snippet', '[Clipboard event]')
            elif event.get('event_type') == 'process':
                details = event.get('process_name', '[Process event]')
            elif event.get('event_type') in ['outlook', 'imap']:
                details = event.get('email_subject', '[Email event]')
            else:
                details = "N/A"

            display_events.append({
                'timestamp': event.get('timestamp', event.get('received_at', 'N/A')),
                'agent_id': event.get('agent_id', 'N/A'),
                'event_type': event.get('event_type', 'unknown'),
                'action': event.get('action', 'N/A'),
                'details': details,
                'risk_score': risk_score,
                'risk_class': risk_class
            })

    # Number of outstanding alerts (recent)
    recent_alerts = [a for a in alerts if (datetime.fromisoformat(a['time']) > local_now() - timedelta(days=7))]
    recent_alert_count = len(recent_alerts)

    # Render dashboard: use original DASHBOARD_HTML you provided (must be defined above)
    return render_template_string(
        DASHBOARD_HTML,
        stats=stats,
        events=display_events,
        threshold=RISK_THRESHOLD,
        event_summary=event_summary
    )

@app.route('/api/stats')
def get_stats():
    """Return current statistics for alert checking"""
    total = len(events_log)
    high_risk = len([e for e in events_log if e.get('risk_score', 0) > RISK_THRESHOLD])
    avg_risk = sum(e.get('risk_score', 0) for e in events_log) / total if total > 0 else 0
    return jsonify({
        'total_events': total,
        'high_risk': high_risk,
        'avg_risk': avg_risk,
        'file_events': event_counter.get('file', 0),
        'usb_events': event_counter.get('usb', 0),
        'logon_events': event_counter.get('logon', 0),
        'clipboard_events': event_counter.get('clipboard', 0),
        'process_events': event_counter.get('process', 0),
        'outlook_events': event_counter.get('outlook', 0),
        'imap_events': event_counter.get('imap', 0),
        'total_alerts': len(alerts),
    })

@app.route('/api/users')
def get_users():
    """Return unique usernames, agent endpoints, and per-machine user sets (multi-LAN)."""
    agents = set()
    for event in events_log:
        aid = event.get('agent_id')
        if aid:
            agents.add(aid)

    # Drop noisy/technical usernames from dropdown (keeps it “my name + other person”)
    def _is_real_user(u: str):
        if not u:
            return False
        s = str(u).strip()
        if not s:
            return False
        if s.lower() in ("unknown", "system"):
            return False
        if s.upper().startswith("DWM-") or s.upper().startswith("UMFD-"):
            return False
        # Don't show endpoints inside the user list
        if s in agents:
            return False
        return True

    users = set()
    agent_hostname = {}
    agent_users_map = defaultdict(set)
    for event in events_log:
        user = event.get('user') or event.get('username')
        if user:
            users.add(user)
        aid = event.get('agent_id')
        if not aid:
            continue
        hn = (event.get('hostname') or "").strip()
        if hn:
            agent_hostname[aid] = hn
        if user and _is_real_user(user):
            name = str(user).split("\\")[-1].strip()
            if name:
                agent_users_map[aid].add(name)

    filtered_users = sorted([u for u in users if _is_real_user(u)])
    # Normalize DOMAIN\username -> username and de-duplicate
    normalized_users = []
    seen_users = set()
    for u in filtered_users:
        name = str(u).split("\\")[-1].strip()
        if not name:
            continue
        key = name.lower()
        if key in seen_users:
            continue
        seen_users.add(key)
        normalized_users.append(name)

    machines = []
    for aid in sorted(agents):
        ulist = sorted(agent_users_map.get(aid, set()), key=lambda x: x.lower())
        machines.append({
            "agent_id": aid,
            "hostname": agent_hostname.get(aid, ""),
            "users": ulist,
        })

    return jsonify({
        'users': sorted(normalized_users, key=lambda x: x.lower()),
        'agents': sorted(agents),
        'machines': machines,
    })

@app.route('/api/admin/dashboard')
def admin_dashboard():
    """Return admin dashboard data with high-risk users and critical incidents"""
    total = len(events_log)
    high_risk = len([e for e in events_log if e.get('risk_score', 0) > RISK_THRESHOLD])
    avg_risk = sum(e.get('risk_score', 0) for e in events_log) / total if total > 0 else 0
    
    # Get high-risk users
    user_risk_scores = defaultdict(float)
    user_event_counts = defaultdict(int)
    for event in events_log:
        user = event.get('user') or event.get('username') or event.get('agent_id') or 'Unknown'
        risk = float(event.get('risk_score', 0))
        user_risk_scores[user] = max(user_risk_scores[user], risk)
        user_event_counts[user] += 1
    
    high_risk_users = []
    for user, risk_score in sorted(user_risk_scores.items(), key=lambda x: x[1], reverse=True)[:10]:
        if risk_score > 0.3:  # Only show users with some risk
            risk_level = 'CRITICAL' if risk_score > 0.8 else 'HIGH' if risk_score > 0.6 else 'MEDIUM' if risk_score > 0.4 else 'LOW'
            high_risk_users.append({
                'username': user,
                'risk_score': risk_score,
                'risk_level': risk_level,
                'event_count': user_event_counts[user]
            })
    
    # Get recent alerts
    recent_alerts = sorted(alerts, key=lambda x: x.get('time', ''), reverse=True)[:10]
    
    return jsonify({
        'total_events': total,
        'high_risk_count': high_risk,
        'avg_risk': avg_risk,
        'total_alerts': len(alerts),
        'high_risk_users': high_risk_users,
        'recent_alerts': recent_alerts,
        'event_counts': {
            'file': event_counter.get('file', 0),
            'usb': event_counter.get('usb', 0),
            'logon': event_counter.get('logon', 0),
            'clipboard': event_counter.get('clipboard', 0),
            'process': event_counter.get('process', 0),
            'outlook': event_counter.get('outlook', 0),
            'imap': event_counter.get('imap', 0),
        }
    })

@app.route('/api/events')
def get_events():
    """Return last 50 events as JSON for dynamic UI updates - supports user + agent filtering"""
    display_events = []
    user_filter = request.args.get('user', '').strip()
    agent_filter = request.args.get('agent', '').strip()
    
    # Expand any batch/legacy wrappers when building the JSON list
    for raw_event in reversed(events_log[-200:]):  # Last 200 events (for filtering)
        for event in _expand_possible_wrapper(raw_event):
            if agent_filter and (event.get('agent_id') or '') != agent_filter:
                continue
            # Apply user filter if provided
            if user_filter:
                event_user = event.get('user') or event.get('username') or event.get('agent_id') or ''
                if event_user != user_filter:
                    continue
            
            risk_score = event.get('risk_score', 0)

            if risk_score > 0.8:
                risk_class = 'risk-critical'
            elif risk_score > 0.6:
                risk_class = 'risk-high'
            elif risk_score > 0.4:
                risk_class = 'risk-medium'
            else:
                risk_class = 'risk-low'

            # Format details (same logic as dashboard)
            if event.get('event_type') == 'file':
                path = event.get('path', 'N/A')
                file_name = os.path.basename(path)
                details = f"{file_name}"
            elif event.get('event_type') == 'usb':
                details = f"{event.get('drive', 'Unknown')} ({event.get('total_size_gb', 0)} GB)"
            elif event.get('event_type') == 'logon':
                details = f"{event.get('user', 'Unknown')} - {event.get('logon_type_name', 'Unknown')}"
            elif event.get('event_type') == 'http':
                details = f"{event.get('url', '')}"
            elif event.get('event_type') == 'clipboard':
                details = event.get('content_snippet', '[Clipboard event]')
            elif event.get('event_type') == 'process':
                details = event.get('process_name', '[Process event]')
            elif event.get('event_type') in ['outlook', 'imap']:
                details = event.get('email_subject', '[Email event]')
            else:
                details = "N/A"

            display_events.append({
                'timestamp': event.get('timestamp', event.get('received_at', 'N/A')),
                'agent_id': event.get('agent_id', 'N/A'),
                'user': event.get('user') or event.get('username') or event.get('agent_id') or 'N/A',
                'event_type': event.get('event_type', 'unknown'),
                'action': event.get('action', 'N/A'),
                'details': details,
                'risk_score': risk_score,
                'risk_class': risk_class
            })
            
            if len(display_events) >= 50:  # Limit to 50 results
                break
        if len(display_events) >= 50:
            break

    return jsonify(display_events)


@app.route('/api/dashboard/alerts', methods=['GET'])
def dashboard_alerts():
    """Threshold + high-risk activity rows for the main dashboard (filter by user / agent)."""
    user_filter = request.args.get('user', '').strip()
    agent_filter = request.args.get('agent', '').strip()
    thr = float(config.get('risk_display_threshold', RISK_THRESHOLD))
    out = []
    for a in reversed(alerts[-400:]):
        if user_filter and a.get('user') != user_filter:
            continue
        if agent_filter and (a.get('agent_id') or '') != agent_filter:
            continue
        out.append({
            'time': a.get('time'),
            'user': a.get('user'),
            'metric': a.get('metric'),
            'note': a.get('note', ''),
            'severity': a.get('severity', 'MEDIUM'),
            'source': 'threshold',
            'agent_id': a.get('agent_id'),
        })
    seen = {(str(x.get('time')), x.get('user'), x.get('note')) for x in out}
    for e in reversed(events_log[-600:]):
        try:
            rs = float(e.get('risk_score', 0) or 0)
        except (TypeError, ValueError):
            rs = 0.0
        if rs < thr:
            continue
        uid = e.get('user') or e.get('username') or e.get('agent_id')
        if user_filter and uid != user_filter:
            continue
        if agent_filter and (e.get('agent_id') or '') != agent_filter:
            continue
        note = f"{e.get('event_type', '?')}: {e.get('action', '')}"
        if str(e.get('event_type', '')).lower() in ('outlook', 'imap', 'email', 'email_sent', 'email_received'):
            note = _format_email_event_details(e)
        tkey = str(e.get('timestamp') or e.get('received_at') or '')
        tup = (tkey, uid, note)
        if tup in seen:
            continue
        seen.add(tup)
        email_expl = " ".join(str(x) for x in (e.get('explanation') or []))
        inferred_high = 'HIGH' in email_expl.upper() or 'CRITICAL' in email_expl.upper()
        out.append({
            'time': e.get('timestamp') or e.get('received_at'),
            'user': uid,
            'metric': 'high_risk_event',
            'note': note,
            'severity': 'CRITICAL' if rs >= 0.9 else 'HIGH' if (rs >= 0.7 or inferred_high) else 'MEDIUM',
            'source': 'activity',
            'agent_id': e.get('agent_id'),
            'risk_score': rs,
        })
    out.sort(key=lambda x: str(x.get('time') or ''), reverse=True)
    return jsonify({'alerts': out[:150]}), 200


@app.route('/update_threshold', methods=['POST'])
def update_threshold():
    global RISK_THRESHOLD, config
    data = request.get_json(force=True)
    try:
        new_threshold = float(data.get('threshold', RISK_THRESHOLD))
    except:
        new_threshold = RISK_THRESHOLD
    RISK_THRESHOLD = new_threshold
    config['risk_display_threshold'] = RISK_THRESHOLD
    save_config(config)
    print(f"🎯 Threshold updated: {RISK_THRESHOLD}")
    return jsonify({"status": "success", "risk_display_threshold": RISK_THRESHOLD})

@app.route('/clear_all', methods=['POST'])
def clear_all():
    global events_log, event_counter
    events_log = []
    event_counter = Counter()
    print("🗑️ All events cleared")
    return jsonify({"status": "success"})

@app.route('/export_csv')
def export_csv():
    import csv
    csv_path = 'data/user_activity_export.csv'
    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            if events_log:
                fieldnames = sorted(set().union(*[event.keys() for event in events_log]))
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(events_log)
    except Exception as e:
        print("⚠️ Export failed:", e)
    return send_file(csv_path, as_attachment=True, download_name='user_activity.csv')

@app.route('/alerts')
def get_alerts():
    """Return last 200 alerts as JSON (useful for frontend)"""
    return jsonify(load_past_alerts(limit=200))

@app.route('/api/sessions')
def get_sessions():
    """Return user session information - login/logout tracking"""
    return jsonify({
        'active_sessions': {
            user: {
                'login_time': session.get('login_time', '').isoformat() if hasattr(session.get('login_time', ''), 'isoformat') else str(session.get('login_time', '')),
                'agent_id': session.get('agent_id'),
                'logon_type': session.get('logon_type'),
                'session_id': session.get('session_id')
            }
            for user, session in active_sessions.items()
        },
        'user_session_history': {
            user: [
                {
                    'login_time': s.get('login_time', '').isoformat() if hasattr(s.get('login_time', ''), 'isoformat') else str(s.get('login_time', '')),
                    'logout_time': s.get('logout_time', '').isoformat() if hasattr(s.get('logout_time', ''), 'isoformat') else str(s.get('logout_time', '')),
                    'agent_id': s.get('agent_id'),
                    'logon_type': s.get('logon_type'),
                    'duration_seconds': s.get('duration_seconds')
                }
                for s in user_sessions.get(user, [])
            ]
            for user in list(user_sessions.keys())[-50:]  # Last 50 users
        }
    })

@app.route('/config')
def get_config():
    """Return current config & thresholds"""
    return jsonify(config)

@app.route('/api/activity_logs')
def api_activity_logs():
    """Return activity logs as JSON for AJAX refresh"""
    try:
        logs = []
        with open(os.path.join('data', 'user_activity.jsonl'), 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    evt = json.loads(line)
                    risk_score = float(evt.get('risk_score', 0))
                    
                    # Determine risk class
                    if risk_score > 0.8:
                        risk_class = 'risk-critical'
                    elif risk_score > 0.6:
                        risk_class = 'risk-high'
                    elif risk_score > 0.4:
                        risk_class = 'risk-medium'
                    else:
                        risk_class = 'risk-low'
                    
                    # Format details
                    if evt.get('event_type') == 'file':
                        path = evt.get('path', 'N/A')
                        file_name = os.path.basename(path)
                        details = f"{file_name}"
                    elif evt.get('event_type') == 'usb':
                        details = f"{evt.get('drive', 'Unknown')} ({evt.get('total_size_gb', 0)} GB)"
                    elif evt.get('event_type') in ['logon', 'session']:
                        username = evt.get('username') or evt.get('user', 'Unknown')
                        hostname = evt.get('hostname', 'Unknown')
                        session_type = evt.get('session_type', 'Unknown')
                        logon_type = evt.get('logon_type', 'Unknown')
                        
                        # Format with hostname for multi-system monitoring
                        details = [
                            f"User: {username}",
                            f"System: {hostname}",
                            f"Session: {session_type}",
                            f"Type: {logon_type}"
                        ]
                        details = "\n".join(details)
                    elif evt.get('event_type') == 'http':
                        details = f"{evt.get('url', '')}"
                    elif evt.get('event_type') == 'clipboard':
                        details = evt.get('content_snippet', '[Clipboard event]')
                    elif evt.get('event_type') == 'process':
                        details = evt.get('process_name', '[Process event]')
                    elif evt.get('event_type') in ['outlook', 'imap']:
                        details = _format_email_event_details(evt)
                    else:
                        details = evt.get('details', 'N/A')
                    
                    logs.append({
                        'timestamp': evt.get('timestamp', evt.get('received_at', 'N/A')),
                        'agent_id': evt.get('agent_id', 'N/A'),
                        'event_type': evt.get('event_type', 'unknown'),
                        'action': evt.get('action', 'N/A'),
                        'details': details,
                        'risk_score': risk_score,
                        'risk_class': risk_class
                    })
        
        # Sort logs by timestamp, most recent first
        logs.sort(key=lambda x: x['timestamp'], reverse=True)
        return jsonify(logs)
    except Exception as e:
        print(f"Error loading activity logs: {e}")
        return jsonify([])

@app.route('/api/activity_logs_by_agent')
def api_activity_logs_by_agent():
    """Return activity logs organized by agent/system"""
    try:
        logs_by_agent = defaultdict(list)
        
        with open(os.path.join('data', 'user_activity.jsonl'), 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    evt = json.loads(line)
                    risk_score = float(evt.get('risk_score', 0))
                    
                    # Determine risk class
                    if risk_score > 0.8:
                        risk_class = 'risk-critical'
                    elif risk_score > 0.6:
                        risk_class = 'risk-high'
                    elif risk_score > 0.4:
                        risk_class = 'risk-medium'
                    else:
                        risk_class = 'risk-low'
                    
                    # Format details
                    if evt.get('event_type') == 'file':
                        path = evt.get('path', 'N/A')
                        file_name = os.path.basename(path)
                        details = f"{file_name}"
                    elif evt.get('event_type') == 'usb':
                        details = f"{evt.get('drive', 'Unknown')} ({evt.get('total_size_gb', 0)} GB)"
                    elif evt.get('event_type') in ['logon', 'session']:
                        username = evt.get('username') or evt.get('user', 'Unknown')
                        hostname = evt.get('hostname', 'Unknown')
                        session_type = evt.get('session_type', 'Unknown')
                        logon_type = evt.get('logon_type', 'Unknown')
                        
                        details = [
                            f"User: {username}",
                            f"System: {hostname}",
                            f"Session: {session_type}",
                            f"Type: {logon_type}"
                        ]
                        details = "\n".join(details)
                    elif evt.get('event_type') == 'http':
                        details = f"{evt.get('url', '')}"
                    elif evt.get('event_type') == 'clipboard':
                        details = evt.get('content_snippet', '[Clipboard event]')
                    elif evt.get('event_type') == 'process':
                        details = evt.get('process_name', '[Process event]')
                    elif evt.get('event_type') in ['outlook', 'imap']:
                        details = evt.get('email_subject', '[Email event]')
                    else:
                        details = evt.get('details', 'N/A')
                    
                    agent_id = evt.get('agent_id', 'Unknown Agent')
                    user = evt.get('user', evt.get('username', 'Unknown User'))
                    
                    log_entry = {
                        'timestamp': evt.get('timestamp', evt.get('received_at', 'N/A')),
                        'user': user,
                        'event_type': evt.get('event_type', 'unknown'),
                        'action': evt.get('action', 'N/A'),
                        'details': details,
                        'risk_score': risk_score,
                        'risk_class': risk_class
                    }
                    
                    logs_by_agent[agent_id].append(log_entry)
        
        # Sort logs within each agent by timestamp, most recent first
        for agent_id in logs_by_agent:
            logs_by_agent[agent_id].sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Convert to list of dicts with agent metadata
        result = []
        for agent_id, logs in sorted(logs_by_agent.items()):
            result.append({
                'agent_id': agent_id,
                'total_events': len(logs),
                'latest_event': logs[0]['timestamp'] if logs else 'N/A',
                'logs': logs[:100]  # Limit to 100 most recent per agent
            })
        
        return jsonify(result)
    except Exception as e:
        print(f"Error loading activity logs by agent: {e}")
        return jsonify([])

@app.route('/export_activity_logs')
def export_activity_logs():
    """Export activity logs as CSV"""
    import csv
    from io import StringIO
    try:
        logs = []
        with open(os.path.join('data', 'user_activity.jsonl'), 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    if line.strip():
                        logs.append(json.loads(line.strip()))
                except json.JSONDecodeError as je:
                    print(f"Warning: Skipping invalid JSON line: {je}")

        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=[
            'timestamp', 'agent_id', 'event_type', 'action', 'details', 'risk_score'
        ])
        writer.writeheader()

        for log in logs:
            writer.writerow({
                'timestamp': log.get('timestamp', log.get('received_at', 'N/A')),
                'agent_id': log.get('agent_id', 'N/A'),
                'event_type': log.get('event_type', 'unknown'),
                'action': log.get('action', 'N/A'),
                'details': log.get('details', 'N/A'),
                'risk_score': log.get('risk_score', 0)
            })

        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=activity_logs.csv'}
        )
    except Exception as e:
        print(f"Error exporting activity logs: {e}")
        return "Error exporting logs", 500

@app.route('/api/screenshots')
def get_screenshots():
    """Return list of available screenshot files"""
    try:
        screenshots = []
        shot_dir = os.path.join('data', 'screenshots')
        if not os.path.exists(shot_dir):
            return jsonify([])
        for filename in os.listdir(shot_dir):
            if filename.startswith('screenshot_') and filename.endswith('.png'):
                filepath = os.path.join(shot_dir, filename)
                stat = os.stat(filepath)
                screenshots.append({
                    'filename': filename,
                    'timestamp': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'size': stat.st_size
                })

        # Sort by timestamp, newest first
        screenshots.sort(key=lambda x: x['timestamp'], reverse=True)
        return jsonify(screenshots)
    except Exception as e:
        print(f"Error listing screenshots: {e}")
        return jsonify([])

@app.route('/screenshot/<filename>')
def serve_screenshot(filename):
    """Serve screenshot files"""
    try:
        if not filename.startswith('screenshot_') or not filename.endswith('.png'):
            return "Invalid filename", 400

        shot_dir = os.path.join('data', 'screenshots')
        filepath = os.path.join(shot_dir, filename)
        if not os.path.exists(filepath):
            return "Screenshot not found", 404

        return send_file(filepath, mimetype='image/png')
    except Exception as e:
        print(f"Error serving screenshot {filename}: {e}")
        return "Error serving screenshot", 500

@app.route('/welcome', methods=['GET'])
def welcome():
    """
    Returns a welcome message and logs the request metadata
    """
    app.logger.info(f"Request received: {request.method} {request.path}")
    return jsonify({"message": "Welcome to the Flask API Service!"})

@app.route('/')
def home():
    if session.get('logged_in'):
        return redirect('/dashboard')
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login endpoint"""
    if request.method == 'POST':
        data = request.get_json() or {}
        username = data.get('username', 'admin')
        password = data.get('password', '')
        
        # Simple authentication (in production, use proper password hashing)
        # Default credentials: admin/admin
        if username and len(password) > 0:
            session['logged_in'] = True
            session['username'] = username
            session.permanent = True
            
            if audit_trail:
                try:
                    al = audit_trail.ACTION_TYPES.get('USER_LOGIN', 'user_login')
                except Exception:
                    al = 'user_login'
                audit_trail.log_action(al, username, username, target='dashboard', details={'message': f'User {username} logged in'})
            
            return jsonify({'status': 'success', 'message': 'Logged in successfully'}), 200
        else:
            return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401
    
    # Show login page
    if session.get('logged_in'):
        return redirect('/dashboard')
    
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>DeepSentinel Login</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
            }
            .login-container {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.2);
                width: 100%;
                max-width: 400px;
            }
            .login-header {
                text-align: center;
                margin-bottom: 30px;
            }
            .login-header h1 {
                color: #333;
                font-size: 28px;
                margin-bottom: 5px;
            }
            .login-header p {
                color: #666;
                font-size: 14px;
            }
            .form-group {
                margin-bottom: 20px;
            }
            .form-group label {
                display: block;
                margin-bottom: 8px;
                color: #333;
                font-weight: 500;
            }
            .form-group input {
                width: 100%;
                padding: 12px;
                border: 1px solid #ddd;
                border-radius: 5px;
                font-size: 14px;
                transition: border-color 0.3s;
            }
            .form-group input:focus {
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }
            .login-btn {
                width: 100%;
                padding: 12px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.2s, box-shadow 0.2s;
            }
            .login-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
            }
            .login-btn:active {
                transform: translateY(0);
            }
            .error-message {
                color: #e74c3c;
                font-size: 14px;
                margin-bottom: 20px;
                display: none;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="login-header">
                <h1>🛡️ DeepSentinel</h1>
                <p>Insider Threat Detection System</p>
            </div>
            <div class="error-message" id="errorMsg"></div>
            <form id="loginForm">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" placeholder="admin" required>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" placeholder="••••••••" required>
                </div>
                <button type="submit" class="login-btn">Login</button>
            </form>
        </div>
        
        <script>
            document.getElementById('loginForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                
                try {
                    const response = await fetch('/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, password })
                    });
                    
                    const data = await response.json();
                    if (response.ok) {
                        window.location.href = '/dashboard';
                    } else {
                        document.getElementById('errorMsg').textContent = data.message || 'Login failed';
                        document.getElementById('errorMsg').style.display = 'block';
                    }
                } catch (error) {
                    document.getElementById('errorMsg').textContent = 'Network error';
                    document.getElementById('errorMsg').style.display = 'block';
                }
            });
        </script>
    </body>
    </html>
    '''

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """Logout endpoint"""
    username = session.get('username', 'unknown')
    session.clear()
    
    if audit_trail:
        try:
            al = audit_trail.ACTION_TYPES.get('USER_LOGOUT', 'user_logout')
        except Exception:
            al = 'user_logout'
        audit_trail.log_action(al, username, username, target='dashboard', details={'message': f'User {username} logged out'})
    
    return redirect('/login')

# Error handler for debugging
@app.errorhandler(500)
def handle_500(error):
    import traceback
    return jsonify({
        "error": str(error),
        "traceback": traceback.format_exc()
    }), 500

from screenshot_addon import wire_screenshot
wire_screenshot(app)

from action_engine import ActionEngine
ActionEngine().wire(app)

from admin_commands import register_commands, enqueue_agent_command
register_commands(app)

from multi_lan_addon import register_multi_lan
register_multi_lan(app)

# ========== NEW SECURITY MODULES ==========
print("🔧 Initializing advanced security modules...")

# Email filtering with ML classification
email_filter = None

def ensure_email_filter():
    """Lazy-load EmailFilter so email approvals never silently break."""
    global email_filter
    if email_filter is not None:
        return email_filter
    try:
        from email_filter import EmailFilter
        email_filter = EmailFilter()
        print("✅ Email filter loaded - 3-tier ML classification active")
    except Exception as e:
        print(f"⚠️ Email filter not available: {e}")
        email_filter = None
    return email_filter

ensure_email_filter()

# NLP-based explainability engine
try:
    from explainability import Explainer
    explainer = Explainer()
    print("✅ Explainability engine loaded - NLP threat explanations active")
    
    # Add explainability endpoint
    @app.route("/api/explain/<event_id>", methods=["GET"])
    def explain_event(event_id):
        """Get NLP-based explanation for why an event was flagged."""
        # Find event in events_log
        event = next((e for e in events_log if str(e.get('_id', '')) == event_id or str(id(e)) == event_id), None)
        if not event:
            return jsonify({"error": "Event not found"}), 404
        
        explanation = explainer.explain_event(event)
        return jsonify(explanation), 200
    
except Exception as e:
    print(f"⚠️ Explainability engine not available: {e}")
    explainer = None

# Honeypot trap system
try:
    from honeypot_manager import HoneypotManager
    honeypot = HoneypotManager()
    honeypot.wire(app)
    print("✅ Honeypot system loaded - 3 decoy file systems active")
except Exception as e:
    print(f"⚠️ Honeypot system not available: {e}")
    honeypot = None

# User blocking & admin actions
try:
    from user_blocking import UserBlockingManager
    blocking_manager = UserBlockingManager()
    blocking_manager.wire(app)
    print("✅ User blocking & isolation system loaded - Admin controls active")
except Exception as e:
    print(f"⚠️ User blocking system not available: {e}")
    blocking_manager = None

# Email approval workflow endpoint
@app.route("/api/email/classify", methods=["POST"])
def classify_email():
    """Classify email and queue for approval if needed."""
    ef = ensure_email_filter()
    if not ef:
        return jsonify({"error": "Email filter not available"}), 503
    data = request.get_json(force=True) or {}
    classification = ef.classify_email(data)

    if classification["classification"] in ("MEDIUM", "HIGH"):
        email_id = ef.queue_for_approval(data, classification)
        return jsonify({
            "status": "pending_approval",
            "email_id": email_id,
            "classification": classification
        }), 200

    return jsonify(classification), 200

# ========== ADVANCED BEHAVIORAL ANALYTICS ==========
print("🧠 Initializing AI behavioral analytics...")

# UEBA - User & Entity Behavior Analytics
try:
    from ueba import UEBAEngine
    ueba = UEBAEngine()
    
    # Build baseline from existing events
    if events_log:
        ueba.learn_user_behavior(events_log)
    
    print("✅ UEBA engine loaded - Behavior baseline learning active")
    
    @app.route("/api/ueba/check/<user_id>", methods=["POST"])
    def check_user_anomaly(user_id):
        """Check if recent user activity is anomalous."""
        data = request.get_json(force=True) or {}
        event = data.get('event', {})
        event['user_id'] = user_id
        
        anomaly = ueba.detect_anomaly(event)
        return jsonify(anomaly), 200
    
    @app.route("/api/ueba/profile/<user_id>", methods=["GET"])
    def get_user_profile(user_id):
        """Get behavior profile for user."""
        profile = ueba.get_user_profile(user_id)
        if not profile:
            return jsonify({"error": "No profile found"}), 404
        return jsonify(profile), 200
    
    @app.route("/api/ueba/anomalies", methods=["GET"])
    def get_ueba_anomalies():
        """Get recent detected anomalies."""
        limit = request.args.get('limit', 50, type=int)
        anomalies = ueba.get_all_anomalies(limit=limit)
        return jsonify({"count": len(anomalies), "anomalies": anomalies}), 200
    
except Exception as e:
    print(f"⚠️ UEBA engine not available: {e}")
    ueba = None

# Peer Group Analysis
try:
    from peer_analysis import PeerGroupAnalyzer
    peer_analyzer = PeerGroupAnalyzer()
    
    # Build access matrix from existing events
    if events_log:
        peer_analyzer.build_access_matrix(events_log)
    
    print("✅ Peer Group Analysis loaded - Anomaly detection relative to peer groups active")
    
    @app.route("/api/peer/check/<user_id>", methods=["POST"])
    def check_peer_anomaly(user_id):
        """Check if file access is anomalous for peer group."""
        data = request.get_json(force=True) or {}
        resource = data.get('resource')
        access_type = data.get('access_type', 'read')
        
        if not resource:
            return jsonify({"error": "resource required"}), 400
        
        anomaly = peer_analyzer.check_peer_anomaly(user_id, resource, access_type)
        return jsonify(anomaly), 200
    
    @app.route("/api/peer/exfiltration/<user_id>", methods=["POST"])
    def check_exfiltration_risk(user_id):
        """Flag potential data exfiltration."""
        data = request.get_json(force=True) or {}
        files = data.get('files', [])
        total_size = data.get('total_size_mb')
        
        risk = peer_analyzer.flag_data_exfiltration_risk(user_id, files, total_size)
        return jsonify(risk), 200
    
    @app.route("/api/peer/violations", methods=["GET"])
    def get_peer_violations():
        """Get peer anomaly violations."""
        limit = request.args.get('limit', 50, type=int)
        severity = request.args.get('severity')
        violations = peer_analyzer.get_recent_violations(limit=limit, severity=severity)
        return jsonify({"count": len(violations), "violations": violations}), 200
    
    @app.route("/api/peer/group/<department>", methods=["GET"])
    def get_group_stats(department):
        """Get file access stats for department."""
        stats = peer_analyzer.get_group_file_access_summary(department)
        return jsonify(stats), 200
    
except Exception as e:
    print(f"⚠️ Peer Group Analysis not available: {e}")
    peer_analyzer = None

# Time-Based Anomaly Detection
try:
    from time_anomaly import TimeAnomalyDetector
    time_detector = TimeAnomalyDetector()
    
    print("✅ Time-Based Anomaly Detection loaded - Activity chain detection active")
    
    @app.route("/api/time/chains/<user_id>", methods=["POST"])
    def detect_activity_chains(user_id):
        """Detect suspicious activity chains for user."""
        data = request.get_json(force=True) or {}
        events = data.get('events', [])
        
        chains = time_detector.detect_activity_chain(user_id, events)
        return jsonify({"user_id": user_id, "chains_detected": len(chains), "chains": chains}), 200
    
    @app.route("/api/time/baseline/<user_id>", methods=["GET"])
    def get_hourly_baseline(user_id):
        """Get activity baseline by hour."""
        # Filter events for this user
        user_events = [e for e in events_log if e.get('user_id') == user_id]
        baseline = time_detector.get_hourly_activity_baseline(user_id, user_events)
        return jsonify({"user_id": user_id, "hourly_baseline": baseline}), 200
    
    @app.route("/api/time/spike/<user_id>", methods=["GET"])
    def check_off_hours_spike(user_id):
        """Check for unusual off-hours activity spikes."""
        user_events = [e for e in events_log if e.get('user_id') == user_id]
        spike = time_detector.detect_off_hours_spike(user_id, user_events)
        return jsonify(spike), 200
    
    @app.route("/api/time/summary", methods=["GET"])
    def get_activity_summary():
        """Get activity summary for time period."""
        hours = request.args.get('hours', 24, type=int)
        summary = time_detector.get_activity_summary(events_log, time_window_hours=hours)
        return jsonify(summary), 200
    
except Exception as e:
    print(f"⚠️ Time-Based Anomaly Detection not available: {e}")
    time_detector = None

# ========== MOBILE DASHBOARD ==========
print("📱 Registering mobile dashboard routes...")

@app.route("/mobile")
def mobile_dashboard():
    """Serve mobile-optimized dashboard."""
    try:
        with open(os.path.join(ROOT, "templates", "mobile_dashboard.html"), 'r', encoding='utf-8') as f:
            return f.read()
    except:
        return "<h1>Mobile Dashboard</h1><p>Unable to load mobile dashboard</p>"

@app.route("/api/mobile/summary", methods=["GET"])
def mobile_summary():
    """Get dashboard summary for mobile."""
    return jsonify({
        "total_alerts": len(alerts),
        "blocked_users": len(blocked_users) if 'blocked_users' in dir() else 0,
        "emails_count": sum(1 for e in events_log if e.get('type') == 'email'),
        "honeypot_triggers": honeypot.get_honeypot_stats() if honeypot else {},
        "high_risk_users": blocking_manager.get_blocked_users_list()[:5] if blocking_manager else [],
        "critical_alerts": [a for a in alerts if a.get('severity') == 'CRITICAL'][:5]
    }), 200


@app.route("/api/email/pending_approvals", methods=["GET"])
def api_email_pending_approvals():
    """Emails pending admin review (requires email_filter module)."""
    ef = ensure_email_filter()
    if not ef:
        return jsonify([]), 200
    pending = ef.get_pending_approvals()
    return jsonify(pending), 200


def _try_send_outgoing_email_smtp(email_data: dict):
    """
    Send the approved email using SMTP.
    Note: the queue may not contain real attachment file paths; we send body as text.
    """
    try:
        import os
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        to_email = (email_data.get("recipient") or "").strip()
        if not to_email:
            return False, "Missing recipient in queued email"

        subject = (email_data.get("subject") or "(no subject)").strip()
        body = email_data.get("body") or ""
        if not body:
            body = "(empty message body provided by email agent)"

        # Reuse the existing SMTP config from NotificationManager if available.
        smtp_server = (notif_mgr.config.get("smtp_server") if 'notif_mgr' in globals() and notif_mgr else None) or "localhost"
        smtp_port = int((notif_mgr.config.get("smtp_port") if 'notif_mgr' in globals() and notif_mgr else None) or 25)
        from_email = None
        smtp_username = None
        smtp_password = None
        if 'notif_mgr' in globals() and notif_mgr:
            from_email = notif_mgr.config.get("from_email")
            smtp_username = notif_mgr.config.get("smtp_username")
            smtp_password = notif_mgr.config.get("smtp_password")
        smtp_username = smtp_username or os.environ.get("SMTP_USERNAME")
        smtp_password = smtp_password or os.environ.get("SMTP_PASSWORD")
        from_email = (from_email or email_data.get("sender") or "deepsentinel@deepsec.ai").strip()

        msg = MIMEMultipart()
        msg["From"] = from_email
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as s:
            # Many servers support STARTTLS; try and ignore if not supported.
            try:
                s.starttls()
            except Exception:
                pass
            if smtp_username and smtp_password:
                s.login(smtp_username, smtp_password)
            s.send_message(msg)

        return True, "sent"
    except Exception as e:
        return False, str(e)


@app.route("/api/email/approve/<path:email_id>", methods=["POST"])
def api_email_approve(email_id):
    ef = ensure_email_filter()
    if not ef:
        return jsonify({"success": False, "message": "Email filter not available"}), 503
    record = ef.get_pending_record(email_id) or {}
    email_data = record.get("data") or {}

    success = ef.approve_email(email_id)
    if not success:
        return jsonify({
            "success": False,
            "message": "Email not found"
        }), 200

    release_via_agent = bool(email_data.get("release_via_agent"))
    originating_agent = (email_data.get("agent_id") or email_data.get("originating_agent_id") or "").strip()

    if release_via_agent and originating_agent:
        enqueue_agent_command(
            originating_agent,
            "send_pending_email",
            reason=f"Admin approved held email {email_id}",
            admin_user="admin",
            email_id=email_id,
        )
        sent_ok, send_msg = True, "release command queued to agent"
    else:
        sent_ok, send_msg = _try_send_outgoing_email_smtp(email_data) if email_data else (False, "No queued email_data to send")

    return jsonify({
        "success": True,
        "message": "Email approved" + (f" and sent ({send_msg})" if sent_ok else " but send failed"),
        "sent": sent_ok,
        "send_message": send_msg
    }), 200


@app.route("/api/email/reject/<path:email_id>", methods=["POST"])
def api_email_reject(email_id):
    ef = ensure_email_filter()
    if not ef:
        return jsonify({"success": False, "message": "Email filter not available"}), 503
    data = request.get_json(force=True) or {}
    reason = data.get("reason", "Admin rejected")
    record = ef.get_pending_record(email_id) or {}
    email_data = record.get("data") or {}
    success = ef.reject_email(email_id, reason)
    release_via_agent = bool(email_data.get("release_via_agent"))
    originating_agent = (email_data.get("agent_id") or email_data.get("originating_agent_id") or "").strip()
    if success and release_via_agent and originating_agent:
        enqueue_agent_command(
            originating_agent,
            "reject_pending_email",
            reason=reason,
            admin_user="admin",
            email_id=email_id,
        )
    return jsonify({
        "success": success,
        "message": "Email rejected" if success else "Email not found"
    }), 200


@app.route("/api/email/stats", methods=["GET"])
def api_email_stats():
    ef = ensure_email_filter()
    if not ef:
        return jsonify({"total": 0, "low": 0, "medium": 0, "high": 0, "blocked": 0, "pending_approval": 0, "disabled": True}), 200
    return jsonify(ef.get_approval_stats()), 200


# ========== INCIDENT MANAGEMENT ROUTES ==========
if incident_mgr:
    @app.route('/incidents', methods=['GET'])
    def list_incidents():
        """List stored incidents plus high-risk activity rows derived from events."""
        try:
            if not incident_mgr:
                return jsonify({'incidents': [], 'total': 0}), 200
            
            status = request.args.get('status')
            limit = request.args.get('limit', 100, type=int)
            incidents = incident_mgr.list_incidents(status=status, limit=limit)
            for inc in incidents:
                if isinstance(inc, dict) and inc.get('created_at') and not inc.get('timestamp'):
                    inc['timestamp'] = inc['created_at']
                if isinstance(inc, dict) and inc.get('status'):
                    inc['status'] = str(inc.get('status', '')).upper()
            derived = derived_incidents_from_events(limit=40)
            merged = incidents + [d for d in derived if d.get('id') not in {i.get('id') for i in incidents if isinstance(i, dict)}]
            merged.sort(key=lambda x: str(x.get('timestamp') or x.get('created_at') or ''), reverse=True)
            user_q = request.args.get('user', '').strip()
            agent_q = request.args.get('agent', '').strip()
            if user_q:
                merged = [
                    x for x in merged
                    if user_q in (x.get('affected_users') or [])
                    or user_q in str(x.get('title', ''))
                ]
            if agent_q:
                merged = [x for x in merged if str(x.get('agent_id', '') or '') == agent_q]
            return jsonify({
                'incidents': merged[: max(limit, 50)],
                'total': len(merged),
            }), 200
        except Exception as e:
            print(f"Error listing incidents: {e}")
            return jsonify({'incidents': [], 'total': 0}), 200
    
    @app.route('/incidents', methods=['POST'])
    def create_incident():
        """Create new incident from alert(s)"""
        try:
            if not incident_mgr:
                return jsonify({'error': 'Incident management not available'}), 503
            
            data = request.get_json()
            title = data.get('title', 'Unnamed Incident')
            severity = data.get('severity', 'HIGH')
            alert_ids = data.get('alert_ids', [])
            
            incident_id = incident_mgr.create_incident(title, severity, alert_ids)
            incident = incident_mgr.get_incident(incident_id)
            
            # Log to audit trail
            if audit_trail:
                try:
                    audit_trail.log_incident_action(
                        audit_trail.ACTION_TYPES['INCIDENT_CREATED'],
                        incident_id,
                        data.get('created_by', 'system'),
                        data.get('created_by_name', 'System'),
                        details={'title': title, 'severity': severity}
                    )
                except:
                    pass
            
            return jsonify(incident), 201
        except Exception as e:
            print(f"Error creating incident: {e}")
            return jsonify({'incidents': [], 'total': 0}), 200
    
    @app.route('/incidents/<incident_id>', methods=['GET'])
    def get_incident(incident_id):
        """Get incident details"""
        incident = incident_mgr.get_incident(incident_id)
        if not incident:
            return jsonify({'error': 'Incident not found'}), 404
        return jsonify(incident), 200
    
    @app.route('/incidents/<incident_id>/notes', methods=['POST'])
    def add_incident_note(incident_id):
        """Add investigation note to incident"""
        data = request.get_json()
        user_id = data.get('user_id', 'unknown')
        user_name = data.get('user_name', 'Unknown')
        note_text = data.get('note', '')
        
        incident_mgr.add_note(incident_id, note_text, user_name)
        
        if audit_trail:
            audit_trail.log_incident_action(
                'incident_note_added',
                incident_id,
                user_id,
                user_name,
                details={'note': note_text}
            )
        
        return jsonify({'status': 'ok'}), 200
    
    @app.route('/incidents/<incident_id>/assign', methods=['POST'])
    def assign_incident(incident_id):
        """Assign incident to analyst"""
        data = request.get_json()
        assigned_to = data.get('assigned_to', '')
        
        incident_mgr.assign(incident_id, assigned_to)
        
        if audit_trail:
            audit_trail.log_incident_action(
                audit_trail.ACTION_TYPES['INCIDENT_ASSIGNED'],
                incident_id,
                data.get('assigned_by', 'unknown'),
                data.get('assigned_by_name', 'Unknown'),
                details={'assigned_to': assigned_to}
            )
        
        return jsonify({'status': 'ok'}), 200
    
    @app.route('/incidents/<incident_id>/resolve', methods=['POST'])
    def resolve_incident(incident_id):
        """Mark incident as resolved"""
        data = request.get_json()
        resolution = data.get('resolution_notes', '')
        resolved_by = data.get('resolved_by', 'unknown')
        resolved_by_name = data.get('resolved_by_name', 'Unknown')
        
        incident_mgr.resolve(incident_id, resolution, resolved_by_name)
        
        if audit_trail:
            audit_trail.log_incident_action(
                audit_trail.ACTION_TYPES['INCIDENT_RESOLVED'],
                incident_id,
                resolved_by,
                resolved_by_name,
                details={'resolution': resolution}
            )
        
        return jsonify({'status': 'ok'}), 200
    
    @app.route('/incidents/stats', methods=['GET'])
    def get_incident_stats():
        """Get incident statistics"""
        stats = incident_mgr.get_incident_stats()
        return jsonify(stats), 200

# ========== AUDIT TRAIL ROUTES ==========
@app.route('/api/audit_log', methods=['GET'])
def get_audit_log():
    """Get audit log entries (normalized for dashboard: admin, action, target_user)."""
    try:
        if not audit_trail:
            return jsonify({'logs': [], 'total': 0, 'entries': []}), 200
        
        action_type = request.args.get('action_type')
        user_id = request.args.get('user_id')
        target = request.args.get('target')
        limit = request.args.get('limit', 100, type=int)
        
        # dashboard passes the selected username into `user_id`.
        # audit_trail stores both `user_id` and `user_name` in different meanings
        # depending on the event source (login/logout vs admin actions),
        # so we match against either field.
        logs = audit_trail.get_logs(limit=limit, action_type=action_type, user_id=None, target=target)
        if user_id:
            logs = [
                l for l in logs
                if str(l.get('user_id', '')) == str(user_id) or str(l.get('user_name', '')) == str(user_id)
            ]
            if not logs:
                # If the audit trail has no stored records for the selected user,
                # derive a small set of "sensitive activity" audit entries from events.
                # This keeps the dashboard useful for multi-LAN user drill-down.
                try:
                    thr = float(config.get("risk_display_threshold", RISK_THRESHOLD))
                except Exception:
                    thr = RISK_THRESHOLD
                derived = []
                for e in reversed(events_log[-5000:]):
                    try:
                        rs = float(e.get("risk_score", 0) or 0)
                    except (TypeError, ValueError):
                        rs = 0.0
                    if rs < thr:
                        continue
                    uid = e.get("user") or e.get("username") or e.get("agent_id") or ""
                    if str(uid) != str(user_id):
                        continue
                    derived.append({
                        "timestamp": e.get("timestamp") or e.get("received_at") or "",
                        "action_type": audit_trail.ACTION_TYPES.get("ALERT_CREATED", "alert_created"),
                        "user_id": uid,
                        "user_name": "DeepSentinel",
                        "target": uid,
                        "details": {
                            "event_type": e.get("event_type"),
                            "action": e.get("action"),
                            "risk_score": rs,
                        },
                        "status": "DERIVED",
                    })
                    if len(derived) >= min(25, limit):
                        break
                logs = derived
        entries = normalize_audit_entries_for_ui(logs)
        return jsonify({'logs': logs, 'total': len(entries), 'entries': entries}), 200
    except Exception as e:
        print(f"Error getting audit log: {e}")
        return jsonify({'logs': [], 'total': 0, 'entries': []}), 200

@app.route('/api/audit_log/user/<user_id>', methods=['GET'])
def get_user_audit_log(user_id):
    """Get all actions by a specific user"""
    try:
        if not audit_trail:
            return jsonify({'user_id': user_id, 'logs': []}), 200
        
        limit = request.args.get('limit', 50, type=int)
        logs = audit_trail.get_user_timeline(user_id, limit=limit)
        return jsonify({'user_id': user_id, 'logs': logs}), 200
    except Exception as e:
        print(f"Error getting user audit log: {e}")
        return jsonify({'user_id': user_id, 'logs': []}), 200

@app.route('/api/audit_log/target/<target>', methods=['GET'])
def get_target_audit_log(target):
    """Get all actions affecting a target"""
    try:
        if not audit_trail:
            return jsonify({'target': target, 'logs': []}), 200
        
        limit = request.args.get('limit', 50, type=int)
        logs = audit_trail.get_target_timeline(target, limit=limit)
        return jsonify({'target': target, 'logs': logs}), 200
    except Exception as e:
        print(f"Error getting target audit log: {e}")
        return jsonify({'target': target, 'logs': []}), 200

@app.route('/api/audit_log/summary', methods=['GET'])
def get_audit_summary():
    """Get summary of recent actions"""
    try:
        if not audit_trail:
            return jsonify({'summary': {}}), 200
        
        days = request.args.get('days', 7, type=int)
        summary = audit_trail.get_action_summary(days=days)
        return jsonify(summary), 200
    except Exception as e:
        print(f"Error getting audit summary: {e}")
        return jsonify({'summary': {}}), 200

@app.route('/api/audit_log/export', methods=['GET'])
def export_audit_log():
    """Export audit log as CSV"""
    try:
        if not audit_trail:
            return jsonify({'error': 'Audit trail not available'}), 503
        
        format_type = request.args.get('format', 'csv')
        action_type = request.args.get('action_type')
        
        data = audit_trail.export_audit_log(format=format_type, action_type=action_type)
        
        if format_type == 'csv':
            return Response(data, mimetype='text/csv', headers={
                'Content-Disposition': 'attachment;filename=audit_log.csv'
            })
        else:
            return jsonify(json.loads(data)), 200
    except Exception as e:
        print(f"Error exporting audit log: {e}")
        return jsonify({'error': 'Export failed'}), 500

# ========== USER RISK SCORING ROUTES ==========
@app.route('/api/users/risk/<user_id>', methods=['GET'])
def get_user_risk(user_id):
    """Get risk score for specific user"""
    try:
        if not risk_scorer:
            return jsonify({'risk_score': 0, 'risk_level': 'LOW'}), 200
        score = risk_scorer.get_user_risk(user_id)
        if not score:
            return jsonify({'error': 'User not found'}), 404
        return jsonify(score), 200
    except Exception as e:
        print(f"Error getting user risk: {e}")
        return jsonify({'risk_score': 0, 'risk_level': 'LOW'}), 200

# ========== USER RISK LEADERBOARD ROUTES ==========
@app.route('/api/users/risk_leaderboard', methods=['GET'])
def get_risk_leaderboard():
    """Top users by composite risk from activity (always aligned with events on disk)."""
    global user_risk_cache
    limit = request.args.get('limit', 20, type=int)
    risk_level = request.args.get('risk_level')
    
    try:
        all_users = set()
        for event in events_log:
            user = event.get('user') or event.get('username') or event.get('agent_id')
            if user:
                all_users.add(user)
        
        for user in all_users:
            calculate_composite_user_risk(user)
        
        leaderboard = []
        for row in user_risk_cache.values():
            norm = normalize_leaderboard_row(row)
            if norm:
                leaderboard.append(norm)
        
        if risk_scorer and hasattr(risk_scorer, 'get_risk_leaderboard'):
            try:
                extra = risk_scorer.get_risk_leaderboard(limit=limit * 2, risk_level=risk_level)
                seen = {r['username'] for r in leaderboard}
                for row in extra or []:
                    norm = normalize_leaderboard_row(row)
                    if norm and norm['username'] not in seen:
                        seen.add(norm['username'])
                        leaderboard.append(norm)
            except Exception:
                pass
        
        if risk_level:
            leaderboard = [l for l in leaderboard if l.get('risk_level') == risk_level]
        
        leaderboard.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
        return jsonify({'leaderboard': leaderboard[:limit]}), 200
    except Exception as e:
        print(f"Error loading leaderboard: {e}")
        return jsonify({'leaderboard': []}), 200

@app.route('/api/users/risk_distribution', methods=['GET'])
def get_risk_distribution():
    """Get distribution of users by risk level"""
    global user_risk_cache
    
    try:
        # First try to use risk_scorer if it has data
        if risk_scorer and hasattr(risk_scorer, 'get_risk_distribution'):
            try:
                distribution = risk_scorer.get_risk_distribution()
                if any(distribution.values()):  # If it has data
                    return jsonify(distribution), 200
            except:
                pass
        
        # Calculate risk for all users if not done yet
        all_users = set()
        for event in events_log:
            user = event.get('user') or event.get('username') or event.get('agent_id')
            if user:
                all_users.add(user)
        
        for user in all_users:
            if user not in user_risk_cache:
                calculate_composite_user_risk(user)
        
        # Build distribution from cache
        distribution = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        for risk_data in user_risk_cache.values():
            risk_level = risk_data.get('risk_level', 'LOW')
            if risk_level in distribution:
                distribution[risk_level] += 1
        
        return jsonify(distribution), 200
    except Exception as e:
        print(f"Error getting risk distribution: {e}")
        return jsonify({'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}), 200

@app.route('/api/users/high_risk', methods=['GET'])
def get_high_risk_users():
    """Get users above risk threshold"""
    try:
        threshold = request.args.get('threshold', 0.6, type=float)
        if not risk_scorer:
            return jsonify({'users': [], 'count': 0}), 200
        users = risk_scorer.get_high_risk_threshold_users(threshold=threshold)
        return jsonify({'users': users, 'count': len(users)}), 200
    except Exception as e:
        print(f"Error getting high risk users: {e}")
        return jsonify({'users': [], 'count': 0}), 200

@app.route('/api/users/risk/estimate', methods=['POST'])
def estimate_user_risk():
    """Calculate risk score for user"""
    try:
        if not risk_scorer:
            return jsonify({'risk_score': 0, 'risk_level': 'LOW'}), 200
        data = request.get_json()
        user_id = data.get('user_id')
        user_data = data.get('user_data', {})
        
        score = risk_scorer.calculate_user_risk(user_id, user_data)
        return jsonify(score), 200
    except Exception as e:
        print(f"Error estimating user risk: {e}")
        return jsonify({'risk_score': 0, 'risk_level': 'LOW'}), 200

# ========== REAL-TIME NOTIFICATIONS ROUTES ==========
@app.route('/api/notifications/alert', methods=['POST'])
def send_alert_notification():
    """Send an alert via configured channels"""
    try:
        if not notif_mgr:
            return jsonify({'status': 'dismissed', 'reason': 'Notification manager not available'}), 503
        data = request.get_json()
        
        alert_data = {
            'alert_id': data.get('alert_id'),
            'severity': data.get('severity', 'HIGH'),
            'alert_type': data.get('alert_type'),
            'user_id': data.get('user_id'),
            'message': data.get('message'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        channels = data.get('channels', ['websocket', 'email'])
        immediate = data.get('immediate', False)
        
        result = notif_mgr.notify_alert(alert_data, channels=channels, immediate=immediate)
        
        return jsonify({
            'status': 'queued' if not immediate else 'sent',
            'alert_id': alert_data['alert_id']
        }), 200 if result else 400
    except Exception as e:
        print(f"Error sending notification: {e}")
        return jsonify({'status': 'failed'}), 500

@app.route('/api/notifications/history', methods=['GET'])
def get_notification_history():
    """Get notification history"""
    try:
        if not notif_mgr:
            return jsonify({'notifications': []}), 200
        user_id = request.args.get('user_id')
        limit = request.args.get('limit', 100, type=int)
        
        history = notif_mgr.get_notification_history(user_id=user_id, limit=limit)
        return jsonify({'notifications': history}), 200
    except Exception as e:
        print(f"Error getting notification history: {e}")
        return jsonify({'notifications': []}), 200

@app.route('/api/notifications/config', methods=['GET', 'POST'])
def notification_config():
    """Get or update notification configuration"""
    try:
        if not notif_mgr:
            return jsonify({'status': 'not_available'}), 503
        if request.method == 'POST':
            data = request.get_json()
            
            if 'smtp_server' in data:
                notif_mgr.configure_smtp(
                    data.get('smtp_server'),
                    data.get('smtp_port', 25),
                    data.get('from_email')
                )
            
            if 'slack_webhook' in data:
                notif_mgr.configure_slack(data.get('slack_webhook'))
            
            if 'min_severity' in data:
                notif_mgr.set_min_severity(data.get('min_severity'))
            
            return jsonify({'status': 'config updated'}), 200
        
        return jsonify(notif_mgr.config), 200
    except Exception as e:
        print(f"Error with notification config: {e}")
        return jsonify({'status': 'error'}), 500

@app.route('/api/notifications/test', methods=['POST'])
def test_notification():
    """Send test notification"""
    try:
        if not notif_mgr:
            return jsonify({'status': 'not_available'}), 503
        data = request.get_json()
        channel = data.get('channel', 'email')
        
        test_alert = {
            'alert_id': 'test_' + str(datetime.utcnow().timestamp()),
            'severity': 'HIGH',
            'alert_type': 'TEST',
            'user_id': data.get('user_id', 'testuser'),
            'message': 'This is a test notification',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        result = notif_mgr.notify_alert(test_alert, channels=[channel], immediate=True)
        
        return jsonify({
            'status': 'sent' if result else 'failed',
            'channel': channel
        }), 200 if result else 400
    except Exception as e:
        print(f"Error sending test notification: {e}")
        return jsonify({'status': 'failed'}), 500

# ========== SCREEN RECORDING ROUTES ==========
@app.route('/api/recordings/start', methods=['POST'])
def start_screen_recording():
    """Start screen recording on user's machine"""
    try:
        if not recording_mgr:
            return jsonify({'status': 'not_available'}), 503
        data = request.get_json()
        user_id = data.get('user_id')
        hostname = data.get('hostname', 'unknown')
        trigger_reason = data.get('trigger_reason', 'Unknown')
        duration = data.get('duration', 30)
        
        recording = recording_mgr.start_recording(user_id, hostname, trigger_reason, duration)
        
        if audit_trail:
            try:
                audit_trail.log_action(
                    'screenshot_requested',
                    data.get('requested_by', 'unknown'),
                    data.get('requested_by_name', 'Unknown'),
                    target=user_id,
                    details={'duration': duration, 'reason': trigger_reason}
                )
            except:
                pass
        
        return jsonify(recording), 201
    except Exception as e:
        print(f"Error starting recording: {e}")
        return jsonify({'status': 'failed'}), 500

@app.route('/api/recordings/list', methods=['GET'])
def list_recordings():
    """List recent recordings"""
    try:
        if not recording_mgr:
            return jsonify({'recordings': [], 'count': 0}), 200
        user_id = request.args.get('user_id')
        hours = request.args.get('hours', 24, type=int)
        
        recordings = recording_mgr.list_recordings(user_id=user_id, hours=hours)
        return jsonify({'recordings': recordings, 'count': len(recordings)}), 200
    except Exception as e:
        print(f"Error listing recordings: {e}")
        return jsonify({'recordings': [], 'count': 0}), 200

@app.route('/api/recordings/<recording_id>', methods=['GET'])
def get_recording_status(recording_id):
    """Get status of a recording"""
    try:
        if not recording_mgr:
            return jsonify({'error': 'Recording manager not available'}), 503
        recording = recording_mgr.get_recording_status(recording_id)
        if not recording:
            return jsonify({'error': 'Recording not found'}), 404
        return jsonify(recording), 200
    except Exception as e:
        print(f"Error getting recording status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/recordings/<recording_id>/download', methods=['GET'])
def download_recording(recording_id):
    """Download recording file"""
    try:
        if not recording_mgr:
            return jsonify({'error': 'Recording manager not available'}), 503
        file_path = recording_mgr.download_recording(recording_id)
        if not file_path:
            return jsonify({'error': 'Recording not available'}), 404
        
        return send_file(file_path, as_attachment=True)
    except Exception as e:
        print(f"Error downloading recording: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/recordings/<recording_id>', methods=['DELETE'])
def delete_recording(recording_id):
    """Delete recording"""
    try:
        if not recording_mgr:
            return jsonify({'error': 'Recording manager not available'}), 503
        reason = request.args.get('reason', 'User request')
        result = recording_mgr.delete_recording(recording_id, reason=reason)
        return jsonify({'status': 'deleted' if result else 'failed'}), 200 if result else 404
    except Exception as e:
        print(f"Error deleting recording: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/recordings/storage_stats', methods=['GET'])
def recording_storage_stats():
    """Get recording storage statistics"""
    try:
        if not recording_mgr:
            return jsonify({'stats': {}}), 200
        stats = recording_mgr.get_storage_stats()
        return jsonify(stats), 200
    except Exception as e:
        print(f"Error getting storage stats: {e}")
        return jsonify({'stats': {}}), 200

@app.route('/api/recordings/cleanup', methods=['POST'])
def cleanup_recordings():
    """Delete old recordings"""
    try:
        if not recording_mgr:
            return jsonify({'status': 'not_available'}), 503
        days = request.get_json().get('days', 30)
        result = recording_mgr.cleanup_old_recordings(days=days)
        return jsonify(result), 200
    except Exception as e:
        print(f"Error cleaning up recordings: {e}")
        return jsonify({'status': 'failed'}), 500

# ========================================
# Analytics API Endpoints (Real-time)
# ========================================

from datetime import timedelta

def parse_event_timestamp(event):
    """Helper to parse event timestamp in format 'YYYY-MM-DD HH:MM:SS' or ISO format"""
    try:
        ts_str = event.get('timestamp') or event.get('received_at') or event.get('event_time', '')
        if not ts_str:
            return None
        # Try space-separated format first (2025-10-26 12:00:55)
        try:
            return datetime.strptime(ts_str[:19], '%Y-%m-%d %H:%M:%S')
        except:
            # Fall back to ISO format
            return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
    except:
        return None

@app.route('/api/analytics/live-stats')
def analytics_live_stats():
    """Count total events for live event counter"""
    # Use all events for historical data
    recent_events = events_log[-100:] if len(events_log) > 100 else events_log
    
    return jsonify({
        'count': len(recent_events),
        'percentage': (len(recent_events) / len(events_log) * 100) if events_log else 0,
        'timestamp': local_iso()
    }), 200

@app.route('/api/analytics/event-types')
def analytics_event_types():
    """Group events by type"""
    # Use all events for historical data distribution
    recent_events = events_log
    
    event_type_counts = Counter([e.get('event_type', 'unknown') for e in recent_events])
    
    return jsonify({
        'types': dict(event_type_counts),
        'total': len(recent_events),
        'timestamp': local_iso()
    }), 200

@app.route('/api/analytics/top-users')
def analytics_top_users():
    """Top active users"""
    # Use all events for user activity analysis
    recent_events = events_log
    
    user_counts = Counter([e.get('user') or e.get('username') or e.get('agent_id') or 'Unknown' for e in recent_events])
    
    top_users = [{'username': user, 'count': count} for user, count in user_counts.most_common(5)]
    
    return jsonify({
        'users': top_users,
        'timestamp': local_iso()
    }), 200

@app.route('/api/analytics/events-per-minute')
def analytics_events_per_minute():
    """Event rate distribution by minute"""
    # Use all events for rate analysis
    recent_events = events_log
    
    # Group events by minute
    minute_counts = defaultdict(int)
    for e in recent_events:
        try:
            ts = parse_event_timestamp(e)
            if ts:
                minute = ts.replace(second=0, microsecond=0)
                minute_counts[minute.isoformat()] += 1
        except Exception:
            pass
    
    # Sort by time and create data for line chart
    sorted_minutes = sorted(minute_counts.keys())
    # Use last 20 distinct minutes for chart
    data = [{'minute': m, 'count': minute_counts[m]} for m in sorted_minutes[-20:]] if sorted_minutes else [{'minute': '00:00', 'count': 0}]
    
    return jsonify({
        'data': data,
        'total': len(recent_events),
        'timestamp': local_iso()
    }), 200

@app.route('/api/analytics/risk-meter')
def analytics_risk_meter():
    """Calculate threat score (failed_login +10, usb +15, honeypot +30, max 100)"""
    # Use all events for comprehensive threat assessment
    recent_events = events_log
    
    threat_score = 0
    failed_logins = 0
    usb_events = 0
    honeypot_events = 0
    
    for e in recent_events:
        event_type = e.get('event_type', '').lower()
        action = e.get('action', '').lower()
        
        # Failed logins: +10 each
        if event_type in ('logon', 'session', 'authentication') and 'failed' in action:
            threat_score += 10
            failed_logins += 1
        
        # USB events: +15 each
        elif event_type == 'usb':
            threat_score += 15
            usb_events += 1
        
        # Honeypot/decoy access: +30 each
        elif 'honeypot' in event_type or 'decoy' in event_type or 'honeypot' in action:
            threat_score += 30
            honeypot_events += 1
    
    # Cap at 100
    threat_score = min(threat_score, 100)
    
    # Determine risk level and color
    if threat_score >= 71:
        risk_level = 'CRITICAL'
        color = '#EF4444'  # Red
    elif threat_score >= 31:
        risk_level = 'WARNING'
        color = '#FBBF24'  # Yellow
    else:
        risk_level = 'SAFE'
        color = '#10B981'  # Green
    
    return jsonify({
        'score': threat_score,
        'percentage': threat_score,  # 0-100
        'risk_level': risk_level,
        'color': color,
        'breakdown': {
            'failed_logins': failed_logins,
            'usb_events': usb_events,
            'honeypot_events': honeypot_events
        },
        'timestamp': local_iso()
    }), 200

@app.route('/api/analytics/data-transfer')
def analytics_data_transfer():
    """USB & File Transfer activity analysis"""
    # Use all events for data transfer analysis
    recent_events = events_log
    
    transfer_counts = {
        'usb_copy': 0,
        'file_copy': 0,
        'file_download': 0,
        'file_upload': 0,
        'email_attachment': 0
    }
    
    for e in recent_events:
        event_type = e.get('event_type', '').lower()
        action = e.get('action', '').lower()
        
        if event_type == 'usb':
            transfer_counts['usb_copy'] += 1
        elif event_type == 'file':
            if 'copy' in action:
                transfer_counts['file_copy'] += 1
            elif 'download' in action:
                transfer_counts['file_download'] += 1
            elif 'upload' in action:
                transfer_counts['file_upload'] += 1
        elif event_type in ('outlook', 'imap', 'email_sent', 'email'):
            if 'attachment' in action or e.get('attachments'):
                transfer_counts['email_attachment'] += 1
    
    # Create bar chart data sorted by count descending
    bars = [{'type': k, 'count': v, 'color': '#3B82F6' if k.startswith('usb') else '#EF4444' if k.startswith('email') else '#549af0'} 
            for k, v in transfer_counts.items() if v > 0]
    bars.sort(key=lambda x: x['count'], reverse=True)
    
    return jsonify({
        'data': bars,
        'total': sum(transfer_counts.values()),
        'timestamp': datetime.utcnow().isoformat()
    }), 200


# ===========================================
# LLM-POWERED REPORT GENERATION ENDPOINTS
# ===========================================

@app.route('/api/reports/generate-incident', methods=['POST'])
def api_generate_incident_report():
    """Generate AI-powered incident investigation report with REAL risk scoring"""
    try:
        data = request.json or {}
        username = data.get('username', '').strip()
        event_types = data.get('event_types', None)  # Optional: file, usb, email, etc.
        
        if not username:
            return jsonify({'success': False, 'error': 'Username required'}), 400
        
        # Initialize report generator
        try:
            from incident_report_generator_v2 import IncidentReportGeneratorV2
            gen = IncidentReportGeneratorV2(events_log)
            # AUTOMATIC risk scoring based on actual behavior anomalies
            result = gen.generate_incident_pdf(username, event_types=event_types)
            
            if 'error' in result:
                return jsonify({'success': False, 'error': result['error']}), 400
            
            return jsonify({
                'success': True,
                'pdf_url': f'/download-report/{result["filename"]}',
                'filename': result['filename'],
                'risk_score': result['risk_score'],
                'risk_factors': result['risk_factors'],
                'events_analyzed': result['events_analyzed'],
                'message': f'Incident report generated for {username} (Risk Score: {result["risk_score"]:.1f}/10)'
            }), 200
        except Exception as e:
            print(f"Report generation error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500
            
    except Exception as e:
        print(f"API error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/reports/generate-behavior', methods=['POST'])
def api_generate_behavior_report():
    """Generate AI-powered user behavior analysis report (30-day)"""
    try:
        data = request.json or {}
        username = data.get('username', '').strip()
        
        if not username:
            return jsonify({'success': False, 'error': 'Username required'}), 400
        
        # Initialize report generator
        try:
            from incident_report_generator_v2 import UserBehaviorReportGenerator
            gen = UserBehaviorReportGenerator(events_log)
            result = gen.generate_behavior_report_pdf(username)
            
            return jsonify({
                'success': True,
                'pdf_url': f'/download-report/{result["filename"]}',
                'filename': result['filename'],
                'message': f'Behavior report generated for {username}'
            }), 200
        except Exception as e:
            print(f"Report generation error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500
            
    except Exception as e:
        print(f"API error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/reports/list', methods=['GET'])
def api_list_reports():
    """List all generated reports"""
    try:
        from pathlib import Path
        reports_dir = Path('data/reports')
        
        if not reports_dir.exists():
            return jsonify({'reports': []}), 200
        
        reports = []
        for pdf_file in sorted(reports_dir.glob('*.pdf'), reverse=True)[:50]:
            filename = pdf_file.name
            # Parse filename: incident_username_timestamp.pdf or behavior_username_timestamp.pdf
            parts = filename.replace('.pdf', '').split('_')
            report_type = parts[0] if parts else 'unknown'
            username = parts[1] if len(parts) > 1 else 'unknown'
            
            reports.append({
                'filename': filename,
                'type': report_type,
                'username': username,
                'created': pdf_file.stat().st_mtime
            })
        
        return jsonify({'reports': reports}), 200
    except Exception as e:
        print(f"List reports error: {e}")
        return jsonify({'reports': []}), 200


@app.route('/download-report/<filename>', methods=['GET'])
def download_report(filename):
    """Download a generated report PDF"""
    try:
        from pathlib import Path
        reports_dir = Path('data/reports')
        file_path = reports_dir / filename
        
        # Security check: ensure the file is in the reports directory
        if not file_path.exists() or not str(file_path.resolve()).startswith(str(reports_dir.resolve())):
            return "File not found", 404
        
        return send_file(str(file_path), mimetype='application/pdf', as_attachment=True, download_name=filename)
    except Exception as e:
        print(f"Download error: {e}")
        return "Error downloading file", 500


print("="*70)
print("🔐 Advanced Security Suite Initialized!")
print("="*70)
print("✨ Available features:")
print("   📧 Email ML Filter (3-tier: Low/Medium/High risk)")
print("   🔍 NLP Explainability (why threats are flagged)")
print("   🪤 Honeypot Detection (4 decoy systems)")
print("   🛑 User Blocking & Isolation")
print("   🎯 AdminApproval Workflow")
print("   📊 Incident Management (auto-grouping, collaboration)")
print("   🔐 Audit Trail (all admin actions logged)")
print("   ⚠️  User Risk Scoring (composite risk leaderboard)")
print("   🔔 Real-Time Notifications (WebSocket, Email, Slack)")
print("   🎥 Screen Recording (forensic video capture)")
print("   📑 LLM-Powered Reports (AI incident investigation & behavior analysis)")
print("="*70)

# ========================================
# NEW SECURITY FEATURE ENDPOINTS (v4.0)
# ========================================

# --- Clipboard Monitor API ---
@app.route('/api/clipboard/scan', methods=['POST'])
def clipboard_api_scan():
    """Scan clipboard content for sensitive data"""
    if not clipboard_monitor:
        return jsonify({'error': 'Clipboard monitor not available'}), 503
    try:
        data = request.get_json() or {}
        content = data.get('content', '')
        if not content:
            return jsonify({'error': 'No content provided'}), 400
        
        result = clipboard_monitor.scan_clipboard(content=content)
        return jsonify({
            'is_sensitive': result['is_sensitive'],
            'detections': result['detections'],
            'risk_score': result['risk_score']
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/clipboard/statistics', methods=['GET'])
def clipboard_api_stats():
    """Get clipboard monitoring statistics"""
    if not clipboard_monitor:
        return jsonify({'error': 'Clipboard monitor not available'}), 503
    try:
        stats = clipboard_monitor.get_statistics()
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/clipboard/alerts', methods=['GET'])
def clipboard_api_alerts():
    """Get recent clipboard alerts"""
    if not clipboard_monitor:
        return jsonify({'error': 'Clipboard monitor not available'}), 503
    try:
        limit = request.args.get('limit', 20, type=int)
        alerts_data = clipboard_monitor.get_recent_alerts(limit=limit)
        return jsonify({'alerts': alerts_data}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- Malicious File Detector API ---
@app.route('/api/files/scan', methods=['POST'])
def file_api_scan():
    """Scan file for malware and threats"""
    if not file_detector:
        return jsonify({'error': 'File detector not available'}), 503
    try:
        data = request.get_json() or {}
        file_path = data.get('file_path')
        if not file_path:
            return jsonify({'error': 'No file_path provided'}), 400
        
        result = file_detector.scan_file(file_path)
        return jsonify({
            'is_malicious': result['is_malicious'],
            'threat_type': result.get('threat_type', 'unknown'),
            'threat_score': result.get('threat_score', 0.0),
            'detections': result.get('detections', []),
            'quarantined': result.get('quarantined', False)
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/quarantine', methods=['GET'])
def file_api_quarantine():
    """Get list of quarantined files"""
    if not file_detector:
        return jsonify({'error': 'File detector not available'}), 503
    try:
        files_list = file_detector.get_quarantined_files()
        return jsonify({'quarantined_files': files_list}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/statistics', methods=['GET'])
def file_api_stats():
    """Get file detection statistics"""
    if not file_detector:
        return jsonify({'error': 'File detector not available'}), 503
    try:
        stats = file_detector.get_statistics()
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- High-Risk Alerts Manager API ---
@app.route('/api/alerts/high-risk/create', methods=['POST'])
def highrisk_api_create():
    """Create a high-risk alert"""
    if not high_risk_alerts:
        return jsonify({'error': 'High-risk alert manager not available'}), 503
    try:
        data = request.get_json() or {}
        alert_type = data.get('alert_type', 'credential_theft')
        user = data.get('user', 'unknown')
        severity = data.get('severity', 'HIGH')
        details = data.get('details', {})
        
        alert_id = high_risk_alerts.create_high_risk_alert(
            alert_type=alert_type,
            user=user,
            severity=severity,
            details=details
        )
        return jsonify({
            'alert_id': alert_id,
            'status': 'created',
            'actions_triggered': data.get('auto_actions', True)
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/high-risk/active', methods=['GET'])
def highrisk_api_active():
    """Get active high-risk alerts"""
    if not high_risk_alerts:
        return jsonify({'error': 'High-risk alert manager not available'}), 503
    try:
        alerts_list = high_risk_alerts.get_active_alerts()
        return jsonify({'active_alerts': alerts_list}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/high-risk/statistics', methods=['GET'])
def highrisk_api_stats():
    """Get high-risk alert statistics"""
    if not high_risk_alerts:
        return jsonify({'error': 'High-risk alert manager not available'}), 503
    try:
        stats = high_risk_alerts.get_alert_statistics()
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/high-risk/resolve/<alert_id>', methods=['POST'])
def highrisk_api_resolve(alert_id):
    """Resolve a high-risk alert"""
    if not high_risk_alerts:
        return jsonify({'error': 'High-risk alert manager not available'}), 503
    try:
        data = request.get_json() or {}
        notes = data.get('resolution_notes', 'Resolved by admin')
        high_risk_alerts.resolve_alert(alert_id, notes)
        return jsonify({'status': 'resolved', 'alert_id': alert_id}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/high-risk/correlate', methods=['GET'])
def highrisk_api_correlate():
    """Get correlated incidents"""
    if not high_risk_alerts:
        return jsonify({'error': 'High-risk alert manager not available'}), 503
    try:
        correlations = high_risk_alerts.correlate_incidents()
        return jsonify({'correlations': correlations}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- Outlook Integration API ---
@app.route('/api/outlook/send-alert', methods=['POST'])
def outlook_api_send():
    """Send high-risk alert via Outlook"""
    if not outlook_notifier:
        return jsonify({'error': 'Outlook integration not available'}), 503
    try:
        data = request.get_json() or {}
        alert_data = data.get('alert', {})
        severity = data.get('severity', 'HIGH')
        recipient_override = data.get('recipient')
        
        result = outlook_notifier.send_high_risk_alert(
            alert_type=alert_data.get('type', 'security_threat'),
            severity=severity,
            user=alert_data.get('user', 'unknown'),
            details=alert_data.get('details', {}),
            triggered_actions=alert_data.get('actions', [])
        )
        return jsonify({
            'status': 'sent' if result.get('sent') else 'queued',
            'email_id': result.get('email_id'),
            'recipient': result.get('recipient')
        }), 200 if result.get('sent') else 202
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/outlook/queue', methods=['GET'])
def outlook_api_queue():
    """Get queued emails (when Outlook unavailable)"""
    if not outlook_notifier:
        return jsonify({'error': 'Outlook integration not available'}), 503
    try:
        queued = outlook_notifier.get_queued_emails()
        return jsonify({'queued_emails': queued}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/outlook/history', methods=['GET'])
def outlook_api_history():
    """Get notification delivery history"""
    if not outlook_notifier:
        return jsonify({'error': 'Outlook integration not available'}), 503
    try:
        limit = request.args.get('limit', 50, type=int)
        history = outlook_notifier.get_notification_history(limit=limit)
        return jsonify({'history': history}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/outlook/retry', methods=['POST'])
def outlook_api_retry():
    """Retry sending queued emails"""
    if not outlook_notifier:
        return jsonify({'error': 'Outlook integration not available'}), 503
    try:
        result = outlook_notifier.retry_queued_emails()
        return jsonify({
            'retried_count': result.get('retried', 0),
            'successful': result.get('successful', 0),
            'failed': result.get('failed', 0)
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- Integration Health Check ---
@app.route('/api/system/security-modules', methods=['GET'])
def security_modules_status():
    """Check status of all security modules"""
    return jsonify({
        'clipboard_monitor': {
            'available': clipboard_monitor is not None,
            'status': '✅ Active' if clipboard_monitor else '❌ Unavailable'
        },
        'malicious_file_detector': {
            'available': file_detector is not None,
            'status': '✅ Active' if file_detector else '❌ Unavailable'
        },
        'high_risk_alerts': {
            'available': high_risk_alerts is not None,
            'status': '✅ Active' if high_risk_alerts else '❌ Unavailable'
        },
        'outlook_integration': {
            'available': outlook_notifier is not None,
            'status': '✅ Active' if outlook_notifier else '❌ Unavailable'
        },
        'timestamp': datetime.utcnow().isoformat()
    }), 200

if __name__ == '__main__':
    print("="*70)
    print("🛡️  THREATWATCH SIEM v4.0")
    print("="*70)
    print("🌐 Server: http://0.0.0.0:5000")
    print("="*70)
    print("✨ Features:")
    print("   • User activity only (no system noise)")
    print("   • Modern Splunk/Prisma-style UI")
    print("   • Adjustable risk threshold (persisted to config.json)")
    print("   • Alerts persisted to data/alerts.jsonl")
    print("   • Auto-refresh: 60 seconds (dashboard)")
    print("   • ML-powered threat detection")
    print("="*70)
    print(f"🎯 Risk Threshold: {RISK_THRESHOLD}")
    print("="*70)
    print()
    # Allow host/port override via environment (safer than hard-coded IP).
    
    host = os.environ.get('THREATWATCH_HOST', '0.0.0.0')
    try:
        port = int(os.environ.get('THREATWATCH_PORT', 5000))
    except Exception:
        port = 5000
    print(f"🌐 Server: http://{host}:{port}")
    try:
        # Calculate risk for all users in loaded data
        all_users = set()
        for event in events_log:
            user = event.get('user') or event.get('username') or event.get('agent_id')
            if user:
                all_users.add(user)
        
        print(f"📊 Calculating risk for {len(all_users)} users...")
        for user in all_users:
            calculate_composite_user_risk(user)
        print(f"✅ Risk calculated for all users")
        
        # Run Flask app; wrap in try/except so startup errors are logged to disk for diagnosis
        app.run(host=host, port=port, debug=True)
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print("❌ Server failed to start. See data/server_error.log for traceback.")
        try:
            os.makedirs('data', exist_ok=True)
            with open(os.path.join('data', 'server_error.log'), 'a', encoding='utf-8') as ferr:
                ferr.write(f"--- {datetime.utcnow().isoformat()} ---\n")
                ferr.write(tb + "\n\n")
        except Exception:
            pass
        raise
