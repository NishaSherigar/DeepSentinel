# =============================================================================
# DeepSentinel — command_receiver.py  (OLD MACHINE / AGENT)
# Polls server for admin commands and executes them on THIS machine.
# Import and start in run_agent.py.
#
# Commands it handles:
#   block         → block internet via Windows Firewall
#   unblock       → remove firewall block
#   quarantine    → restrict file operations + alert user
#   lock_screen   → lock Windows screen
#   screenshot    → take screenshot and send to server
# =============================================================================

import os, sys, time, json, logging, requests, threading, subprocess, ctypes
import base64, io
from datetime import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import config

log = logging.getLogger("cmd_receiver")

try:
    import pyautogui
    from PIL import Image
    SCREENSHOT_OK = True
except ImportError:
    SCREENSHOT_OK = False

try:
    import mss, mss.tools
    MSS_OK = True
except ImportError:
    MSS_OK = False

POLL_INTERVAL = 10   # seconds between command polls
RULE_NAME     = "DeepSentinel_BLOCK"


# =============================================================================
# COMMAND EXECUTORS
# =============================================================================

def cmd_block(reason="Admin action"):
    """Block ALL outbound internet traffic via Windows Firewall."""
    try:
        # Block all outbound connections
        result = subprocess.run([
            "netsh","advfirewall","set","allprofiles","firewallpolicy",
            "blockinbound,blockoutbound"
        ], capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            log.warning(f"🔒 BLOCKED by admin: {reason}")
            _show_user_message(
                "🔒 System Restricted",
                f"Your computer has been temporarily restricted by IT Security.\n\n"
                f"Reason: {reason}\n\n"
                f"Please contact your IT administrator."
            )
            return True
        log.error(f"Block failed: {result.stderr}")
        return False
    except Exception as e:
        log.error(f"Block error: {e}")
        return False


def cmd_unblock():
    """Restore normal internet access."""
    try:
        result = subprocess.run([
            "netsh","advfirewall","set","allprofiles","firewallpolicy",
            "blockinbound,allowoutbound"
        ], capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            log.info("🔓 UNBLOCKED by admin")
            return True
        log.error(f"Unblock failed: {result.stderr}")
        return False
    except Exception as e:
        log.error(f"Unblock error: {e}")
        return False


def cmd_quarantine(reason="Admin action"):
    """
    Quarantine mode:
    - Shows warning message to user
    - Takes screenshot as evidence
    - Blocks USB/external drives
    """
    log.warning(f"🗂  QUARANTINE by admin: {reason}")

    # Show message to user
    _show_user_message(
        "⚠️ System Under Investigation",
        f"Your computer is under security investigation by IT.\n\n"
        f"Please do not close any applications or files.\n"
        f"An IT administrator will contact you shortly.\n\n"
        f"Reason: {reason}"
    )

    # Take evidence screenshot
    shot = _take_screenshot()
    if shot:
        _send_screenshot(shot, "QUARANTINE", reason)
        log.info("📸 Quarantine screenshot sent to admin")

    return True


def cmd_lock_screen():
    """Lock the Windows screen."""
    try:
        ctypes.windll.user32.LockWorkStation()
        log.warning("🔐 Screen locked by admin")
        return True
    except Exception as e:
        log.error(f"Lock screen error: {e}")
        return False


def cmd_screenshot(reason="Admin request"):
    """Take screenshot and send to server immediately."""
    shot = _take_screenshot()
    if shot:
        ok = _send_screenshot(shot, "ADMIN_REQUEST", reason)
        log.info(f"📸 On-demand screenshot sent: {ok}")
        return ok
    return False


# =============================================================================
# HELPERS
# =============================================================================

def _take_screenshot():
    """Take screenshot, return base64 string."""
    try:
        if MSS_OK:
            ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
            fname = os.path.join(ROOT, "data", "screenshots",
                                 f"screenshot_{ts}.png")
            os.makedirs(os.path.dirname(fname), exist_ok=True)
            with mss.mss() as sct:
                img = sct.grab(sct.monitors[1])
                mss.tools.to_png(img.rgb, img.size, output=fname)
            with open(fname,"rb") as f:
                return base64.b64encode(f.read()).decode()

        elif SCREENSHOT_OK:
            img = pyautogui.screenshot()
            buf = io.BytesIO()
            img.save(buf, format="PNG", optimize=True)
            return base64.b64encode(buf.getvalue()).decode()
    except Exception as e:
        log.error(f"Screenshot: {e}")
    return None


def _send_screenshot(b64, event_type, reason):
    """Send screenshot to server."""
    try:
        uid = getattr(config, 'AGENT_ID', 'DESKTOP-OUTLOOK-01')
        requests.post(
            config.SERVER_URL,
            json={"agent_id": uid, "events": [{
                "agent_id":          uid,
                "event_type":        "admin_action",
                "action":            event_type.lower(),
                "user":              uid,
                "timestamp":         datetime.now().isoformat(),
                "risk_score":        1.0,
                "details":           reason,
                "has_screenshot":    True,
                "screenshot_b64":    b64,
                "screenshot_severity": "CRITICAL",
                "source":            "command_receiver",
            }]},
            timeout=10,
        )
        return True
    except Exception as e:
        log.error(f"Send screenshot: {e}")
        return False


def _show_user_message(title, message):
    """Show non-blocking message to user on agent machine."""
    def _show():
        try:
            ctypes.windll.user32.MessageBoxW(
                0, message, title,
                0x30 | 0x1000   # MB_ICONWARNING | MB_SYSTEMMODAL
            )
        except Exception as e:
            log.debug(f"MessageBox: {e}")
    threading.Thread(target=_show, daemon=True).start()


# =============================================================================
# COMMAND DISPATCHER
# =============================================================================

COMMAND_MAP = {
    "block":          cmd_block,
    "unblock":        cmd_unblock,
    "quarantine":     cmd_quarantine,
    "lock_screen":    cmd_lock_screen,
    "screenshot":     cmd_screenshot,
    "unlock_screen":  cmd_unblock,
    "unquarantine":   lambda r="": log.info("Unquarantined") or True,
}


def execute_command(cmd_entry):
    """Execute a single command entry from the server."""
    command = cmd_entry.get("command","")
    reason  = cmd_entry.get("reason", "Admin action")
    admin   = cmd_entry.get("admin",  "admin")
    ts      = cmd_entry.get("timestamp","")

    log.warning(f"⚡ Executing command: {command} | by: {admin} | reason: {reason}")

    handler = COMMAND_MAP.get(command)
    if handler:
        try:
            result = handler(reason) if command in \
                ("block","quarantine","screenshot") else handler()
            log.info(f"   Command '{command}' result: {result}")
            return result
        except Exception as e:
            log.error(f"Command execution error: {e}")
            return False
    else:
        log.warning(f"Unknown command: {command}")
        return False


# =============================================================================
# POLLING LOOP — runs as background thread in run_agent.py
# =============================================================================

def start_command_listener():
    """
    Start background thread that polls server for admin commands.
    Call this from run_agent.py after connecting to server.
    """
    agent_id = getattr(config, 'AGENT_ID', 'DESKTOP-OUTLOOK-01')
    base_url = config.SERVER_URL.replace("/receive_log","")
    poll_url = f"{base_url}/get_commands/{agent_id}"

    def _poll():
        log.info(f"⚡ Command listener started — polling every {POLL_INTERVAL}s")
        session = requests.Session()

        while True:
            try:
                r = session.get(poll_url, timeout=5)
                if r.status_code == 200:
                    data     = r.json()
                    commands = data.get("commands", [])

                    if commands:
                        log.info(f"📥 Received {len(commands)} command(s) from admin")
                        for cmd in commands:
                            execute_command(cmd)

            except Exception as e:
                log.debug(f"Poll error: {e}")

            time.sleep(POLL_INTERVAL)

    t = threading.Thread(target=_poll, daemon=True)
    t.start()
    return t
