# =============================================================================
# DeepSentinel — screen_recorder.py
# Auto screenshot + screen recording triggered on HIGH/CRITICAL events.
# Saves to data/screenshots/ so server.py dashboard shows them.
#
# Install: pip install pyautogui pillow opencv-python numpy mss
# =============================================================================

import os, sys, time, threading, logging
from datetime import datetime

ROOT       = os.path.dirname(os.path.abspath(__file__))
SHOT_DIR   = os.path.join(ROOT, "data", "screenshots")
os.makedirs(SHOT_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [RECORDER] %(message)s")
log = logging.getLogger("recorder")

# ── Imports ───────────────────────────────────────────────────────────────────
try:
    import pyautogui
    from PIL import Image
    SCREENSHOT_OK = True
except ImportError:
    SCREENSHOT_OK = False
    print("[RECORDER] ⚠️  pip install pyautogui pillow")

try:
    import cv2, numpy as np
    VIDEO_OK = True
except ImportError:
    VIDEO_OK = False
    print("[RECORDER] ⚠️  pip install opencv-python numpy  (for video)")

# Global state
_recording       = False
_recorder_thread = None


# =============================================================================
# SCREENSHOT
# =============================================================================

def take_screenshot(user_id="unknown", severity="HIGH", label="") -> str | None:
    """
    Take a full screenshot and save to data/screenshots/.
    Filename starts with 'screenshot_' so server.py /api/screenshots finds it.
    Returns filepath or None.
    """
    if not SCREENSHOT_OK:
        log.warning("pyautogui not installed — cannot take screenshot")
        return None
    try:
        ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_user = user_id.replace("@","_").replace(".","_")[:20]
        safe_lbl  = label.replace(" ","_")[:20] if label else ""
        fname     = f"screenshot_{severity}_{safe_user}_{safe_lbl}_{ts}.png"
        fpath     = os.path.join(SHOT_DIR, fname)

        img = pyautogui.screenshot()
        img.save(fpath)

        size_kb = os.path.getsize(fpath) // 1024
        log.info(f"📸 Screenshot saved → {fname} ({size_kb}KB)")
        return fpath

    except Exception as e:
        log.error(f"Screenshot failed: {e}")
        return None


# =============================================================================
# SCREEN RECORDING
# =============================================================================

def start_recording(user_id="unknown", severity="HIGH",
                    duration_sec=15) -> str | None:
    """
    Record the screen for duration_sec seconds.
    Saves as .avi to data/screenshots/.
    Non-blocking — runs in background thread.
    Returns filepath (recording may still be in progress).
    """
    global _recording, _recorder_thread

    if not VIDEO_OK:
        log.warning("opencv not installed — falling back to 3 screenshots")
        return _screenshot_burst(user_id, severity, count=3)

    if not SCREENSHOT_OK:
        log.warning("pyautogui not installed")
        return None

    if _recording:
        log.warning("Already recording — skipping")
        return None

    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_user = user_id.replace("@","_").replace(".","_")[:20]
    fname     = f"screenshot_{severity}_{safe_user}_recording_{ts}.avi"
    fpath     = os.path.join(SHOT_DIR, fname)

    _recording = True

    def _record():
        global _recording
        try:
            screen = pyautogui.screenshot()
            w, h   = screen.size
            fourcc = cv2.VideoWriter_fourcc(*"XVID")
            out    = cv2.VideoWriter(fpath, fourcc, 5.0, (w, h))

            log.info(f"🎥 Recording started ({duration_sec}s) → {fname}")
            start = time.time()

            while _recording and (time.time() - start) < duration_sec:
                frame = cv2.cvtColor(np.array(pyautogui.screenshot()),
                                     cv2.COLOR_RGB2BGR)
                out.write(frame)
                time.sleep(0.2)   # 5fps

            out.release()
            elapsed = round(time.time() - start, 1)
            log.info(f"🎥 Recording saved ({elapsed}s) → {fname}")

        except Exception as e:
            log.error(f"Recording failed: {e}")
        finally:
            _recording = False

    _recorder_thread = threading.Thread(target=_record, daemon=True)
    _recorder_thread.start()
    return fpath


def stop_recording():
    global _recording
    if _recording:
        _recording = False
        log.info("Recording stopped manually")


def _screenshot_burst(user_id, severity, count=3) -> str | None:
    """Take N screenshots 3 seconds apart as fallback."""
    paths = []
    for i in range(count):
        p = take_screenshot(user_id, severity, label=f"burst{i+1}")
        if p:
            paths.append(p)
        if i < count - 1:
            time.sleep(3)
    return paths[0] if paths else None


# =============================================================================
# SMART TRIGGER — main entry point called from server.py
# =============================================================================

def capture_evidence(severity: str, user_id: str,
                     event_detail: str = "") -> dict:
    """
    Decides what to capture based on severity.
    Called automatically on every flagged event.

    LOW      → nothing
    MEDIUM   → 1 screenshot
    HIGH     → 1 screenshot + 15s recording
    CRITICAL → 1 screenshot + 30s recording

    Returns dict with screenshot and recording paths.
    """
    result = {"screenshot": None, "recording": None,
              "severity": severity, "user_id": user_id}

    if severity == "LOW" or severity == "NORMAL":
        return result

    # Always take a screenshot
    shot = take_screenshot(user_id, severity, label=event_detail[:15])
    result["screenshot"] = shot

    # HIGH/CRITICAL → also record
    if severity in ("HIGH", "CRITICAL"):
        duration = 30 if severity == "CRITICAL" else 15
        clip = start_recording(user_id, severity, duration_sec=duration)
        result["recording"] = clip

    return result


# =============================================================================
# STANDALONE TEST
# =============================================================================

if __name__ == "__main__":
    print("DeepSentinel — Screen Recorder Test")
    print(f"  Screenshot available : {SCREENSHOT_OK}")
    print(f"  Video available      : {VIDEO_OK}")
    print(f"  Save directory       : {SHOT_DIR}")
    print()

    if SCREENSHOT_OK:
        print("Testing screenshot...")
        p = take_screenshot("test@demo.com", "HIGH", "test")
        if p:
            print(f"  ✅ Screenshot saved: {p}")
        else:
            print("  ❌ Screenshot failed")
        print()

    if VIDEO_OK and SCREENSHOT_OK:
        print("Testing 5-second recording...")
        p = start_recording("test@demo.com", "CRITICAL", duration_sec=5)
        print(f"  Recording started: {p}")
        time.sleep(6)
        print(f"  ✅ Done. Check {SHOT_DIR}")
