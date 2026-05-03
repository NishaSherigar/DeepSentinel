# =============================================================================
# DeepSentinel — screenshot_addon.py (SERVER SIDE)
# ─────────────────────────────────────────────────────────────────────────────
# ⚠️  THIS FILE DOES NOT TAKE ANY SCREENSHOTS.
# It ONLY receives base64 screenshots sent FROM the agent machine
# and saves them to data/screenshots/.
#
# ADD 2 LINES to server.py right before if __name__ == '__main__':
#
#   from screenshot_addon import wire_screenshot
#   wire_screenshot(app)
# =============================================================================

import os, base64, threading
from datetime import datetime

ROOT     = os.path.dirname(os.path.abspath(__file__))
SHOT_DIR = os.path.join(ROOT, "data", "screenshots")
os.makedirs(SHOT_DIR, exist_ok=True)


def wire_screenshot(app):
    """
    Patches /receive_log to extract and save screenshots
    that were taken on the AGENT machine and sent as base64.
    Does NOT take any screenshot on this (server/admin) machine.
    """
    try:
        original = app.view_functions['receive_log']
    except KeyError:
        print("⚠️  receive_log not found")
        return

    def patched_receive_log():
        from flask import request

        # Run original handler first — don't break anything
        response = original()

        # Now extract screenshots from the payload
        try:
            data   = request.get_json(force=True, silent=True) or {}
            events = data.get('events', [])

            # Handle single event format too
            if not events and 'event_type' in data:
                events = [data]

            for evt in events:
                # Skip if no screenshot in payload
                if not evt.get('has_screenshot'):
                    continue
                b64 = evt.get('screenshot_b64')
                if not b64:
                    continue

                # Save in background thread so we don't slow down response
                def _save(event=evt, screenshot_data=b64):
                    try:
                        user     = str(event.get('user') or
                                       event.get('agent_id') or 'unknown')
                        severity = str(event.get('screenshot_severity') or
                                       _score_to_sev(event.get('risk_score', 0)))
                        subject  = str(event.get('email_subject') or
                                       event.get('details') or 'event')

                        safe_user = user.replace("@","_").replace(".","_")[:20]
                        safe_subj = subject.replace(" ","_")[:15]
                        ts        = datetime.now().strftime("%Y%m%d_%H%M%S")

                        # Must start with screenshot_ for /api/screenshots
                        fname = (f"screenshot_{severity}_"
                                 f"{safe_user}_{safe_subj}_{ts}.png")
                        fpath = os.path.join(SHOT_DIR, fname)

                        # Decode and save — this is the agent's screen
                        img_bytes = base64.b64decode(screenshot_data)
                        with open(fpath, "wb") as f:
                            f.write(img_bytes)

                        kb = len(img_bytes) // 1024
                        print(f"📸 AGENT screenshot saved → {fname} ({kb}KB)")
                        print(f"   User: {user} | Severity: {severity}")

                    except Exception as e:
                        print(f"Screenshot save error: {e}")

                threading.Thread(target=_save, daemon=True).start()

        except Exception as e:
            print(f"Screenshot wire error: {e}")

        return response

    app.view_functions['receive_log'] = patched_receive_log
    print("✅ Agent screenshot receiver wired into /receive_log")
    print(f"   Saves to  : {SHOT_DIR}")
    print(f"   Source    : AGENT machine only (no local screenshots)")


def _score_to_sev(score):
    try:
        s = float(score)
        if s >= 0.9: return "CRITICAL"
        if s >= 0.7: return "HIGH"
        if s >= 0.5: return "MEDIUM"
        return "LOW"
    except:
        return "LOW"
