# =============================================================================
# DeepSentinel — admin_commands.py  (SERVER SIDE)
# Adds admin action endpoints to server.py.
# Admin can block/quarantine/unblock agent machines from dashboard.
#
# ADD to server.py before if __name__ == '__main__':
#   from admin_commands import register_commands
#   register_commands(app)
# =============================================================================

import os, sys, json, threading
from datetime import datetime
from flask import request, jsonify

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

os.makedirs(os.path.join(ROOT, "data"),       exist_ok=True)
os.makedirs(os.path.join(ROOT, "quarantine"), exist_ok=True)
os.makedirs(os.path.join(ROOT, "logs"),       exist_ok=True)

# ── Pending commands queue ────────────────────────────────────────────────────
# Format: {agent_id: [{"command": "block", "ts": "...", "reason": "..."}]}
_pending_commands = {}
_quarantined      = {}   # agent_id → quarantine record
_blocked          = {}   # agent_id → block record

COMMANDS_PATH    = os.path.join(ROOT, "data",       "commands.json")
QUARANTINE_PATH  = os.path.join(ROOT, "quarantine", "quarantine_status.json")


def _save_state():
    try:
        with open(COMMANDS_PATH, "w") as f:
            json.dump(_pending_commands, f, indent=2, default=str)
    except: pass


def _load_state():
    global _pending_commands, _quarantined, _blocked
    try:
        if os.path.exists(COMMANDS_PATH):
            with open(COMMANDS_PATH) as f:
                _pending_commands = json.load(f)
    except: pass


_load_state()


def enqueue_agent_command(agent_id, command, reason="Admin action", admin_user="admin", **extra):
    """Queue a command for an agent programmatically from server code."""
    if not agent_id or not command:
        return None

    if agent_id not in _pending_commands:
        _pending_commands[agent_id] = []

    entry = {
        "command": command,
        "reason": reason,
        "admin": admin_user,
        "timestamp": datetime.now().isoformat(),
        "executed": False,
    }
    for key, value in extra.items():
        entry[key] = value

    _pending_commands[agent_id].append(entry)
    _save_state()
    return entry


# =============================================================================
# REGISTER ROUTES
# =============================================================================

def register_commands(app):

    # ── Admin sends command to agent ──────────────────────────────────────────
    @app.route("/admin/command", methods=["POST"])
    def admin_command():
        """
        Admin sends a command to an agent machine.
        Body: {agent_id, command, reason}
        Commands: block | unblock | quarantine | unquarantine | screenshot
        """
        data      = request.get_json(force=True) or {}
        agent_id  = data.get("agent_id", "")
        command   = data.get("command",  "")
        reason    = data.get("reason",   "Admin action")
        admin_user= data.get("admin",    "admin")
        duration_sec = data.get("duration_sec", 15)

        if not agent_id or not command:
            return jsonify({"error": "agent_id and command required"}), 400

        VALID = {"block","unblock","quarantine","unquarantine",
                 "screenshot","screen_record","lock_screen","unlock_screen",
                 "send_pending_email","reject_pending_email"}
        if command not in VALID:
            return jsonify({"error": f"Unknown command. Valid: {VALID}"}), 400

        # Add to pending queue for this agent
        entry = enqueue_agent_command(
            agent_id,
            command,
            reason=reason,
            admin_user=admin_user,
        )
        if command == "screen_record":
            try:
                entry["duration_sec"] = int(duration_sec)
            except (TypeError, ValueError):
                entry["duration_sec"] = 15
        _save_state()

        # Update status records
        ts = datetime.now().isoformat()
        if command == "block":
            _blocked[agent_id] = {"since": ts, "reason": reason, "admin": admin_user}
        elif command == "unblock":
            _blocked.pop(agent_id, None)
        elif command == "quarantine":
            _quarantined[agent_id] = {"since": ts, "reason": reason, "admin": admin_user}
        elif command == "unquarantine":
            _quarantined.pop(agent_id, None)

        print(f"🎮 ADMIN COMMAND: {command} → {agent_id} | reason: {reason}")

        # Log it
        log_entry = {
            "timestamp": ts,
            "admin":     admin_user,
            "command":   command,
            "agent_id":  agent_id,
            "reason":    reason,
        }
        with open(os.path.join(ROOT,"logs","admin_commands.jsonl"),
                  "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")

        return jsonify({
            "status":   "queued",
            "command":  command,
            "agent_id": agent_id,
            "message":  f"Command '{command}' queued for {agent_id}",
        })


    # ── Agent polls for pending commands ─────────────────────────────────────
    @app.route("/get_commands/<agent_id>", methods=["GET"])
    def get_commands(agent_id):
        """
        Agent calls this every 10 seconds to get pending commands.
        Returns list of unexecuted commands.
        """
        pending = _pending_commands.get(agent_id, [])
        unexecuted = [c for c in pending if not c.get("executed")]

        # Mark as executed
        for c in unexecuted:
            c["executed"] = True
        _save_state()

        return jsonify({
            "agent_id": agent_id,
            "commands": unexecuted,
            "is_blocked":     agent_id in _blocked,
            "is_quarantined": agent_id in _quarantined,
        })


    # ── Status endpoints ──────────────────────────────────────────────────────
    @app.route("/admin/status")
    def admin_status():
        """Returns current block/quarantine status of all agents."""
        return jsonify({
            "blocked":     _blocked,
            "quarantined": _quarantined,
            "pending_commands": {
                k: len([c for c in v if not c.get("executed")])
                for k, v in _pending_commands.items()
            }
        })


    @app.route("/admin/unblock/<agent_id>", methods=["POST"])
    def unblock_agent(agent_id):
        """Quick unblock endpoint."""
        _blocked.pop(agent_id, None)
        if agent_id in _pending_commands:
            _pending_commands[agent_id].append({
                "command":   "unblock",
                "reason":    "Admin unblock",
                "timestamp": datetime.now().isoformat(),
                "executed":  False,
            })
        _save_state()
        return jsonify({"status": "ok", "message": f"{agent_id} unblocked"})


    print("✅ Admin command routes registered:")
    print("   POST /admin/command          → send command to agent")
    print("   GET  /get_commands/<agent>   → agent polls for commands")
    print("   GET  /admin/status           → see blocked/quarantined agents")
    print("   POST /admin/unblock/<agent>  → quick unblock")
