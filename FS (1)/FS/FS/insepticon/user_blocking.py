# =============================================================================
# DeepSentinel — user_blocking.py
# Admin action module for blocking/unblocking suspicious users
# Allows admin to take immediate action on detected threats
#
# ADD to server.py before if __name__ == '__main__':
#   from user_blocking import UserBlockingManager
#   blocking_manager = UserBlockingManager()
#   blocking_manager.wire(app)
# =============================================================================

import os
import json
import threading
from datetime import datetime, timedelta
from typing import Dict, List
from collections import defaultdict

ROOT = os.path.dirname(os.path.abspath(__file__))


class UserBlockingManager:
    """Manage user blocking and admin actions."""

    def __init__(self):
        self.blocked_users = {}     # username → block_record
        self.watched_users = {}     # username → watch_record
        self.isolation_queue = {}   # username → isolation_details
        self._lock = threading.Lock()
        
        self.blocking_path = os.path.join(ROOT, "data", "blocked_users.json")
        self.actions_log_path = os.path.join(ROOT, "logs", "admin_actions.jsonl")
        
        os.makedirs(os.path.join(ROOT, "data"), exist_ok=True)
        os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
        
        self._load_blocks()

    def _load_blocks(self):
        """Load previously blocked users."""
        if os.path.exists(self.blocking_path):
            try:
                with open(self.blocking_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.blocked_users = data.get("blocked", {})
                    self.watched_users = data.get("watched", {})
            except:
                pass

    def _save_blocks(self):
        """Save block state."""
        with open(self.blocking_path, 'w', encoding='utf-8') as f:
            json.dump({
                "blocked": self.blocked_users,
                "watched": self.watched_users,
                "last_updated": datetime.now().isoformat()
            }, f, indent=2)

    def _log_action(self, action_type: str, username: str, admin: str, reason: str, details: Dict = None):
        """Log administrative action."""
        record = {
            "timestamp": datetime.now().isoformat(),
            "action": action_type,
            "username": username,
            "admin": admin,
            "reason": reason,
            "details": details or {}
        }
        
        with open(self.actions_log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(record) + '\n')
        
        return record

    def block_user(self, username: str, admin: str, reason: str, duration_hours: int = 24, details: Dict = None):
        """Block a user's access."""
        with self._lock:
            block_until = datetime.now() + timedelta(hours=duration_hours)
            
            self.blocked_users[username] = {
                "username": username,
                "blocked_at": datetime.now().isoformat(),
                "blocked_until": block_until.isoformat(),
                "blocked_by": admin,
                "reason": reason,
                "status": "blocked",
                "details": details or {},
                "actions_blocked": [
                    "file_access",
                    "network_access",
                    "usb_access",
                    "email_send",
                    "application_launch"
                ]
            }
            
            self._save_blocks()
            self._log_action("BLOCK_USER", username, admin, reason, details)
            
            return self.blocked_users[username]

    def unblock_user(self, username: str, admin: str, reason: str = ""):
        """Unblock a previously blocked user."""
        with self._lock:
            if username in self.blocked_users:
                old_record = self.blocked_users[username].copy()
                del self.blocked_users[username]
                self._save_blocks()
                self._log_action("UNBLOCK_USER", username, admin, reason or "User unblocked", {
                    "previous_record": old_record
                })
                return True
        return False

    def watch_user(self, username: str, admin: str, reason: str, watch_duration_hours: int = 48):
        """Put a user under elevated monitoring."""
        with self._lock:
            watch_until = datetime.now() + timedelta(hours=watch_duration_hours)
            
            self.watched_users[username] = {
                "username": username,
                "watch_started": datetime.now().isoformat(),
                "watch_until": watch_until.isoformat(),
                "watch_initiated_by": admin,
                "reason": reason,
                "event_count": 0,
                "high_risk_events": [],
                "status": "watched"
            }
            
            self._save_blocks()
            self._log_action("WATCH_USER", username, admin, reason, {
                "watch_duration_hours": watch_duration_hours
            })
            
            return self.watched_users[username]

    def isolate_user(self, username: str, admin: str, reason: str, details: Dict = None):
        """Isolate a user's machine from network."""
        with self._lock:
            self.isolation_queue[username] = {
                "username": username,
                "isolation_requested": datetime.now().isoformat(),
                "requested_by": admin,
                "reason": reason,
                "status": "pending",
                "isolation_type": "network",  # network, machine, account
                "details": details or {},
                "machines_affected": details.get("machines", []) if details else []
            }
            
            self._log_action("ISOLATE_USER", username, admin, reason, details)
            
            return self.isolation_queue[username]

    def is_user_blocked(self, username: str) -> bool:
        """Check if user is currently blocked."""
        if username not in self.blocked_users:
            return False
        
        block_record = self.blocked_users[username]
        
        # Check if block has expired
        try:
            block_until = datetime.fromisoformat(block_record["blocked_until"])
            if datetime.now() > block_until:
                # Block expired, remove it
                self.unblock_user(username, "system", "Block expired")
                return False
        except:
            pass
        
        return block_record["status"] == "blocked"

    def is_user_watched(self, username: str) -> bool:
        """Check if user is under watch."""
        if username not in self.watched_users:
            return False
        
        watch_record = self.watched_users[username]
        
        # Check if watch has expired
        try:
            watch_until = datetime.fromisoformat(watch_record["watch_until"])
            if datetime.now() > watch_until:
                # Watch expired, remove it
                with self._lock:
                    del self.watched_users[username]
                    self._save_blocks()
                return False
        except:
            pass
        
        return watch_record["status"] == "watched"

    def get_user_action_list(self, username: str):
        """Get list of actions blocked for a particular user."""
        if self.is_user_blocked(username):
            return self.blocked_users[username].get("actions_blocked", [])
        return []

    def get_blocked_users_list(self) -> List[Dict]:
        """Get list of all currently blocked users."""
        blocked = []
        with self._lock:
            for username, record in list(self.blocked_users.items()):
                if self.is_user_blocked(username):
                    blocked.append(record)
        return blocked

    def get_watched_users_list(self) -> List[Dict]:
        """Get list of all currently watched users."""
        watched = []
        with self._lock:
            for username, record in list(self.watched_users.items()):
                if self.is_user_watched(username):
                    watched.append(record)
        return watched

    def get_pending_isolations(self) -> List[Dict]:
        """Get pending isolation requests."""
        return [iso for iso in self.isolation_queue.values() 
                if iso["status"] == "pending"]

    def approve_isolation(self, username: str, admin: str):
        """Approve network isolation for user."""
        if username in self.isolation_queue:
            self.isolation_queue[username]["status"] = "approved"
            self.isolation_queue[username]["approved_at"] = datetime.now().isoformat()
            self.isolation_queue[username]["approved_by"] = admin
            self._log_action("APPROVE_ISOLATION", username, admin, "Isolation approved")
            return True
        return False

    def reject_isolation(self, username: str, admin: str, reason: str):
        """Reject network isolation request."""
        if username in self.isolation_queue:
            self.isolation_queue[username]["status"] = "rejected"
            self.isolation_queue[username]["rejected_at"] = datetime.now().isoformat()
            self.isolation_queue[username]["rejected_by"] = admin
            self._log_action("REJECT_ISOLATION", username, admin, f"Isolation rejected: {reason}")
            return True
        return False

    def get_admin_dashboard_data(self) -> Dict:
        """Get summary data for admin dashboard."""
        return {
            "blocked_users_count": len(self.get_blocked_users_list()),
            "watched_users_count": len(self.get_watched_users_list()),
            "pending_isolations": len(self.get_pending_isolations()),
            "blocked_users": self.get_blocked_users_list(),
            "watched_users": self.get_watched_users_list(),
            "isolation_queue": self.get_pending_isolations()
        }

    def wire(self, app):
        """Wire user blocking endpoints into Flask app."""
        from flask import request, jsonify
        
        @app.route("/api/admin/block_user", methods=["POST"])
        def block_user_route():
            """Admin blocks a user."""
            data = request.get_json(force=True) or {}
            username = data.get("username")
            admin = data.get("admin", "admin")
            reason = data.get("reason", "Suspicious activity detected")
            duration_hours = data.get("duration_hours", 24)
            
            if not username:
                return jsonify({"error": "username required"}), 400
            
            result = self.block_user(username, admin, reason, duration_hours)
            return jsonify({
                "success": True,
                "message": f"User {username} blocked for {duration_hours} hours",
                "record": result
            }), 200

        @app.route("/api/admin/unblock_user", methods=["POST"])
        def unblock_user_route():
            """Admin unblocks a user."""
            data = request.get_json(force=True) or {}
            username = data.get("username")
            admin = data.get("admin", "admin")
            reason = data.get("reason", "")
            
            if not username:
                return jsonify({"error": "username required"}), 400
            
            success = self.unblock_user(username, admin, reason)
            return jsonify({
                "success": success,
                "message": f"User {username} unblocked" if success else "User not blocked"
            }), 200

        @app.route("/api/admin/watch_user", methods=["POST"])
        def watch_user_route():
            """Put user under elevated monitoring."""
            data = request.get_json(force=True) or {}
            username = data.get("username")
            admin = data.get("admin", "admin")
            reason = data.get("reason")
            duration_hours = data.get("duration_hours", 48)
            
            if not username or not reason:
                return jsonify({"error": "username and reason required"}), 400
            
            result = self.watch_user(username, admin, reason, duration_hours)
            return jsonify({
                "success": True,
                "message": f"User {username} is now under watch",
                "record": result
            }), 200

        @app.route("/api/admin/isolate_user", methods=["POST"])
        def isolate_user_route():
            """Request to isolate user's machine."""
            data = request.get_json(force=True) or {}
            username = data.get("username")
            admin = data.get("admin", "admin")
            reason = data.get("reason")
            
            if not username or not reason:
                return jsonify({"error": "username and reason required"}), 400
            
            result = self.isolate_user(username, admin, reason, data)
            return jsonify({
                "success": True,
                "message": f"Isolation request for {username} queued",
                "record": result
            }), 200

        @app.route("/api/admin/is_blocked/<username>")
        def check_blocked(username):
            """Check if user is blocked."""
            is_blocked = self.is_user_blocked(username)
            is_watched = self.is_user_watched(username)
            
            return jsonify({
                "username": username,
                "is_blocked": is_blocked,
                "is_watched": is_watched,
                "block_record": self.blocked_users.get(username) if is_blocked else None,
                "watch_record": self.watched_users.get(username) if is_watched else None
            }), 200

        @app.route("/api/admin/dashboard")
        def admin_dashboard():
            """Get admin control dashboard data."""
            return jsonify(self.get_admin_dashboard_data()), 200

        @app.route("/api/admin/approve_isolation/<username>", methods=["POST"])
        def approve_isolation_route(username):
            """Approve network isolation."""
            data = request.get_json(force=True) or {}
            admin = data.get("admin", "admin")
            
            success = self.approve_isolation(username, admin)
            return jsonify({
                "success": success,
                "message": "Isolation approved" if success else "Not found"
            }), 200

        @app.route("/api/admin/reject_isolation/<username>", methods=["POST"])
        def reject_isolation_route(username):
            """Reject network isolation."""
            data = request.get_json(force=True) or {}
            admin = data.get("admin", "admin")
            reason = data.get("reason", "")
            
            success = self.reject_isolation(username, admin, reason)
            return jsonify({
                "success": success,
                "message": "Isolation rejected" if success else "Not found"
            }), 200
