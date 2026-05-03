# =============================================================================
# DeepSentinel — honeypot_manager.py
# Honeypot system to trap and log suspicious activity
# Creates decoy resources that appear real but are monitored
#
# ADD to server.py before if __name__ == '__main__':
#   from honeypot_manager import HoneypotManager
#   honeypot = HoneypotManager()
#   honeypot.wire(app)
# =============================================================================

import os
import json
import uuid
from datetime import datetime
from flask import jsonify, request
from collections import defaultdict

ROOT = os.path.dirname(os.path.abspath(__file__))


class HoneypotManager:
    """Honeypot system for trapping suspicious activity."""

    def __init__(self):
        self.honeypots = {
            "files": {},       # Decoy files
            "credentials": {}, # Fake credentials
            "services": {}     # Fake services/endpoints
        }
        self.traps_triggered = []  # Log of triggered traps
        self.logs_path = os.path.join(ROOT, "logs", "honeypot.jsonl")
        
        os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
        self._init_honeypots()
        self._load_traps()

    def _init_honeypots(self):
        """Initialize decoy honeypot resources."""
        
        # Decoy files (high-value targets)
        self.honeypots["files"] = {
            "admin_passwords.docx": {
                "id": str(uuid.uuid4()),
                "name": "admin_passwords.docx",
                "path": r"C:\Users\Admin\Documents\admin_passwords.docx",
                "type": "credential_file",
                "content": "Admin credentials (honeypot - not real)",
                "created": datetime.now().isoformat(),
                "accessed": 0,
                "alerts": []
            },
            "financial_report_2025.xlsx": {
                "id": str(uuid.uuid4()),
                "name": "financial_report_2025.xlsx",
                "path": r"C:\Finance\financial_report_2025.xlsx",
                "type": "financial_data",
                "content": "Financial data (honeypot - not real)",
                "created": datetime.now().isoformat(),
                "accessed": 0,
                "alerts": []
            },
            "employee_database.sql": {
                "id": str(uuid.uuid4()),
                "name": "employee_database.sql",
                "path": r"C:\Database\employee_database.sql",
                "type": "database",
                "content": "Employee data (honeypot - not real)",
                "created": datetime.now().isoformat(),
                "accessed": 0,
                "alerts": []
            },
            "private_key.pem": {
                "id": str(uuid.uuid4()),
                "name": "private_key.pem",
                "path": r"C:\Security\private_key.pem",
                "type": "encryption_key",
                "content": "Private key (honeypot - not real)",
                "created": datetime.now().isoformat(),
                "accessed": 0,
                "alerts": []
            }
        }
        
        # Decoy credentials
        self.honeypots["credentials"] = {
            "admin_account": {
                "id": str(uuid.uuid4()),
                "username": "admin_backup",
                "password": "HoneyPot_P@ssw0rd_2025!",
                "email": "admin_old@company.internal",
                "description": "Decoy admin account for detection",
                "created": datetime.now().isoformat(),
                "attempts": 0,
                "alerts": []
            },
            "database_user": {
                "id": str(uuid.uuid4()),
                "username": "db_admin",
                "password": "SqlSer4er_H0neyP0t!",
                "email": "db_admin@company.internal",
                "description": "Decoy database admin account",
                "created": datetime.now().isoformat(),
                "attempts": 0,
                "alerts": []
            },
            "service_account": {
                "id": str(uuid.uuid4()),
                "username": "service_acct",
                "password": "Svc_H0neyP0t_2025!",
                "email": "service@company.internal",
                "description": "Decoy service account",
                "created": datetime.now().isoformat(),
                "attempts": 0,
                "alerts": []
            }
        }
        
        # Decoy services/shares
        self.honeypots["services"] = {
            "fake_share": {
                "id": str(uuid.uuid4()),
                "name": "\\\\SERVER-BACKUP\\Sensitive",
                "type": "network_share",
                "description": "Decoy network share",
                "created": datetime.now().isoformat(),
                "accessed": 0,
                "alerts": []
            },
            "sql_server": {
                "id": str(uuid.uuid4()),
                "name": "SQL-BACKUP.internal",
                "type": "database_server",
                "port": 1433,
                "description": "Decoy SQL server",
                "created": datetime.now().isoformat(),
                "attempts": 0,
                "alerts": []
            }
        }

    def log_trap(self, trap_type, trap_id, user, action, source_ip=None, details=None):
        """Log when a honeypot trap is triggered."""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "trap_type": trap_type,
            "trap_id": trap_id,
            "severity": "CRITICAL",  # All honeypot access is critical
            "user": user,
            "action": action,
            "source_ip": source_ip,
            "details": details or {},
            "response": "BLOCKING_USER"
        }
        
        self.traps_triggered.append(alert)
        
        # Save to log
        with open(self.logs_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(alert) + '\n')
        
        return alert

    def check_file_access(self, user, file_path, action="access"):
        """Check if a file access is a honeypot trap."""
        for file_id, file_info in self.honeypots["files"].items():
            if file_info["path"].lower() == file_path.lower():
                # Trap triggered!
                file_info["accessed"] += 1
                alert = self.log_trap(
                    "file_access",
                    file_info["id"],
                    user,
                    f"Attempted to {action} honeypot file: {file_id}",
                    details={"file_name": file_id, "file_type": file_info["type"]}
                )
                file_info["alerts"].append(alert)
                return True, alert
        return False, None

    def check_credential_use(self, username, password=None):
        """Check if credentials are decoy honeypot credentials."""
        for cred_id, cred_info in self.honeypots["credentials"].items():
            if cred_info["username"].lower() == username.lower():
                cred_info["attempts"] += 1
                
                # Check password match (if provided)
                is_exact_match = password and password == cred_info["password"]
                
                alert = self.log_trap(
                    "credential_use",
                    cred_info["id"],
                    username,
                    f"Attempted login with honeypot account: {username}",
                    details={
                        "account_type": "decoy",
                        "password_matched": is_exact_match,
                        "total_attempts": cred_info["attempts"]
                    }
                )
                cred_info["alerts"].append(alert)
                return True, alert, is_exact_match
        return False, None, False

    def check_service_access(self, service_name, user=None, action="connect"):
        """Check if service access is a honeypot trap."""
        for service_id, service_info in self.honeypots["services"].items():
            if service_info["name"].lower() == service_name.lower():
                service_info["accessed"] += 1
                
                alert = self.log_trap(
                    "service_access",
                    service_info["id"],
                    user or "unknown",
                    f"Attempted to {action} honeypot service: {service_name}",
                    details={"service_type": service_info["type"]}
                )
                service_info["alerts"].append(alert)
                return True, alert
        return False, None

    def get_honeypot_stats(self):
        """Get honeypot statistics."""
        file_accesses = sum(f["accessed"] for f in self.honeypots["files"].values())
        cred_attempts = sum(c["attempts"] for c in self.honeypots["credentials"].values())
        service_accesses = sum(s["accessed"] for s in self.honeypots["services"].values())
        
        return {
            "total_honeypots": (
                len(self.honeypots["files"]) +
                len(self.honeypots["credentials"]) +
                len(self.honeypots["services"])
            ),
            "file_traps": len(self.honeypots["files"]),
            "credential_traps": len(self.honeypots["credentials"]),
            "service_traps": len(self.honeypots["services"]),
            "traps_triggered": len(self.traps_triggered),
            "file_accesses": file_accesses,
            "credential_attempts": cred_attempts,
            "service_accesses": service_accesses,
            "critical_alerts": len([a for a in self.traps_triggered if a.get("severity") == "CRITICAL"])
        }

    def get_trap_details(self, trap_type=None):
        """Get detailed honeypot information."""
        if trap_type == "files":
            return {
                "type": "file",
                "traps": list(self.honeypots["files"].values())
            }
        elif trap_type == "credentials":
            return {
                "type": "credential",
                "traps": [
                    {
                        "id": c["id"],
                        "username": c["username"],
                        "attempts": c["attempts"],
                        "description": c["description"]
                    }
                    for c in self.honeypots["credentials"].values()
                ]
            }
        elif trap_type == "services":
            return {
                "type": "service",
                "traps": list(self.honeypots["services"].values())
            }
        else:
            return {
                "files": list(self.honeypots["files"].values()),
                "credentials": list(self.honeypots["credentials"].values()),
                "services": list(self.honeypots["services"].values()),
                "recent_alerts": self.traps_triggered[-10:]
            }

    def _load_traps(self):
        """Load historical trap triggers."""
        if os.path.exists(self.logs_path):
            try:
                with open(self.logs_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.strip():
                            self.traps_triggered.append(json.loads(line))
            except:
                pass

    def wire(self, app):
        """Wire honeypot endpoints into Flask app."""
        
        @app.route("/api/honeypot/stats")
        def honeypot_stats():
            """Get honeypot statistics."""
            return jsonify(self.get_honeypot_stats())

        @app.route("/api/honeypot/details")
        def honeypot_details():
            """Get honeypot details."""
            trap_type = request.args.get("type")
            return jsonify(self.get_trap_details(trap_type))

        @app.route("/api/honeypot/check_file", methods=["POST"])
        def check_file_trap():
            """Check if file access should trigger honeypot."""
            data = request.get_json(force=True) or {}
            user = data.get("user", "unknown")
            file_path = data.get("file_path", "")
            action = data.get("action", "access")
            
            is_trap, alert = self.check_file_access(user, file_path, action)
            
            if is_trap:
                return jsonify({
                    "is_honeypot": True,
                    "severity": "CRITICAL",
                    "message": "Honeypot trap triggered!",
                    "alert": alert,
                    "action": "BLOCK_AND_ISOLATE"
                }), 200
            
            return jsonify({"is_honeypot": False}), 200

        @app.route("/api/honeypot/check_credential", methods=["POST"])
        def check_credential_trap():
            """Check if credential use is a honeypot."""
            data = request.get_json(force=True) or {}
            username = data.get("username", "")
            password = data.get("password")
            
            is_trap, alert, matched = self.check_credential_use(username, password)
            
            if is_trap:
                return jsonify({
                    "is_honeypot": True,
                    "severity": "CRITICAL",
                    "message": "Honeypot credential detected!",
                    "password_matched": matched,
                    "alert": alert,
                    "action": "BLOCK_ACCOUNT_AND_ISOLATE"
                }), 200
            
            return jsonify({"is_honeypot": False}), 200

        @app.route("/api/honeypot/check_service", methods=["POST"])
        def check_service_trap():
            """Check if service access is a honeypot."""
            data = request.get_json(force=True) or {}
            service_name = data.get("service_name", "")
            user = data.get("user")
            action = data.get("action", "connect")
            
            is_trap, alert = self.check_service_access(service_name, user, action)
            
            if is_trap:
                return jsonify({
                    "is_honeypot": True,
                    "severity": "CRITICAL",
                    "message": "Honeypot service access detected!",
                    "alert": alert,
                    "action": "BLOCK_AND_ISOLATE"
                }), 200
            
            return jsonify({"is_honeypot": False}), 200
