# =============================================================================
# DeepSentinel — audit_trail.py
# Audit Trail System
# Tracks all admin actions for compliance and investigations
# =============================================================================

import os
import json
from datetime import datetime
from collections import defaultdict

ROOT = os.path.dirname(os.path.abspath(__file__))


class AuditTrail:
    """Tracks all administrative actions"""
    
    ACTION_TYPES = {
        'USER_LOGIN': 'user_login',
        'USER_LOGOUT': 'user_logout',
        'ALERT_CREATED': 'alert_created',
        'ALERT_ACKNOWLEDGED': 'alert_acknowledged',
        'INCIDENT_CREATED': 'incident_created',
        'INCIDENT_ASSIGNED': 'incident_assigned',
        'INCIDENT_RESOLVED': 'incident_resolved',
        'USER_BLOCKED': 'user_blocked',
        'USER_UNBLOCKED': 'user_unblocked',
        'USER_QUARANTINED': 'user_quarantined',
        'THRESHOLD_CHANGED': 'threshold_changed',
        'RULE_CREATED': 'rule_created',
        'RULE_DELETED': 'rule_deleted',
        'CONFIG_CHANGED': 'config_changed',
        'SCREENSHOT_REQUESTED': 'screenshot_requested',
        'COMMAND_EXECUTED': 'command_executed',
        'EXPORT_DATA': 'export_data',
        'SEARCH_PERFORMED': 'search_performed'
    }
    
    def __init__(self):
        self.audit_path = os.path.join(ROOT, "data", "audit_trail.jsonl")
        self.audit_log = []  # In-memory cache
        
        os.makedirs(os.path.join(ROOT, "data"), exist_ok=True)
        self._load_audit_log()
    
    def _load_audit_log(self):
        """Load audit log from disk"""
        if os.path.exists(self.audit_path):
            try:
                with open(self.audit_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.strip():
                            try:
                                self.audit_log.append(json.loads(line))
                            except:
                                pass
            except:
                pass
    
    def log_action(self, action_type, user_id, user_name, target=None, details=None, ip_address=None):
        """Log an administrative action"""
        
        entry = {
            'timestamp': datetime.now().isoformat(),
            'action_type': action_type,
            'user_id': user_id,
            'user_name': user_name,
            'target': target,  # What was affected (user, incident, alert, etc)
            'details': details or {},
            'ip_address': ip_address,
            'status': 'SUCCESS'
        }
        
        self.audit_log.append(entry)
        
        # Persist to disk
        try:
            with open(self.audit_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry) + '\n')
        except:
            pass
        
        return entry
    
    def log_block_user(self, user_id, target_user, reason, admin_id, admin_name, ip_address=None):
        """Log user blocking action"""
        return self.log_action(
            self.ACTION_TYPES['USER_BLOCKED'],
            admin_id,
            admin_name,
            target=target_user,
            details={'reason': reason},
            ip_address=ip_address
        )
    
    def log_unblock_user(self, target_user, admin_id, admin_name, ip_address=None):
        """Log user unblocking action"""
        return self.log_action(
            self.ACTION_TYPES['USER_UNBLOCKED'],
            admin_id,
            admin_name,
            target=target_user,
            ip_address=ip_address
        )
    
    def log_incident_action(self, action, incident_id, user_id, user_name, details=None, ip_address=None):
        """Log incident-related action"""
        return self.log_action(
            action,
            user_id,
            user_name,
            target=incident_id,
            details=details,
            ip_address=ip_address
        )
    
    def log_configuration_change(self, config_key, old_value, new_value, user_id, user_name, ip_address=None):
        """Log configuration changes"""
        return self.log_action(
            self.ACTION_TYPES['CONFIG_CHANGED'],
            user_id,
            user_name,
            target=config_key,
            details={
                'old_value': str(old_value),
                'new_value': str(new_value)
            },
            ip_address=ip_address
        )
    
    def get_logs(self, limit=100, action_type=None, user_id=None, target=None):
        """Query audit logs"""
        logs = self.audit_log
        
        if action_type:
            logs = [l for l in logs if l['action_type'] == action_type]
        
        if user_id:
            logs = [l for l in logs if l['user_id'] == user_id]
        
        if target:
            logs = [l for l in logs if l.get('target') == target]
        
        # Sort by timestamp, newest first
        logs.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return logs[:limit]
    
    def get_user_timeline(self, user_id, limit=50):
        """Get all actions performed by a user"""
        return self.get_logs(limit=limit, user_id=user_id)
    
    def get_target_timeline(self, target, limit=50):
        """Get all actions affecting a target (incident, user, etc)"""
        return self.get_logs(limit=limit, target=target)
    
    def get_action_summary(self, days=7):
        """Get summary of actions in the last N days"""
        from datetime import timedelta, datetime as dt
        from collections import defaultdict as dd
        
        cutoff = dt.now() - timedelta(days=days)
        recent = [
            l for l in self.audit_log
            if dt.fromisoformat(l['timestamp'].replace('Z', '+00:00')) > cutoff
        ]
        
        summary = {
            'total_actions': len(recent),
            'by_type': dd(int),
            'by_user': dd(int),
            'by_day': dd(int)
        }
        
        for log in recent:
            summary['by_type'][log['action_type']] += 1
            summary['by_user'][log['user_name']] += 1
            
            # Extract day from timestamp
            day = log['timestamp'].split('T')[0]
            summary['by_day'][day] += 1
        
        return {
            'total_actions': len(recent),
            'by_type': dict(summary['by_type']),
            'by_user': dict(summary['by_user']),
            'by_day': dict(summary['by_day'])
        }
    
    def export_audit_log(self, format='json', action_type=None):
        """Export audit log in different formats"""
        logs = self.get_logs(limit=10000, action_type=action_type)
        
        if format == 'json':
            return json.dumps(logs, indent=2)
        elif format == 'csv':
            import csv
            from io import StringIO
            
            output = StringIO()
            if logs:
                writer = csv.DictWriter(output, fieldnames=logs[0].keys())
                writer.writeheader()
                writer.writerows(logs)
            
            return output.getvalue()
        
        return None
