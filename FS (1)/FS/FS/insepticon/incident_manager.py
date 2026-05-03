# =============================================================================
# DeepSentinel — incident_manager.py
# Incident Management System
# Groups related alerts into incidents with collaboration workflow
# =============================================================================

import os
import json
import uuid
from datetime import datetime, timedelta
from collections import defaultdict
import threading

ROOT = os.path.dirname(os.path.abspath(__file__))


class Incident:
    """Represents a security incident (group of related alerts)"""
    
    STATUS = {
        'OPEN': 'open',
        'IN_PROGRESS': 'in_progress',
        'RESOLVED': 'resolved',
        'FALSE_POSITIVE': 'false_positive',
        'CLOSED': 'closed'
    }
    
    def __init__(self, title, severity, alert_ids=None):
        self.id = str(uuid.uuid4())[:12]
        self.title = title
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW
        self.status = self.STATUS['OPEN']
        self.related_alerts = alert_ids or []
        self.created_at = datetime.now()
        self.updated_at = datetime.now()
        self.assigned_to = None  # User ID
        self.notes = []  # [{"text": "...", "author": user_id, "timestamp": "..."}]
        self.timeline = []  # Activity log
        self.resolution_notes = None
        self.affected_users = set()
        self.affected_resources = set()
        self.tags = []  # For categorization
    
    def add_alert(self, alert_id, alert_data):
        """Correlate alert to incident"""
        if alert_id not in self.related_alerts:
            self.related_alerts.append(alert_id)
            self.updated_at = datetime.now()
            
            # Extract context
            if 'user_id' in alert_data:
                self.affected_users.add(alert_data['user_id'])
            if 'resource' in alert_data:
                self.affected_resources.add(alert_data['resource'])
            
            self.timeline.append({
                'action': 'alert_added',
                'alert_id': alert_id,
                'timestamp': datetime.now().isoformat(),
                'details': alert_data.get('message', '')
            })
    
    def assign(self, user_id):
        """Assign incident to analyst"""
        self.assigned_to = user_id
        self.status = self.STATUS['IN_PROGRESS']
        self.updated_at = datetime.now()
        self.timeline.append({
            'action': 'assigned',
            'assigned_to': user_id,
            'timestamp': datetime.now().isoformat()
        })
    
    def add_note(self, text, user_id, user_name):
        """Investigation note"""
        note = {
            'id': str(uuid.uuid4())[:8],
            'text': text,
            'author_id': user_id,
            'author_name': user_name,
            'timestamp': datetime.now().isoformat()
        }
        self.notes.append(note)
        self.updated_at = datetime.now()
        self.timeline.append({
            'action': 'note_added',
            'note_id': note['id'],
            'author': user_name,
            'timestamp': datetime.now().isoformat()
        })
    
    def resolve(self, resolution_text, user_id, user_name):
        """Mark incident as resolved"""
        self.status = self.STATUS['RESOLVED']
        self.resolution_notes = {
            'text': resolution_text,
            'resolved_by': user_id,
            'resolved_by_name': user_name,
            'resolved_at': datetime.now().isoformat()
        }
        self.updated_at = datetime.now()
        self.timeline.append({
            'action': 'resolved',
            'resolved_by': user_name,
            'timestamp': datetime.now().isoformat()
        })
    
    def to_dict(self):
        """Convert to JSON-serializable dict"""
        return {
            'id': self.id,
            'title': self.title,
            'severity': self.severity,
            'status': self.status,
            'related_alerts': self.related_alerts,
            'alert_count': len(self.related_alerts),
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'assigned_to': self.assigned_to,
            'affected_users': list(self.affected_users),
            'affected_resources': list(self.affected_resources),
            'notes_count': len(self.notes),
            'tags': self.tags,
            'resolution_notes': self.resolution_notes
        }


class IncidentManager:
    """Manages incident lifecycle"""
    
    def __init__(self):
        self.incidents = {}  # incident_id → Incident
        self.incidents_path = os.path.join(ROOT, "data", "incidents.jsonl")
        self.incident_correlation = {}  # alert_id → incident_id
        
        os.makedirs(os.path.join(ROOT, "data"), exist_ok=True)
        self._load_incidents()
    
    def _load_incidents(self):
        """Load incidents from disk"""
        if os.path.exists(self.incidents_path):
            try:
                with open(self.incidents_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.strip():
                            data = json.loads(line)
                            incident = self._dict_to_incident(data)
                            self.incidents[incident.id] = incident
                            
                            # Build correlation map
                            for alert_id in incident.related_alerts:
                                self.incident_correlation[alert_id] = incident.id
            except:
                pass
    
    def _dict_to_incident(self, data):
        """Convert dict back to Incident object"""
        incident = Incident(data['title'], data['severity'], data.get('related_alerts', []))
        incident.id = data['id']
        incident.status = data.get('status', 'open')
        incident.assigned_to = data.get('assigned_to')
        incident.notes = data.get('notes', [])
        incident.timeline = data.get('timeline', [])
        incident.resolution_notes = data.get('resolution_notes')
        incident.tags = data.get('tags', [])
        incident.affected_users = set(data.get('affected_users', []))
        incident.affected_resources = set(data.get('affected_resources', []))
        return incident
    
    def _persist_incident(self, incident):
        """Save incident to disk"""
        with open(self.incidents_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(incident.to_dict()) + '\n')
    
    def create_incident(self, title, severity, alert_ids=None, auto_from_alerts=False):
        """Create new incident"""
        incident = Incident(title, severity, alert_ids)
        self.incidents[incident.id] = incident
        
        # Map alerts to incident
        for alert_id in (alert_ids or []):
            self.incident_correlation[alert_id] = incident.id
        
        self._persist_incident(incident)
        return incident.id
    
    def auto_group_alerts(self, alerts):
        """
        Automatically group related alerts into incidents
        
        Grouping rules:
        1. Same user + similar type + within 10 minutes = same incident
        2. Honeypot triggered + file access + USB = data theft incident
        3. Failed logins x3 + successful login = breach attempt incident
        """
        
        # Find alerts in last 10 minutes
        cutoff = datetime.now() - timedelta(minutes=10)
        recent_alerts = [
            a for a in alerts
            if datetime.fromisoformat(a.get('timestamp', datetime.now().isoformat()).replace('Z', '+00:00')) > cutoff
        ]
        
        for alert in recent_alerts:
            alert_id = alert.get('id')
            if not alert_id or alert_id in self.incident_correlation:
                continue
            
            # Check if same user + similar type already has incident
            user_id = alert.get('user_id')
            event_type = alert.get('event_type')
            severity = alert.get('severity')
            
            similar_incident = None
            for inc in self.incidents.values():
                if inc.status != 'OPEN':
                    continue
                
                if user_id in inc.affected_users and inc.severity == severity:
                    # Same user, same severity = related
                    similar_incident = inc
                    break
            
            if similar_incident:
                similar_incident.add_alert(alert_id, alert)
                self.incident_correlation[alert_id] = similar_incident.id
            else:
                # Create new incident
                title = f"{severity} - {event_type} - {user_id}"
                incident_id = self.create_incident(title, severity, [alert_id])
    
    def get_incident(self, incident_id):
        """Get incident by ID"""
        return self.incidents.get(incident_id)
    
    def list_incidents(self, status=None, assigned_to=None, limit=50):
        """List incidents with optional filtering"""
        incidents = list(self.incidents.values())
        
        if status:
            incidents = [i for i in incidents if i.status == status]
        
        if assigned_to:
            incidents = [i for i in incidents if i.assigned_to == assigned_to]
        
        # Sort by severity, most recent first
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        incidents.sort(key=lambda x: (severity_order.get(x.severity, 999), x.updated_at), reverse=True)
        
        return [i.to_dict() for i in incidents[:limit]]
    
    def assign_incident(self, incident_id, user_id):
        """Assign incident to analyst"""
        incident = self.incidents.get(incident_id)
        if incident:
            incident.assign(user_id)
            self._persist_incident(incident)
    
    def add_note(self, incident_id, text, user_id, user_name):
        """Add investigation note"""
        incident = self.incidents.get(incident_id)
        if incident:
            incident.add_note(text, user_id, user_name)
            self._persist_incident(incident)
            return True
        return False
    
    def resolve_incident(self, incident_id, resolution_text, user_id, user_name):
        """Mark incident as resolved"""
        incident = self.incidents.get(incident_id)
        if incident:
            incident.resolve(resolution_text, user_id, user_name)
            self._persist_incident(incident)
            return True
        return False
    
    def get_incident_stats(self):
        """Get incident statistics"""
        total = len(self.incidents)
        open_count = sum(1 for i in self.incidents.values() if i.status == 'OPEN')
        critical_count = sum(1 for i in self.incidents.values() if i.severity == 'CRITICAL')
        resolved_count = sum(1 for i in self.incidents.values() if i.status == 'RESOLVED')
        
        # Average time to resolve
        resolved_incidents = [i for i in self.incidents.values() if i.status == 'RESOLVED']
        avg_resolve_time = None
        if resolved_incidents:
            times = [(
                datetime.fromisoformat(i.resolution_notes['resolved_at'].replace('Z', '+00:00')) -
                i.created_at
            ).total_seconds() / 3600 for i in resolved_incidents]  # hours
            avg_resolve_time = sum(times) / len(times)
        
        return {
            'total_incidents': total,
            'open': open_count,
            'critical': critical_count,
            'resolved': resolved_count,
            'false_positive': sum(1 for i in self.incidents.values() if i.status == 'FALSE_POSITIVE'),
            'avg_resolve_time_hours': round(avg_resolve_time, 1) if avg_resolve_time else None,
            'sla_status': 'ON_TRACK' if avg_resolve_time and avg_resolve_time < 2 else 'AT_RISK'
        }
