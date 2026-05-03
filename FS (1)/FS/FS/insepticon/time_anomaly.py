# =============================================================================
# DeepSentinel — time_anomaly.py
# Time-Based Anomaly Detection
# Detects unusual activity chains (e.g., 3 AM access + USB use + process launch = intrusion)
# =============================================================================

import os
import json
from datetime import datetime, timedelta
from collections import defaultdict

ROOT = os.path.dirname(os.path.abspath(__file__))


class TimeAnomalyDetector:
    """Detects anomalous activity chains across time windows."""

    def __init__(self):
        self.activity_chains = []
        self.alert_path = os.path.join(ROOT, "data", "time_anomalies.jsonl")
        
        os.makedirs(os.path.join(ROOT, "data"), exist_ok=True)
        
        # Define suspicious activity chains
        self.risk_chains = [
            {
                "name": "After-Hours Data Theft",
                "activities": ["logon", "file_access", "usb_access"],
                "time_window_minutes": 30,
                "min_activities": 3,
                "severity": "CRITICAL",
                "hours": (22, 6)  # 10 PM to 6 AM
            },
            {
                "name": "Privilege Escalation Chain",
                "activities": ["process_launch", "file_access", "registry_modification"],
                "time_window_minutes": 15,
                "min_activities": 2,
                "severity": "CRITICAL",
                "sensitive_processes": ["cmd", "powershell", "psexec", "runas"]
            },
            {
                "name": "USB + Download Pattern",
                "activities": ["usb_access", "download", "file_copy"],
                "time_window_minutes": 45,
                "min_activities": 2,
                "severity": "HIGH"
            },
            {
                "name": "Screenshare + Access Pattern",
                "activities": ["screenshot", "logon", "file_access"],
                "time_window_minutes": 10,
                "min_activities": 2,
                "severity": "HIGH",
                "note": "Potential insider with remote access"
            },
            {
                "name": "Failed Logins + Successful Access",
                "activities": ["failed_login", "successful_login", "file_access"],
                "time_window_minutes": 5,
                "min_activities": 3,
                "severity": "MEDIUM",
                "note": "Password guessing followed by successful breach"
            },
            {
                "name": "Lateral Movement Chain",
                "activities": ["network_access", "file_access", "process_launch"],
                "time_window_minutes": 20,
                "min_activities": 2,
                "severity": "HIGH",
                "target_networks": ["smb", "rpc", "wmi"]
            }
        ]

    def detect_activity_chain(self, user_id, recent_events):
        """
        Detect suspicious activity chains in recent events.
        
        Event format:
        {
            "user_id": "john@company.com",
            "timestamp": "2026-03-15T22:15:00",
            "type": "file_access|usb_access|process_launch|...",
            "details": "..."
        }
        """
        
        detected_chains = []
        
        # Check against each risk chain pattern
        for chain_pattern in self.risk_chains:
            chain_name = chain_pattern.get('name')
            required_activities = chain_pattern.get('activities', [])
            time_window = timedelta(minutes=chain_pattern.get('time_window_minutes', 30))
            min_activities = chain_pattern.get('min_activities', 2)
            severity = chain_pattern.get('severity', 'MEDIUM')
            
            # Filter events matching the pattern
            matching_events = []
            for event in recent_events:
                event_type = event.get('type', '').lower()
                
                # Check if event type matches any in the chain
                for required_type in required_activities:
                    if required_type.lower() in event_type:
                        # Special checks for specific chains
                        if chain_pattern.get('hours'):
                            try:
                                dt = datetime.fromisoformat(event.get('timestamp', '').replace('Z', '+00:00'))
                                hour = dt.hour
                                start_hour, end_hour = chain_pattern['hours']
                                is_after_hours = (hour >= start_hour or hour < end_hour)
                                if not is_after_hours:
                                    continue
                            except:
                                pass
                        
                        matching_events.append({
                            'type': event_type,
                            'event': event,
                            'timestamp': event.get('timestamp', datetime.now().isoformat())
                        })
                        break
            
            # Check if we have enough activities within time window
            if len(matching_events) >= min_activities:
                # Verify they're within time window
                try:
                    timestamps = [datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) for e in matching_events]
                    time_span = max(timestamps) - min(timestamps)
                    
                    if time_span <= time_window:
                        chain_alert = {
                            "user_id": user_id,
                            "chain_name": chain_name,
                            "severity": severity,
                            "activities_found": len(matching_events),
                            "required_activities": required_activities,
                            "time_window_minutes": chain_pattern.get('time_window_minutes'),
                            "detected_activities": [
                                {
                                    'type': e['type'],
                                    'timestamp': e['timestamp'],
                                    'details': e['event'].get('details', '')
                                } for e in matching_events
                            ],
                            "alert_timestamp": datetime.now().isoformat()
                        }
                        
                        detected_chains.append(chain_alert)
                        
                        # Log alert
                        with open(self.alert_path, 'a', encoding='utf-8') as f:
                            f.write(json.dumps(chain_alert) + '\n')
                except:
                    pass
        
        return detected_chains

    def get_hourly_activity_baseline(self, user_id, events):
        """
        Get baseline activity for each hour of day.
        
        Returns:
        {
            "0": {"logon": 0, "file_access": 0, ...},
            "1": {"logon": 0, ...},
            ...
            "23": {"logon": 5, "file_access": 120, ...}
        }
        """
        
        hourly_baseline = {str(h): defaultdict(int) for h in range(24)}
        
        for event in events:
            if event.get('user_id') != user_id:
                continue
            
            try:
                dt = datetime.fromisoformat(event.get('timestamp', '').replace('Z', '+00:00'))
                hour = str(dt.hour)
                event_type = event.get('type', 'unknown').lower()
                
                hourly_baseline[hour][event_type] += 1
            except:
                pass
        
        # Convert defaultdicts to regular dicts
        return {hour: dict(activities) for hour, activities in hourly_baseline.items()}

    def detect_off_hours_spike(self, user_id, events, hour_threshold=3):
        """
        Detect unusual spikes in off-hours activity.
        
        Returns:
        {
            "is_spike": bool,
            "severity": "LOW|MEDIUM|HIGH",
            "reason": "...",
            "spike_hour": 22,
            "spike_count": 50,
            "normal_count": 5
        }
        """
        
        # Find off-hours (8 PM to 6 AM)
        off_hours = list(range(20, 24)) + list(range(0, 6))
        on_hours = list(range(6, 20))
        
        off_hours_count = 0
        on_hours_count = 0
        spike_hour = None
        hourly_counts = {}
        
        for event in events:
            if event.get('user_id') != user_id:
                continue
            
            try:
                dt = datetime.fromisoformat(event.get('timestamp', '').replace('Z', '+00:00'))
                hour = dt.hour
                
                if hour in off_hours:
                    off_hours_count += 1
                    hourly_counts[hour] = hourly_counts.get(hour, 0) + 1
                elif hour in on_hours:
                    on_hours_count += 1
            except:
                pass
        
        # Check for spikes
        if hourly_counts:
            spike_hour = max(hourly_counts, key=hourly_counts.get)
            spike_count = hourly_counts[spike_hour]
            
            avg_on_hours = on_hours_count / len(on_hours) if on_hours_count > 0 else 0
            
            if spike_count > avg_on_hours * hour_threshold:
                return {
                    "is_spike": True,
                    "severity": "HIGH" if spike_count > avg_on_hours * 5 else "MEDIUM",
                    "reason": f"Unusual spike in off-hours activity at {spike_hour}:00",
                    "spike_hour": spike_hour,
                    "spike_count": spike_count,
                    "normal_count": int(avg_on_hours),
                    "multiplier": round(spike_count / avg_on_hours, 1) if avg_on_hours > 0 else 0
                }
        
        return {
            "is_spike": False,
            "severity": "LOW",
            "reason": "Normal off-hours activity",
            "spike_hour": None,
            "spike_count": off_hours_count,
            "normal_count": on_hours_count
        }

    def get_recent_chains(self, user_id=None, limit=50, severity=None):
        """Get recent detected activity chains."""
        try:
            chains = []
            if os.path.exists(self.alert_path):
                with open(self.alert_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    for line in lines[-limit:]:
                        if line.strip():
                            chain = json.loads(line)
                            if user_id and chain.get('user_id') != user_id:
                                continue
                            if severity and chain.get('severity') != severity:
                                continue
                            chains.append(chain)
            return list(reversed(chains))
        except:
            return []

    def get_activity_summary(self, events, time_window_hours=24):
        """Get summary of activity types in time window."""
        cutoff_time = datetime.now() - timedelta(hours=time_window_hours)
        
        activity_counts = defaultdict(int)
        user_activity = defaultdict(int)
        
        for event in events:
            try:
                dt = datetime.fromisoformat(event.get('timestamp', '').replace('Z', '+00:00'))
                if dt >= cutoff_time:
                    activity_counts[event.get('type', 'unknown')] += 1
                    user_activity[event.get('user_id', 'unknown')] += 1
            except:
                pass
        
        return {
            "time_window_hours": time_window_hours,
            "total_activities": sum(activity_counts.values()),
            "activity_breakdown": dict(activity_counts),
            "user_breakdown": dict(user_activity),
            "top_users": sorted(user_activity.items(), key=lambda x: x[1], reverse=True)[:10]
        }
