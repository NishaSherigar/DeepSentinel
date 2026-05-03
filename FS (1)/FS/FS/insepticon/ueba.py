# =============================================================================
# DeepSentinel — ueba.py
# User & Entity Behavior Analytics (UEBA)
# Learns normal behavior patterns and detects anomalies
# =============================================================================

import os
import json
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import statistics

ROOT = os.path.dirname(os.path.abspath(__file__))


class UEBAEngine:
    """User & Entity Behavior Analytics - detects deviation from baselines."""

    def __init__(self):
        self.user_profiles = {}  # user_id → behavior profile
        self.baseline_window = 30  # Days to build baseline
        self.anomaly_threshold = 2.5  # Standard deviations
        
        self.profile_path = os.path.join(ROOT, "data", "user_profiles.jsonl")
        self.anomalies_path = os.path.join(ROOT, "data", "anomalies.jsonl")
        
        os.makedirs(os.path.join(ROOT, "data"), exist_ok=True)
        self._load_profiles()

    def _load_profiles(self):
        """Load user behavior profiles."""
        if os.path.exists(self.profile_path):
            try:
                with open(self.profile_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.strip():
                            profile = json.loads(line)
                            user_id = profile.get('user_id')
                            if user_id:
                                self.user_profiles[user_id] = profile
            except:
                pass

    def learn_user_behavior(self, events):
        """
        Learn user baseline from historical events.
        
        Event format:
        {
            "user_id": "john@company.com",
            "timestamp": "2026-03-15T14:30:00",
            "event_type": "file_access|logon|email|usb|process",
            "resource": "path/filename",
            "source_ip": "192.168.1.100",
            "time_of_day": 14,
            ...
        }
        """
        
        users_data = defaultdict(lambda: {
            'logins': [],
            'logoffs': [],
            'file_accesses': [],
            'process_launches': [],
            'usb_accesses': [],
            'emails_sent': [],
            'ips': [],
            'hours_active': [],
            'days_active': [],
            'locations': [],
            'files_accessed': []
        })
        
        # Aggregate events by user
        for event in events:
            user_id = event.get('user_id')
            if not user_id:
                continue
            
            event_type = event.get('type', '').lower()
            timestamp_str = event.get('timestamp', '')
            
            # Parse timestamp
            try:
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            except:
                continue
            
            user_data = users_data[user_id]
            
            # Track activity by type
            if 'logon' in event_type or 'login' in event_type:
                user_data['logins'].append(dt)
                user_data['hours_active'].append(dt.hour)
            
            elif 'logoff' in event_type:
                user_data['logoffs'].append(dt)
            
            elif 'file' in event_type:
                user_data['file_accesses'].append(dt)
                user_data['hours_active'].append(dt.hour)
                resource = event.get('resource', event.get('path', ''))
                if resource:
                    user_data['files_accessed'].append(resource)
            
            elif 'process' in event_type:
                user_data['process_launches'].append(dt)
                user_data['hours_active'].append(dt.hour)
            
            elif 'email' in event_type:
                user_data['emails_sent'].append(dt)
            
            elif 'usb' in event_type:
                user_data['usb_accesses'].append(dt)
            
            # Track source IP
            ip = event.get('source_ip', event.get('ip'))
            if ip:
                user_data['ips'].append(ip)
            
            # Track day of week
            user_data['days_active'].append(dt.weekday())
        
        # Build profiles from aggregated data
        for user_id, data in users_data.items():
            profile = self._create_profile(user_id, data)
            self.user_profiles[user_id] = profile
            
            # Persist
            with open(self.profile_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(profile) + '\n')
        
        print(f"✅ UEBA baseline learned for {len(users_data)} users")
        return len(users_data)

    def _create_profile(self, user_id, data):
        """Create baseline profile for a user."""
        
        def safe_mean(values):
            return statistics.mean(values) if values else 0
        
        def safe_stdev(values):
            return statistics.stdev(values) if len(values) > 1 else 0
        
        profile = {
            'user_id': user_id,
            'profile_updated': datetime.now().isoformat(),
            'login_frequency': {
                'mean': safe_mean([len(data['logins'])]),  # logins per profile period
                'stdev': 0
            },
            'active_hours': {
                'mean': safe_mean(data['hours_active']) if data['hours_active'] else 9,
                'stdev': safe_stdev(data['hours_active']),
                'normal_hours': (6, 22)  # 6 AM to 10 PM
            },
            'active_days': {
                'weekdays': Counter(data['days_active']).most_common(5),
                'unusual_days': [d for d in range(7) if d not in data['days_active']]
            },
            'favorite_files': Counter(data['files_accessed']).most_common(20),
            'favorite_ips': Counter(data['ips']).most_common(5),
            'file_access_frequency': {
                'mean': safe_mean([len(data['file_accesses'])]),
                'stdev': 0
            },
            'process_launch_frequency': {
                'mean': safe_mean([len(data['process_launches'])]),
                'stdev': 0
            },
            'email_frequency': {
                'mean': safe_mean([len(data['emails_sent'])]),
                'stdev': 0
            },
            'usb_access_count': len(data['usb_accesses']),
            'anomalies_detected': []
        }
        
        return profile

    def detect_anomaly(self, event):
        """
        Detect if event is anomalous for user.
        
        Returns:
        {
            "is_anomaly": bool,
            "severity": "LOW|MEDIUM|HIGH|CRITICAL",
            "reasons": ["reason1", "reason2"],
            "deviation_score": 0.0-1.0
        }
        """
        
        user_id = event.get('user_id')
        if not user_id or user_id not in self.user_profiles:
            return {'is_anomaly': False, 'severity': 'LOW', 'reasons': ['No baseline']}
        
        profile = self.user_profiles[user_id]
        reasons = []
        deviation_scores = []
        
        # Parse timestamp
        try:
            dt = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00')) if 'timestamp' in event else datetime.now()
        except:
            dt = datetime.now()
        
        # 1. Check hour of day anomaly
        event_hour = dt.hour
        profile_mean_hour = profile['active_hours']['mean']
        profile_stdev_hour = profile['active_hours'].get('stdev', 2)
        
        if profile_stdev_hour == 0:
            profile_stdev_hour = 2
        
        hour_deviation = abs(event_hour - profile_mean_hour) / max(profile_stdev_hour, 1)
        if hour_deviation > self.anomaly_threshold:
            reasons.append(f"Activity at unusual hour ({event_hour}:00, baseline: {profile_mean_hour:.0f}:00)")
            deviation_scores.append(min(hour_deviation / 5, 1.0))  # Normalize
        
        # 2. Check day of week anomaly
        event_day = dt.weekday()
        unusual_days = profile['active_days'].get('unusual_days', [])
        if event_day in unusual_days:
            reasons.append(f"Activity on unusual day ({['Mon','Tue','Wed','Thu','Fri','Sat','Sun'][event_day]})")
            deviation_scores.append(0.6)
        
        # 3. Check if after-hours + high activity chain
        is_after_hours = event_hour < 6 or event_hour > 22
        if is_after_hours:
            reasons.append(f"After-hours activity ({event_hour}:00)")
            deviation_scores.append(0.5)
        
        # 4. Check for unusual file access
        if event.get('type', '').lower() in ['file_access', 'file_operation']:
            resource = event.get('resource', event.get('path', ''))
            favorite_files = [f[0] for f in profile.get('favorite_files', [])]
            
            if resource and resource not in favorite_files:
                # Check if accessing sensitive paths
                sensitive_paths = ['c:\\windows', 'c:\\program files', '/etc', '/root', '/var/log']
                if any(sensitive in resource.lower() for sensitive in sensitive_paths):
                    reasons.append(f"Accessing sensitive path: {resource[:50]}")
                    deviation_scores.append(0.7)
        
        # 5. Check for unusual source IP
        source_ip = event.get('source_ip', event.get('ip'))
        if source_ip:
            favorite_ips = [ip[0] for ip in profile.get('favorite_ips', [])]
            if source_ip not in favorite_ips and favorite_ips:
                reasons.append(f"Login from unusual IP: {source_ip}")
                deviation_scores.append(0.6)
        
        # Calculate overall deviation score
        deviation_score = sum(deviation_scores) / len(deviation_scores) if deviation_scores else 0
        
        # Determine if anomaly
        is_anomaly = len(reasons) >= 2 or (len(reasons) == 1 and deviation_score > 0.7)
        
        # Determine severity
        if is_anomaly:
            if deviation_score > 0.9:
                severity = "CRITICAL"
            elif deviation_score > 0.7:
                severity = "HIGH"
            elif deviation_score > 0.5:
                severity = "MEDIUM"
            else:
                severity = "LOW"
        else:
            severity = "LOW"
        
        # Log anomaly
        if is_anomaly:
            anomaly_log = {
                "timestamp": datetime.now().isoformat(),
                "user_id": user_id,
                "event_type": event.get('type'),
                "severity": severity,
                "reasons": reasons,
                "deviation_score": round(deviation_score, 3)
            }
            
            with open(self.anomalies_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(anomaly_log) + '\n')
        
        return {
            "is_anomaly": is_anomaly,
            "severity": severity,
            "reasons": reasons,
            "deviation_score": round(deviation_score, 3),
            "user_baseline": {
                "typical_activity_hours": f"{int(profile_mean_hour)}:00 ± 2h",
                "favorite_ips": [ip[0] for ip in profile.get('favorite_ips', [])[:3]],
                "typical_workdays": [['Mon','Tue','Wed','Thu','Fri','Sat','Sun'][d] for d, _ in profile.get('active_days', {}).get('weekdays', [])]
            }
        }

    def get_user_profile(self, user_id):
        """Get behavior profile for user."""
        return self.user_profiles.get(user_id)

    def get_all_anomalies(self, limit=100):
        """Get recent anomalies."""
        try:
            anomalies = []
            if os.path.exists(self.anomalies_path):
                with open(self.anomalies_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    for line in lines[-limit:]:
                        if line.strip():
                            anomalies.append(json.loads(line))
            return anomalies
        except:
            return []
