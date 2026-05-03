# =============================================================================
# DeepSentinel — peer_analysis.py
# Peer Group Anomaly Detection
# Flags unusual file access compared to similar users
# =============================================================================

import os
import json
from datetime import datetime
from collections import defaultdict, Counter
import statistics

ROOT = os.path.dirname(os.path.abspath(__file__))


class PeerGroupAnalyzer:
    """Detects behavior anomalies relative to peer group."""

    def __init__(self):
        self.user_groups = {}  # department → users
        self.resource_access_matrix = defaultdict(lambda: defaultdict(int))  # user → resource → count
        self.peer_violations_path = os.path.join(ROOT, "data", "peer_violations.jsonl")
        
        os.makedirs(os.path.join(ROOT, "data"), exist_ok=True)
        self._load_groups()

    def _load_groups(self):
        """Load user groupings from config."""
        groups_path = os.path.join(ROOT, "config", "user_groups.json")
        if os.path.exists(groups_path):
            try:
                with open(groups_path, 'r') as f:
                    self.user_groups = json.load(f)
            except:
                self._create_default_groups()
        else:
            self._create_default_groups()

    def _create_default_groups(self):
        """Create default user groups by department."""
        self.user_groups = {
            "IT": ["admin@company.com", "it_user1@company.com", "it_user2@company.com"],
            "Finance": ["finance1@company.com", "finance2@company.com", "finance3@company.com"],
            "HR": ["hr@company.com", "hr_manager@company.com"],
            "Engineering": ["engineer1@company.com", "engineer2@company.com", "engineer3@company.com"],
            "Marketing": ["marketing1@company.com", "marketing2@company.com"],
            "Sales": ["sales1@company.com", "sales2@company.com", "sales3@company.com"]
        }

    def build_access_matrix(self, events):
        """
        Build resource access patterns for all users.
        
        Event format:
        {
            "user_id": "john@company.com",
            "type": "file_access",
            "resource": "C:\\Finance\\2025_Budget.xlsx",
            "department": "Sales"
        }
        """
        
        for event in events:
            user_id = event.get('user_id')
            resource = event.get('resource', event.get('path', ''))
            
            if user_id and resource:
                self.resource_access_matrix[user_id][resource] += 1
        
        print(f"✅ Built access matrix for {len(self.resource_access_matrix)} users")
        return len(self.resource_access_matrix)

    def _get_user_department(self, user_id):
        """Get department for user."""
        for dept, users in self.user_groups.items():
            if user_id in users:
                return dept
        return None

    def _get_peer_group(self, user_id):
        """Get peer group for user."""
        dept = self._get_user_department(user_id)
        if not dept:
            return []
        return self.user_groups.get(dept, [])

    def _standardize_path(self, path):
        """Standardize path for comparison."""
        if not path:
            return ""
        return path.lower().split('\\')[-1].split('/')[-1]  # Just filename

    def check_peer_anomaly(self, user_id, resource, access_type="read"):
        """
        Check if user's resource access is anomalous compared to peers.
        
        Returns:
        {
            "is_anomaly": bool,
            "severity": "LOW|MEDIUM|HIGH|CRITICAL",
            "reason": "description",
            "peer_access_percentage": 0-100,
            "peer_count": N,
            "unusual_access": ["reason1", "reason2"]
        }
        """
        
        peers = self._get_peer_group(user_id)
        if not peers:
            return {'is_anomaly': False, 'severity': 'LOW', 'reason': 'No peer group'}
        
        # Count how many peers accessed this resource
        peers_with_access = sum(1 for peer in peers if resource in self.resource_access_matrix.get(peer, {}))
        peer_percentage = (peers_with_access / len(peers)) * 100 if peers else 0
        
        unusual_access = []
        severity = "LOW"
        
        # Flag if user is alone in accessing resource
        if peers_with_access == 0:
            unusual_access.append(f"Only user in peer group accessing: {self._standardize_path(resource)}")
            severity = "HIGH"
        elif peer_percentage < 10:
            unusual_access.append(f"Only {peers_with_access} of {len(peers)} peers access {self._standardize_path(resource)}")
            severity = "MEDIUM"
        
        # Check for sensitive resources
        sensitive_keywords = ['payroll', 'salary', 'ssn', 'personal', 'medical', 'credentials',
                            'passwords', 'private', 'confidential', 'trade secret', 'financial']
        respath_lower = resource.lower()
        
        if any(keyword in respath_lower for keyword in sensitive_keywords):
            # Marketing person accessing payroll would be critical
            if access_type.lower() == "read" and peer_percentage < 25:
                unusual_access.append(f"Accessing sensitive resource: {self._standardize_path(resource)}")
                if severity == "LOW":
                    severity = "HIGH"
                else:
                    severity = "CRITICAL"
        
        # Check for large data transfers/downloads
        if 'download' in access_type.lower() or 'export' in access_type.lower():
            if peer_percentage < 50:
                unusual_access.append(f"Downloading data less common in peer group")
                severity = "MEDIUM" if severity == "LOW" else severity
        
        is_anomaly = len(unusual_access) > 0
        
        # Log violation
        if is_anomaly:
            violation = {
                "timestamp": datetime.now().isoformat(),
                "user_id": user_id,
                "resource": resource,
                "access_type": access_type,
                "severity": severity,
                "reasons": unusual_access,
                "peer_access_percentage": round(peer_percentage, 1),
                "peer_count_with_access": peers_with_access,
                "total_peers": len(peers)
            }
            
            with open(self.peer_violations_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(violation) + '\n')
        
        return {
            "is_anomaly": is_anomaly,
            "severity": severity,
            "reason": unusual_access[0] if unusual_access else "Normal access pattern",
            "peer_access_percentage": round(peer_percentage, 1),
            "peer_count_with_access": peers_with_access,
            "total_peers": len(peers),
            "unusual_access": unusual_access
        }

    def get_group_file_access_summary(self, department):
        """Get file access summary for department."""
        if department not in self.user_groups:
            return {}
        
        users_in_dept = self.user_groups[department]
        file_access_summary = Counter()
        
        for user in users_in_dept:
            for resource, count in self.resource_access_matrix.get(user, {}).items():
                file_access_summary[resource] += count
        
        # Group by category
        sensitive_files = [f for f in file_access_summary if any(
            keyword in f.lower() for keyword in ['payroll', 'salary', 'budget', 'financial']
        )]
        
        return {
            "department": department,
            "user_count": len(users_in_dept),
            "total_files_accessed": len(file_access_summary),
            "most_accessed": file_access_summary.most_common(10),
            "sensitive_files_accessed": sensitive_files,
            "file_frequency_stats": {
                "median_accesses": statistics.median(file_access_summary.values()) if file_access_summary else 0,
                "max_accesses": max(file_access_summary.values()) if file_access_summary else 0
            }
        }

    def flag_data_exfiltration_risk(self, user_id, files_accessed, total_size_mb=None):
        """
        Flag potential data exfiltration based on unusual volume.
        
        Returns risk assessment.
        """
        
        peers = self._get_peer_group(user_id)
        
        if not peers:
            return {'risk': 'LOW', 'reason': 'No peer baseline'}
        
        # Count typical files accessed by peers
        typical_file_count = []
        for peer in peers:
            typical_file_count.append(len(self.resource_access_matrix.get(peer, {})))
        
        median_file_count = statistics.median(typical_file_count) if typical_file_count else 0
        user_file_count = len(files_accessed)
        
        # Check if accessing significantly more files
        if median_file_count > 0:
            ratio = user_file_count / median_file_count
        else:
            ratio = 1.0
        
        reasons = []
        risk = "LOW"
        
        if ratio > 3:
            reasons.append(f"Accessing {ratio:.1f}x more files than typical peer ({int(median_file_count)} vs {user_file_count})")
            risk = "CRITICAL"
        elif ratio > 1.5:
            reasons.append(f"Accessing {ratio:.1f}x more files than typical peer")
            risk = "HIGH"
        
        if total_size_mb and total_size_mb > 1000:
            reasons.append(f"Large volume download: {total_size_mb:.0f} MB")
            risk = "CRITICAL" if risk == "HIGH" else "HIGH"
        
        return {
            "user_id": user_id,
            "risk": risk,
            "file_count": user_file_count,
            "peer_median_file_count": int(median_file_count),
            "access_ratio": round(ratio, 2),
            "reasons": reasons
        }

    def get_recent_violations(self, limit=50, severity=None):
        """Get recent peer group violations."""
        try:
            violations = []
            if os.path.exists(self.peer_violations_path):
                with open(self.peer_violations_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    for line in lines[-limit:]:
                        if line.strip():
                            v = json.loads(line)
                            if severity is None or v.get('severity') == severity:
                                violations.append(v)
            return list(reversed(violations))
        except:
            return []
