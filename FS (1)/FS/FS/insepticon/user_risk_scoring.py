# =============================================================================
# DeepSentinel — user_risk_scoring.py
# User Risk Scoring System
# Calculates composite risk scores from all threat signals
# =============================================================================

import os
import json
from datetime import datetime, timedelta
from collections import defaultdict

ROOT = os.path.dirname(os.path.abspath(__file__))


class UserRiskScorer:
    """Calculates user risk scores from multiple signals"""
    
    # Weights for different risk factors (sum to 100)
    WEIGHTS = {
        'email_risk': 0.20,          # Email-based threats
        'behavioral_deviation': 0.25, # Activity anomalies
        'peer_anomaly': 0.20,         # Compared to peer group
        'threat_activity': 0.20,      # Honeypots, sensitive access
        'login_risk': 0.15             # Failed logins, unusual times
    }
    
    def __init__(self):
        self.user_scores_path = os.path.join(ROOT, "data", "user_risk_scores.jsonl")
        self.user_scores = {}
        self._load_user_scores()
    
    def _load_user_scores(self):
        """Load previously calculated risk scores"""
        if os.path.exists(self.user_scores_path):
            try:
                with open(self.user_scores_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.strip():
                            try:
                                data = json.loads(line)
                                self.user_scores[data['user_id']] = data
                            except:
                                pass
            except:
                pass
    
    def calculate_user_risk(self, user_id, user_data, email_module=None, ueba_module=None, 
                            peer_module=None, threat_module=None):
        """
        Calculate composite risk score for user
        Returns: {
            'user_id': str,
            'user_name': str,
            'risk_score': float (0.0-1.0),
            'risk_percentage': int (0-100),
            'risk_level': str ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'),
            'factors': {...},
            'timestamp': str,
            'trend': float (7-day trend)
        }
        """
        
        # Get component scores (0.0-1.0)
        email_risk = self._get_email_risk(user_id, email_module)
        behavioral_risk = self._get_behavioral_risk(user_id, ueba_module)
        peer_risk = self._get_peer_risk(user_id, peer_module)
        threat_risk = self._get_threat_risk(user_id, threat_module)
        login_risk = self._get_login_risk(user_id, user_data)
        
        # Composite score (weighted average, 0.0-1.0)
        composite_score = (
            email_risk * self.WEIGHTS['email_risk'] +
            behavioral_risk * self.WEIGHTS['behavioral_deviation'] +
            peer_risk * self.WEIGHTS['peer_anomaly'] +
            threat_risk * self.WEIGHTS['threat_activity'] +
            login_risk * self.WEIGHTS['login_risk']
        )
        
        # Clip to 0-1 range
        composite_score = min(1.0, max(0.0, composite_score))
        
        # Calculate trend (7-day comparison)
        trend = self._calculate_trend(user_id)
        
        # Determine risk level
        if composite_score >= 0.80:
            risk_level = 'CRITICAL'
        elif composite_score >= 0.60:
            risk_level = 'HIGH'
        elif composite_score >= 0.40:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        score_entry = {
            'user_id': user_id,
            'user_name': user_data.get('user_name', user_id),
            'risk_score': round(composite_score, 3),
            'risk_percentage': int(composite_score * 100),
            'risk_level': risk_level,
            'factors': {
                'email_risk': round(email_risk, 3),
                'behavioral_deviation': round(behavioral_risk, 3),
                'peer_anomaly': round(peer_risk, 3),
                'threat_activity': round(threat_risk, 3),
                'login_risk': round(login_risk, 3)
            },
            'timestamp': datetime.now().isoformat(),
            'trend': round(trend, 3)  # +X% increase, -X% decrease over 7 days
        }
        
        # Persist
        self.user_scores[user_id] = score_entry
        try:
            with open(self.user_scores_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(score_entry) + '\n')
        except:
            pass
        
        return score_entry
    
    def _get_email_risk(self, user_id, email_module=None):
        """Risk from email threats (phishing, malware, suspicious attachments)"""
        if not email_module:
            return 0.0
        
        try:
            # Get user's email history
            risky_emails = getattr(email_module, 'get_user_risky_emails', lambda x: [])(user_id)
            
            if not risky_emails:
                return 0.0
            
            # HIGH confidence malicious = 1.0, MEDIUM = 0.5, LOW = 0.2
            high_count = sum(1 for e in risky_emails if e.get('confidence', 0) > 0.8)
            med_count = sum(1 for e in risky_emails if 0.5 <= e.get('confidence', 0) <= 0.8)
            
            risk = (high_count * 1.0 + med_count * 0.5) / max(1, len(risky_emails))
        except:
            risk = 0.0
        
        return min(1.0, risk)
    
    def _get_behavioral_risk(self, user_id, ueba_module=None):
        """Risk from behavioral deviations from baseline"""
        if not ueba_module:
            return 0.0
        
        try:
            # Get user's UEBA anomaly score
            profile = getattr(ueba_module, 'get_user_profile', lambda x: {})(user_id)
            anomalies = getattr(ueba_module, 'get_user_anomalies', lambda x: [])(user_id)
            
            if not anomalies:
                return 0.0
            
            # Count anomalies: each is 0-1 score
            if anomalies:
                risk = sum(a.get('anomaly_score', 0.5) for a in anomalies) / len(anomalies)
            else:
                risk = 0.0
        except:
            risk = 0.0
        
        return min(1.0, risk)
    
    def _get_peer_risk(self, user_id, peer_module=None):
        """Risk from anomalies compared to peer group"""
        if not peer_module:
            return 0.0
        
        try:
            # Get peer analysis results
            anomalies = getattr(peer_module, 'get_user_anomalies', lambda x: [])(user_id)
            
            if not anomalies:
                return 0.0
            
            # Peer anomalies (user is only one accessing resource, etc)
            risk = sum(a.get('risk_score', 0.5) for a in anomalies) / len(anomalies)
        except:
            risk = 0.0
        
        return min(1.0, risk)
    
    def _get_threat_risk(self, user_id, threat_module=None):
        """Risk from honeypot triggers and sensitive access"""
        if not threat_module:
            return 0.0
        
        try:
            # Check honeypot activity
            honeypot_triggers = getattr(threat_module, 'get_user_trap_triggers', lambda x: [])(user_id)
            
            # Honeypot trigger = high confidence threat
            if honeypot_triggers:
                risk = min(1.0, len(honeypot_triggers) * 0.3)  # Each trap trigger adds 0.3
            else:
                risk = 0.0
        except:
            risk = 0.0
        
        return min(1.0, risk)
    
    def _get_login_risk(self, user_id, user_data):
        """Risk from failed logins and unusual login patterns"""
        # Get failed login count (from last 24 hours)
        failed_logins = user_data.get('failed_logins_24h', 0)
        
        # Each failed login adds risk
        login_risk = min(1.0, failed_logins * 0.1)  # 10 failed logins = 1.0 risk
        
        return login_risk
    
    def _calculate_trend(self, user_id):
        """Calculate 7-day trend (% change in risk)"""
        now = datetime.now()
        week_ago = now - timedelta(days=7)
        
        # Find scores for this user
        current_score = None
        old_score = None
        
        for score in self.user_scores.values() if isinstance(self.user_scores, dict) else []:
            if isinstance(score, dict) and score.get('user_id') == user_id:
                timestamp = datetime.fromisoformat(score.get('timestamp', '').replace('Z', '+00:00'))
                
                if timestamp > week_ago:
                    if current_score is None:
                        current_score = score['risk_score']
                if timestamp < week_ago:
                    old_score = score['risk_score']
        
        # Check file-based history
        if self.user_scores and isinstance(self.user_scores.get(user_id), dict):
            current_score = self.user_scores[user_id].get('risk_score', 0.0)
        
        if current_score is not None and old_score is not None:
            trend = ((current_score - old_score) / old_score) * 100 if old_score > 0 else 0
        else:
            trend = 0.0
        
        return trend
    
    def get_risk_leaderboard(self, limit=20, risk_level=None):
        """Get top N users by risk score"""
        scores = list(self.user_scores.values()) if self.user_scores else []
        
        # Filter by risk level if specified
        if risk_level:
            scores = [s for s in scores if s.get('risk_level') == risk_level]
        
        # Sort by risk score descending
        scores.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
        
        return scores[:limit]
    
    def get_high_risk_threshold_users(self, threshold=0.6):
        """Get users above risk threshold"""
        scores = list(self.user_scores.values()) if self.user_scores else []
        return [s for s in scores if s.get('risk_score', 0) >= threshold]
    
    def get_user_risk(self, user_id):
        """Get current risk score for user"""
        return self.user_scores.get(user_id, None)
    
    def get_risk_distribution(self):
        """Get distribution of users by risk level"""
        scores = list(self.user_scores.values()) if self.user_scores else []
        
        distribution = {
            'CRITICAL': len([s for s in scores if s.get('risk_level') == 'CRITICAL']),
            'HIGH': len([s for s in scores if s.get('risk_level') == 'HIGH']),
            'MEDIUM': len([s for s in scores if s.get('risk_level') == 'MEDIUM']),
            'LOW': len([s for s in scores if s.get('risk_level') == 'LOW'])
        }
        
        return distribution
