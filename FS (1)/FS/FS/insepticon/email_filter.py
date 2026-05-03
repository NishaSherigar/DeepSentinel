# =============================================================================
# DeepSentinel — email_filter.py
# ML-based email classification with 3 risk tiers using NLP
# - LOW RISK: Normal emails → Auto-allowed
# - MEDIUM RISK: Suspicious patterns → Send to admin for review
# - HIGH RISK: Malicious indicators → Block immediately
#
# ADD to server.py before if __name__ == '__main__':
#   from email_filter import EmailFilter
#   email_filter = EmailFilter()
# =============================================================================

import os
import json
import re
from datetime import datetime
from collections import Counter

# Try to import ML libraries, gracefully degrade if not available
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import RandomForestClassifier
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

try:
    import nltk
    from nltk.tokenize import word_tokenize
    from nltk.corpus import stopwords
    NLTK_AVAILABLE = True
    # Try to download required NLTK data
    try:
        nltk.data.find('tokenizers/punkt')
    except LookupError:
        nltk.download('punkt', quiet=True)
    try:
        nltk.data.find('corpora/stopwords')
    except LookupError:
        nltk.download('stopwords', quiet=True)
except ImportError:
    NLTK_AVAILABLE = False

ROOT = os.path.dirname(os.path.abspath(__file__))


class EmailFilter:
    """ML-powered email classification and risk assessment."""

    def __init__(self):
        self.pending_approval = {}  # email_id → email_data for admin review
        self.email_history = []
        self.model = None
        self.vectorizer = None
        self.risk_rules = self._init_risk_rules()
        # Keep medium-band aligned with the ML version in `email_filter_ml.py`
        # and with the dashboard's common "medium" risk feel.
        self.approval_threshold = 0.45  # Between LOW and MEDIUM
        self.block_threshold = 0.75    # Between MEDIUM and HIGH
        
        # File paths
        self.pending_path = os.path.join(ROOT, "data", "pending_emails.jsonl")
        self.history_path = os.path.join(ROOT, "data", "email_history.jsonl")
        
        os.makedirs(os.path.join(ROOT, "data"), exist_ok=True)
        self._load_history()
        self._load_pending()

    def _load_pending(self):
        """Restore pending approvals after server restart."""
        if not os.path.exists(self.pending_path):
            return
        try:
            with open(self.pending_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    eid = obj.get("email_id")
                    if eid and obj.get("status") == "pending":
                        self.pending_approval[eid] = obj
        except Exception:
            pass

    def _init_risk_rules(self):
        """High-risk keywords and patterns."""
        return {
            "malware_keywords": [
                "ransomware", "trojan", "exploit", "payload", "backdoor",
                "credential", "bank", "urgent action required", "verify account",
                "confirm identity", "click immediately", "act now"
            ],
            "phishing_keywords": [
                "click here", "update payment", "verify credentials",
                "suspicious activity", "unusual sign-in", "confirm password",
                "banking details", "social security", "credit card"
            ],
            "suspicious_tlds": [
                ".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".loan",
                ".ru", ".cn" # high-risk TLDs for phishing
            ],
            "zero_day_indicators": [
                "zero-day", "0-day", "vuln", "exploit", "rce",
                "remote code execution", "privilege escalation"
            ],
            "data_exfiltration": [
                "export", "download", "send", "transfer", "backup",
                "compress", "zip", "password", "decrypt", "encryption key"
            ]
        }

    def _load_history(self):
        """Load historical email classifications."""
        if os.path.exists(self.history_path):
            try:
                with open(self.history_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.strip():
                            self.email_history.append(json.loads(line))
            except:
                pass

    def _save_email_record(self, email_data, risk_score, classification, reasons):
        """Save email classification result."""
        record = {
            "timestamp": datetime.now().isoformat(),
            "email_id": email_data.get('email_id'),
            "sender": email_data.get('sender', ''),
            "recipient": email_data.get('recipient', ''),
            "subject": email_data.get('subject', '')[:100],
            "risk_score": risk_score,
            "classification": classification,
            "reasons": reasons[:3],  # Top 3 reasons
            "processed": False
        }
        
        # Save to history
        with open(self.history_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(record) + '\n')
        
        self.email_history.append(record)
        return record

    def _extract_features(self, email_data):
        """Extract risk indicators from email."""
        features = {
            "keyword_matches": [],
            "sender_reputation": 1.0,
            "url_count": 0,
            "attachment_count": 0,
            "urgency_score": 0.0,
            "spoofing_score": 0.0
        }

        subject = email_data.get('subject', '').lower()
        body = email_data.get('body', '').lower()
        sender = email_data.get('sender', '').lower()
        text = f"{subject} {body}"

        # 1. Check for high-risk keywords
        for category, keywords in self.risk_rules.items():
            for keyword in keywords:
                if keyword.lower() in text:
                    features["keyword_matches"].append(keyword)

        # 2. URL analysis
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
        features["url_count"] = len(urls)
        
        # Check for suspicious TLDs in URLs
        for url in urls:
            for bad_tld in self.risk_rules["suspicious_tlds"]:
                if bad_tld in url:
                    features["keyword_matches"].append(f"Suspicious TLD: {bad_tld}")

        # 3. Attachment analysis
        attachments = email_data.get('attachments', [])
        features["attachment_count"] = len(attachments)
        suspicious_exts = ['.exe', '.bat', '.cmd', '.scr', '.vbs', '.js']
        for att in attachments:
            if any(att.lower().endswith(ext) for ext in suspicious_exts):
                features["keyword_matches"].append(f"Suspicious attachment: {att}")

        # 4. Urgency indicators (phishing tactic)
        urgency_words = ["urgent", "immediately", "act now", "confirm", "verify", "update"]
        for word in urgency_words:
            if word in subject:
                features["urgency_score"] += 0.1

        # 5. Sender spoofing check
        if sender:
            # Check if sender domain matches recipient domain (internal email)
            recipient = email_data.get('recipient', '').lower()
            sender_domain = sender.split('@')[-1] if '@' in sender else ''
            recipient_domain = recipient.split('@')[-1] if '@' in recipient else ''
            
            if sender_domain != recipient_domain and sender_domain:
                features["spoofing_score"] = 0.3  # External email - slight risk

        features["urgency_score"] = min(features["urgency_score"], 1.0)
        return features

    def classify_email(self, email_data):
        """
        Classify email as LOW, MEDIUM, or HIGH risk.
        
        Returns:
            {
                "classification": "LOW|MEDIUM|HIGH",
                "risk_score": 0.0-1.0,
                "reasons": ["reason1", "reason2", ...],
                "action": "allow|approve|block"
            }
        """
        features = self._extract_features(email_data)
        
        # Calculate risk score (0.0 to 1.0)
        risk_score = 0.0
        reasons = []
        
        # Weight different risk factors
        keyword_count = len(features["keyword_matches"])
        if keyword_count > 0:
            risk_score += min(keyword_count * 0.15, 0.4)
            reasons.append(f"Found {keyword_count} suspicious keywords: {', '.join(features['keyword_matches'][:2])}")
        
        if features["url_count"] > 0:
            risk_score += min(features["url_count"] * 0.05, 0.15)
            if features["url_count"] > 5:
                reasons.append(f"{features['url_count']} URLs detected (typical of spam)")
        
        if features["attachment_count"] > 0:
            risk_score += features["attachment_count"] * 0.1
            reasons.append(f"{features['attachment_count']} attachment(s)")
        
        if features["urgency_score"] > 0.2:
            risk_score += features["urgency_score"] * 0.2
            reasons.append("High urgency language detected (phishing tactic)")
        
        if features["spoofing_score"] > 0.2:
            risk_score += features["spoofing_score"] * 0.25
            reasons.append("External sender (potential spoofing)")
        
        risk_score = min(risk_score, 1.0)
        
        # Classify based on thresholds
        if risk_score >= self.block_threshold:
            classification = "HIGH"
            action = "block"
        elif risk_score >= self.approval_threshold:
            classification = "MEDIUM"
            action = "approve"
        else:
            classification = "LOW"
            action = "allow"
        
        # Save record
        record = self._save_email_record(email_data, risk_score, classification, reasons)
        
        return {
            "email_id": email_data.get('email_id'),
            "classification": classification,
            "risk_score": round(risk_score, 3),
            "reasons": reasons,
            "action": action,
            "timestamp": record["timestamp"]
        }

    def queue_for_approval(self, email_data, classification):
        """Queue email for admin approval."""
        email_id = email_data.get('email_id', f"email_{datetime.now().timestamp()}")
        self.pending_approval[email_id] = {
            "email_id": email_id,
            "data": email_data,
            "classification": classification,
            "queued_at": datetime.now().isoformat(),
            "status": "pending",
            "admin_decision": None
        }
        self._save_pending()
        return email_id

    def approve_email(self, email_id):
        """Admin approves email to be sent."""
        if email_id in self.pending_approval:
            self.pending_approval[email_id]["status"] = "approved"
            self.pending_approval[email_id]["admin_decision"] = "approved"
            self._save_pending()
            return True
        return False

    def reject_email(self, email_id, reason=""):
        """Admin rejects email (blocks sending)."""
        if email_id in self.pending_approval:
            self.pending_approval[email_id]["status"] = "rejected"
            self.pending_approval[email_id]["admin_decision"] = "rejected"
            self.pending_approval[email_id]["rejection_reason"] = reason
            self._save_pending()
            return True
        return False

    def _save_pending(self):
        """Save pending approvals to file."""
        with open(self.pending_path, 'w', encoding='utf-8') as f:
            for email_id, email in self.pending_approval.items():
                f.write(json.dumps(email) + '\n')

    def get_pending_approvals(self):
        """Get all emails pending admin review."""
        return [email for email in self.pending_approval.values() 
                if email["status"] == "pending"]

    def get_pending_record(self, email_id: str):
        """Return the full pending record (pending/approved/rejected)."""
        return self.pending_approval.get(email_id)

    def get_approval_stats(self):
        """Get statistics on email filtering."""
        total = len(self.email_history)
        if not total:
            return {"total": 0, "low": 0, "medium": 0, "high": 0, "blocked": 0}
        
        low = sum(1 for e in self.email_history if e.get("classification") == "LOW")
        medium = sum(1 for e in self.email_history if e.get("classification") == "MEDIUM")
        high = sum(1 for e in self.email_history if e.get("classification") == "HIGH")
        
        return {
            "total": total,
            "low": low,
            "medium": medium,
            "high": high,
            "blocked": high,
            "pending_approval": len(self.get_pending_approvals())
        }
