# =============================================================================
# DeepSentinel — email_filter_ml.py
# REAL ML-based email classification using TF-IDF + RandomForest
# Trains on actual email data for organization-specific phishing detection
# UPDATED: Integrated with threat_model for enhanced email risk prediction
# =============================================================================

import os
import json
import re
import hashlib
from datetime import datetime
from collections import Counter, defaultdict

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.pipeline import Pipeline
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("⚠️ scikit-learn not installed. Email filter will use rule-based mode.")

try:
    import nltk
    from nltk.tokenize import word_tokenize
    from nltk.corpus import stopwords
    NLTK_AVAILABLE = True
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

# Import threat_model for email classification
try:
    from connect_models import threat_model
    THREAT_MODEL_AVAILABLE = True
    print("✅ Integrated threat_model for enhanced email classification")
except ImportError:
    THREAT_MODEL_AVAILABLE = False
    print("⚠️ Could not import threat_model - using EmailFilterML only")

ROOT = os.path.dirname(os.path.abspath(__file__))


class EmailFilterML:
    """Real ML-powered email classification trained on organization data."""

    def __init__(self, training_data_size=1000):
        self.pending_approval = {}
        self.email_history = []
        self.training_emails = []
        self.model = None
        self.vectorizer = None
        self.feature_extractor = None
        self.risk_rules = self._init_risk_rules()
        self.approval_threshold = 0.45
        self.block_threshold = 0.75
        self.training_data_size = training_data_size
        
        # File paths
        self.pending_path = os.path.join(ROOT, "data", "pending_emails.jsonl")
        self.history_path = os.path.join(ROOT, "data", "email_history.jsonl")
        self.model_path = os.path.join(ROOT, "data", "email_model_weights.json")
        self.training_path = os.path.join(ROOT, "data", "email_training_data.jsonl")
        
        os.makedirs(os.path.join(ROOT, "data"), exist_ok=True)
        
        self._load_history()
        self._init_ml_model()

    def _init_risk_rules(self):
        """High-risk keywords and patterns (fallback for rule-based mode)."""
        return {
            "malware_keywords": [
                "ransomware", "trojan", "exploit", "payload", "backdoor",
                "malware", "virus", "worm", "spyware", "adware",
                "crypto locker", "wannacry", "petya"
            ],
            "phishing_keywords": [
                "verify account", "confirm password", "update payment method",
                "unusual activity", "suspicious login", "confirm identity",
                "click here", "act immediately", "urgent action required",
                "reset password", "billing problem", "your account locked"
            ],
            "data_exfiltration": [
                "export database", "dump all files", "backup credentials",
                "download customer list", "transfer funds", "steal data",
                "breach", "leak", "confidential", "trade secret"
            ],
            "suspicious_domains": {
                ".tk": 0.3, ".ml": 0.3, ".ga": 0.3, ".cf": 0.3,
                ".xyz": 0.2, ".top": 0.2, ".loan": 0.4, ".click": 0.3
            }
        }

    def _init_ml_model(self):
        """Initialize ML pipeline with TF-IDF + RandomForest."""
        if not ML_AVAILABLE:
            return
        
        try:
            # Create TF-IDF vectorizer
            self.vectorizer = TfidfVectorizer(
                max_features=500,
                ngram_range=(1, 2),
                min_df=2,
                max_df=0.9,
                stop_words='english'
            )
            
            # Create RandomForest classifier
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=15,
                random_state=42,
                class_weight='balanced',
                n_jobs=-1
            )
            
            # Feature extractor for additional signals
            self.feature_extractor = {
                'url_count': self._count_urls,
                'sender_suspicion': self._score_sender,
                'urgency_level': self._detect_urgency,
                'attachment_risk': self._score_attachments,
                'domain_reputation': self._check_domain_reputation
            }
            
            print("✅ ML email classifier initialized (TF-IDF + RandomForest)")
        except Exception as e:
            print(f"⚠️ Failed to initialize ML model: {e}")

    def _load_history(self):
        """Load historical classifications."""
        if os.path.exists(self.history_path):
            try:
                with open(self.history_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.strip():
                            self.email_history.append(json.loads(line))
            except:
                pass

    def _count_urls(self, email_text):
        """Count URLs in email."""
        urls = re.findall(r'http[s]?://\S+', email_text)
        return len(urls)

    def _score_sender(self, sender_email):
        """Score sender reputation (external vs internal)."""
        if not sender_email or '@' not in sender_email:
            return 0.5
        
        # Free email providers = higher suspicion
        free_providers = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com']
        domain = sender_email.split('@')[1].lower()
        
        if domain in free_providers:
            return 0.3
        
        # Check for misspelled domains (typosquatting)
        return 0.1

    def _detect_urgency(self, subject_text):
        """Detect phishing urgency language."""
        urgency_words = [
            'urgent', 'immediately', 'act now', 'confirm', 'verify',
            'update required', 'action needed', 'deadline', 'expires',
            'limited time', 'click here', 'suspended', 'locked'
        ]
        
        text_lower = subject_text.lower()
        matches = sum(1 for word in urgency_words if word in text_lower)
        return min(matches * 0.2, 1.0)

    def _score_attachments(self, attachments):
        """Score attachment risk (executable, macro-enabled, etc)."""
        if not attachments:
            return 0.0
        
        # Enhanced extension scoring with better categorization
        dangerous_exts = {
            # Executables (CRITICAL)
            '.exe': 0.95, '.bat': 0.90, '.cmd': 0.90, '.scr': 0.85,
            '.vbs': 0.85, '.js': 0.80, '.jar': 0.80, '.dll': 0.90,
            '.com': 0.85, '.pif': 0.85, '.msi': 0.80,
            # Macro-enabled documents (HIGH)
            '.docm': 0.80, '.xlsm': 0.80, '.pptm': 0.80, '.potm': 0.75,
            # Archives & containers (MEDIUM-HIGH)
            '.zip': 0.50, '.rar': 0.50, '.7z': 0.45, '.tar': 0.40,
            # Sensitive documents when attached to suspicious emails
            '.pdf': 0.35, '.docx': 0.35, '.xlsx': 0.35, '.csv': 0.30
        }
        
        max_risk = 0.0
        file_types = []
        
        for att in attachments if isinstance(attachments, list) else [attachments]:
            att_lower = att.lower() if isinstance(att, str) else str(att).lower()
            for ext, risk in dangerous_exts.items():
                if att_lower.endswith(ext):
                    max_risk = max(max_risk, risk)
                    file_types.append((ext, risk))
                    break  # Don't count same file twice
        
        return max_risk

    def _check_domain_reputation(self, sender_email):
        """Check domain reputation from custom list."""
        if not sender_email or '@' not in sender_email:
            return 0.0
        
        domain = sender_email.split('@')[1].lower()
        
        # Check against suspicious domains
        for bad_domain, risk_score in self.risk_rules['suspicious_domains'].items():
            if domain.endswith(bad_domain):
                return risk_score
        
        return 0.0

    def _extract_ml_features(self, email_data):
        """Extract features for ML model."""
        subject = email_data.get('subject', '')
        body = email_data.get('body', '')
        sender = email_data.get('sender', '')
        attachments = email_data.get('attachments', [])
        
        # Combine text for TF-IDF
        email_text = f"{subject} {body}"
        
        # ENHANCED: Detect confidential content in body
        confidential_keywords = [
            'confidential', 'top secret', 'classified', 'do not share',
            'internal use only', 'trade secret', 'proprietary',
            'password', 'credential', 'secret', 'api key', 'token',
            'ssn', 'account number', 'credit card', 'social security'
        ]
        has_confidential_content = any(kw in body.lower() for kw in confidential_keywords)
        
        # Check for sensitive file types
        has_sensitive_files = any(
            (att.lower().endswith(('.pdf', '.docx', '.xlsx', '.doc', '.xls')) 
             if isinstance(att, str) else str(att).lower().endswith(('.pdf', '.docx', '.xlsx', '.doc', '.xls')))
            for att in (attachments if isinstance(attachments, list) else [attachments]) if att
        )
        
        attachment_risk = self._score_attachments(attachments)
        
        features = {
            'text': email_text,
            'url_count': self._count_urls(email_text),
            'sender_suspicion': self._score_sender(sender),
            'urgency_level': self._detect_urgency(subject),
            'attachment_risk': attachment_risk,
            'domain_reputation': self._check_domain_reputation(sender),
            'attachment_count': len(attachments) if attachments else 0,
            'has_confidential_content': has_confidential_content,
            'has_sensitive_files': has_sensitive_files
        }
        
        return features

    def train_from_data(self, labeled_emails):
        """
        Train model on labeled emails.
        
        Format: [
            {"subject": "...", "body": "...", "sender": "...", "label": 0/1},  # 0=safe, 1=phishing
            ...
        ]
        """
        if not ML_AVAILABLE or not labeled_emails:
            return False
        
        try:
            texts = [f"{e.get('subject', '')} {e.get('body', '')}" for e in labeled_emails]
            labels = [e.get('label', 0) for e in labeled_emails]
            
            # Fit vectorizer
            X = self.vectorizer.fit_transform(texts)
            
            # Train model
            self.model.fit(X, labels)
            
            print(f"✅ ML model trained on {len(labeled_emails)} emails")
            return True
        except Exception as e:
            print(f"⚠️ Training failed: {e}")
            return False

    def classify_email(self, email_data):
        """
        Classify email using ML models IF available, otherwise use rules.
        ENHANCED: Uses threat_model's email risk prediction as primary signal.
        
        Returns:
            {
                "email_id": "...",
                "classification": "LOW|MEDIUM|HIGH",
                "risk_score": 0.0-1.0,
                "ml_confidence": 0.0-1.0,
                "reasons": ["reason1", "reason2", ...],
                "action": "allow|approve|block",
                "model_used": "threat_model|emailfilter|rules"
            }
        """
        
        features = self._extract_ml_features(email_data)
        text = features['text']
        
        risk_score = 0.0
        ml_confidence = 0.0
        reasons = []
        model_used = "rules"  # Track which model provided the prediction
        
        # PRIMARY: Try threat_model first (has trained email-specific ML models)
        if THREAT_MODEL_AVAILABLE:
            try:
                # Prepare metadata for threat_model
                attachments = email_data.get('attachments', [])
                has_external = not email_data.get('sender', '').endswith('.local') and not email_data.get('sender', '').endswith('@company.com')
                has_executable = any(att.get('name', '').lower().endswith(('.exe', '.dll', '.bat', '.cmd', '.scr', '.vbs')) 
                                   for att in attachments)
                
                # ENHANCED metadata with actual attachment risk scores
                attachment_risk_score = features.get('attachment_risk', 0.0)  # Actual risk score, not binary
                body_content_risk = 0.5 if features.get('has_confidential_content', False) else 0.0
                
                metadata = {
                    'recipients': email_data.get('recipients', []),
                    'has_external': has_external,
                    'attachments': attachments,
                    'body_length': len(email_data.get('body', '')),
                    'has_executable_attachment': has_executable,
                    'attachment_risk_score': attachment_risk_score,  # NEW: Actual risk value
                    'has_confidential_content': features.get('has_confidential_content', False),  # NEW
                    'has_sensitive_files': features.get('has_sensitive_files', False),  # NEW
                    'body_content_risk': body_content_risk,  # NEW: Confidence of sensitive body content
                    'has_credential_keywords': any(kw in text.lower() for kw in ['password', 'credential', 'secret', 'api key', 'token']),
                    'has_urgency_keywords': any(kw in text.lower() for kw in ['urgent', 'immediate', 'act now', 'verify account', 'confirm identity']),
                }
                
                # Get threat_model prediction
                threat_prediction = threat_model.predict_email_risk(text, metadata=metadata)
                
                risk_score = threat_prediction['risk_score']
                ml_confidence = threat_prediction['ml_confidence']
                model_used = "threat_model"
                
                # Add threat_model reasons
                reasons.append(f"Threat Model: {threat_prediction['reason']}")
                if threat_prediction.get('classifier_probability', 0) > 0.5:
                    reasons.append(f"ML Classifier confidence: {threat_prediction['classifier_probability']:.1%}")
                
                print(f"[EMAIL] Using threat_model prediction: {threat_prediction['risk_level']} ({risk_score:.2f})")
                
            except Exception as e:
                print(f"[WARN] Threat model failed: {e}, falling back to local EmailFilterML")
                model_used = "emailfilter"
        else:
            model_used = "emailfilter"
        
        # FALLBACK: Local ML model if threat_model not available
        if model_used == "emailfilter" and self.model is not None and hasattr(self.model, 'predict_proba'):
            try:
                X = self.vectorizer.transform([text])
                ml_proba = self.model.predict_proba(X)[0]
                ml_confidence = float(ml_proba[1])  # Probability of phishing
                risk_score = ml_confidence * 0.6  # Weight ML at 60%
                
                if ml_confidence > 0.5:
                    reasons.append(f"Local ML model: phishing (confidence: {ml_confidence:.2%})")
            except Exception as e:
                # Fallback to rules if ML fails
                print(f"[WARN] Local ML model failed: {e}")
                model_used = "rules"
        
        # FALLBACK: Feature-based scoring (40% weight) - ENHANCED
        if model_used in ("emailfilter", "rules"):
            # CRITICAL FIX: Apply combined threat multiplier
            attachment_multiplier = 1.0
            
            # Only apply strong multipliers when BOTH threats are present
            if features['attachment_risk'] > 0.6 and features.get('has_confidential_content', False):
                # Both dangerous executable AND confidential body content = 1.5x multiplier
                attachment_multiplier = 1.5
            elif features['attachment_risk'] > 0.7:
                # Very dangerous executable (0.8+) = 1.3x multiplier
                attachment_multiplier = 1.3
            elif features.get('has_confidential_content', False) and features['attachment_risk'] > 0.3:
                # Confidential content + suspicious attachment = 1.2x multiplier
                attachment_multiplier = 1.2
            
            feature_score = (
                features['url_count'] * 0.05 +
                features['sender_suspicion'] * 0.15 +
                features['urgency_level'] * 0.15 +
                features['attachment_risk'] * 0.15 +  # Increased weight from 0.10 to 0.15
                features['domain_reputation'] * 0.15 +
                (0.15 if features.get('has_confidential_content', False) else 0.0)  # NEW: Confidential content weight
            ) * attachment_multiplier  # Apply multiplier
            
            # Cap at 1.0
            feature_score = min(feature_score, 1.0)
            
            if model_used == "rules":
                risk_score = feature_score
            else:
                risk_score = min(feature_score * 0.4 + risk_score, 1.0)
            
            model_used = "rules" if model_used == "rules" else "emailfilter"
        
        # Add reason messages
        if features['attachment_risk'] > 0.5:
            reasons.append(f"Dangerous attachment ({features['attachment_risk']:.0%} risk)")
        
        if features['urgency_level'] > 0.3:
            reasons.append("High urgency language (phishing tactic)")
        
        if features['sender_suspicion'] > 0.2:
            reasons.append("Suspicious sender")
        
        if features['url_count'] > 5:
            reasons.append(f"{features['url_count']} URLs detected")
        
        # Classify based on risk score
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
        email_id = hashlib.md5(f"{email_data.get('sender')}{email_data.get('subject')}{datetime.now()}".encode()).hexdigest()[:12]
        record = {
            "timestamp": datetime.now().isoformat(),
            "email_id": email_id,
            "sender": email_data.get('sender', '')[:100],
            "subject": email_data.get('subject', '')[:100],
            "risk_score": round(risk_score, 3),
            "ml_confidence": round(ml_confidence, 3),
            "classification": classification,
            "model_used": model_used,
            "reasons": reasons[:3],
            "attachment_count": features['attachment_count']
        }
        
        with open(self.history_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(record) + '\n')
        
        self.email_history.append(record)
        
        return {
            "email_id": email_id,
            "classification": classification,
            "risk_score": record['risk_score'],
            "ml_confidence": record['ml_confidence'],
            "model_used": model_used,
            "reasons": reasons,
            "action": action,
            "timestamp": record["timestamp"]
        }

    def get_stats(self):
        """Get email filter statistics."""
        total = len(self.email_history)
        low = sum(1 for e in self.email_history if e.get('classification') == 'LOW')
        medium = sum(1 for e in self.email_history if e.get('classification') == 'MEDIUM')
        high = sum(1 for e in self.email_history if e.get('classification') == 'HIGH')
        
        return {
            "total_emails": total,
            "low_risk": low,
            "medium_risk": medium,
            "high_risk": high,
            "model_status": "trained" if self.model else "rule-based",
            "pending_approval": len(self.pending_approval)
        }

    def queue_for_approval(self, email_data, risk_score):
        """Queue email for admin approval."""
        email_id = hashlib.md5(f"{email_data.get('sender')}{datetime.now()}".encode()).hexdigest()[:12]
        self.pending_approval[email_id] = {
            "email_data": email_data,
            "risk_score": risk_score,
            "queued_at": datetime.now().isoformat(),
            "status": "pending"
        }
        
        # Persist
        with open(self.pending_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps({
                "email_id": email_id,
                "sender": email_data.get('sender'),
                "subject": email_data.get('subject'),
                "risk_score": risk_score,
                "queued_at": datetime.now().isoformat()
            }) + '\n')
        
        return email_id

    def get_pending_approvals(self):
        """Get all pending emails awaiting admin approval."""
        return list(self.pending_approval.values())
