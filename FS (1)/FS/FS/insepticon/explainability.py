# =============================================================================
# DeepSentinel — explainability.py
# NLP-powered explainability for threat detection
# Provides human-readable explanations for why events are flagged
#
# ADD to server.py before if __name__ == '__main__':
#   from explainability import Explainer
#   explainer = Explainer()
# =============================================================================

import re
from datetime import datetime
from typing import Dict, List, Tuple

# Try to import NLP libraries
try:
    import nltk
    from nltk.corpus import stopwords
    from nltk.tokenize import word_tokenize
    NLTK_AVAILABLE = True
    try:
        nltk.data.find('tokenizers/punkt')
        nltk.data.find('corpora/stopwords')
    except LookupError:
        nltk.download('punkt', quiet=True)
        nltk.download('stopwords', quiet=True)
except ImportError:
    NLTK_AVAILABLE = False


class Explainer:
    """NLP-based threat explanation engine."""

    def __init__(self):
        self.threat_categories = {
            "data_exfiltration": {
                "keywords": ["usb", "drive", "external", "download", "upload", "send", "copy", "backup", "compress", "zip"],
                "description": "Data Exfiltration Risk",
                "severity": "high"
            },
            "malware": {
                "keywords": ["exe", "malware", "virus", "trojan", "ransomware", "payload", "inject", "execute"],
                "description": "Malware indicators",
                "severity": "critical"
            },
            "credential_theft": {
                "keywords": ["password", "credential", "login", "authenticate", "token", "secret", "api key"],
                "description": "Credential Access Risk",
                "severity": "high"
            },
            "after_hours_activity": {
                "keywords": ["night", "weekend", "holiday", "off-hours"],
                "description": "After-hours activity",
                "severity": "medium"
            },
            "suspicious_email": {
                "keywords": ["phishing", "spoofing", "urgent", "verify", "confirm", "update account", "unusual activity"],
                "description": "Email security threat",
                "severity": "high"
            },
            "privilege_escalation": {
                "keywords": ["admin", "root", "sudo", "privilege", "elevation", "escalation"],
                "description": "Privilege Escalation Attempt",
                "severity": "critical"
            },
            "lateral_movement": {
                "keywords": ["share", "smb", "network", "lateral", "pivot", "move"],
                "description": "Lateral Movement within network",
                "severity": "high"
            },
            "c2_communication": {
                "keywords": ["c2", "command", "control", "beacon", "callback", "remote execution"],
                "description": "Command & Control communication",
                "severity": "critical"
            }
        }

    def explain_event(self, event: Dict) -> Dict:
        """
        Generate human-readable explanation for why an event was flagged.
        
        Args:
            event: Event dictionary with type, details, risk_score, etc.
            
        Returns:
            {
                "short_summary": "Quick explanation",
                "detailed_reasons": ["Reason 1", "Reason 2", ...],
                "severity": "LOW|MEDIUM|HIGH|CRITICAL",
                "recommendations": ["Action 1", "Action 2", ...],
                "confidence": 0.0-1.0
            }
        """
        event_type = event.get('event_type', '').lower()
        risk_score = float(event.get('risk_score', 0))
        details = event.get('details', {})
        
        detailed_reasons = []
        threat_indicators = []
        confidence = 0.0
        
        # ── Event-specific explanations ──
        
        if event_type == 'file':
            explanation = self._explain_file_event(event, details)
            detailed_reasons = explanation['reasons']
            threat_indicators = explanation['threat_indicators']
            confidence = explanation['confidence']
        
        elif event_type in ['outlook', 'imap', 'email_sent']:
            explanation = self._explain_email_event(event, details)
            detailed_reasons = explanation['reasons']
            threat_indicators = explanation['threat_indicators']
            confidence = explanation['confidence']
        
        elif event_type == 'logon':
            explanation = self._explain_logon_event(event, details)
            detailed_reasons = explanation['reasons']
            threat_indicators = explanation['threat_indicators']
            confidence = explanation['confidence']
        
        elif event_type == 'usb':
            explanation = self._explain_usb_event(event, details)
            detailed_reasons = explanation['reasons']
            threat_indicators = explanation['threat_indicators']
            confidence = explanation['confidence']
        
        elif event_type == 'process':
            explanation = self._explain_process_event(event, details)
            detailed_reasons = explanation['reasons']
            threat_indicators = explanation['threat_indicators']
            confidence = explanation['confidence']
        
        else:
            detailed_reasons = [f"Unknown event type: {event_type}"]
            confidence = 0.3
        
        # Determine severity based on risk score
        if risk_score >= 0.9:
            severity = "CRITICAL"
            icon = "💀"
        elif risk_score >= 0.7:
            severity = "HIGH"
            icon = "🔴"
        elif risk_score >= 0.5:
            severity = "MEDIUM"
            icon = "🟡"
        else:
            severity = "LOW"
            icon = "🟢"
        
        short_summary = self._generate_summary(event_type, threat_indicators, severity)
        recommendations = self._get_recommendations(threat_indicators, severity)
        
        return {
            "icon": icon,
            "severity": severity,
            "short_summary": f"{icon} {short_summary}",
            "detailed_reasons": detailed_reasons,
            "threat_categories": threat_indicators,
            "recommendations": recommendations,
            "confidence": round(confidence, 2),
            "event_type": event_type,
            "risk_score": risk_score
        }

    def _explain_file_event(self, event: Dict, details: Dict) -> Dict:
        """Explain file-related events."""
        reasons = []
        threat_indicators = []
        confidence = 0.5
        
        action = event.get('action', '').lower()
        path = event.get('path', '').lower()
        
        # Check for file type
        suspicious_exts = ['.exe', '.bat', '.cmd', '.scr', '.vbs', '.js', '.dll', '.sys']
        if any(path.endswith(ext) for ext in suspicious_exts):
            reasons.append(f"⚠️ Suspicious file type: {path.split('.')[-1].upper()} executable")
            threat_indicators.append("malware")
            confidence += 0.2
        
        # Check for sensitive file types
        sensitive_exts = ['.pdf', '.docx', '.xlsx', '.pptx', '.sql', '.csv', '.zip']
        if any(path.endswith(ext) for ext in sensitive_exts):
            if action in ['file_copied', 'file_moved', 'file_deleted']:
                reasons.append(f"⚠️ Sensitive document being {action.split('_')[1]}: {path.split(chr(92))[-1]}")
                threat_indicators.append("data_exfiltration")
                confidence += 0.15
        
        # Check for suspicious paths
        suspicious_paths = ['temp', 'appdata', 'downloads', 'usb', 'network share', 'cloud']
        for sp in suspicious_paths:
            if sp in path:
                if action in ['file_copied', 'file_moved']:
                    reasons.append(f"⚠️ Movement to {sp.upper()} folder (common exfiltration vector)")
                    threat_indicators.append("data_exfiltration")
                    confidence += 0.15
        
        # Action-specific
        if action == 'file_deleted':
            reasons.append(f"🗑️ File deletion detected (could indicate cover-up)")
            confidence += 0.1
        elif action == 'file_shared':
            reasons.append(f"🔗 File shared externally (check authorization)")
            threat_indicators.append("data_exfiltration")
            confidence += 0.2
        
        confidence = min(confidence, 1.0)
        
        return {
            "reasons": reasons if reasons else ["File activity detected"],
            "threat_indicators": threat_indicators,
            "confidence": confidence
        }

    def _explain_email_event(self, event: Dict, details: Dict) -> Dict:
        """Explain email-related events."""
        reasons = []
        threat_indicators = []
        confidence = 0.5
        
        subject = event.get('email_subject', '').lower()
        sender = event.get('sender', '').lower()
        attachment_count = len(event.get('attachments', []))
        
        # Phishing keywords
        phishing_keywords = ['verify', 'urgent action', 'confirm identity', 'unusual activity',
                            'suspicious login', 'update password', 'verify account', 'click here']
        for keyword in phishing_keywords:
            if keyword in subject:
                reasons.append(f"⚠️ Phishing indicator: '{keyword}' in subject line")
                threat_indicators.append("suspicious_email")
                confidence += 0.15
                break
        
        # Attachment analysis
        if attachment_count > 0:
            reasons.append(f"📎 {attachment_count} attachment(s) detected")
            suspicious_exts = ['.exe', '.zip', '.rar', '.bat']
            if any(att.lower().endswith(ext) for att in event.get('attachments', []) for ext in suspicious_exts):
                reasons.append(f"🚨 Potentially malicious attachment detected")
                threat_indicators.append("malware")
                confidence += 0.25
        
        # External sender
        if sender and not sender.endswith('@yourcompany.com'):  # Adjust domain as needed
            reasons.append(f"🔗 External email from {sender.split('@')[-1]}")
            threat_indicators.append("suspicious_email")
            confidence += 0.1
        
        confidence = min(confidence, 1.0)
        
        return {
            "reasons": reasons if reasons else ["Email activity logged"],
            "threat_indicators": threat_indicators,
            "confidence": confidence
        }

    def _explain_logon_event(self, event: Dict, details: Dict) -> Dict:
        """Explain logon-related events."""
        reasons = []
        threat_indicators = []
        confidence = 0.5
        
        hour = event.get('hour_of_day', 12)
        logon_type = event.get('logon_type_name', '').lower()
        ip_address = event.get('source_ip', '')
        
        # After-hours detection
        if hour < 7 or hour > 20:
            reasons.append(f"🌙 After-hours login at {hour:02d}:00 (outside normal 9-5)")
            threat_indicators.append("after_hours_activity")
            confidence += 0.15
        
        # Logon type analysis
        if 'remote' in logon_type or 'vpn' in logon_type:
            reasons.append(f"🌐 Remote access via {logon_type}")
            threat_indicators.append("lateral_movement")
            confidence += 0.1
        
        if 'network' in logon_type:
            reasons.append(f"🔌 Network logon detected (potential privilege escalation)")
            threat_indicators.append("privilege_escalation")
            confidence += 0.15
        
        # Failed multiple attempts
        if event.get('failed_attempts', 0) > 2:
            reasons.append(f"❌ {event.get('failed_attempts')} failed login attempts")
            threat_indicators.append("credential_theft")
            confidence += 0.2
        
        confidence = min(confidence, 1.0)
        
        return {
            "reasons": reasons if reasons else ["User logon recorded"],
            "threat_indicators": threat_indicators,
            "confidence": confidence
        }

    def _explain_usb_event(self, event: Dict, details: Dict) -> Dict:
        """Explain USB-related events."""
        reasons = []
        threat_indicators = ["data_exfiltration"]
        confidence = 0.7  # USB activity is inherently suspicious
        
        drive = event.get('drive', '')
        files_count = event.get('files_count', 0)
        action = event.get('action', '').lower()
        
        reasons.append(f"💾 USB device '{drive}' activity detected")
        
        if action == 'files_copied':
            reasons.append(f"📋 {files_count} files copied to USB (potential data theft)")
            confidence += 0.15
        elif action == 'files_deleted':
            reasons.append(f"🗑️ Files removed from USB")
        elif action == 'mounted':
            reasons.append(f"🔌 USB device mounted")
        
        confidence = min(confidence, 1.0)
        
        return {
            "reasons": reasons,
            "threat_indicators": threat_indicators,
            "confidence": confidence
        }

    def _explain_process_event(self, event: Dict, details: Dict) -> Dict:
        """Explain process-related events."""
        reasons = []
        threat_indicators = []
        confidence = 0.5
        
        process_name = event.get('process_name', '').lower()
        parent = event.get('parent_process', '').lower()
        
        # Suspicious processes
        suspicious_processes = ['powershell', 'cmd', 'wscript', 'cscript', 'regsvcs', 'msiexec']
        if any(susp in process_name for susp in suspicious_processes):
            reasons.append(f"⚠️ Suspicious process: {process_name.upper()}")
            threat_indicators.append("malware")
            confidence += 0.2
        
        # Execution from suspicious paths
        if 'temp' in process_name or 'appdata' in process_name or 'downloads' in process_name:
            reasons.append(f"📌 Process spawned from suspicious location")
            threat_indicators.append("malware")
            confidence += 0.15
        
        # Parent-child relationship
        if parent and 'svchost' not in parent and 'explorer' not in parent:
            reasons.append(f"🔗 Child process of {parent}")
            confidence += 0.1
        
        confidence = min(confidence, 1.0)
        
        return {
            "reasons": reasons if reasons else ["Process activity detected"],
            "threat_indicators": threat_indicators,
            "confidence": confidence
        }

    def _generate_summary(self, event_type: str, indicators: List[str], severity: str) -> str:
        """Generate a short, human-readable summary."""
        summaries = {
            "file": "File activity detected",
            "outlook": "Email event detected",
            "imap": "Email event detected",
            "email_sent": "Email sent",
            "logon": "User login detected",
            "usb": "USB activity detected",
            "process": "Process execution detected",
            "clipboard": "Clipboard access detected",
            "network": "Network activity detected"
        }
        
        base = summaries.get(event_type, f"{event_type} activity detected")
        
        if indicators:
            first_indicator = indicators[0]
            if first_indicator == "data_exfiltration":
                return f"{base} - possible data exfiltration"
            elif first_indicator == "malware":
                return f"{base} - malware indicators detected"
            elif first_indicator == "credential_theft":
                return f"{base} - credential access attempt"
            elif first_indicator == "suspicious_email":
                return f"{base} - phishing/spoofing alert"
            elif first_indicator == "after_hours_activity":
                return f"{base} - after-hours activity"
            elif first_indicator == "privilege_escalation":
                return f"{base} - privilege escalation attempt"
        
        return base

    def _get_recommendations(self, threat_indicators: List[str], severity: str) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        for indicator in threat_indicators:
            if indicator == "data_exfiltration":
                recommendations.append("🛑 Review file access permissions")
                recommendations.append("🔍 Check for unauthorized data transfers")
                recommendations.append("⚠️ Consider blocking USB/external storage")
            elif indicator == "malware":
                recommendations.append("🛑 ISOLATE affected machine immediately")
                recommendations.append("🔍 Run full antivirus scan")
                recommendations.append("📋 Review activity logs for spread")
            elif indicator == "credential_theft":
                recommendations.append("🛑 Reset user password immediately")
                recommendations.append("🔍 Review account activity logs")
                recommendations.append("⚠️ Check for lateral movement")
            elif indicator == "suspicious_email":
                recommendations.append("🛑 Block sender/domain")
                recommendations.append("🔍 Check for email forwarding rules")
                recommendations.append("⚠️ Educate user about phishing")
            elif indicator == "after_hours_activity":
                recommendations.append("🔍 Contact user to verify activity")
                recommendations.append("⚠️ Check for unauthorized access")
            elif indicator == "privilege_escalation":
                recommendations.append("🛑 Monitor for lateral movement")
                recommendations.append("🔍 Review Group Policy changes")
                recommendations.append("⚠️ Check domain admin activity")
        
        # Add general recommendations based on severity
        if severity == "CRITICAL":
            if not any("ISOLATE" in r for r in recommendations):
                recommendations.insert(0, "🛑 ISOLATE MACHINE - CRITICAL THREAT")
        elif severity == "HIGH":
            if not any("Block\|Review" in r for r in recommendations):
                recommendations.insert(0, "⚠️ Escalate to security team")
        
        return recommendations[:5]  # Return top 5
