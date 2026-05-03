# Email ML Model Testing - Practical Examples

## Quick Start: Testing the Email Risk Scoring

### Method 1: Direct Python Testing (Quickest)

```python
from connect_models import threat_model

# Test Case 1: The Bug - High-risk body + Confidential file
email_text = "We have discussed trade secret information and database credentials"
metadata = {
    'recipients': ['user@company.com'],
    'has_external': False,
    'attachments': [{'name': 'confidential_design.pdf', 'size_mb': 2}],
    'body_length': 100,
    'has_executable_attachment': False,
    'attachment_risk_score': 0.35,  # PDF = 0.35 risk
    'has_confidential_content': True,  # Keywords detected
    'has_credential_keywords': True,
    'has_urgency_keywords': False,
}

result = threat_model.predict_email_risk(email_text, metadata=metadata)
print(f"Risk Score: {result['risk_score']:.3f}")
print(f"Risk Level: {result['risk_level']}")
print(f"Reason: {result['reason']}")

# Output:
# Risk Score: 0.733
# Risk Level: HIGH
# Reason: ML predicted HIGH risk (classifier: 55.85%) [BOOST 1.2x: attachment+confidential]
```

---

## Complete Testing Examples

### ✅ Example 1: HIGH RISK (Confidential + Dangerous Attachment)

```python
from email_filter_ml import EmailFilterML

email_filter = EmailFilterML()

email_data = {
    "subject": "Meeting Agenda",  # Normal subject
    "body": "Here is our API key: sk-1234567890. Our database password is SecureDB123. This is confidential trade secret information.",
    "sender": "external@company.com",
    "recipients": ["admin@company.com"],
    "attachments": [
        {"name": "credentials.xlsx", "size_mb": 1}
    ]
}

result = email_filter.classify_email(email_data)

print("=" * 60)
print("TEST: Confidential Content + Dangerous File")
print("=" * 60)
print(f"Risk Score: {result['risk_score']:.3f}")
print(f"Classification: {result['classification']}")
print(f"Action: {result['action']}")
print(f"Reasons:")
for reason in result['reasons']:
    print(f"  - {reason}")
print()

# EXPECTED OUTPUT:
# Risk Score: 0.735+
# Classification: HIGH or CRITICAL
# Action: block or approve
# Reasons: Shows attachment risk + confidential content + boost
```

---

### ✅ Example 2: CRITICAL RISK (Executable + Sensitive Body)

```python
email_data = {
    "subject": "Important Update",
    "body": "Execute this update. It contains our internal proprietary algorithms worth $5M. Password: TopSecret123. SSN: 123-45-6789",
    "sender": "unknown@external-bank.tk",  # Suspicious domain
    "recipients": ["team@company.com"],
    "attachments": [
        {"name": "update_installer.exe", "size_mb": 5}
    ]
}

result = email_filter.classify_email(email_data)

print("=" * 60)
print("TEST: Executable + Highly Sensitive Content")
print("=" * 60)
print(f"Risk Score: {result['risk_score']:.3f}")
print(f"Classification: {result['classification']}")
print(f"Action: {result['action']}")
print(f"Confidence: {result['ml_confidence']:.1%}")
print()

# EXPECTED OUTPUT:
# Risk Score: 0.80+
# Classification: CRITICAL
# Action: block
# Confidence: 90%
```

---

### ✅ Example 3: LOW RISK (Legitimate Business Email)

```python
email_data = {
    "subject": "Q4 Budget Review",
    "body": "Please review the quarterly budget summary attached. Meeting scheduled for Thursday at 2 PM.",
    "sender": "manager@company.com",
    "recipients": ["finance-team@company.com"],
    "attachments": [
        {"name": "Q4_Budget_Summary.docx", "size_mb": 2}
    ]
}

result = email_filter.classify_email(email_data)

print("=" * 60)
print("TEST: Normal Business Email")
print("=" * 60)
print(f"Risk Score: {result['risk_score']:.3f}")
print(f"Classification: {result['classification']}")
print(f"Action: {result['action']}")
print()

# EXPECTED OUTPUT:
# Risk Score: 0.15-0.35
# Classification: LOW
# Action: allow
```

---

### ✅ Example 4: MEDIUM RISK (Phishing Attempt)

```python
email_data = {
    "subject": "Verify Your Account - Action Required",
    "body": "Click the link below to verify your account. Enter your password when prompted. This is urgent!",
    "sender": "support@bank-verify.com",  # Suspicious domain
    "recipients": ["user@company.com"],
    "attachments": []
}

result = email_filter.classify_email(email_data)

print("=" * 60)
print("TEST: Phishing/Credential Harvesting")
print("=" * 60)
print(f"Risk Score: {result['risk_score']:.3f}")
print(f"Classification: {result['classification']}")
print(f"Action: {result['action']}")
print(f"Model Used: {result['model_used']}")
print()

# EXPECTED OUTPUT:
# Risk Score: 0.45-0.65
# Classification: MEDIUM or HIGH
# Action: approve or block
```

---

### ✅ Example 5: NO SUBJECT + HIGH-RISK BODY (The Bug Case!)

```python
email_data = {
    "subject": "",  # EMPTY SUBJECT - sender tried to hide
    "body": "Password: CompanyDB@123. Credit Card: 4111-1111-1111-1111. Social Security Number: 123-45-6789. This is our financial data.",
    "sender": "unknown@external.com",
    "recipients": ["finance@company.com"],
    "attachments": [
        {"name": "financial_exports.xlsx", "size_mb": 3}
    ]
}

result = email_filter.classify_email(email_data)

print("=" * 60)
print("TEST: No Subject + Critical Credentials (BUG CASE)")
print("=" * 60)
print(f"Risk Score: {result['risk_score']:.3f}")
print(f"Classification: {result['classification']}")
print(f"Action: {result['action']}")
print(f"Reasons: {result['reasons']}")
print()

# EXPECTED (WITH FIX):
# Risk Score: 0.75+
# Classification: CRITICAL
# Action: block
# (Before fix would have been ~0.20 - LOW!)
```

---

## Running All Tests

### Option A: Run the Automated Test Suite

```bash
cd "c:\Users\Dell\Desktop\APPS\DEEPSENTINEL\FS (1)\FS\FS\insepticon"
python test_email_ml_fix.py
```

Output shows:
- ✅ 3 tests passing (High-risk, Sensitive, Executable scenarios)
- Test scores and confidence levels
- Boost multipliers applied

### Option B: Create Your Own Test Script

**`my_email_tests.py`**:
```python
#!/usr/bin/env python3
import sys
from connect_models import threat_model
from email_filter_ml import EmailFilterML

print("\n" + "="*70)
print("TESTING EMAIL ML MODEL - CUSTOM CASES")
print("="*70 + "\n")

email_filter = EmailFilterML()

test_cases = [
    {
        "name": "Confidential PDF + API Keys",
        "email": {
            "subject": "Project Update",
            "body": "Here is our API key: sk_live_5125s... and database password: Secure123!",
            "sender": "contractor@external.com",
            "recipients": ["dev@company.com"],
            "attachments": [{"name": "project_data.pdf", "size_mb": 2}]
        },
        "expect_high": True
    },
    {
        "name": "Normal Email with Docx",
        "email": {
            "subject": "Weekly Report",
            "body": "Please find the weekly status attached.",
            "sender": "teammate@company.com",
            "recipients": ["manager@company.com"],
            "attachments": [{"name": "status_report.docx", "size_mb": 1}]
        },
        "expect_high": False
    },
]

for test in test_cases:
    result = email_filter.classify_email(test["email"])
    is_high_risk = result['classification'] in ['HIGH', 'CRITICAL']
    
    status = "✅" if is_high_risk == test["expect_high"] else "❌"
    print(f"{status} {test['name']}")
    print(f"   Score: {result['risk_score']:.3f} | Level: {result['classification']}")
    print(f"   Action: {result['action']}")
    print()
```

Run it:
```bash
python my_email_tests.py
```

---

## Understanding the Scores

### Risk Score Ranges

| Score | Level | Action | Meaning |
|-------|-------|--------|---------|
| 0.00 - 0.40 | LOW | ✅ Allow | Safe email, auto-approve |
| 0.40 - 0.60 | MEDIUM | ⏸️ Approve | Review needed by admin |
| 0.60 - 0.75 | HIGH | ⚠️ Block | Likely malicious, block |
| 0.75 - 1.00 | CRITICAL | 🚫 Block | Definitely dangerous, immediate block |

### Multipliers Applied

The fix applies these multipliers:

```
1.5x - When: Executable (0.6+) + Confidential body content
       Example: .exe + "password" = HIGH RISK
       
1.3x - When: Very dangerous executable alone (0.7+)
       Example: .exe file = HIGH RISK
       
1.2x - When: Confidential content + suspicious file (0.3+)
       Example: "trade secret" + .pdf = MEDIUM→HIGH
```

### Keywords Detected

**Critical**: password, credential, SSN, account number, API key, token  
**Sensitive**: confidential, top secret, trade secret, proprietary, "do not share"  
**Phishing**: verify account, confirm identity, urgent action, click here

---

## Integration with Your System

### Use in email_filter.py

```python
# In your email filter route/handler
email_data = {
    "subject": request.subject,
    "body": request.body_text,
    "sender": request.sender,
    "recipients": request.recipients,
    "attachments": request.attachments
}

result = email_filter.classify_email(email_data)

if result['classification'] == 'CRITICAL':
    # Block immediately
    email.block(f"Blocked: {result['reasons'][0]}")
elif result['classification'] == 'HIGH':
    # Block with notification
    email.block_notify_admin(result)
elif result['classification'] == 'MEDIUM':
    # Send to approval queue
    email.quarantine_for_approval(result)
else:
    # Allow through
    email.allow()
```

---

## Troubleshooting

### Q: Why is a normal email getting flagged as HIGH?
**A:** Check the `has_confidential_content` flag. It may have detected a common word used in context. Review `confidential_keywords` list.

### Q: Executable .EXE file not being caught?
**A:** Ensure attachment name/extension is correct. Check `_score_attachments()` is being called.

### Q: ML model not running, using heuristic fallback?
**A:** Models need to be loaded. Check:
```python
if threat_model.model_load_status["email_classifier"]:
    print("✅ ML Models Loaded")
else:
    print("⚠️ Using Heuristic Fallback")
```

---

## Quick Test Commands

```powershell
# Terminal Test 1: Check model loads
python -c "from connect_models import threat_model; print('✅ Model ready')"

# Terminal Test 2: Run email classification
python -c "
from email_filter_ml import EmailFilterML
ef = EmailFilterML()
result = ef.classify_email({'subject': 'Test', 'body': 'password here', 'sender': 'test@test.com', 'attachments': []})
print(f'Score: {result[\"risk_score\"]:.3f}')
"

# Terminal Test 3: Run full test suite
python test_email_ml_fix.py
```

---

## What's Fixed

**Before (0.200 score - WRONG):**
```
📧 Subject: "Meeting"
📝 Body: "We have confidential API keys and trade secrets..."
📎 Attachment: confidential.pdf
❌ Score: 0.200 LOW (BUG)
```

**After (0.733 score - CORRECT):**
```
📧 Subject: "Meeting"  
📝 Body: "We have confidential API keys and trade secrets..."
📎 Attachment: confidential.pdf
✅ Score: 0.733 HIGH (WITH 1.2x MULTIPLIER)
```

The fix properly detects that this is a dangerous email combining sensitive content with confidential files!
