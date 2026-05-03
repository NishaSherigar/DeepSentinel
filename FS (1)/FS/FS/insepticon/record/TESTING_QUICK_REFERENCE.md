# Email ML Model Testing - Quick Reference Guide

## 3 Ways to Test

### ⚡ Method 1: Run the Demo (Fastest)
```powershell
cd "c:\Users\Dell\Desktop\APPS\DEEPSENTINEL\FS (1)\FS\FS\insepticon"
python DEMO_EMAIL_FIX.py
```
**Shows:**
- ✅ High-risk body + PDF = 0.733 (HIGH) - FIXED!
- ✅ No subject + Credentials = 0.823 (CRITICAL)
- ✅ Executable + Trade Secret = 0.963 (CRITICAL) with 1.5x boost

---

### 🧪 Method 2: Run Automated Tests
```powershell
cd "c:\Users\Dell\Desktop\APPS\DEEPSENTINEL\FS (1)\FS\FS\insepticon"
python test_email_ml_fix.py
```
**Shows:** 5 test scenarios with pass/fail status

---

### 🎮 Method 3: Interactive Testing
```powershell
cd "c:\Users\Dell\Desktop\APPS\DEEPSENTINEL\FS (1)\FS\FS\insepticon"
python test_email_interactive.py
```
**Shows:**
- Menu with 5 test scenarios
- Pick test #1-5 to run individually
- See real-time scoring

Or run batch:
```powershell
python test_email_interactive.py --batch
```

---

## Key Test Results (DEMO)

| Test | Email | Score | Level | Status |
|------|-------|-------|-------|--------|
| 1 | High-risk body + PDF | **0.733** | HIGH | ✅ FIXED |
| 2 | No subject + Credentials | **0.823** | CRITICAL | ✅ FIXED |
| 3 | Executable + Trade Secret | **0.963** | CRITICAL | ✅ FIXED |

**What was wrong:**
- Test 1 used to score **0.200 (LOW)** ❌
- Now correctly scores **0.733 (HIGH)** ✅

---

## In Your Code - Quick Example

```python
from connect_models import threat_model

# Prepare email
email_text = "Subject: Normal | Body: Contains password and API key"

metadata = {
    'recipients': ['user@company.com'],
    'has_external': False,
    'attachments': [{'name': 'sensitive.xlsx'}],
    'body_length': 100,
    'has_executable_attachment': False,
    'attachment_risk_score': 0.35,     # ✅ NEW: Actual risk 0.35, not binary
    'has_confidential_content': True,   # ✅ NEW: Keyword detection
    'has_credential_keywords': True,    # ✅ NEW: Secure data detected
    'has_urgency_keywords': False,
}

# Get risk prediction
result = threat_model.predict_email_risk(email_text, metadata=metadata)

# Result:
# {
#     'risk_score': 0.735,
#     'risk_level': 'HIGH',
#     'reason': 'ML predicted... [BOOST 1.2x: attachment+confidential]',
#     'ml_confidence': 0.9
# }

# Use in decision logic
if result['risk_level'] == 'CRITICAL':
    email.block()  # Immediate block
elif result['risk_level'] == 'HIGH':
    email.quarantine()  # Review needed
elif result['risk_level'] == 'MEDIUM':
    email.approve()  # Admin approval
else:
    email.allow()  # Safe to send
```

---

## What the Fix Detects

### ✅ Confidential Keywords (NEW)
- password, credential, API key, token, SSN
- account number, credit card, social security
- confidential, trade secret, proprietary
- "do not share", "internal use only"

### ✅ File Risk Scoring (ENHANCED)
- .exe (0.95) | .bat (0.90) | .dll (0.90) - EXECUTABLES
- .xlsx (0.80) | .docm (0.80) - MACRO-ENABLED
- .pdf (0.35) | .docx (0.35) - DOCUMENTS
- Previous: Only binary 0 or 1 ❌ Now: Actual scores ✅

### ✅ Multiplier System (NEW)
- **1.5x** when: Dangerous file (0.6+) + Confidential body
- **1.3x** when: Very dangerous file (0.7+)
- **1.2x** when: Suspicious file (0.3+) + Confidential

---

## Testing Checklist

- [ ] Run DEMO_EMAIL_FIX.py and see 0.733 score for Test 1
- [ ] Verify "BOOST 1.5x" appears in Test 3 results
- [ ] Check that normal emails stay LOW risk
- [ ] Test in your email filter module
- [ ] Verify emails with credentials get > 0.60 score
- [ ] Confirm .exe files get CRITICAL classification

---

## Troubleshooting

**Q: Getting 0.50 score for high-risk email?**
A: Ensure metadata['has_confidential_content'] is True
   Check that attachment_risk_score is correct (0.35-0.95)

**Q: Model says it's using heuristic fallback?**
A: Models may not be loaded. Check:
   ```python
   python -c "from connect_models import threat_model; print('Ready')"
   ```

**Q: Score doesn't match expected?**
A: Verify metadata values are correct:
   - attachment_risk_score: 0.0-1.0
   - has_executable_attachment: bool
   - has_confidential_content: bool
   - has_credential_keywords: bool

---

## Files Modified

1. **email_filter_ml.py** - Enhanced feature extraction + multipliers
2. **connect_models.py** - Updated predict_email_risk() with multipliers
3. **test_email_ml_fix.py** - Automated testing suite
4. **DEMO_EMAIL_FIX.py** - Quick demo of the fix
5. **test_email_interactive.py** - Interactive tester
6. **TESTING_EMAIL_ML_EXAMPLES.md** - Full documentation

---

## Next Steps

Now that email ML is fixed, you wanted to work on:

1. **Office Hours Thresholds** (8-5 or 9-5)
2. **Role-Based File Limits** (Developer vs Finance)
3. **Email Control Rules** (Prevent sending based on risk)

Ready to implement those? 🎯
