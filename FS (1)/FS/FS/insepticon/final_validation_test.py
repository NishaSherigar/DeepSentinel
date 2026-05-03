"""
Final Validation Results - Post Phase 1-4 Fixes
Tests the 10 original validation scenarios with the improved model
"""

import csv
from pathlib import Path
from connect_models import ThreatDetectionModel, user_session_data
import sys

def run_validation_tests():
    """Run the 10 original validation test scenarios."""
    
    print("\n" + "="*70)
    print("FINAL VALIDATION - Post Phase 1-4 Fixes")
    print("="*70)
    print()
    
    model = ThreatDetectionModel()
    
    # Define the 10 test scenarios (same as original validation_results.csv structure)
    test_scenarios = [
        {
            "num": 1,
            "description": "Normal Document Creation (Business Hours)",
            "events": [
                {"agent_id": "USER-001", "event_type": "file", "action": "created", "is_executable": False, "hour_of_day": 14}
            ],
            "expected_range": (0.1, 0.35)
        },
        {
            "num": 2,
            "description": "Executable File Creation (After Hours)",
            "events": [
                {"agent_id": "USER-002", "event_type": "file", "action": "created", "is_executable": True, "hour_of_day": 23}
            ],
            "expected_range": (0.65, 0.9)
        },
        {
            "num": 3,
            "description": "USB Device Plugged (Business Hours)",
            "events": [
                {"agent_id": "USER-003", "event_type": "usb", "action": "inserted", "hour_of_day": 14}
            ],
            "expected_range": (0.5, 0.8)
        },
        {
            "num": 4,
            "description": "USB Device Plugged (After Hours)",
            "events": [
                {"agent_id": "USER-004", "event_type": "usb", "action": "inserted", "hour_of_day": 2}
            ],
            "expected_range": (0.75, 0.95)
        },
        {
            "num": 5,
            "description": "User Login (Business Hours)",
            "events": [
                {"agent_id": "USER-005", "event_type": "logon", "is_remote": False, "hour_of_day": 9}
            ],
            "expected_range": (0.1, 0.35)
        },
        {
            "num": 6,
            "description": "Remote Login (After Hours)",
            "events": [
                {"agent_id": "USER-006", "event_type": "logon", "is_remote": True, "hour_of_day": 22}
            ],
            "expected_range": (0.6, 0.85)
        },
        {
            "num": 7,
            "description": "Bulk File Activity (50 files in session)",
            "events": [
                {"agent_id": "USER-007", "event_type": "file", "action": "created"}
            ] * 50,
            "expected_range": (0.5, 0.75)
        },
        {
            "num": 8,
            "description": "File Deletion (Sensitive Path)",
            "events": [
                {"agent_id": "USER-008", "event_type": "file", "action": "deleted", "in_sensitive_path": True}
            ],
            "expected_range": (0.35, 0.65)
        },
        {
            "num": 9,
            "description": "Weekend Activity (Normal Document)",
            "events": [
                {"agent_id": "USER-009", "event_type": "file", "action": "created", "hour_of_day": 14, "day_of_week": 5}
            ],
            "expected_range": (0.2, 0.5)
        },
        {
            "num": 10,
            "description": "Multiple Risk Factors (Worst Case)",
            "events": [
                {"agent_id": "USER-010", "event_type": "usb", "action": "inserted"},
                {"agent_id": "USER-010", "event_type": "file", "action": "created", "is_executable": True, "in_sensitive_path": True},
                {"agent_id": "USER-010", "event_type": "logon", "is_remote": True, "hour_of_day": 3},
                {"agent_id": "USER-010", "event_type": "email_sent", "has_external": True, "email_subject": "confidential files", "attachments": [{"name": "data.zip", "size_mb": 50}]}
            ],
            "expected_range": (0.8, 0.95)
        }
    ]
    
    results = []
    
    for scenario in test_scenarios:
        print(f"Test {scenario['num']}: {scenario['description']}")
        
        risk_scores = []
        for event in scenario['events']:
            try:
                risk, expl = model.predict_with_explanation(event)
                risk_scores.append(risk)
            except Exception as e:
                print(f"  ERROR: {e}")
                continue
        
        if risk_scores:
            avg_risk = sum(risk_scores) / len(risk_scores)
            max_risk = max(risk_scores)
            
            # Check if within expected range
            expected_min, expected_max = scenario['expected_range']
            within_range = expected_min <= max_risk <= expected_max
            
            status = "PASS" if within_range else "FAIL"
            
            print(f"  Risk: {max_risk:.4f} | Expected: {expected_min:.2f}-{expected_max:.2f} | {status}")
            print()
            
            results.append({
                "test": scenario['num'],
                "description": scenario['description'],
                "risk_score": max_risk,
                "expected": f"{expected_min:.2f}-{expected_max:.2f}",
                "passed": within_range
            })
        else:
            results.append({
                "test": scenario['num'],
                "description": scenario['description'],
                "risk_score": 0.0,
                "expected": f"{expected_min:.2f}-{expected_max:.2f}",
                "passed": False
            })
    
    # Write results to CSV
    output_file = Path(__file__).parent / "validation_results_final.csv"
    
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["test", "description", "risk_score", "expected", "passed"])
        writer.writeheader()
        writer.writerows(results)
    
    # Print summary
    print("="*70)
    print("[SUMMARY] Validation Results")
    print("="*70)
    
    passed = sum(1 for r in results if r['passed'])
    total = len(results)
    accuracy = (passed/total*100) if total > 0 else 0
    
    print(f"Total Tests: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {total - passed}")
    print(f"Accuracy: {accuracy:.1f}%")
    print()
    print(f"Results saved to: {output_file}")
    print()
    
    return accuracy, passed, total

if __name__ == "__main__":
    try:
        accuracy, passed, total = run_validation_tests()
        sys.exit(0 if accuracy == 100 else 1)
    except Exception as e:
        print(f"[ERROR] Validation failed: {e}")
        sys.exit(1)
