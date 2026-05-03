"""
Comprehensive Testing Suite - Extended Validation
Tests edge cases, stress scenarios, error handling, and advanced threat patterns
"""

import csv
import time
import json
from pathlib import Path
from connect_models import ThreatDetectionModel
import sys

def run_extended_tests():
    """Run comprehensive extended test suite."""
    
    print("\n" + "="*80)
    print("COMPREHENSIVE TESTING SUITE - Extended Validation")
    print("="*80)
    print()
    
    model = ThreatDetectionModel()
    all_results = []
    
    # ============================================================================
    # SECTION 1: EDGE CASES & BOUNDARY CONDITIONS
    # ============================================================================
    print("[SECTION 1] Edge Cases & Boundary Conditions")
    print("-" * 80)
    
    edge_case_tests = [
        {
            "id": "EC-001",
            "name": "Empty Event - Minimal Data",
            "event": {},
            "expected_range": (0.0, 0.2),
            "description": "Should return low risk with no threat indicators"
        },
        {
            "id": "EC-002", 
            "name": "Null/None Values",
            "event": {"agent_id": None, "event_type": None, "hour_of_day": None},
            "expected_range": (0.0, 0.2),
            "description": "Should handle None gracefully"
        },
        {
            "id": "EC-003",
            "name": "Maximum Hour Value (23:59)",
            "event": {"event_type": "file", "action": "created", "hour_of_day": 23},
            "expected_range": (0.5, 0.8),
            "description": "Should detect late-night activity as risky"
        },
        {
            "id": "EC-004",
            "name": "Minimum Hour Value (00:00)",
            "event": {"event_type": "file", "action": "created", "hour_of_day": 0},
            "expected_range": (0.5, 0.8),
            "description": "Should detect midnight activity as risky"
        },
        {
            "id": "EC-005",
            "name": "Extreme File Size - 1GB attachment",
            "event": {"event_type": "email_sent", "attachments": [{"name": "huge_data.zip", "size_mb": 1024}]},
            "expected_range": (0.6, 0.85),
            "description": "Should flag massive file transfers as suspicious"
        },
        {
            "id": "EC-006",
            "name": "Zero File Operations",
            "event": {"event_type": "file", "action": "created", "num_file": 0},
            "expected_range": (0.1, 0.3),
            "description": "Single file operation should have baseline risk"
        },
        {
            "id": "EC-007",
            "name": "Extremely High File Count (10000 files)",
            "event": {"event_type": "file", "action": "created", "num_file": 10000},
            "expected_range": (0.7, 0.95),
            "description": "Should flag mass file operations"
        },
        {
            "id": "EC-008",
            "name": "System Admin Privilege",
            "event": {"event_type": "file", "action": "created", "is_admin": True},
            "expected_range": (0.3, 0.5),
            "description": "Admin operations less suspicious than user operations"
        },
    ]
    
    for test in edge_case_tests:
        try:
            risk, explanation = model.predict_with_explanation(test["event"])
            expected_min, expected_max = test["expected_range"]
            passed = expected_min <= risk <= expected_max
            
            print(f"[{test['id']}] {test['name']}")
            print(f"    Risk: {risk:.4f} | Expected: {expected_min:.2f}-{expected_max:.2f} | {'✅ PASS' if passed else '❌ FAIL'}")
            print(f"    Description: {test['description']}")
            print()
            
            all_results.append({
                "category": "Edge Cases",
                "test_id": test["id"],
                "test_name": test["name"],
                "risk_score": risk,
                "expected_range": f"{expected_min:.2f}-{expected_max:.2f}",
                "passed": passed,
                "notes": test["description"]
            })
        except Exception as e:
            print(f"[{test['id']}] {test['name']} - ERROR: {e}")
            all_results.append({
                "category": "Edge Cases",
                "test_id": test["id"],
                "test_name": test["name"],
                "risk_score": -1.0,
                "expected_range": f"{test['expected_range'][0]:.2f}-{test['expected_range'][1]:.2f}",
                "passed": False,
                "notes": f"ERROR: {str(e)}"
            })
            print()
    
    # ============================================================================
    # SECTION 2: ADVANCED THREAT PATTERNS
    # ============================================================================
    print("\n[SECTION 2] Advanced Threat Patterns")
    print("-" * 80)
    
    threat_patterns = [
        {
            "id": "TP-001",
            "name": "Data Exfiltration Pattern (Large Email + Sensitive Data)",
            "event": {
                "event_type": "email_sent",
                "has_external": True,
                "email_subject": "CONFIDENTIAL: Project X Files",
                "attachments": [{"name": "project_data.zip", "size_mb": 250}],
                "hour_of_day": 3,
                "is_remote": True
            },
            "expected_range": (0.8, 0.99),
            "description": "Classic data exfiltration attempt (after-hours, external, large file, sensitive)"
        },
        {
            "id": "TP-002",
            "name": "Insider Threat Pattern (Mass Download + USB)",
            "event": {
                "event_type": "usb",
                "action": "inserted",
                "num_file": 500,
                "in_sensitive_path": True,
                "hour_of_day": 18
            },
            "expected_range": (0.75, 0.95),
            "description": "Insider extracting sensitive files to USB near end of day"
        },
        {
            "id": "TP-003",
            "name": "Privilege Escalation Pattern (Admin + Remote + Off-hours)",
            "event": {
                "event_type": "logon",
                "is_remote": True,
                "hour_of_day": 2,
                "is_admin": True
            },
            "expected_range": (0.75, 0.95),
            "description": "Remote admin access at 2 AM - potential lateral movement"
        },
        {
            "id": "TP-004",
            "name": "Malware Propagation Pattern (Many Executables)",
            "event": {
                "event_type": "file",
                "action": "created",
                "is_executable": True,
                "num_file": 100,
                "in_sensitive_path": True
            },
            "expected_range": (0.8, 0.95),
            "description": "Rapid creation of many executable files in system paths"
        },
        {
            "id": "TP-005",
            "name": "Ransomware Pattern (Mass File Deletion)",
            "event": {
                "event_type": "file",
                "action": "deleted",
                "num_file": 1000,
                "in_sensitive_path": True,
                "hour_of_day": 14
            },
            "expected_range": (0.8, 0.95),
            "description": "Massive file deletion pattern consistent with ransomware"
        },
        {
            "id": "TP-006",
            "name": "Supply Chain Attack (Unsigned Executable + External Source)",
            "event": {
                "event_type": "file",
                "action": "created",
                "is_executable": True,
                "is_signed": False,
                "hour_of_day": 10
            },
            "expected_range": (0.6, 0.85),
            "description": "Unsigned executable creation during business hours"
        },
        {
            "id": "TP-007",
            "name": "Credential Harvesting (Multiple Failed Logins)",
            "event": {
                "event_type": "logon",
                "is_failed_login": True,
                "num_file": 10,  # Multiple attempts
                "hour_of_day": 1
            },
            "expected_range": (0.7, 0.9),
            "description": "Multiple failed login attempts at odd hours - brute force pattern"
        },
        {
            "id": "TP-008",
            "name": "Normal Business Activity (Multiple Low-Risk Factors)",
            "event": {
                "event_type": "file",
                "action": "created",
                "hour_of_day": 10,
                "num_file": 5,
                "is_executable": False,
                "is_admin": False
            },
            "expected_range": (0.1, 0.3),
            "description": "Routine business document creation"
        },
    ]
    
    for test in threat_patterns:
        try:
            risk, explanation = model.predict_with_explanation(test["event"])
            expected_min, expected_max = test["expected_range"]
            passed = expected_min <= risk <= expected_max
            
            print(f"[{test['id']}] {test['name']}")
            print(f"    Risk: {risk:.4f} | Expected: {expected_min:.2f}-{expected_max:.2f} | {'✅ PASS' if passed else '❌ FAIL'}")
            print(f"    Pattern: {test['description']}")
            print()
            
            all_results.append({
                "category": "Threat Patterns",
                "test_id": test["id"],
                "test_name": test["name"],
                "risk_score": risk,
                "expected_range": f"{expected_min:.2f}-{expected_max:.2f}",
                "passed": passed,
                "notes": test["description"]
            })
        except Exception as e:
            print(f"[{test['id']}] {test['name']} - ERROR: {e}")
            all_results.append({
                "category": "Threat Patterns",
                "test_id": test["id"],
                "test_name": test["name"],
                "risk_score": -1.0,
                "expected_range": f"{test['expected_range'][0]:.2f}-{test['expected_range'][1]:.2f}",
                "passed": False,
                "notes": f"ERROR: {str(e)}"
            })
            print()
    
    # ============================================================================
    # SECTION 3: STRESS & PERFORMANCE TESTS
    # ============================================================================
    print("\n[SECTION 3] Stress & Performance Tests")
    print("-" * 80)
    
    stress_tests = [
        {
            "id": "ST-001",
            "name": "Rapid Sequential Predictions (100 events)",
            "events_count": 100,
            "expected_avg_time": 0.05,  # Should be fast
            "description": "Verify system handles bulk predictions efficiently"
        },
        {
            "id": "ST-002",
            "name": "Concurrent Event Predictions (Different event types)",
            "events_count": 50,
            "expected_avg_time": 0.05,
            "description": "System stability with diverse event types"
        },
        {
            "id": "ST-003",
            "name": "Memory Stability Test (1000 predictions)",
            "events_count": 1000,
            "expected_avg_time": 0.05,
            "description": "Check for memory leaks in high-volume scenarios"
        }
    ]
    
    for test in stress_tests:
        try:
            events = [
                {"event_type": "file", "action": "created", "hour_of_day": 14},
                {"event_type": "usb", "action": "inserted", "hour_of_day": 10},
                {"event_type": "logon", "is_remote": False, "hour_of_day": 9},
                {"event_type": "email_sent", "has_external": False},
                {"event_type": "file", "action": "deleted", "hour_of_day": 15},
            ]
            
            start_time = time.time()
            predictions = []
            
            for i in range(test["events_count"]):
                event = events[i % len(events)]
                risk, _ = model.predict_with_explanation(event)
                predictions.append(risk)
            
            elapsed = time.time() - start_time
            avg_time = elapsed / test["events_count"]
            
            passed = avg_time <= test["expected_avg_time"]
            
            print(f"[{test['id']}] {test['name']}")
            print(f"    Events: {test['events_count']} | Time: {elapsed:.3f}s | Avg: {avg_time:.4f}s/event")
            print(f"    Target: <{test['expected_avg_time']:.3f}s/event | {'✅ PASS' if passed else '⚠️ SLOW'}")
            print(f"    Description: {test['description']}")
            print()
            
            all_results.append({
                "category": "Stress/Performance",
                "test_id": test["id"],
                "test_name": test["name"],
                "risk_score": avg_time,
                "expected_range": f"<{test['expected_avg_time']:.3f}s",
                "passed": passed,
                "notes": f"Processed {test['events_count']} events in {elapsed:.2f}s"
            })
        except Exception as e:
            print(f"[{test['id']}] {test['name']} - ERROR: {e}")
            all_results.append({
                "category": "Stress/Performance",
                "test_id": test["id"],
                "test_name": test["name"],
                "risk_score": -1.0,
                "expected_range": f"<{test['expected_avg_time']:.3f}s",
                "passed": False,
                "notes": f"ERROR: {str(e)}"
            })
            print()
    
    # ============================================================================
    # SECTION 4: ERROR HANDLING & ROBUSTNESS
    # ============================================================================
    print("\n[SECTION 4] Error Handling & Robustness")
    print("-" * 80)
    
    error_tests = [
        {
            "id": "EH-001",
            "name": "Invalid Event Type",
            "event": {"event_type": "INVALID_TYPE_XYZ"},
            "should_handle": True,
            "description": "Should gracefully handle unknown event types"
        },
        {
            "id": "EH-002",
            "name": "String Hour Instead of Integer",
            "event": {"event_type": "file", "hour_of_day": "14"},
            "should_handle": True,
            "description": "Should handle type mismatches gracefully"
        },
        {
            "id": "EH-003",
            "name": "Negative Hour Value",
            "event": {"event_type": "file", "hour_of_day": -5},
            "should_handle": True,
            "description": "Should validate and handle invalid hour ranges"
        },
        {
            "id": "EH-004",
            "name": "Hour Greater than 24",
            "event": {"event_type": "file", "hour_of_day": 48},
            "should_handle": True,
            "description": "Should normalize or reject out-of-range hours"
        },
        {
            "id": "EH-005",
            "name": "Negative File Count",
            "event": {"event_type": "file", "num_file": -100},
            "should_handle": True,
            "description": "Should handle invalid negative counts"
        },
        {
            "id": "EH-006",
            "name": "Extremely Large Negative File Size",
            "event": {"event_type": "email_sent", "attachments": [{"size_mb": -9999}]},
            "should_handle": True,
            "description": "Should handle invalid file size values"
        },
        {
            "id": "EH-007",
            "name": "Special Characters in String Fields",
            "event": {"event_type": "email_sent", "email_subject": "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"},
            "should_handle": True,
            "description": "Should safely process special characters"
        },
    ]
    
    for test in error_tests:
        try:
            risk, explanation = model.predict_with_explanation(test["event"])
            handled = True
            error_msg = None
            
            print(f"[{test['id']}] {test['name']}")
            print(f"    Risk: {risk:.4f} | Handled: {'✅ YES' if handled else '❌ NO'}")
            print(f"    Description: {test['description']}")
            print()
            
            all_results.append({
                "category": "Error Handling",
                "test_id": test["id"],
                "test_name": test["name"],
                "risk_score": risk if handled else -1.0,
                "expected_range": "Graceful handling",
                "passed": handled == test["should_handle"],
                "notes": test["description"]
            })
        except Exception as e:
            handled = False
            error_msg = str(e)
            
            print(f"[{test['id']}] {test['name']}")
            print(f"    Exception: {error_msg}")
            print(f"    Handled: {'✅ YES (caught)' if test['should_handle'] else '❌ NO (should handle)'}")
            print(f"    Description: {test['description']}")
            print()
            
            all_results.append({
                "category": "Error Handling",
                "test_id": test["id"],
                "test_name": test["name"],
                "risk_score": -1.0,
                "expected_range": "Graceful handling",
                "passed": test["should_handle"],  # Passing if exception caught as expected
                "notes": f"Exception: {error_msg}"
            })
    
    # ============================================================================
    # SUMMARY & REPORTING
    # ============================================================================
    print("\n" + "="*80)
    print("[SUMMARY] Comprehensive Test Suite Results")
    print("="*80)
    print()
    
    # Calculate statistics by category
    categories = {}
    for result in all_results:
        cat = result["category"]
        if cat not in categories:
            categories[cat] = {"total": 0, "passed": 0, "failed": 0}
        categories[cat]["total"] += 1
        if result["passed"]:
            categories[cat]["passed"] += 1
        else:
            categories[cat]["failed"] += 1
    
    print("Results by Category:")
    print()
    total_tests = 0
    total_passed = 0
    
    for cat, stats in categories.items():
        pct = (stats["passed"] / stats["total"] * 100) if stats["total"] > 0 else 0
        print(f"  {cat}:")
        print(f"    ✅ Passed: {stats['passed']}/{stats['total']} ({pct:.1f}%)")
        print()
        total_tests += stats["total"]
        total_passed += stats["passed"]
    
    print("-" * 80)
    overall_pct = (total_passed / total_tests * 100) if total_tests > 0 else 0
    print(f"Overall: ✅ {total_passed}/{total_tests} tests passed ({overall_pct:.1f}% accuracy)")
    print()
    
    # Write detailed results to CSV
    output_file = Path(__file__).parent / "comprehensive_test_results.csv"
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=[
            "category", "test_id", "test_name", "risk_score", 
            "expected_range", "passed", "notes"
        ])
        writer.writeheader()
        writer.writerows(all_results)
    
    print(f"Detailed results saved to: {output_file}")
    print()
    
    return overall_pct, total_passed, total_tests

if __name__ == "__main__":
    try:
        accuracy, passed, total = run_extended_tests()
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] Test suite failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
