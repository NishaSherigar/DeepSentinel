"""
Fixed Validation Script - Standalone Version
Tests model with independent scenarios (no session accumulation)
"""

import sys
sys.path.append(r'C:\Users\Dell\Desktop\insepticon')

# Force reload of connect_models
import importlib
if 'connect_models' in sys.modules:
    importlib.reload(sys.modules['connect_models'])

from connect_models import threat_model, user_session_data
import pandas as pd
import time

# Color codes
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def clear_session(agent_id):
    """Clear session data for independent testing"""
    if agent_id in user_session_data:
        del user_session_data[agent_id]

def print_header(text):
    print("\n" + "="*80)
    print(Colors.BOLD + text + Colors.END)
    print("="*80)

def print_test(scenario_num, description):
    print(f"\n{Colors.BLUE}📋 Test {scenario_num}: {description}{Colors.END}")

def print_result(risk_score, expected_range, reasons):
    if risk_score < 0.4:
        color = Colors.GREEN
        emoji = "🟢"
        level = "LOW"
    elif risk_score < 0.7:
        color = Colors.YELLOW
        emoji = "🟡"
        level = "MEDIUM"
    else:
        color = Colors.RED
        emoji = "🔴"
        level = "HIGH/CRITICAL"
    
    print(f"{color}   {emoji} Risk Score: {risk_score:.3f} ({level}){Colors.END}")
    print(f"   Expected Range: {expected_range}")
    
    min_risk, max_risk = map(float, expected_range.split('-'))
    if min_risk <= risk_score <= max_risk:
        print(f"   {Colors.GREEN}✅ PASS - Within expected range{Colors.END}")
    else:
        print(f"   {Colors.RED}❌ FAIL - Outside expected range{Colors.END}")
    
    print(f"   Reasons:")
    for reason in reasons[:3]:
        print(f"      • {reason}")

test_scenarios = [
    {
        "num": 1,
        "description": "Normal Document Creation (Business Hours)",
        "event": {
            "agent_id": "TEST-1",
            "event_type": "file",
            "action": "file_created",
            "is_executable": False,
            "is_document": True,
            "in_sensitive_path": False,
            "hour_of_day": 10,
            "day_of_week": "Wednesday",
            "file_size": 15000
        },
        "expected_range": "0.1-0.35"
    },
    {
        "num": 2,
        "description": "Executable File Creation (After Hours)",
        "event": {
            "agent_id": "TEST-2",
            "event_type": "file",
            "action": "file_created",
            "is_executable": True,
            "in_sensitive_path": True,
            "hour_of_day": 23,
            "day_of_week": "Saturday",
            "file_size": 1024000
        },
        "expected_range": "0.65-0.9"
    },
    {
        "num": 3,
        "description": "USB Device Plugged (Business Hours)",
        "event": {
            "agent_id": "TEST-3",
            "event_type": "usb",
            "action": "plugged",
            "drive": "E:\\",
            "total_size_gb": 8.0,
            "hour_of_day": 14,
            "day_of_week": "Monday"
        },
        "expected_range": "0.5-0.8"
    },
    {
        "num": 4,
        "description": "USB Device Plugged (After Hours)",
        "event": {
            "agent_id": "TEST-4",
            "event_type": "usb",
            "action": "plugged",
            "drive": "E:\\",
            "total_size_gb": 16.0,
            "hour_of_day": 3,
            "day_of_week": "Sunday"
        },
        "expected_range": "0.75-0.95"
    },
    {
        "num": 5,
        "description": "User Login (Business Hours)",
        "event": {
            "agent_id": "TEST-5",
            "event_type": "logon",
            "action": "user_logon",
            "user": "John.Doe",
            "logon_type": "2",
            "is_remote": False,
            "hour_of_day": 9,
            "day_of_week": "Tuesday"
        },
        "expected_range": "0.1-0.35"
    },
    {
        "num": 6,
        "description": "Remote Login (After Hours)",
        "event": {
            "agent_id": "TEST-6",
            "event_type": "logon",
            "action": "user_logon",
            "user": "John.Doe",
            "logon_type": "10",
            "is_remote": True,
            "hour_of_day": 2,
            "day_of_week": "Sunday"
        },
        "expected_range": "0.6-0.85"
    },
    {
        "num": 7,
        "description": "Bulk File Activity (50 files in session)",
        "event": {
            "agent_id": "TEST-BULK",
            "event_type": "file",
            "action": "file_created",
            "is_executable": False,
            "in_sensitive_path": True,
            "hour_of_day": 15,
            "day_of_week": "Thursday",
            "file_size": 5000
        },
        "expected_range": "0.5-0.75",
        "simulate_bulk": 50
    },
    {
        "num": 8,
        "description": "File Deletion (Sensitive Path)",
        "event": {
            "agent_id": "TEST-8",
            "event_type": "file",
            "action": "file_deleted",
            "is_executable": False,
            "in_sensitive_path": True,
            "hour_of_day": 16,
            "day_of_week": "Friday",
            "file_size": 50000
        },
        "expected_range": "0.35-0.65"
    },
    {
        "num": 9,
        "description": "Weekend Activity (Normal Document)",
        "event": {
            "agent_id": "TEST-9",
            "event_type": "file",
            "action": "file_created",
            "is_executable": False,
            "in_sensitive_path": False,
            "hour_of_day": 11,
            "day_of_week": "Saturday",
            "file_size": 10000
        },
        "expected_range": "0.2-0.5"
    },
    {
        "num": 10,
        "description": "Multiple Risk Factors (Worst Case)",
        "event": {
            "agent_id": "TEST-10",
            "event_type": "file",
            "action": "file_deleted",
            "is_executable": True,
            "in_sensitive_path": True,
            "hour_of_day": 3,
            "day_of_week": "Sunday",
            "file_size": 5000000,
            "has_special_chars": True
        },
        "expected_range": "0.8-0.95",
        "add_usb": True
    }
]

def run_validation():
    print_header("🧪 INSIDER THREAT DETECTION - VALIDATION TEST (FIXED)")
    
    print(f"\n{Colors.BOLD}Model Status:{Colors.END}")
    print(f"   Isolation Forest: {'✅' if threat_model.isolation_forest else '❌'}")
    print(f"   Autoencoder: {'✅' if threat_model.autoencoder else '❌'}")
    print(f"   Scaler: {'✅' if threat_model.scaler else '❌'}")
    
    results = []
    passed = 0
    failed = 0
    
    for scenario in test_scenarios:
        print_test(scenario["num"], scenario["description"])
        
        # Clear session for independent test
        agent_id = scenario["event"]["agent_id"]
        clear_session(agent_id)
        
        # Simulate bulk activity
        if scenario.get("simulate_bulk"):
            count = scenario["simulate_bulk"]
            print(f"   📊 Simulating {count} file events in same session...")
            for i in range(count):
                threat_model.predict_with_explanation(scenario["event"])
        
        # Add USB event if needed
        if scenario.get("add_usb"):
            print(f"   💾 Adding USB activity to same session...")
            usb_event = {
                "agent_id": agent_id,
                "event_type": "usb",
                "action": "plugged",
                "hour_of_day": scenario["event"]["hour_of_day"],
                "day_of_week": scenario["event"]["day_of_week"]
            }
            threat_model.predict_with_explanation(usb_event)
        
        # Final prediction
        risk_score, explanation = threat_model.predict_with_explanation(scenario["event"])
        
        print_result(risk_score, scenario["expected_range"], explanation["top_factors"])
        
        # Check pass/fail
        min_risk, max_risk = map(float, scenario["expected_range"].split('-'))
        is_pass = min_risk <= risk_score <= max_risk
        
        if is_pass:
            passed += 1
        else:
            failed += 1
        
        results.append({
            "test": scenario["num"],
            "description": scenario["description"],
            "risk_score": risk_score,
            "expected": scenario["expected_range"],
            "passed": is_pass
        })
        
        time.sleep(0.3)
    
    # Summary
    print_header("📊 VALIDATION SUMMARY")
    
    total = len(test_scenarios)
    accuracy = (passed / total) * 100
    
    print(f"\n{Colors.BOLD}Results:{Colors.END}")
    print(f"   Total Tests: {total}")
    print(f"   {Colors.GREEN}Passed: {passed} ✅{Colors.END}")
    print(f"   {Colors.RED}Failed: {failed} ❌{Colors.END}")
    print(f"   {Colors.BOLD}Accuracy: {accuracy:.1f}%{Colors.END}")
    
    if accuracy >= 90:
        grade = "A+"
        comment = "Excellent! Production ready."
        color = Colors.GREEN
    elif accuracy >= 80:
        grade = "A"
        comment = "Very Good! Minor tuning needed."
        color = Colors.GREEN
    elif accuracy >= 70:
        grade = "B"
        comment = "Good! Some improvements recommended."
        color = Colors.YELLOW
    elif accuracy >= 60:
        grade = "C"
        comment = "Acceptable. Needs calibration."
        color = Colors.YELLOW
    else:
        grade = "D"
        comment = "Needs significant improvement."
        color = Colors.RED
    
    print(f"\n{color}{Colors.BOLD}Grade: {grade}{Colors.END}")
    print(f"{color}Assessment: {comment}{Colors.END}")
    
    # Detailed results
    print(f"\n{Colors.BOLD}Detailed Results:{Colors.END}")
    print("-" * 80)
    print(f"{'Test':<6} {'Description':<42} {'Risk':<8} {'Expected':<12} {'Result':<8}")
    print("-" * 80)
    
    for r in results:
        status = f"{Colors.GREEN}PASS{Colors.END}" if r['passed'] else f"{Colors.RED}FAIL{Colors.END}"
        desc = r['description'][:40]
        print(f"{r['test']:<6} {desc:<42} {r['risk_score']:<8.3f} {r['expected']:<12} {status}")
    
    print("-" * 80)
    
    # Performance comparison
    print(f"\n{Colors.BOLD}Performance Comparison:{Colors.END}")
    print(f"   Your System:        {accuracy:.1f}%")
    print(f"   Research Papers:    88-94%")
    print(f"   Industry Standard:  85-90%")
    
    if accuracy >= 85:
        print(f"\n   {Colors.GREEN}✅ Meets/exceeds industry standards!{Colors.END}")
    elif accuracy >= 70:
        print(f"\n   {Colors.YELLOW}⚠️ Close to target, minor tuning needed{Colors.END}")
    else:
        print(f"\n   {Colors.RED}❌ Needs significant calibration{Colors.END}")
    
    # Save results
    df = pd.DataFrame(results)
    df.to_csv('validation_results_fixed.csv', index=False)
    print(f"\n{Colors.BOLD}Results exported to: validation_results_fixed.csv{Colors.END}")
    
    # Recommendations
    print(f"\n{Colors.BOLD}Recommendations:{Colors.END}")
    if accuracy >= 85:
        print(f"   {Colors.GREEN}✅ System validated! Ready for deployment{Colors.END}")
        print(f"   • Monitor false positives in production")
        print(f"   • Consider adding SHAP explanations")
    else:
        print(f"   • Review failed test cases")
        if failed > 0:
            print(f"   • Adjust model threshold or retrain")
        print(f"   • Collect more diverse training data")

if __name__ == "__main__":
    print(f"\n{Colors.BOLD}Fixed Validation Suite{Colors.END}")
    print(f"Each test uses independent session (no accumulation)\n")
    
    input("Press Enter to begin...")
    
    start_time = time.time()
    run_validation()
    end_time = time.time()
    
    print(f"\n{Colors.BOLD}Execution time: {end_time - start_time:.2f}s{Colors.END}")
    print(f"\n{Colors.GREEN}{Colors.BOLD}✅ Validation complete!{Colors.END}\n")