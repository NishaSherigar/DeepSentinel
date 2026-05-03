import requests
import json
from datetime import datetime

base_url = "http://localhost:5000"

# Test 1: After-hours login (3 AM - outside 9am-5pm)
print("=" * 60)
print("TEST 1: After-Hours Login Alert")
print("=" * 60)

after_hours_event = {
    "event_type": "logon",
    "action": "user_logon",
    "username": "testuser_night",
    "timestamp": datetime.utcnow().isoformat(),
    "hour_of_day": 3,  # 3 AM
    "risk_score": 0.6,
    "alert": True,
    "alert_message": "SECURITY ALERT: Login at 03:00 - Outside business hours (09:00-17:00)"
}

response = requests.post(
    f"{base_url}/receive_log",
    json=after_hours_event,
    headers={"Content-Type": "application/json"}
)
print(f"Status: {response.status_code}")
print(f"Response: {json.dumps(response.json(), indent=2)}")

# Test 2: Large USB transfer (15GB)
print("\n" + "=" * 60)
print("TEST 2: Large USB Transfer Alert (15GB)")
print("=" * 60)

usb_event = {
    "event_type": "usb",
    "action": "plugged",
    "agent_id": "LAPTOP-TEST-001",
    "username": "securitytester",
    "timestamp": datetime.utcnow().isoformat(),
    "drive": "E:\\",
    "device_type": "removable_storage",
    "total_size_gb": 15.5,
    "free_space_gb": 14.2,
    "risk_score": 0.8
}

response = requests.post(
    f"{base_url}/receive_log",
    json=usb_event,
    headers={"Content-Type": "application/json"}
)
print(f"Status: {response.status_code}")
print(f"Response: {json.dumps(response.json(), indent=2)}")

# Test 3: Check dashboard alerts
print("\n" + "=" * 60)
print("TEST 3: Fetching Dashboard Alerts")
print("=" * 60)

response = requests.get(f"{base_url}/api/dashboard/alerts")
if response.status_code == 200:
    alerts_response = response.json()
    # Handle either list of alerts or dict with alerts key
    if isinstance(alerts_response, list):
        alerts = alerts_response
    else:
        alerts = alerts_response if isinstance(alerts_response, list) else []
    
    print(f"Total alerts fetched: {len(alerts)}")
    print("\nLatest alerts:")
    for i, alert in enumerate(alerts[-10:] if alerts else [], 1):
        if isinstance(alert, dict):
            print(f"\n  {i}. [{alert.get('time')}]")
            print(f"     User: {alert.get('user')}")
            print(f"     Metric: {alert.get('metric')}")
            print(f"     Severity: {alert.get('severity', 'MEDIUM')}")
            print(f"     Note: {alert.get('note')}")
else:
    print(f"Error fetching alerts: {response.status_code}")

print("\n✅ Test completed!")
