import json
import os

# Check alerts.jsonl file directly
alerts_file = 'data/alerts.jsonl'
if os.path.exists(alerts_file):
    with open(alerts_file, 'r', encoding='utf-8', errors='ignore') as f:
        alerts = [json.loads(line) for line in f if line.strip()]
        print(f"✅ Total alerts in system: {len(alerts)}")
        print("\n📋 Latest 10 alerts:")
        for i, alert in enumerate(alerts[-10:], 1):
            severity_icon = "🔴" if alert.get('severity') == 'CRITICAL' else "🟠" if alert.get('severity') == 'HIGH' else "🟡"
            print(f"\n{i}. {severity_icon} [{alert.get('time')}]")
            print(f"   User: {alert.get('user')}")
            print(f"   Metric: {alert.get('metric')}")
            print(f"   Note: {alert.get('note')}")
else:
    print("❌ No alerts file found")
