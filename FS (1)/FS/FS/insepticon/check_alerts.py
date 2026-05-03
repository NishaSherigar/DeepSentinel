import json
import os

# Check what alerts currently exist
try:
    alerts_file = 'data/alerts.jsonl'
    if os.path.exists(alerts_file):
        with open(alerts_file, 'r', encoding='utf-8') as f:
            alerts = [json.loads(line) for line in f if line.strip()]
            print(f'Total alerts: {len(alerts)}')
            print('\nAlert types:')
            alert_types = {}
            for a in alerts:
                mt = a.get('metric', 'unknown')
                alert_types[mt] = alert_types.get(mt, 0) + 1
            for mt, count in sorted(alert_types.items(), key=lambda x: -x[1]):
                print(f'  {mt}: {count}')
            
            print('\nRecent alerts:')
            for a in alerts[-5:]:
                print(f"  [{a.get('time')}] {a.get('user')}: {a.get('metric')} - {a.get('note')}")
    else:
        print('No alerts file found yet')
except Exception as e:
    print(f'Error: {e}')
