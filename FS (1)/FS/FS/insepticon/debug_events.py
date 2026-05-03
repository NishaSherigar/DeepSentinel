import json
from pathlib import Path
from collections import Counter

events_file = Path('data/user_activity.jsonl.fixed')

# Get DESKTOP-HOST-001 events
user_events = []
with open(events_file, 'r', encoding='utf-8', errors='replace') as f:
    for line in f:
        if not line.strip():
            continue
        try:
            event = json.loads(line)
            events = [event] if isinstance(event, dict) else event if isinstance(event, list) else []
            
            for e in events:
                if isinstance(e, dict):
                    user = e.get('user') or e.get('username') or e.get('agent_id')
                    if user == 'DESKTOP-HOST-001':
                        user_events.append(e)
        except:
            pass

print(f'Total events for DESKTOP-HOST-001: {len(user_events)}')
print('\nEvent types:')
type_counter = Counter(e.get('event_type') for e in user_events)
for et, count in type_counter.most_common(15):
    print(f'  {et}: {count}')

if user_events:
    print('\nSample events (first 3):')
    for i, e in enumerate(user_events[:3]):
        print(f'\nSample {i+1}:')
        print(f'  Type: {e.get("event_type")}')
        print(f'  User field: {e.get("user")}')
        print(f'  Agent ID: {e.get("agent_id")}')
        print(f'  Timestamp: {e.get("timestamp")}')
        print(f'  Keys: {list(e.keys())}')
