import json
from pathlib import Path

events_file = Path('data/user_activity.jsonl.fixed')

# Simulate what server.py's _expand_possible_wrapper does
def expand(raw_evt):
    out = []
    if isinstance(raw_evt, list):
        for item in raw_evt:
            out.extend(expand(item))
        return out
    if isinstance(raw_evt, dict):
        if 'events' in raw_evt and isinstance(raw_evt['events'], list):
            for sub in raw_evt['events']:
                if isinstance(sub, dict):
                    if 'agent_id' not in sub:
                        sub['agent_id'] = raw_evt.get('agent_id')
                    out.append(sub)
            return out
    out.append(raw_evt)
    return out

# Count expanded events for DESKTOP-HOST-001
count = 0
file_count = 0
usb_count = 0
process_count = 0
sample_events = []

with open(events_file, 'r', encoding='utf-8', errors='replace') as f:
    for line in f:
        if not line.strip():
            continue
        try:
            event = json.loads(line)
            expanded = expand(event)
            
            for e in expanded:
                if isinstance(e, dict):
                    agent = e.get('agent_id')
                    if agent == 'DESKTOP-HOST-001':
                        count += 1
                        et = e.get('event_type')
                        if et == 'file':
                            file_count += 1
                        elif et == 'usb':
                            usb_count += 1
                        elif et == 'process':
                            process_count += 1
                        
                        if len(sample_events) < 5:
                            sample_events.append(e)
        except Exception as ex:
            pass

print(f'DESKTOP-HOST-001 events after expansion: {count}')
print(f'  File events: {file_count}')
print(f'  USB events: {usb_count}')
print(f'  Process events: {process_count}')

print('\nSample expanded events:')
for i, e in enumerate(sample_events):
    et = e.get('event_type')
    agent = e.get('agent_id')
    ts = e.get('timestamp')
    print(f'Event {i+1}: type={et}, agent={agent}, timestamp={ts}')
