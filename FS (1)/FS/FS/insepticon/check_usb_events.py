import json

# Check what USB events look like
usb_count = 0
with open('data/user_activity.jsonl.fixed', 'r', encoding='utf-8', errors='ignore') as f:
    for i, line in enumerate(f):
        if i > 20000:  # Check first 20K lines
            break
        try:
            evt = json.loads(line)
            if evt.get('event_type') == 'usb':
                print(f"\n=== USB Event #{usb_count + 1} ===")
                print(json.dumps(evt, indent=2))
                usb_count += 1
                if usb_count >= 3:
                    break
        except:
            pass

print(f"\n\nTotal USB events checked: {usb_count}")
