# Convert data.json to output.jsonl with sanitization and etc
# LINE 32: CHANGE 1 FOR MALICIOUS

import json
import base64
import re

def sanitize_value(value):
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            value = base64.b64encode(value).decode("ascii")

    if not isinstance(value, str):
        value = str(value)

    value = value.replace("\x00", "")
    value = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
    return value

with open('data.json', 'r') as f:
    json_data = json.load(f)
    requests = json_data.get("data", [])

with open('output.jsonl', 'w', encoding='utf-8') as file:
    for item in requests:
        record = {
            "body": sanitize_value(item),

            # XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
            "label": 1, # CHANGE 1 FOR MALICIOUS
            # XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
            
        }
        file.write(json.dumps(record, ensure_ascii=False) + "\n")