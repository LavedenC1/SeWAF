from mitmproxy import http
from mitmproxy.tools.main import mitmdump
import json
import csv
import re
from pathlib import Path
from ai_detector.detector import Detector
from urllib.parse import unquote, unquote_plus, parse_qs

LOG_DATA = True

if LOG_DATA:
    DATA_FILE = Path(__file__).resolve().with_name("data.json")

    if not DATA_FILE.exists():
        DATA_FILE.write_text("{\"data\":[]}", encoding="utf-8")

class SeWAF:
    def __init__(self):
        with open("custom/custom_rules.txt", "r") as f:
            self.blocked_patterns = [line.strip() for line in f if line.strip()]
        with open("custom/blocked_ips.txt", "r") as f:
            self.blocked_ips = {line.strip() for line in f if line.strip()}
    
    def request(self, flow: http.HTTPFlow) -> None:
        client_ip = flow.client_conn.address[0]
        if client_ip in self.blocked_ips:
            flow.response = http.Response.make(403, "Access Denied")
            return
        
        full_text = unquote(flow.request.path + (flow.request.text or ""))
        if LOG_DATA:
            try:
                with DATA_FILE.open("r", encoding="utf-8") as f:
                    data = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                data = {"data": []}

            data.setdefault("data", []).append(full_text)

            with DATA_FILE.open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
        
        # Custom rules
        for pattern in self.blocked_patterns:
            if re.search(pattern, full_text, re.IGNORECASE):
                flow.response = http.Response.make(403, "Malicious Request Blocked")
                return
        
        # AI Detection :D
        detector = Detector()
        if detector.is_malicious(full_text):
            flow.response = http.Response.make(403, "Malicious Request Blocked")
            return

addons = [SeWAF()]