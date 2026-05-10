import requests
import random

with open("xsspayloads.txt", "r") as f:
    payloads = f.read().splitlines()

blocked = 0
allowed = 0

for payload in payloads:
    try:
        url = f"http://localhost:8888/search?q={payload}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 403:
                blocked += 1
            else:
                allowed += 1
        except requests.Timeout:
            print(f"Timeout with payload: {payload}")

        except requests.RequestException as exc:
            print(f"Error with payload: {payload} | Exception: {exc}")
    except:
        pass

print(f"Blocked: {blocked}, Allowed: {allowed}")