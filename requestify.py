import requests

proxies = {
    "http": "http://localhost:8888"
}

with open("xsspayloads.txt", "r") as f:
    payloads = f.read().splitlines()

for payload in payloads:
    url = f"http://localhost:5001/xss?q={payload}"
    try:
        response = requests.get(url, proxies=proxies, timeout=5)
        print(f"Payload: {payload} | Status Code: {response.status_code}")
    except requests.RequestException as exc:
        print(f"Error with payload: {payload} | Exception: {exc}")
