# LWAF

LWAF is a small lab for experimenting with a reverse-proxy web application firewall and a deliberately vulnerable Flask target app. The root project runs a mitmproxy addon that blocks requests using custom regex rules, a blocked IP list, and a simple machine-learning detector.

This repository is intended for testing and training only. The demo app under `vuln_app/` contains intentional security flaws such as reflected XSS, SQL injection, unsafe file handling, SSRF, and an insecure admin cookie.

## What’s in the repo

- `main.py` - mitmproxy addon that inspects requests, stores observed traffic in `data.json`, applies custom rules, and calls the ML detector.
- `run.sh` - convenience script that starts the proxy in reverse mode on port `8888` and forwards to the demo app on `127.0.0.1:5001`.
- `requestify.py` - sends a list of XSS payloads through the proxy for testing.
- `convert.py` - converts captured requests from `data.json` into `output.jsonl` for model training.
- `ai_detector/detector.py` - loads `waf.pkl` and predicts whether a request is malicious.
- `ai_detector/train.py` - trains a character-level TF-IDF + LinearSVC model from `data.jsonl` and writes `waf.pkl`.
- `custom/custom_rules.txt` - regex patterns for signature-based blocking.
- `custom/blocked_ips.txt` - IPs that are blocked before inspection.
- `xsspayloads.txt` - payload list used by `requestify.py`.
- `vuln_app/` - Flask demo app with intentionally vulnerable routes and a static landing page.

## How it works

The proxy flow in `main.py` is:

1. Check the client IP against `custom/blocked_ips.txt`.
2. Append the request path and body to `data.json`.
3. Match the request against regexes from `custom/custom_rules.txt`.
4. Ask the ML detector whether the request is malicious.
5. Return `403` if any check flags the request.

The detector currently loads `waf.pkl`, which is a scikit-learn pipeline trained on character n-grams. If you change the dataset, retrain the model and replace the pickle.

## Setup

Create and activate a virtual environment, then install the proxy/runtime dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If you want to run the demo app by itself, you can also install its local requirements:

```bash
pip install -r vuln_app/requirements.txt
```

If you plan to rebuild the model, also install the training stack:

```bash
pip install pandas scikit-learn joblib
```

## Run the vulnerable app

Start the Flask app from the `vuln_app/` directory:

```bash
cd vuln_app
python app.py
```

It listens on `http://127.0.0.1:5001` and serves the landing page from `vuln_app/static/index.html`.

## Run the WAF proxy

From the repository root, start mitmproxy in reverse mode:

```bash
bash run.sh
```

That launches the proxy on port `8888` and forwards traffic to the vulnerable app on port `5001`.

## Test payloads

With the proxy running, you can replay the bundled XSS payloads through the WAF:

```bash
python requestify.py
```

The script sends requests to `/xss` through the proxy and prints the status code for each payload.

## Train or rebuild the model

If you want to regenerate the model:

1. Capture requests in `data.json` by running the proxy.
2. Convert the captured data into JSONL:

```bash
python convert.py
```

3. Ensure the resulting `data.jsonl` has the right labels.
4. Train the model:

```bash
python ai_detector/train.py
```

This writes a new `waf.pkl` at the repository root.

## Demo routes

The vulnerable app exposes these examples:

- `/xss?q=...` - reflected XSS
- `/login?username=...&password=...` - SQL injection demo
- `/file?name=...` - unsafe file read / traversal demo
- `/upload` - file upload without validation
- `/ssrf?url=...` - server-side request forgery demo
- `/echo?msg=...` - raw HTML echo
- `/set_admin` and `/admin` - insecure cookie-based admin check

## Notes

- `main.py` creates `data.json` automatically if it does not exist.
- `custom/custom_rules.txt` is empty by default, so signature-based blocking only works after you add rules.
- `custom/blocked_ips.txt` currently contains one example IP.
- The project is noisy by design and should not be used as a production security control.