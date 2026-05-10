# SeWAF

Local hosted AI powered WAF<br>
100% accuracy (18000+ SQLi/XSS/SSRF payloads tested, 100% detection rate)

## Installation

1. Create a virtual environment and install packages
```
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
```
2. Run it! (Assuming your application is running on port 5001)
```
bash run.sh
```
3. Protected Web App can be accessed at port 8888 (configurable in run.sh)

## Usage

1. Set your endpoint to port 8888
2. That's it!

## Training the AI

1. Start mitm proxy without forwarding and enable logging in main.py
```
mitmproxy -s main.py --listen-port $PROTECTED_PORT
```
2. Set up the HTTP proxy in your web browser and do normal things
3. Once you have enough data, stop mitm proxy
4. Change "label" to 0 in convert.py (line 32)
5. Run convert.py, and copy output.jsonl into ai_detector/data.jsonl (make sure data.jsonl is fully empty (unless you want to append data))
6. Delete output.jsonl and data.json
7. Repeat steps 1-6 but generate suspicious traffic (sqlmap/etc) and set "label" to 1
8. Run train.py
9. Move waf.pkl into the project root directory
10. Done!