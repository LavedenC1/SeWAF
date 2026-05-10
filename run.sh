#!/bin/bash

UNPROTECTED_PORT=5001
PROTECTED_PORT=8888

# run this in the virtual environment
mitmproxy -s main.py --mode reverse:http://127.0.0.1:$UNPROTECTED_PORT --listen-port $PROTECTED_PORT