#!/bin/bash

mitmproxy -s main.py --mode reverse:http://127.0.0.1:5001 --listen-port 8888