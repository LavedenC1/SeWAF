import asyncio
from datetime import datetime
import json
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import unquote
from mitmproxy import http
from ai_detector.detector import Detector

global config

with open("config.json", "r", encoding="utf-8") as config_file:
    config = json.load(config_file)

WORKER_THREADS = config["worker_threads"]

BLOCK_PAGE = Path(__file__).resolve().parent / "static" / "blocked.html"

LOG_TRAINING_DATA = config["ai_data"]["log_training_data"]
TRAINING_DATA_FILE = Path(__file__).resolve().with_name(config["ai_data"]["training_data_output_file"])
TRAINING_DATA_IS_MALICIOUS = int(config["ai_data"]["is_malicious"])

if LOG_TRAINING_DATA and not TRAINING_DATA_FILE.exists():
    TRAINING_DATA_FILE.write_text('', encoding="utf-8")

class SeWAF:
    def __init__(self) -> None:
        global config
        allow_patterns = config["allow_rules"]
        self._allow_rules = [re.compile(p, re.IGNORECASE) for p in allow_patterns]

        block_patterns = config["block_rules"]
        self._block_rules = [re.compile(p, re.IGNORECASE) for p in block_patterns]

        self._blocked_ips = set(config["blocked_ip_addresses"])
        self._detector = Detector()
        self._block_html = BLOCK_PAGE.read_bytes()

        self._executor = ThreadPoolExecutor(max_workers=WORKER_THREADS,
                                            thread_name_prefix="sewaf")

        self._log_queue: asyncio.Queue[str] = asyncio.Queue()
        self._log_task: asyncio.Task | None = None

    def running(self) -> None:
        if LOG_TRAINING_DATA:
            self._log_task = asyncio.get_event_loop().create_task(
                self._generate_training_data(), name="sewaf-log-writer"
            )

    def done(self) -> None:
        self._executor.shutdown(wait=True)
        if self._log_task:
            self._log_task.cancel()

    async def request(self, flow: http.HTTPFlow) -> None:
        client_ip = flow.client_conn.address[0]

        if client_ip in self._blocked_ips:
            flow.response = http.Response.make(403, "Access Denied")
            return

        full_text = unquote(flow.request.path + " -- " + (flow.request.text or ""))

        if LOG_TRAINING_DATA:
            await self._log_queue.put(full_text)

        loop = asyncio.get_event_loop()
        blocked, reason = await loop.run_in_executor(
            self._executor, self._analyse, full_text
        )

        if blocked:
            request_id = uuid.uuid4().hex[:12].upper()
            timestamp = datetime.now().isoformat()

            with open("blocked_requests.jsonl", "a", encoding="utf-8") as log_file:
                log_file.write(json.dumps({"timestamp": timestamp, "request_id": request_id, "request": full_text, "ip_address": client_ip, "reason": reason}) + "\n")

            block_html = (
                self._block_html
                .decode("utf-8")
                .replace("{request_id}", request_id)
                .replace("{timestamp}", timestamp)
                .encode("utf-8")
            )

            flow.response = http.Response.make(
                403,
                block_html,
                {"Content-Type": "text/html; charset=utf-8"}
            )

    def _analyse(self, text: str) -> tuple[bool, str]:
        for pattern in self._allow_rules:
            if pattern.search(text):
                return False, "allow_rule"
        for pattern in self._block_rules:
            if pattern.search(text):
                return True, "block_rule"
        return self._detector.is_malicious(text)[0], "ai_detector"
    
    async def _generate_training_data(self) -> None:
        while True:
            try:
                full_text = await self._log_queue.get()

                try:
                    data = TRAINING_DATA_FILE.read_text(encoding="utf-8")
                except FileNotFoundError:
                    data = ""

                lines = data.splitlines()                                          # fix 1: keep reference
                lines.append(json.dumps({"body": full_text,                        # fix 2: serialize to JSON string
                                        "label": TRAINING_DATA_IS_MALICIOUS}))
                TRAINING_DATA_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")

                self._log_queue.task_done()
            except asyncio.CancelledError:
                while not self._log_queue.empty():
                    full_text = self._log_queue.get_nowait()
                    try:
                        data = TRAINING_DATA_FILE.read_text(encoding="utf-8")
                    except FileNotFoundError:
                        data = ""
                    lines = data.splitlines()                                      # same fixes in drain block
                    lines.append(json.dumps({"body": full_text,
                                            "label": TRAINING_DATA_IS_MALICIOUS}))
                    TRAINING_DATA_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
                break

addons = [SeWAF()]