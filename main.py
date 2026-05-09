"""
SeWAF — mitmproxy addon
───────────────────────
Concurrency model
  • request() is async  →  never blocks mitmproxy's event loop
  • CPU-bound work (regex + ML inference) runs in a ThreadPoolExecutor
  • Logging uses an asyncio.Queue  →  a single background coroutine
    drains it and does all file I/O, so writes are never concurrent

Other fixes over v1
  • Detector loaded once at startup, not per-request
  • Regex patterns pre-compiled once at startup
  • Log file is JSONL (one record per line, append-only — no read/parse/rewrite)
"""

import asyncio
import json
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import unquote

from mitmproxy import http

from ai_detector.detector import Detector

LOG_DATA      = False
LOG_FILE      = Path(__file__).resolve().with_name("data.jsonl")
WORKER_THREADS = 4


def _load_lines(path: str) -> list[str]:
    return [l.strip() for l in Path(path).read_text().splitlines() if l.strip()]

class SeWAF:

    def __init__(self) -> None:
        raw_patterns        = _load_lines("custom/custom_rules.txt")
        self._patterns      = [re.compile(p, re.IGNORECASE) for p in raw_patterns]
        self._blocked_ips   = set(_load_lines("custom/blocked_ips.txt"))

        self._detector = Detector()

        self._executor = ThreadPoolExecutor(max_workers=WORKER_THREADS,
                                            thread_name_prefix="sewaf")

        self._log_queue: asyncio.Queue[str] = asyncio.Queue()
        self._log_task: asyncio.Task | None = None

    def running(self) -> None:
        if LOG_DATA:
            self._log_task = asyncio.get_event_loop().create_task(
                self._log_writer(), name="sewaf-log-writer"
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

        full_text = unquote(flow.request.path + (flow.request.text or ""))

        if LOG_DATA:
            entry = json.dumps({"ip": client_ip,
                                "path": flow.request.path,
                                "body": full_text})
            await self._log_queue.put(entry)

        loop    = asyncio.get_event_loop()
        blocked = await loop.run_in_executor(
            self._executor, self._analyse, full_text
        )

        if blocked:
            flow.response = http.Response.make(403, "Malicious Request Blocked")


    def _analyse(self, text: str) -> bool:
        """Return True if the request should be blocked. Thread-safe."""
        for pattern in self._patterns:
            if pattern.search(text):
                return True

        return self._detector.is_malicious(text)

    async def _log_writer(self) -> None:
        """
        Drain the log queue and append to a JSONL file.

        JSONL (one JSON object per line) lets us append without
        reading or rewriting the whole file.
        """
        LOG_FILE.touch(exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as fh:
            while True:
                try:
                    entry = await self._log_queue.get()
                    fh.write(entry + "\n")
                    fh.flush()
                    self._log_queue.task_done()
                except asyncio.CancelledError:
                    while not self._log_queue.empty():
                        entry = self._log_queue.get_nowait()
                        fh.write(entry + "\n")
                    break


addons = [SeWAF()]