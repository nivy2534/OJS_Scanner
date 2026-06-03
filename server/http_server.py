"""
server/http_server.py

HTTP server yang terima POST dari Security Agent Plugin OJS.
Menggantikan SimpleHTTPRequestHandler yang tidak bisa handle POST body.

Endpoint:
    POST /scan      → terima request scan dari plugin, jalankan semgrep
    GET  /health    → cek server hidup
"""

import http.server
import socketserver
import threading
import json
import logging

log = logging.getLogger("http_server")


class AgentRequestHandler(http.server.BaseHTTPRequestHandler):

    on_scan = None

    def log_message(self, format, *args):
        log.debug(f"{self.address_string()} - {format % args}")

    def _is_authorized(self) -> bool:
        from server.http_server import HttpServer
        token = HttpServer.AGENT_TOKEN
        auth  = self.headers.get("Authorization", "")
        return not token or auth == f"Bearer {token}"

    def _send_json(self, code: int, data: dict):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                return {}
            raw = self.rfile.read(length)
            return json.loads(raw.decode("utf-8"))
        except Exception as e:
            log.error(f"Failed to read body: {e}")
            return None

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {"status": "ok"})
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        if self.path == "/scan":
            print(f"[Agent] Received scan request from {self.client_address[0]}")
            self._handle_scan()
        elif self.path == "/collect":
            self._handle_collect()
        else:
            self._send_json(404, {"error": "Not found"})

    def _handle_scan(self):
        print(f"[Agent] Scanning!")
        print(f"[Agent] on_scan registered: {callable(AgentRequestHandler.on_scan)}")  
        if not self._is_authorized():
            log.warning("Unauthorized scan request")
            self._send_json(401, {"error": "Unauthorized"})
            return

        payload = self._read_body()
        if payload is None:
            self._send_json(400, {"error": "Invalid JSON body"})
            return

        if "path" not in payload:
            self._send_json(400, {"error": "Missing 'path' in body"})
            return

        log.info(f"Scan request: path={payload['path']} event={payload.get('event', 'manual')}")

        if callable(AgentRequestHandler.on_scan):
            try:
                result = AgentRequestHandler.on_scan(payload)
                self._send_json(200, result)
            except Exception as e:
                log.error(f"Scan error: {e}")
                self._send_json(500, {"error": str(e)})
        else:
            self._send_json(503, {"error": "Scan handler not registered"})

    def _handle_collect(self):
        """Terima data dari RequestCollector dan ResponseCollector."""
        if not self._is_authorized():
            self._send_json(401, {"error": "Unauthorized"})
            return

        payload = self._read_body()
        if payload is None:
            self._send_json(400, {"error": "Invalid JSON"})
            return
        
        event_type = payload.get("type", "unknown")
        url        = payload.get("url", "")
        if event_type == "content_injection_alert":
            threat_count = payload.get("threat_count", 0)
            threats      = payload.get("threats", [])
            print(f"\n[🚨 ALERT] Content injection terdeteksi!")
            print(f"  URL     : {url}")
            print(f"  Threats : {threat_count} finding(s)")
            for t in threats:
                print(f"  [{t.get('severity','?').upper()}] {t.get('description','')}")
                print(f"  Match   : {t.get('match','')[:100]}")
        elif event_type == "request":
            print(f"[Agent] request — {payload.get('url', '')}")
        elif event_type == "response_render":
            print(f"[Agent] response_render — {url}")
        elif event_type == "semgrep_findings":
            count = len(payload.get("findings", []))
            print(f"[Agent] semgrep_findings — {count} finding(s) dari {payload.get('path','')}")
        else:
            print(f"[Agent] {event_type} — {url}")
        self._send_json(200, {"status": "ok"})



class HttpServer:
    """
    Wrapper HTTP server yang jalan di background thread.
    JobManager register callback via set_scan_handler().
    """

    AGENT_TOKEN = "AlfiGanteng"

    def __init__(self, host="0.0.0.0", port=60000):
        self.host   = host
        self.port   = port
        self._httpd = None
        self._thread: threading.Thread | None = None

    def set_scan_handler(self, callback):
        """
        Register callback yang dipanggil saat ada POST /scan.
        Dipanggil oleh JobManager sebelum start().

        callback signature: (payload: dict) -> dict
        """
        AgentRequestHandler.on_scan = callback

    def start(self):
        """Start server di background thread — tidak blocking."""
        if self._is_running():
            log.info("HTTP server already running")
            return

        self._httpd = socketserver.TCPServer(
            (self.host, self.port),
            AgentRequestHandler
        )
        self._httpd.allow_reuse_address = True

        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            daemon=True,
            name="agent-http-server",
        )
        self._thread.start()
        log.info(f"HTTP server listening on {self.host}:{self.port}")

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd = None
            log.info("HTTP server stopped")

    def _is_running(self) -> bool:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex((self.host, self.port)) == 0