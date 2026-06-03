from __future__ import annotations
 
import threading
from datetime import datetime
from typing import Optional
 
 
class AlertBuffer:
    """
    Simpan content_injection_alert sementara.
    Saat semgrep selesai, ambil semua alert yang tersimpan
    dan gabungkan dengan semgrep findings.
    """
 
    def __init__(self):
        self._lock   = threading.Lock()
        self._alerts: list[dict] = []
 
    def add(self, payload: dict):
        """Tambahkan alert ke buffer."""
        with self._lock:
            threats = payload.get("threats", [])
            for t in threats:
                self._alerts.append({
                    "source":      "dast_runtime",
                    "type":        "content_injection",
                    "severity":    t.get("severity", "medium"),
                    "rule_id":     "content-injection-runtime",
                    "rule_name":   t.get("description", "Content Injection"),
                    "url":         payload.get("url", ""),
                    "match":       t.get("match", ""),
                    "ts":          payload.get("ts", datetime.now().timestamp()),
                })
 
    def flush(self) -> list[dict]:
        """
        Ambil semua alert yang tersimpan dan kosongkan buffer.
        Dipanggil saat semgrep selesai.
        """
        with self._lock:
            alerts = self._alerts.copy()
            self._alerts.clear()
            return alerts
 
    def peek(self) -> list[dict]:
        """Lihat isi buffer tanpa mengosongkan."""
        with self._lock:
            return self._alerts.copy()
 
    @property
    def count(self) -> int:
        with self._lock:
            return len(self._alerts)
 
 
# ── Singleton ─────────────────────────────────────────────────────────────────
 
_buffer: Optional[AlertBuffer] = None
 
 
def get_alert_buffer() -> AlertBuffer:
    global _buffer
    if _buffer is None:
        _buffer = AlertBuffer()
    return _buffer
