"""
reporter/notifier.py

Trigger notifikasi kalau ada finding dengan risk > safe.
Sekarang: Telegram Bot.
Nanti: tambah channel lain ke CHANNELS list.
"""

from __future__ import annotations

import logging
import os
import requests
from dotenv import load_dotenv
from datetime import datetime

log = logging.getLogger("notifier")
load_dotenv()  # Load .env untuk API bot
# Risk level yang trigger notifikasi
NOTIFY_SEVERITIES = {"critical", "high", "medium"}

RISK_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}


# ── Telegram ──────────────────────────────────────────────────────────────────

def _send_telegram(message: str) -> bool:
    token   = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")

    if not token or not chat_id:
        log.warning("[Notifier] TELEGRAM_BOT_TOKEN atau TELEGRAM_CHAT_ID tidak di-set")
        return False

    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={
                "chat_id":    chat_id,
                "text":       message,
                "parse_mode": "HTML",
            },
            timeout=10,
        )
        return resp.status_code == 200
    except Exception as e:
        log.error(f"[Notifier] Telegram error: {e}")
        return False


# ── Main notify ───────────────────────────────────────────────────────────────

def notify_if_needed(findings: list[dict], report_path: str = "", target: str = "") -> bool:
    """
    Cek apakah ada finding yang perlu dinotifikasi.
    Return True kalau notifikasi terkirim.
    """
    # Filter findings yang severity-nya di atas safe threshold
    risky = [
        f for f in findings
        if f.get("severity", "info").lower() in NOTIFY_SEVERITIES
    ]

    if not risky:
        log.info("[Notifier] Tidak ada finding yang perlu dinotifikasi")
        return False

    # Hitung per severity
    counts: dict[str, int] = {}
    for f in risky:
        sev = f.get("severity", "info").lower()
        counts[sev] = counts.get(sev, 0) + 1

    # Build pesan Telegram
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"🚨 <b>Security Alert — OJS Scanner</b>\n\n"
    msg += f"<b>Target:</b> {target or 'OJS Instance'}\n"
    msg += f"<b>Time:</b> {ts}\n\n"
    msg += f"<b>Findings requiring attention:</b>\n"

    for sev in ["critical", "high", "medium"]:
        if counts.get(sev, 0) > 0:
            msg += f"{RISK_EMOJI[sev]} <b>{sev.upper()}</b>: {counts[sev]}\n"

    # Top 3 findings sebagai preview
    top = sorted(risky, key=lambda x: ["critical","high","medium","low","info"].index(
        x.get("severity","info").lower()
    ))[:3]

    msg += f"\n<b>Top findings:</b>\n"
    for f in top:
        sev   = f.get("severity", "info").lower()
        title = f.get("rule_name") or f.get("rule_id") or f.get("type") or "Unknown"
        url   = f.get("url") or f.get("file") or ""
        msg  += f"{RISK_EMOJI[sev]} {title}"
        if url:
            msg += f"\n   <code>{url[:80]}</code>"
        msg += "\n"

    if report_path:
        msg += f"\n📄 Report: <code>{os.path.basename(report_path)}</code>"

    sent = _send_telegram(msg)
    if sent:
        log.info(f"[Notifier] Telegram notification sent — {len(risky)} findings")
    return sent
