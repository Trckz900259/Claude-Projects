"""
notify.py — optional Discord/Telegram alerts (e.g. when a blind callback fires).

These notifications go to YOUR own webhook/bot, not to the target, so they do not
pass through the scope-guarded HttpEngine (the target scope doesn't apply to your
Discord server). They're best-effort: a failed notification never breaks a run.
"""

from __future__ import annotations

import logging

import requests

from core.config import NotificationsConfig

log = logging.getLogger("notify")


def send_notification(cfg: NotificationsConfig, title: str, message: str) -> None:
    """Send to whichever channels are configured. Never raises."""
    if cfg.discord_webhook:
        try:
            requests.post(
                cfg.discord_webhook,
                json={"content": f"**{title}**\n{message}"},
                timeout=10,
            )
        except Exception as exc:  # pragma: no cover - best effort
            log.debug("discord notify failed: %s", exc)

    if cfg.telegram_bot_token and cfg.telegram_chat_id:
        try:
            requests.post(
                f"https://api.telegram.org/bot{cfg.telegram_bot_token}/sendMessage",
                json={"chat_id": cfg.telegram_chat_id, "text": f"{title}\n{message}"},
                timeout=10,
            )
        except Exception as exc:  # pragma: no cover - best effort
            log.debug("telegram notify failed: %s", exc)
