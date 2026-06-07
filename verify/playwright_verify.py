"""
playwright_verify.py — prove a payload ACTUALLY executes, with minimal impact.

A reflection is only a *candidate*. To avoid ever reporting something unproven,
we load the candidate in a real headless browser (Chromium via Playwright) and
watch for our benign payload to fire. Our payloads only call:

    alert('<marker>')

so "did it execute?" becomes "did a dialog appear carrying our marker?". That is
the least intrusive possible proof — we never perform a destructive action.

On success we capture a screenshot (and optionally a short video) and return
their paths so the report can show a visual PoC. If Playwright isn't installed,
this degrades gracefully: it returns verified=False with a clear message, and
the candidate is kept as UNVERIFIED (never silently dropped, never over-claimed).

Thread-safety: each call spins up its own Playwright context, so the engine can
verify candidates from multiple worker threads safely.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from core.scope import ScopeEnforcer


@dataclass
class VerificationResult:
    verified: bool
    dialog_text: str = ""       # what the alert/confirm/prompt actually said
    dialog_type: str = ""       # alert | confirm | prompt
    screenshot_path: str = ""
    video_path: str = ""
    page_title: str = ""
    error: str = ""


class Verifier:
    def __init__(
        self,
        scope: ScopeEnforcer,
        user_agent: str,
        poc_dir: str | Path = "data/pocs",
        record_video: bool = False,
        verify_tls: bool = True,
        logger: logging.Logger | None = None,
        nav_timeout_ms: int = 12000,
    ) -> None:
        self.scope = scope
        self.user_agent = user_agent
        self.poc_dir = Path(poc_dir)
        self.poc_dir.mkdir(parents=True, exist_ok=True)
        self.record_video = record_video
        self.verify_tls = verify_tls
        self.log = logger or logging.getLogger("verify")
        self.nav_timeout_ms = nav_timeout_ms

    def available(self) -> bool:
        try:
            import playwright.sync_api  # noqa: F401
            return True
        except Exception:
            return False

    def verify_url(self, url: str, marker: str, capture_name: str = "") -> VerificationResult:
        """
        Load `url` and report whether a dialog carrying `marker` fired.

        IMPORTANT: the browser does NOT go through our HttpEngine, so we re-check
        scope here ourselves before navigating — belt and braces.
        """
        decision = self.scope.check(url)
        if not decision.allowed:
            return VerificationResult(False, error=f"refused (out of scope): {decision.reason}")

        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            return VerificationResult(
                False, error="Playwright not installed — candidate left UNVERIFIED"
            )

        stamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
        base = capture_name or marker
        shot_path = self.poc_dir / f"{base}-{stamp}.png"
        seen = {"fired": False, "text": "", "type": ""}

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage"],
                )
                ctx_kwargs = {
                    "user_agent": self.user_agent,
                    "ignore_https_errors": not self.verify_tls,
                }
                if self.record_video:
                    ctx_kwargs["record_video_dir"] = str(self.poc_dir)
                context = browser.new_context(**ctx_kwargs)
                page = context.new_page()

                # The benign proof: catch the dialog our payload raises.
                def on_dialog(dialog):
                    seen["fired"] = True
                    seen["text"] = dialog.message
                    seen["type"] = dialog.type
                    try:
                        dialog.dismiss()
                    except Exception:
                        pass

                page.on("dialog", on_dialog)

                try:
                    page.goto(url, timeout=self.nav_timeout_ms, wait_until="load")
                except Exception as exc:
                    # Navigation hiccups shouldn't crash verification.
                    self.log.debug("nav issue on %s: %s", url, exc)

                # Give async sinks / event handlers a beat to fire.
                page.wait_for_timeout(700)
                title = ""
                try:
                    title = page.title()
                    page.screenshot(path=str(shot_path))
                except Exception as exc:
                    self.log.debug("screenshot issue: %s", exc)

                video_path = ""
                try:
                    if self.record_video and page.video:
                        video_path = page.video.path()
                except Exception:
                    pass

                context.close()
                browser.close()

            # Verified only if the dialog carried OUR marker (avoids false hits
            # from the page's own scripts popping unrelated dialogs).
            verified = seen["fired"] and (marker in seen["text"])
            return VerificationResult(
                verified=verified,
                dialog_text=seen["text"],
                dialog_type=seen["type"],
                screenshot_path=str(shot_path) if shot_path.exists() else "",
                video_path=video_path,
                page_title=title,
            )
        except Exception as exc:
            return VerificationResult(False, error=f"verification error: {exc}")
