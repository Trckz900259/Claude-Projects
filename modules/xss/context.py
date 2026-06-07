"""
context.py — work out WHERE a reflected value lands in the response.

Given the response HTML and the marker we injected, we locate each occurrence
and classify its context, because the right payload depends entirely on it:

  html_body   text between tags        -> inject a new element
  attribute   inside attr="..."        -> break out of the quote/tag first
  url         inside href/src="..."    -> a javascript: URL may fire
  js_string   inside <script> '...'    -> close the string / the script
  css         inside <style> ...       -> close the style block

This is deliberately a pragmatic string scanner (not a full HTML parser): we
care precisely about where *our bytes* landed, which a normalising parser would
obscure.
"""

from __future__ import annotations

from dataclasses import dataclass

URL_ATTRS = {"href", "src", "action", "formaction", "data", "poster", "background"}


@dataclass
class ReflectionContext:
    context: str       # one of payloads.CONTEXTS
    quote: str         # the quote char enclosing the value ('"', "'", or "")
    detail: str        # e.g. the attribute name, for the report
    index: int         # where in the body the marker was found
    snippet: str       # surrounding text, for the human-readable report


def _find_all(haystack: str, needle: str) -> list[int]:
    out, start = [], 0
    while True:
        i = haystack.find(needle, start)
        if i == -1:
            return out
        out.append(i)
        start = i + len(needle)


def _inside_block(lower: str, idx: int, open_prefix: str, close_prefix: str) -> bool:
    last_open = lower.rfind(open_prefix, 0, idx)
    if last_open == -1:
        return False
    last_close = lower.rfind(close_prefix, 0, idx)
    return last_open > last_close


def _attr_and_quote(tag_text: str) -> tuple[str, str]:
    """
    Given the text from the opening '<' up to the marker, find the attribute the
    marker is sitting in and the quote char (if any) that opened its value.
    """
    eq = tag_text.rfind("=")
    if eq == -1:
        return "", ""
    # attribute name = the token immediately before '='
    name = tag_text[:eq].split()[-1].strip().lower() if tag_text[:eq].split() else ""
    # quote = first non-space char after '='
    after = tag_text[eq + 1:].lstrip()
    quote = after[0] if after and after[0] in ("\"", "'") else ""
    return name, quote


def _js_quote(script_region: str) -> str:
    """Guess whether the marker sits inside a '...' or \"...\" string in JS."""
    for q in ("'", '"', "`"):
        if script_region.count(q) % 2 == 1:  # odd number of this quote -> open string
            return q
    return ""


def classify_reflections(html: str, marker: str) -> list[ReflectionContext]:
    """Return one ReflectionContext per DISTINCT (context, quote) the marker hits."""
    lower = html.lower()
    results: list[ReflectionContext] = []
    seen: set[tuple[str, str]] = set()

    for idx in _find_all(html, marker):
        snippet = html[max(0, idx - 40): idx + len(marker) + 40]

        # 1) Inside a <script> block -> JavaScript context.
        if _inside_block(lower, idx, "<script", "</script"):
            region_start = lower.rfind("<script", 0, idx)
            quote = _js_quote(html[region_start:idx])
            ctx = ReflectionContext("js_string", quote, "inside <script>", idx, snippet)

        # 2) Inside a <style> block -> CSS context.
        elif _inside_block(lower, idx, "<style", "</style"):
            ctx = ReflectionContext("css", "", "inside <style>", idx, snippet)

        else:
            last_lt = html.rfind("<", 0, idx)
            last_gt = html.rfind(">", 0, idx)
            if last_lt > last_gt:
                # 3) Inside a tag -> attribute (maybe a URL attribute).
                tag_text = html[last_lt:idx]
                name, quote = _attr_and_quote(tag_text)
                if name in URL_ATTRS:
                    ctx = ReflectionContext("url", quote, f"{name} attribute", idx, snippet)
                else:
                    ctx = ReflectionContext("attribute", quote, f"{name} attribute", idx, snippet)
            else:
                # 4) Plain text between tags.
                ctx = ReflectionContext("html_body", "", "HTML body text", idx, snippet)

        sig = (ctx.context, ctx.quote)
        if sig not in seen:
            seen.add(sig)
            results.append(ctx)

    return results
