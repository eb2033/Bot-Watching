from __future__ import annotations

import re

_ANSI_CSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
_ANSI_OSC_RE = re.compile(r"\x1B\][^\x07\x1B]*(?:\x07|\x1B\\)")
_ANSI_SIMPLE_ESC_RE = re.compile(r"\x1B[@-_]")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1F\x7F-\x9F]")


def sanitize_text(value: str | bytes, max_length: int | None = None) -> str:
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = value.encode("utf-8", errors="replace").decode("utf-8")

    text = _ANSI_OSC_RE.sub("", text)
    text = _ANSI_CSI_RE.sub("", text)
    text = _ANSI_SIMPLE_ESC_RE.sub("", text)
    text = _CONTROL_CHARS_RE.sub("", text)

    if max_length is not None:
        text = text[:max_length]

    return text
