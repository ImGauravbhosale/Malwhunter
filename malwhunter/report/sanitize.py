"""Everything the reports print about a package — evidence excerpts,
script output, descriptions that quote its source — is attacker-controlled
text. Left raw, a package could carry terminal escape sequences (recolour
or rewrite the report, set the window title, hide lines with cursor moves)
or Markdown/HTML that changes how a report reads. This strips the control
characters; the Markdown renderer additionally escapes."""
from __future__ import annotations

import re

# ANSI CSI / OSC / other escape sequences, then any remaining C0/C1 control
# characters except tab and newline.
_ESCAPE_SEQUENCE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|"  # OSC ... BEL or ST
    r"\x1b\[[0-?]*[ -/]*[@-~]|"  # CSI
    r"\x1b[@-Z\\-_]"  # two-byte escapes
)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def sanitize_text(text: str) -> str:
    return _CONTROL.sub("", _ESCAPE_SEQUENCE.sub("", text))


def escape_markdown_inline(text: str) -> str:
    """For text interpolated into a Markdown line: neutralizes the
    characters that would turn it into links, images, HTML or emphasis."""
    text = sanitize_text(text).replace("\n", " ")
    return re.sub(r"([\\`*_{}\[\]<>()#+!|~])", r"\\\1", text)
