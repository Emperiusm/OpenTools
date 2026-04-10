"""Code-block-aware text preprocessor.

Splits a text into non-overlapping regions tagged as 'prose' or 'code'.
Identifies fenced code blocks delimited by triple-backticks and HTML
<pre>...</pre> sections. Remaining text is prose. Used by stage-2
extractors so prose-only rules (user, process) can skip noisy tool
output while IOC extractors continue to harvest across both regions.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal


RegionKind = Literal["prose", "code"]


@dataclass(frozen=True)
class TextRegion:
    start: int
    end: int
    kind: RegionKind


_FENCE_OR_PRE = re.compile(r"```|<pre>|</pre>", re.IGNORECASE)


def split_code_blocks(text: str) -> list[TextRegion]:
    """Return non-overlapping, ordered regions that tile ``text`` exactly.

    Each region is tagged ``"prose"`` or ``"code"``. Fenced code blocks
    (```...```) and ``<pre>...</pre>`` sections become code regions;
    everything else is prose.

    An unclosed fence or unclosed <pre> treats the remainder of the input
    as code.
    """
    if not text:
        return []

    regions: list[TextRegion] = []
    cursor = 0
    in_fence = False      # True while inside ``` ... ```
    in_pre = False        # True while inside <pre> ... </pre>

    for m in _FENCE_OR_PRE.finditer(text):
        token = m.group(0).lower()
        start = m.start()
        end = m.end()

        if in_fence:
            # Only a closing ``` ends a fence. <pre> / </pre> are literal.
            if token == "```":
                # Emit the code region up to and including the closing fence
                regions.append(TextRegion(start=cursor, end=end, kind="code"))
                cursor = end
                in_fence = False
            continue

        if in_pre:
            if token == "</pre>":
                regions.append(TextRegion(start=cursor, end=end, kind="code"))
                cursor = end
                in_pre = False
            continue

        # Not currently inside any code region — emit prose up to match start
        if start > cursor:
            regions.append(TextRegion(start=cursor, end=start, kind="prose"))
        cursor = start

        if token == "```":
            in_fence = True
        elif token == "<pre>":
            in_pre = True
        # </pre> outside a <pre> is treated as stray text; cursor stays put
        # and we'll re-emit it as prose on the next iteration or at EOF.
        elif token == "</pre>":
            # Roll back: treat this token as literal prose.
            # We'll catch it at EOF since cursor is unchanged.
            pass

    # Handle trailing content after the last match
    if cursor < len(text):
        kind: RegionKind = "code" if (in_fence or in_pre) else "prose"
        regions.append(TextRegion(start=cursor, end=len(text), kind=kind))

    return regions
