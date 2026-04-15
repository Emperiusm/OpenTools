"""Advisory skill content scanner: regex red-flag detection."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Advisory:
    pattern: str
    message: str
    line_number: int
    line_content: str
    severity: str = "warning"


_RED_FLAGS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"(curl|wget)\s+.+\|\s*(ba)?sh", re.IGNORECASE),
     "pipe-to-shell", "Downloads and pipes directly to shell interpreter"),
    (re.compile(r"base64\s+(-d|--decode)\s*\|\s*(ba)?sh", re.IGNORECASE),
     "base64-decode-exec", "Decodes base64 and executes via shell"),
    (re.compile(r"chmod\s+777\b", re.IGNORECASE),
     "chmod-777", "Sets world-writable permissions"),
    (re.compile(r"\bsudo\b", re.IGNORECASE),
     "sudo-usage", "Uses sudo for privilege escalation"),
    (re.compile(r"eval\s*\(.*\$\(", re.IGNORECASE),
     "eval-subshell", "Eval with command substitution"),
    (re.compile(r"\bpython\s+-c\s+.*exec\(", re.IGNORECASE),
     "python-exec", "Python one-liner with exec()"),
    (re.compile(r"nc\s+-[el]", re.IGNORECASE),
     "netcat-listener", "Netcat in listen mode (potential reverse shell)"),
    (re.compile(r"/dev/(tcp|udp)/", re.IGNORECASE),
     "bash-net-redirect", "Bash network redirection (/dev/tcp or /dev/udp)"),
]


def scan_skill_content(content: str) -> list[Advisory]:
    advisories: list[Advisory] = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        for pattern, name, message in _RED_FLAGS:
            if pattern.search(line):
                advisories.append(Advisory(
                    pattern=name, message=message,
                    line_number=line_num, line_content=line.strip(),
                ))
    return advisories
