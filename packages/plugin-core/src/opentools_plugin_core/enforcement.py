"""Recipe command structural validation: shlex parsing, container scoping."""

from __future__ import annotations

import shlex
from dataclasses import dataclass


@dataclass
class Violation:
    severity: str  # "red" | "yellow" | "info"
    message: str
    detail: str = ""


SHELL_OPERATORS = {";", "&&", "||", "|", ">", ">>", "<", "$(", "`"}
_VALUE_FLAGS = {"-e", "--env", "-w", "--workdir", "-u", "--user"}


def extract_container_name(tokens: list[str]) -> str | None:
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in _VALUE_FLAGS:
            i += 2
            continue
        if tok.startswith("-"):
            if "=" in tok:
                i += 1
                continue
            i += 1
            continue
        return tok
    return None


def validate_command(command: str, allowed_containers: set[str]) -> list[Violation]:
    violations: list[Violation] = []
    for op in SHELL_OPERATORS:
        if op in command:
            violations.append(Violation(
                severity="red",
                message=f"Shell operator '{op}' not allowed in marketplace recipes",
                detail=f"Command contains '{op}' which could enable shell injection",
            ))
    if violations:
        return violations
    try:
        tokens = shlex.split(command)
    except ValueError as e:
        return [Violation(severity="red", message="Command parsing failed", detail=str(e))]
    if len(tokens) < 3 or tokens[0:2] != ["docker", "exec"]:
        return [Violation(
            severity="red",
            message="Must use 'docker exec <container>' format",
            detail=f"Command starts with '{' '.join(tokens[:2])}' instead of 'docker exec'",
        )]
    container = extract_container_name(tokens[2:])
    if container is None:
        return [Violation(severity="red", message="Could not determine container name")]
    if container not in allowed_containers:
        return [Violation(
            severity="red",
            message=f"Undeclared container: {container}",
            detail=f"Container '{container}' is not in the plugin's allowed set: {allowed_containers}",
        )]
    return []
