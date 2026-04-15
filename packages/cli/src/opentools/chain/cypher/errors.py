"""Query DSL error hierarchy."""
from __future__ import annotations


class QueryParseError(Exception):
    def __init__(self, message: str, *, line: int | None = None, column: int | None = None) -> None:
        self.line = line
        self.column = column
        loc = ""
        if line is not None:
            loc = f" (line {line}"
            if column is not None:
                loc += f", col {column}"
            loc += ")"
        super().__init__(f"{message}{loc}")


class QueryValidationError(Exception):
    pass


class QueryResourceError(Exception):
    def __init__(self, message: str, *, limit_name: str, limit_value: int | float) -> None:
        self.limit_name = limit_name
        self.limit_value = limit_value
        super().__init__(message)
