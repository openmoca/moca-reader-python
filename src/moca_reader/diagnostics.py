"""Diagnostics: stable codes, a severity, a message, and where."""

from __future__ import annotations

from dataclasses import dataclass, field

from .codes import ERROR, WARNING, default_severity


@dataclass
class Diagnostic:
    code: str
    severity: str
    message: str
    file: str | None = None
    line: int | None = None

    def to_json(self) -> dict[str, object]:
        out: dict[str, object] = {"code": self.code, "severity": self.severity, "message": self.message}
        if self.file is not None:
            out["file"] = self.file
        if self.line is not None:
            out["line"] = self.line
        return out


@dataclass
class Diagnostics:
    strict: bool = False
    items: list[Diagnostic] = field(default_factory=list)

    def add(self, code: str, message: str, file: str | None = None, line: int | None = None) -> Diagnostic:
        severity = default_severity(code)
        if self.strict and severity == WARNING:
            severity = ERROR
        entry = Diagnostic(code, severity, message, file, line)
        self.items.append(entry)
        return entry

    def has(self, code: str) -> bool:
        return any(d.code == code for d in self.items)

    @property
    def has_errors(self) -> bool:
        return any(d.severity == ERROR for d in self.items)
