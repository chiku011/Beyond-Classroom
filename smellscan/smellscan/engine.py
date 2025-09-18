from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List, Dict, Set


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    file: str | None = None
    line: int | None = None
    column: int | None = None

    def to_dict(self) -> Dict[str, object]:
        location = None
        if self.file is not None and self.line is not None:
            location = f"{self.file}:{self.line}"
        d = asdict(self)
        d["location"] = location
        return d


def _iter_files(root: Path, allowed_extensions: Set[str]) -> Iterable[Path]:
    if root.is_file():
        if not allowed_extensions or root.suffix in allowed_extensions:
            yield root
        return
    for path in root.rglob("*"):
        if path.is_file() and (not allowed_extensions or path.suffix in allowed_extensions):
            yield path


def _safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""


def scan_text(content: str) -> List[Dict[str, object]]:
    from .detectors.sql import detect_sql_injection_smells
    from .detectors.secrets import detect_secret_smells
    from .detectors.flags import detect_flag_smells

    findings: List[Finding] = []
    findings.extend(detect_sql_injection_smells(content, file=None))
    findings.extend(detect_secret_smells(content, file=None))
    findings.extend(detect_flag_smells(content, file=None))
    return [f.to_dict() for f in findings]


def scan_path(path: Path, allowed_extensions: Set[str] | None = None) -> List[Dict[str, object]]:
    if allowed_extensions is None:
        allowed_extensions = set()
    results: List[Finding] = []

    from .detectors.sql import detect_sql_injection_smells
    from .detectors.secrets import detect_secret_smells
    from .detectors.flags import detect_flag_smells

    for file_path in _iter_files(path, allowed_extensions):
        text = _safe_read_text(file_path)
        results.extend(detect_sql_injection_smells(text, file=str(file_path)))
        results.extend(detect_secret_smells(text, file=str(file_path)))
        results.extend(detect_flag_smells(text, file=str(file_path)))

    return [f.to_dict() for f in results]

