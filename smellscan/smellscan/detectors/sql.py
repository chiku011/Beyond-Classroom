from __future__ import annotations

import re
from typing import List, Optional

from ..engine import Finding


_SQL_KEYWORDS = r"select|insert|update|delete|replace|drop|alter|create|truncate"


def _enumerate_lines(content: str):
    for idx, line in enumerate(content.splitlines(), start=1):
        yield idx, line


def detect_sql_injection_smells(content: str, file: Optional[str]) -> List[Finding]:
    findings: List[Finding] = []

    # Pattern: query built by concatenation or f-string with inputs
    concat_pattern = re.compile(r"(\b(" + _SQL_KEYWORDS + r")\b[^\n;]*)(['\"]\s*\+|\+\s*['\"])", re.IGNORECASE)
    fstring_pattern = re.compile(r"f['\"][^\n]*\b(" + _SQL_KEYWORDS + r")\b[^\n]*\{[^}]+\}", re.IGNORECASE)
    format_pattern = re.compile(r"['\"][^\n]*\b(" + _SQL_KEYWORDS + r")\b[^\n]*['\"][\s]*\.\s*format\(", re.IGNORECASE)
    percent_pattern = re.compile(r"['\"][^\n]*\b(" + _SQL_KEYWORDS + r")\b[^\n]*%\s*[\w({)]", re.IGNORECASE)

    # JS/Java/PHP string concatenation
    plus_concat = re.compile(r"['\"][^\n]*\b(" + _SQL_KEYWORDS + r")\b[^\n]*['\"]\s*\+", re.IGNORECASE)

    for line_no, line in _enumerate_lines(content):
        if concat_pattern.search(line) or fstring_pattern.search(line) or format_pattern.search(line) or percent_pattern.search(line) or plus_concat.search(line):
            findings.append(Finding(
                rule="SQL.Injection.Concat",
                severity="high",
                message="Possible SQL injection: query built via string interpolation/concatenation",
                file=file,
                line=line_no,
            ))

    # Dangerous APIs without parameters
    exec_pattern = re.compile(r"\b(execute|exec|query|rawQuery)\s*\(\s*([`'\"])(?:(?!\2).)*\2\s*\)")
    for line_no, line in _enumerate_lines(content):
        if exec_pattern.search(line):
            if re.search(r"\?\s*[,)]|%s\s*[,)]|:\w+\s*[,)]", line) is None:
                findings.append(Finding(
                    rule="SQL.Injection.NoParams",
                    severity="medium",
                    message="SQL execution without parameters detected",
                    file=file,
                    line=line_no,
                ))

    return findings

