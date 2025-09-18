from __future__ import annotations

import re
from typing import List, Optional

from ..engine import Finding


def _enumerate_lines(content: str):
    for idx, line in enumerate(content.splitlines(), start=1):
        yield idx, line


def detect_flag_smells(content: str, file: Optional[str]) -> List[Finding]:
    findings: List[Finding] = []

    patterns = [
        (re.compile(r"curl\s+[^\n]*\s-?k(\s|$)"), "Flags.TLS.CurlInsecure", "curl with -k/--insecure disables TLS verification"),
        (re.compile(r"requests\.[a-z]+\([^\)]*verify\s*=\s*False"), "Flags.TLS.VerifyFalse", "TLS certificate verification disabled (verify=False)"),
        (re.compile(r"\bDEBUG\s*=\s*True\b"), "Flags.Debug.Enabled", "Debug mode enabled"),
        (re.compile(r"Access-Control-Allow-Origin\s*[:=]\s*['\"]\*['\"]", re.IGNORECASE), "Flags.CORS.Wildcard", "CORS allows any origin"),
        (re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0"), "Flags.TLS.NodeRejectUnauthorized", "Node TLS verification disabled"),
    ]

    for line_no, line in _enumerate_lines(content):
        for regex, rule, message in patterns:
            if regex.search(line):
                severity = "medium" if "Debug" in rule else "high"
                findings.append(Finding(
                    rule=rule,
                    severity=severity,
                    message=message,
                    file=file,
                    line=line_no,
                ))

    return findings

