from __future__ import annotations

import re
from typing import List, Optional

from ..engine import Finding


AWS_ACCESS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
AWS_SECRET_KEY = re.compile(r"(?i)aws.*(secret|key).*[=:]\s*([A-Za-z0-9/+=]{40})")
GOOGLE_API_KEY = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
SLACK_TOKEN = re.compile(r"(xox[baprs]-[0-9A-Za-z-]{10,48})")
PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
GENERIC_TOKEN = re.compile(r"(?i)(api[-_ ]?key|secret|token|password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]")


def _enumerate_lines(content: str):
    for idx, line in enumerate(content.splitlines(), start=1):
        yield idx, line


def detect_secret_smells(content: str, file: Optional[str]) -> List[Finding]:
    findings: List[Finding] = []

    patterns = [
        (AWS_ACCESS_KEY, "Secrets.AWS.AccessKey", "AWS Access Key ID found"),
        (AWS_SECRET_KEY, "Secrets.AWS.Secret", "AWS Secret Access Key pattern found"),
        (GOOGLE_API_KEY, "Secrets.Google.ApiKey", "Google API key pattern found"),
        (SLACK_TOKEN, "Secrets.Slack.Token", "Slack token pattern found"),
        (PRIVATE_KEY_HEADER, "Secrets.PrivateKey", "Private key material found"),
        (GENERIC_TOKEN, "Secrets.Generic", "Hard-coded credential-like value found"),
    ]

    for line_no, line in _enumerate_lines(content):
        for regex, rule, message in patterns:
            if regex.search(line):
                severity = "critical" if "PrivateKey" in rule else "high"
                findings.append(Finding(
                    rule=rule,
                    severity=severity,
                    message=message,
                    file=file,
                    line=line_no,
                ))

    return findings

