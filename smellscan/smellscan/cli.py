from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from .engine import scan_path, scan_text


def main() -> None:
    parser = argparse.ArgumentParser(prog='smellscan', description='Security smell detector')
    sub = parser.add_subparsers(dest='cmd', required=True)

    scan_p = sub.add_parser('scan', help='Scan a path or stdin (-)')
    scan_p.add_argument('target', help='Directory/file to scan, or - for stdin')
    scan_p.add_argument('--format', choices=['text', 'json'], default='text')
    scan_p.add_argument('--output', help='Write JSON/text to file')
    scan_p.add_argument('--extensions', nargs='*', default=['.py', '.js', '.ts', '.java', '.php', '.sh'])

    args = parser.parse_args()

    if args.cmd == 'scan':
        if args.target == '-':
            content = sys.stdin.read()
            findings = scan_text(content)
        else:
            path = Path(args.target)
            findings = scan_path(path, allowed_extensions=set(args.extensions))

        if args.format == 'json':
            output = json.dumps(findings, indent=2)
        else:
            lines = []
            for f in findings:
                loc = f.get('location', '') or ''
                lines.append(f"{f['severity'].upper()} | {f['rule']} | {loc} | {f['message']}")
            output = "\n".join(lines)

        if args.output:
            Path(args.output).write_text(output, encoding='utf-8')
        else:
            print(output)


if __name__ == '__main__':
    main()

