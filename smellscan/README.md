# smellscan

A lightweight security smell detector for quick scans of code snippets or small repos.

## Install

```bash
pip install -e .
```

## Usage

```bash
smellscan scan /path/to/src --format text
smellscan scan /path/to/src --format json --output report.json
smellscan scan - < example.py
```

## What it detects (initial)
- SQL injection risks (string-concatenated queries, unsanitized inputs)
- Hard-coded secrets (AWS keys, generic tokens, private keys)
- Suspicious flags (curl -k, verify=False, DEBUG=True, CORS wildcard)

## Notes
Heuristic-only. False positives are possible.

## Examples

Example quick scan:

```bash
smellscan scan examples --format text
```

JSON output to file:

```bash
smellscan scan examples --format json --output report.json
```
