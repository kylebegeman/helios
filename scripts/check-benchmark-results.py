#!/usr/bin/env python3
"""Reject incomplete runs and comparisons with different benchmark inventories."""
import argparse
from collections import Counter
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--count', type=int, required=True)
parser.add_argument('files', type=Path, nargs='+')
args = parser.parse_args()
reference: Counter[str] | None = None
for path in args.files:
    cases: Counter[str] = Counter()
    for line in path.read_text().splitlines():
        fields = line.split()
        if fields and fields[0].startswith('Benchmark') and 'ns/op' in fields:
            cases[fields[0]] += 1
    if not cases:
        parser.error(f'{path}: no benchmark samples matched')
    incomplete = {name: count for name, count in cases.items() if count != args.count}
    if incomplete:
        parser.error(f'{path}: expected {args.count} samples per case, got {incomplete}')
    if reference is not None and cases != reference:
        missing = sorted(reference.keys() - cases.keys())
        extra = sorted(cases.keys() - reference.keys())
        parser.error(f'{path}: benchmark inventory differs; missing={missing}, extra={extra}')
    reference = cases
print(f'Validated {len(reference or {})} benchmark cases with {args.count} samples each')
