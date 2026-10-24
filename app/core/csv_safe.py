"""CSV export hardening.

Everything this tool exports is *evidence-derived*: carved filenames,
IoC strings, registry values, paths. That content is attacker-controlled
by definition — it came off the suspect's disk.

Spreadsheet programs treat a cell beginning with `=`, `+`, `-`, `@`, or
a leading tab / carriage return as a formula. So a file on the suspect
drive named

    =cmd|'/c calc'!A1

becomes live code the moment the examiner opens the exported CSV in
Excel or LibreOffice — the analysis workstation attacks itself with the
evidence. This is CWE-1236 (formula injection).

The fix is to neutralise the leading character while keeping the value
readable and byte-recoverable: prefix a single quote, which spreadsheets
strip on display and treat as "this is text". The original string is
never altered in the case database or the index — only on the way out
to CSV.
"""
from __future__ import annotations

# Leading characters a spreadsheet may interpret as the start of a formula.
_FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value):
    """Return `value` rendered safe to place in a CSV cell.

    Non-string values pass through untouched (numbers cannot carry a
    formula). Strings that begin with a formula-triggering character are
    prefixed with a single quote.
    """
    if not isinstance(value, str):
        return value
    if value.startswith(_FORMULA_LEADERS):
        return "'" + value
    return value


def csv_safe_row(row):
    """Apply csv_safe to every cell of an iterable row."""
    return [csv_safe(v) for v in row]


def csv_safe_dict(row: dict) -> dict:
    """Apply csv_safe to every value of a dict row (keys are ours)."""
    return {k: csv_safe(v) for k, v in row.items()}
