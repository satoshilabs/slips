# Checks changes to the SLIP-0044 coin type registry in a pull request.
#
# Usage: check_slip44.py BASE_FILE HEAD_FILE
#
# Compares the coin type table in HEAD_FILE (the PR version) against BASE_FILE
# (the target branch version). The whole table is checked for ordering, while
# the remaining checks only apply to rows that are new or modified. Findings are
# printed as GitHub Actions annotations. The script exits with status 1 if
# there are any errors.

import re
import sys
from collections import Counter

MAX_COIN_TYPE = 0x7FFFFFFF

# Values that mean "no symbol" or "no name" and are allowed to repeat.
SYMBOL_PLACEHOLDERS = {"", "---"}
NAME_PLACEHOLDERS = {"", "reserved", "deprecated"}


def parse(path):
    """Return the coin type table as a list of (lineno, coin type, symbol, coin) tuples."""
    rows = []
    header = None
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            # Trim only spaces and line endings, so that other whitespace such
            # as tabs or NBSP stays in the cells and gets reported.
            line = line.strip(" \r\n")
            if "|" not in line:
                # Stop at the first non-table line after the table.
                if header is not None and rows:
                    break
                continue

            # Remove at most one outer pipe on each end, so that "| 748 |||"
            # keeps its empty cells, then trim the space padding of each cell.
            line = line.removeprefix("|").removesuffix("|")
            cells = [c.strip(" ") for c in line.split("|")]
            if header is None:
                if cells[0].lower() == "coin type":
                    header = [c.lower() for c in cells]
                continue

            # Skip the separator row.
            if all(re.fullmatch(r":?-+:?", c) for c in cells):
                continue

            if len(cells) != len(header):
                sys.exit(f"::error file={path},line={lineno}::Row has {len(cells)} cells, expected {len(header)}.")

            row = dict(zip(header, cells))
            rows.append((lineno, row["coin type"], row["symbol"], row["coin"]))

    if not rows:
        sys.exit(f"::error file={path}::Coin type table not found.")

    return rows


def coin_type(s):
    """Parse a coin type as a decimal integer, or return None if malformed."""
    return int(s) if re.fullmatch(r"[0-9]+", s) else None


def normalize(s):
    """Loose comparison key, e.g. "X Coin", "Xcoin", "X.coin" and "X-coin" all map to "xcoin"."""
    return re.sub(r"[\W_]+", "", s.casefold())


def normalize_name(s):
    """Like normalize(), but also drops parenthesized parts, e.g. "X Coin (Legacy)" maps to "xcoin"."""
    return normalize(re.sub(r"\([^)]*\)", "", s))


def has_unusual_whitespace(s):
    """True if s contains whitespace other than single spaces, e.g. tabs, NBSP or double spaces."""
    return "  " in s or re.search(r"[^\S ]", s) is not None


def main(base_path, head_path):
    base = parse(base_path)
    head = parse(head_path)
    errors = 0
    warnings = 0

    # Rows present in the base file, used to skip rows that the PR did not touch.
    unchanged = Counter(r[1:] for r in base)

    # (coin type, value) pairs present in the base file. In a modified row, a
    # symbol or name that was already there is not checked for collisions, so
    # that pre-existing duplicates are not blamed on the PR.
    base_values = {idx: {(r[1], r[idx]) for r in base} for idx in (2, 3)}

    def report(kind, line, msg):
        nonlocal errors, warnings
        print(f"::{kind} file={head_path},line={line}::{msg}")
        if kind == "error":
            errors += 1
        else:
            warnings += 1

    def check_collision(row, idx, label, placeholders, loose_key):
        """Report an error if another row has the same value ignoring case,
        or a warning if it matches only after applying loose_key."""
        value = row[idx]
        if value in placeholders or (row[1], value) in base_values[idx]:
            return

        others = [r for r in head if r is not row]

        exact = [r for r in others if r[idx].casefold() == value.casefold()]
        if exact:
            clash = ", ".join(f"{r[1]} ({r[idx]})" for r in exact)
            report("error", row[0], f"{label} '{value}' is already used by coin type {clash}.")

        loose = [r for r in others if r not in exact and loose_key(r[idx]) == loose_key(value)]
        if loose:
            clash = ", ".join(f"{r[1]} ({r[idx]})" for r in loose)
            report("warning", row[0], f"{label} '{value}' is similar to coin type {clash}.")

    prev = None
    for row in head:
        lineno, ctype, symbol, name = row

        # The whole table must be sorted by coin type.
        n = coin_type(ctype)
        if n is None:
            report("error", lineno, f"Coin type '{ctype}' is not a decimal integer.")
        else:
            if prev is not None and n < prev:
                report("error", lineno, f"Coin type {n} is out of order, it follows {prev}.")
            prev = n

        # Remaining checks apply only to new or modified rows.
        if unchanged[row[1:]]:
            unchanged[row[1:]] -= 1
            continue

        # Coin type must be in range and unique.
        if n is not None:
            if re.fullmatch(r"0[0-9]+", ctype):
                report("error", lineno, f"Coin type '{ctype}' has leading zeros.")

            if n > MAX_COIN_TYPE:
                report("error", lineno, f"Coin type {n} exceeds {MAX_COIN_TYPE}.")

            if any(r is not row and coin_type(r[1]) == n for r in head):
                report("error", lineno, f"Coin type {n} is already registered.")

        # Symbol should be uppercase alphanumeric and must not duplicate an existing one.
        if symbol not in SYMBOL_PLACEHOLDERS and not re.fullmatch(r"[A-Z0-9]+", symbol):
            report("warning", lineno, f"Symbol '{symbol}' is not all-caps ASCII.")

        if has_unusual_whitespace(symbol):
            report("error", lineno, f"Symbol '{symbol}' contains unusual whitespace.")

        check_collision(row, 2, "Symbol", SYMBOL_PLACEHOLDERS, normalize)

        # Coin name is required when a symbol is given, should be ASCII and must
        # not duplicate an existing one. Rows with neither mark unassigned coin types.
        if not name and symbol not in SYMBOL_PLACEHOLDERS:
            report("error", lineno, f"Symbol '{symbol}' has no coin name.")

        if not name.isascii():
            report("warning", lineno, f"Coin name '{name}' contains non-ASCII characters.")

        if has_unusual_whitespace(name):
            report("error", lineno, f"Coin name '{name}' contains unusual whitespace.")

        check_collision(row, 3, "Coin name", NAME_PLACEHOLDERS, normalize_name)

    print(f"{errors} error(s), {warnings} warning(s).")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main(*sys.argv[1:])
