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
from common import Findings, changed_rows, check_name, check_unique, find_table, layout_warning, normalize, normalize_name


MAX_COIN_TYPE = 0x7FFFFFFF

# Symbols are MIN_SYMBOL_LENGTH to MAX_SYMBOL_LENGTH characters long (error),
# and NORMAL_SYMBOL_LENGTHS are the normal lengths (anything else is a warning).
MIN_SYMBOL_LENGTH = 2
MAX_SYMBOL_LENGTH = 6
NORMAL_SYMBOL_LENGTHS = (3, 4)

# Coin names of rows that are not assigned to a coin. They are allowed to repeat.
NAME_PLACEHOLDERS = {"", "*reserved*", "*deprecated*"}


def parse(path):
    """Return the coin type table, whose rows have the cells (coin type, symbol, coin name)."""
    table = find_table(path, "coin type")
    if not table.rows:
        sys.exit(f"::error file={path}::Coin type table is empty.")
    return table


def coin_type(s):
    """Parse a coin type as a decimal integer, or return None if malformed."""
    return int(s) if re.fullmatch(r"[0-9]+", s) else None


def main(base_path, head_path):
    base = parse(base_path)
    head = parse(head_path)
    findings = Findings("SLIP-0044 check", head_path)
    report = findings.report

    # The whole table must be sorted by coin type.
    prev = None
    for row in head.rows:
        n = coin_type(row.cells[0])
        if n is None:
            report("error", row.lineno, f"The coin type '{row.cells[0]}' must be a decimal integer.")
            continue
        if prev is not None and n < prev:
            report("error", row.lineno, f"The table must be sorted by coin type, but coin type {n} follows coin type {prev}.")
        prev = n

    # Symbols and coin names of all rows as (line, description, value) entries,
    # for the uniqueness checks.
    def entries(rows, idx, placeholders):
        return [(r.lineno, f"coin type {r.cells[0]} ('{r.cells[idx]}')", r.cells[idx]) for r in rows if r.cells[idx] not in placeholders]

    symbols = entries(head.rows, 1, {""})
    names = entries(head.rows, 2, NAME_PLACEHOLDERS)
    base_symbols = [e[2] for e in entries(base.rows, 1, {""})]
    base_names = [e[2] for e in entries(base.rows, 2, NAME_PLACEHOLDERS)]

    # The remaining checks only apply to new or modified rows.
    for row in changed_rows(base.rows, head.rows):
        lineno = row.lineno
        ctype, symbol, name = row.cells

        # Rows should be laid out like the base file's table.
        msg = layout_warning(row, base.widths)
        if msg:
            report("warning", lineno, msg)

        # Coin type must be in range and unique.
        n = coin_type(ctype)
        if n is not None:
            if re.fullmatch(r"0[0-9]+", ctype):
                report("error", lineno, f"The coin type '{ctype}' must not have leading zeros.")

            if n > MAX_COIN_TYPE:
                report("error", lineno, f"The coin type {n} must not be greater than {MAX_COIN_TYPE} ({MAX_COIN_TYPE:#x}).")

            if any(r is not row and coin_type(r.cells[0]) == n for r in head.rows):
                report("error", lineno, f"The coin type {n} is already registered. Please choose a different coin type.")

        # Symbol must consist of ASCII letters and digits, should be upper-case and
        # short, and must not duplicate an existing one. It may be empty.
        if symbol:
            if not re.fullmatch(r"[A-Za-z0-9]+", symbol):
                report("error", lineno, f"The symbol '{symbol}' must consist of ASCII letters and digits only.")
            elif symbol != symbol.upper():
                report("warning", lineno, f"The letters of the symbol '{symbol}' should be upper-case.")

            if len(symbol) < MIN_SYMBOL_LENGTH:
                report("error", lineno, f"The symbol '{symbol}' must not be shorter than {MIN_SYMBOL_LENGTH} characters.")
            elif len(symbol) > MAX_SYMBOL_LENGTH:
                report("error", lineno, f"The symbol '{symbol}' must not be longer than {MAX_SYMBOL_LENGTH} characters.")
            elif len(symbol) not in NORMAL_SYMBOL_LENGTHS:
                lengths = " or ".join(map(str, NORMAL_SYMBOL_LENGTHS))
                report("warning", lineno, f"The symbol '{symbol}' should consist of {lengths} characters.")

            entry = next(e for e in symbols if e[0] == lineno)
            check_unique(report, entry, "symbol", base_symbols, symbols, normalize)

        # Coin name is required, should be ASCII and must not duplicate an existing
        # one. Placeholders only appear in rows that are already in the table, except
        # that an existing coin type may be deprecated.
        deprecating = name == "*deprecated*" and any(r.cells[0] == ctype and r.cells[1:] != ("", "") for r in base.rows)
        if name in NAME_PLACEHOLDERS and not deprecating:
            report("error", lineno, "The coin name must not be empty." if not name else f"The coin name must not be '{name}'.")
        elif name not in NAME_PLACEHOLDERS:
            check_name(report, lineno, "coin name", name)
            entry = next(e for e in names if e[0] == lineno)
            check_unique(report, entry, "coin name", base_names, names, normalize_name)

    # Rows must not be removed. Modifying a registration needs the reviewer's attention,
    # since it is only allowed at the request of the registrant. Empty rows may be filled in.
    head_lines = {r.cells[0]: r.lineno for r in head.rows}
    for old in changed_rows(head.rows, base.rows):
        ctype = old.cells[0]
        if ctype not in head_lines:
            report("error", None, f"The coin type {ctype} must not be removed. Please change its coin name to '*deprecated*' instead.")
        elif old.cells[1:] != ("", ""):
            report("warning", head_lines[ctype], f"The row of coin type {ctype} should not be modified unless the change is requested by the party that registered the coin type.")

    findings.finish()


if __name__ == "__main__":
    main(*sys.argv[1:])
