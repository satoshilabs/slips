# Checks changes to the SLIP-0173 registry of human-readable parts in a pull request.
#
# Usage: check_slip173.py BASE_FILE HEAD_FILE
#
# Compares the three tables in HEAD_FILE (the PR version) against BASE_FILE (the
# target branch version):
# - Segwit: Coin | Mainnet | Testnet | Regtest
# - Other:  Project | Mainnet / Production | Testnet | Regtest
# - Codex32: Application | Human-readable part
#
# The Segwit table is checked for ordering as a whole, while the remaining checks
# only apply to rows that are new or modified. All human-readable parts (HRPs)
# share one namespace, so collisions are checked across the three tables.
#
# Findings are printed as GitHub Actions annotations. The script exits with
# status 1 if there are any errors.

import re
import sys
from typing import NamedTuple

from common import Findings, changed_rows, check_name, check_unique, find_table, layout_warning, normalize_name


# BIP-0173 limits.
MAX_HRP_LENGTH = 83
MIN_HRP_CHAR = 33
MAX_HRP_CHAR = 126

# HRPs should be NORMAL_HRP_LENGTH characters long (anything else is a warning).
NORMAL_HRP_LENGTH = (2, 6)

SEGWIT = "Coin"
OTHER = "Project"
CODEX32 = "Application"
TABLES = (SEGWIT, OTHER, CODEX32)

# The pattern that HRPs in each table should match (anything else is a warning).
# The other table allows dashes, e.g. "age-secret-key-".
NORMAL_HRP = {SEGWIT: r"[a-z0-9]+", OTHER: r"[a-z0-9-]+", CODEX32: r"[a-z0-9]+"}


class Entry(NamedTuple):
    table: str
    lineno: int
    name: str  # The first cell. Empty in continuation rows of the other table.
    column: str  # "mainnet", "testnet", "regtest" or "codex32".
    cell: str  # The raw cell, e.g. "`dash` (m)".
    hrp: str  # The HRP, e.g. "dash" or "ln[currency prefix + amount]", or None if the cell is malformed.


def parse_hrp(table, cell):
    """Extract the HRP from a table cell, or return None if the cell is not a single
    HRP in backticks."""
    # The other table marks Bech32m entries with "(m)".
    suffix = r"(?: \(m\))?" if table == OTHER else ""
    m = re.fullmatch(rf"`([^`]+)`{suffix}", cell)
    return m.group(1) if m else None


def is_template(hrp):
    """True for an HRP with variable content, e.g. "age1[name]"."""
    return "[" in hrp


def parse(path):
    """Return {table: Table} for the three tables of the file."""
    return {t: find_table(path, t) for t in TABLES}


def entries(tables):
    """All HRPs in the tables, as a list of Entry."""
    result = []
    for t, table in tables.items():
        for row in table.rows:
            for column, cell in zip(table.header[1:], row.cells[1:]):
                if cell:
                    # Short column label, e.g. "mainnet" for "Mainnet / Production".
                    column = "codex32" if t == CODEX32 else column.split()[0]
                    result.append(Entry(t, row.lineno, row.cells[0], column, cell, parse_hrp(t, cell)))
    return result


def main(base_path, head_path):
    base = parse(base_path)
    head = parse(head_path)
    findings = Findings("SLIP-0173 check", head_path)
    report = findings.report

    # Head rows that are new or modified, per table, and their line numbers.
    changed = {t: changed_rows(base[t].rows, head[t].rows) for t in TABLES}
    changed_lines = {r.lineno for rows in changed.values() for r in rows}

    # The whole Segwit table must be sorted by coin name, ignoring case.
    prev = None
    for row in head[SEGWIT].rows:
        name = row.cells[0]
        if prev is not None and name.casefold() < prev.casefold():
            report("error", row.lineno, f"The table must be sorted alphabetically by coin name, but '{name}' follows '{prev}'.")
        prev = name

    # Names of new or modified rows. A name must be unique within its table.
    name_labels = {SEGWIT: "coin name", OTHER: "project name", CODEX32: "application name"}
    for t in TABLES:
        label = name_labels[t]
        names = [(r.lineno, f"'{r.cells[0]}' on line {r.lineno}", r.cells[0]) for r in head[t].rows if r.cells[0]]
        base_names = [r.cells[0] for r in base[t].rows if r.cells[0]]

        for row in changed[t]:
            # Rows should be laid out like the base file's table.
            msg = layout_warning(row, base[t].widths)
            if msg:
                report("warning", row.lineno, msg)

            # The other table continues a project's rows with an empty name.
            name = row.cells[0]
            if not name:
                if t != OTHER:
                    report("error", row.lineno, f"The {label} must not be empty.")
                continue

            check_name(report, row.lineno, label, name)
            entry = next(e for e in names if e[0] == row.lineno)
            check_unique(report, entry, label, base_names, names, normalize_name)

    # The Segwit table needs a mainnet HRP in every row.
    for row in changed[SEGWIT]:
        if not row.cells[1]:
            report("error", row.lineno, f"The coin '{row.cells[0]}' must have a mainnet HRP.")

    # HRPs in new or modified rows.
    # All HRPs share one namespace across the three tables.
    head_entries = [e for e in entries(head) if e.hrp]
    base_hrps = [e.hrp for e in entries(base) if e.hrp]
    hrps = [(e.lineno, f"{e.name or 'line ' + str(e.lineno)} ({e.column})", e.hrp) for e in head_entries]

    for e in entries(head):
        if e.lineno in changed_lines and not e.hrp:
            report("error", e.lineno, f"The {e.column} cell '{e.cell}' must contain a single HRP enclosed in backticks.")

    for e, hrp_entry in zip(head_entries, hrps):
        if e.lineno not in changed_lines:
            continue
        where = f"The {e.column} HRP '{e.hrp}'"

        # BIP-0173 rules. Variable parts of a template are not checked.
        literal = re.sub(r"\[[^\]]*\]", "", e.hrp) if e.table == OTHER else e.hrp
        if not is_template(e.hrp) and not 1 <= len(e.hrp) <= MAX_HRP_LENGTH:
            report("error", e.lineno, f"{where} must consist of 1 to {MAX_HRP_LENGTH} characters.")
        elif not is_template(e.hrp) and not NORMAL_HRP_LENGTH[0] <= len(e.hrp) <= NORMAL_HRP_LENGTH[1]:
            report("warning", e.lineno, f"{where} should consist of {NORMAL_HRP_LENGTH[0]} to {NORMAL_HRP_LENGTH[1]} characters.")
        if any(not MIN_HRP_CHAR <= ord(c) <= MAX_HRP_CHAR for c in literal):
            report("error", e.lineno, f"{where} must consist of US-ASCII characters in the range 33-126 only.")
        elif literal != literal.lower():
            report("error", e.lineno, f"{where} must not contain upper-case letters.")
        elif literal and not re.fullmatch(NORMAL_HRP[e.table], literal):
            allowed = "lower-case letters, digits and dashes" if e.table == OTHER else "lower-case letters and digits"
            report("warning", e.lineno, f"{where} should consist of {allowed} only.")

        if "1" in literal:
            report("warning", e.lineno, f"{where} should not contain the digit '1', since it can be mistaken for the separator between the HRP and the data part.")

        check_unique(report, hrp_entry, f"{e.column} HRP", base_hrps, hrps)

    findings.finish()


if __name__ == "__main__":
    main(*sys.argv[1:])
