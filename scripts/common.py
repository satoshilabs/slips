# Helpers shared by the registry checks, check_slip44.py and check_slip173.py.

import html
import os
import re
import sys
from collections import Counter
from typing import NamedTuple


class Row(NamedTuple):
    lineno: int
    line: str  # The raw line, without the "\n".
    cells: tuple


class Table(NamedTuple):
    header: tuple  # Lower-cased header cells.
    widths: list  # Column widths taken from the separator row, or None.
    rows: list  # List of Row.


def read_lines(path):
    """Return the lines of a file. Only "\n" ends a line, so a stray "\r" stays visible."""
    with open(path, encoding="utf-8", newline="") as f:
        return f.read().split("\n")


def split_row(line):
    """Split a table line into cells, trimming the space padding of each cell."""
    # Remove at most one outer pipe on each end, so that "| 748 |||" keeps its
    # empty cells.
    line = line.removeprefix("|").removesuffix("|")
    return tuple(c.strip(" ") for c in line.split("|"))


def is_separator(cells):
    return all(re.fullmatch(r":?-+:?", c) for c in cells)


def parse_tables(path):
    """Return the Markdown tables in a file as a list of Table.

    A table starts with a header line followed by a separator line, and it
    ends at the first line without a pipe."""
    raw = read_lines(path)
    # Trim only spaces and line endings, so that other whitespace such as tabs
    # or NBSP stays in the cells and gets reported.
    lines = [line.strip(" \r") for line in raw]

    tables = []
    i = 0
    while i < len(lines):
        if "|" not in lines[i] or i + 1 >= len(lines) or "|" not in lines[i + 1]:
            i += 1
            continue
        header = split_row(lines[i])
        separator = split_row(lines[i + 1])
        if not is_separator(separator):
            i += 1
            continue

        widths = None
        if re.fullmatch(r"\|( -+ \|)+", lines[i + 1]):
            widths = [len(dashes) for dashes in re.findall(r"-+", lines[i + 1])]

        rows = []
        i += 2
        while i < len(lines) and "|" in lines[i]:
            cells = split_row(lines[i])
            if len(cells) != len(header):
                sys.exit(f"::error file={path},line={i + 1}::The row must have {len(header)} cells, but it has {len(cells)}.")
            rows.append(Row(i + 1, raw[i], cells))
            i += 1

        tables.append(Table(tuple(c.lower() for c in header), widths, rows))

    return tables


def find_table(path, first_column):
    """The first table whose first header cell is first_column, ignoring case."""
    for table in parse_tables(path):
        if table.header[0] == first_column.lower():
            return table
    sys.exit(f"::error file={path}::Table with column '{first_column}' not found.")


def layout_warning(row, widths):
    """A warning message if the row is not aligned like the separator row, with
    one space after each pipe and each cell padded to its column width, else None."""
    if not widths:
        return None
    for c, w in zip(row.cells, widths):
        if len(c) > w:
            return f"The cell '{c}' should not be longer than {w} characters."
    expected = "| " + " | ".join(c.ljust(w) for c, w in zip(row.cells, widths)) + " |"
    if row.line != expected:
        return f"The row should be formatted like the other rows, i.e. `` {expected} ``."
    return None


def changed_rows(base_rows, head_rows):
    """The head rows that are new or modified, i.e. not present in base_rows."""
    unchanged = Counter(r.cells for r in base_rows)
    changed = []
    for row in head_rows:
        if unchanged[row.cells]:
            unchanged[row.cells] -= 1
        else:
            changed.append(row)
    return changed


def check_name(report, line, label, name):
    """Report a name that contains non-ASCII characters or unusual whitespace."""
    if not name.isascii():
        report("warning", line, f"The {label} '{name}' should consist of ASCII characters only.")
    if has_unusual_whitespace(name):
        report("error", line, f"The {label} '{name}' must not contain any whitespace characters other than single spaces.")


def check_unique(report, entry, label, base_values, head_entries, loose_key=None):
    """Report an error if another entry has the same value as entry, ignoring case,
    or a warning if it has a similar value, i.e. the same after applying loose_key.

    Entries are (line, description, value) tuples, where the description names
    the entry in the message, e.g. "coin type 0 ('BTC')". A value may repeat only
    as often as it already did in base_values, so that duplicates that are already
    registered are not blamed on the pull request."""
    line, _, value = entry
    for key, kind in ((str.casefold, "error"), (loose_key, "warning")):
        k = key(value) if key else None
        if not k:
            continue
        clash = [e[1] for e in head_entries if e is not entry and key(e[2]) == k]
        if len(clash) + 1 > max(sum(1 for v in base_values if key(v) == k), 1):
            if kind == "error":
                report("error", line, f"The {label} '{value}' is already used by {', '.join(clash)}. Please choose a different {label}.")
            else:
                report("warning", line, f"The {label} '{value}' is too similar to {', '.join(clash)}. Please choose a more distinctive {label}.")
            return


def normalize(s):
    """Loose comparison key, e.g. "X Coin", "Xcoin", "X.coin" and "X-coin" all map to "xcoin"."""
    return re.sub(r"[\W_]+", "", s.casefold())


def normalize_name(s):
    """Like normalize(), but also drops parenthesized parts, e.g. "X Coin (Legacy)" maps to "xcoin"."""
    return normalize(re.sub(r"\([^)]*\)", "", s))


def has_unusual_whitespace(s):
    """True if s contains whitespace other than single spaces, e.g. tabs, NBSP or double spaces."""
    return "  " in s or re.search(r"[^\S ]", s) is not None


class Findings:
    """Collects the findings of a check and prints them as GitHub Actions annotations."""

    def __init__(self, title, path=None):
        self.title = title
        self.path = path  # The file that line numbers refer to, if any.
        self.items = []  # (kind, where, message) tuples with kind "error" or "warning".

    def report(self, kind, line, msg):
        """Report a finding. line is the line number in self.path, or None."""
        where = f"line {line}" if line else ""
        location = f" file={self.path},line={line}" if self.path and line else ""
        print(f"::{kind}{location}::{msg}")
        self.items.append((kind, where, msg))

    def finish(self):
        """Print the totals, add the findings to the GitHub job summary if there is one,
        append them to the file named by FINDINGS_FILE if it is set, and exit.
        The exit status is 1 if there are any errors."""
        errors = sum(1 for kind, _, _ in self.items if kind == "error")
        totals = f"{errors} error(s), {len(self.items) - errors} warning(s)."
        print(totals)

        # The job summary has no limit on the number of findings, unlike annotations.
        path = os.environ.get("GITHUB_STEP_SUMMARY")
        if path:
            with open(path, "a", encoding="utf-8") as f:
                f.write(f"## {self.title}\n\n{totals}\n\n")
                # Errors first, then warnings, each in the order found.
                for kind, where, msg in sorted(self.items, key=lambda x: x[0] != "error"):
                    where = f" ({where})" if where else ""
                    f.write(f"- **{kind.capitalize()}**{where}: {html.escape(msg)}\n")
                f.write("\n")

        # Record the findings, so that the workflow can list the findings of all
        # checks in one place.
        path = os.environ.get("FINDINGS_FILE")
        if path:
            with open(path, "a", encoding="utf-8") as f:
                for kind, where, msg in self.items:
                    where = f", {where}" if where else ""
                    f.write(f"{kind.capitalize()} ({self.title}{where}): {msg}\n")

        sys.exit(1 if errors else 0)
