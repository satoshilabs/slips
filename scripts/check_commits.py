# Checks the commit messages of a pull request.
#
# Usage: check_commits.py REVISION_RANGE
#
# A "fixup!", "squash!" or "amend!" commit in REVISION_RANGE (e.g.
# BASE_SHA..HEAD_SHA) is an error, since it has to be squashed before merging.
#
# For every other non-merge commit in REVISION_RANGE that
# changes a SLIP, i.e. slip-xxxx.md or the slip-xxxx/ folder, the subject line
# must start with "slip-xxxx: " (error). A commit that changes more than one SLIP
# may name any of them, typically the main one, or start with "multi: " instead.
# A commit that changes any file other than a SLIP, e.g. README.md or CI scripts,
# is maintenance and its prefix is not checked.
#
# Findings are printed as GitHub Actions annotations. The script exits with
# status 1 if there are any errors.

import re
import subprocess
import sys

from common import Findings


def git(*args):
    # core.quotePath=false makes git print non-ASCII file names as they are.
    cmd = ["git", "-c", "core.quotePath=false", *args]
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def slip_of(path):
    """The SLIP that a changed file belongs to, e.g. "slip-0039", or None."""
    m = re.match(r"(slip-[0-9]{4})(\.md$|/)", path)
    return m.group(1) if m else None


def changed_files(commit):
    return git("diff-tree", "--no-commit-id", "--name-only", "-r", "--no-renames", commit).splitlines()


def main(revision_range):
    findings = Findings("Commit check")

    log = git("log", "--no-merges", "--format=%H%x00%s", revision_range)
    for entry in log.split("\n")[:-1]:
        commit, subject = entry.split("\0", 1)
        where = f"commit {commit[:10]} '{subject}'"
        files = changed_files(commit)

        # Fixup commits must be squashed into their targets before merging.
        if subject.startswith(("fixup! ", "squash! ", "amend! ")):
            findings.report("error", None, f"The {where} must be squashed into the commit that it amends.")
            continue

        # The subject prefix must name the SLIP that the commit changes. A commit
        # that changes several SLIPs may name its main one, or use "multi". The
        # prefix of a commit that also changes non-SLIP files is not checked.
        slips = {slip_of(f) for f in files} - {None}
        maintenance = any(slip_of(f) is None for f in files)
        allowed = sorted(slips) + (["multi"] if len(slips) > 1 else [])
        if allowed and not maintenance and not any(subject.startswith(f"{p}: ") for p in allowed):
            prefixes = " or ".join(repr(p + ": ") for p in allowed)
            findings.report("error", None, f"The subject of the {where} must start with {prefixes}.")

    findings.finish()


if __name__ == "__main__":
    main(*sys.argv[1:])
