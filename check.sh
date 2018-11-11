echo SLIP-0044 duplicates:
grep '^[0-9]' slip-0044.md | cut -f 3,4 -d '|' | grep -v '|$' | sort | uniq -d
