echo SLIP-0044 duplicates:
grep '^[0-9]' slip-0044.md | cut -f 3 -d '|' | tr -d ' ' | sort | uniq -d

echo SLIP-0044: uppercase:
grep '0x80[^ ]*[A-F]' slip-0044.md
