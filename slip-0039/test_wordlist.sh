#!/bin/bash

# wordlist is alphabetically sorted
diff wordlist.txt <(sort wordlist.txt) && echo OK

# no word is shorter than 4 letters
diff wordlist.txt <(grep '^....' wordlist.txt) && echo OK

# no word is longer than 8 letters
! grep -q '^.........' wordlist.txt && echo OK

# all words have unique 4-letter prefix
diff <(cut -c 1-4 wordlist.txt) <(cut -c 1-4 wordlist.txt | sort -u) && echo OK

# wordlist contains only common English words (+ the word "satoshi")
test "$(comm -23 wordlist.txt <(aspell -l en dump master | tr [A-Z] [a-z] | sort ))" = "satoshi" && echo OK
