#!/bin/sh
# check-spelling.sh: fail if user-facing sources use common British
# spellings. User-facing text is American English (owner decision,
# 2026-11-05).
#
# Scans the Svelte and TS sources under src/, the Rust under src-tauri/src
# and src-tauri/crates/vettid-device/src, the NSIS hooks and
# tauri.conf.json. Lines that are only a comment are skipped; comments
# are not user-facing. Real exceptions (identifiers, wire strings) are in
# scripts/spelling-allow.txt.
#
# POSIX sh, find, grep -E and awk. Run from anywhere:
#   sh scripts/check-spelling.sh
set -eu

cd "$(dirname "$0")/.."
allow=scripts/spelling-allow.txt

# British forms, as word-boundary EREs (matched case-insensitively).
british='\b(colour[a-z]*|favourite[a-z]*|centre[sd]?|licence[sd]?|grey(s|ed|ish)?|cancell(ed|ing)|labell(ed|ing)|travell(ed|ing|er|ers)|signall(ed|ing)|dial(led|ling)|modell(ed|ing)|(un)?(authori|recogni|organi|reali|apologi|customi|initiali|minimi|maximi|normali|optimi|prioriti|seriali|summari|synchroni|utili|categori|finali|visuali|standardi|personali|memori|emphasi|critici|itemi|saniti)s(e|ed|es|ing|ation|ations)\b|analys(e|ed|ing)|catalogue[sd]?|dialogue[s]?|behaviour[a-z]*|defence[s]?|offence[s]?|judgement[s]?|whilst|enrol(s|led|ling|ment|ments)?|honour[a-z]*|acknowledgement[s]?)\b'

for p in src src-tauri/src src-tauri/crates/vettid-device/src src-tauri/windows src-tauri/tauri.conf.json "$allow"; do
  [ -e "$p" ] || { echo "check-spelling: $p is missing" >&2; exit 2; }
done

scan() {
  find src -type f \( -name '*.svelte' -o -name '*.ts' \) -exec grep -HniE "$british" {} + || true
  find src-tauri/src src-tauri/crates/vettid-device/src -type f -name '*.rs' -exec grep -HniE "$british" {} + || true
  find src-tauri/windows -type f -name '*.nsh' -exec grep -HniE "$british" {} + || true
  grep -HniE "$british" src-tauri/tauri.conf.json || true
}

hits=$(scan)

# Drop comment-only lines: //, ///, /*, *, # and ; (NSIS), <!--.
hits=$(printf '%s\n' "$hits" | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|/\*|\*|#|;|<!--)' || true)

# Remove allow-listed tokens (scoped by path), then look again.
# Each allow-list entry is: PATH-ERE TOKEN-ERE  # why
left=$(printf '%s\n' "$hits" | awk '
  FNR == NR {
    line = $0
    sub(/[[:space:]]+#.*$/, "", line)
    if (line ~ /^[[:space:]]*(#|$)/) next
    if ($0 !~ /[[:space:]]#[[:space:]]*[^[:space:]]/) {
      print "spelling-allow.txt: entry without a reason: " $0 > "/dev/stderr"
      bad = 1
      next
    }
    n++
    split(line, f, /[[:space:]]+/)
    path[n] = f[1]; tok[n] = f[2]
    next
  }
  $0 == "" { next }
  {
    p = $0; sub(/:.*/, "", p)
    rest = substr($0, length(p) + 2)
    for (i = 1; i <= n; i++) if (p ~ path[i]) gsub(tok[i], "", rest)
    print p ":" rest
  }
  END { if (bad) exit 2 }
' "$allow" -) || exit 2
left=$(printf '%s\n' "$left" | grep -iE "^[^:]+:[0-9]+:.*$british" || true)

if [ -n "$left" ]; then
  echo "British spellings in user-facing sources (use American English):" >&2
  printf '%s\n' "$left" >&2
  echo "A real exception (an identifier, a wire string) goes in $allow, with why." >&2
  exit 1
fi
echo "check-spelling: no British spellings in user-facing sources."
