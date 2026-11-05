#!/bin/sh
# check-spelling.sh: fail if user-facing sources use common British
# spellings. User-facing text is American English (owner decision,
# 2026-11-05).
#
# Scans the Svelte and TS sources under src/, the Rust under src-tauri/src
# and src-tauri/crates/vettid-device/src, the NSIS hooks, index.html,
# tauri.conf.json and src-tauri/Info.plist (the macOS permission prompts).
# Lines that are only a comment are skipped, as comments are not
# user-facing: in .nsh files a line starting with # or ;, elsewhere a line
# starting with //, /*, * (then a space, / or the line's end) or <!--.
# A line starting with #[ (a Rust attribute, e.g. #[error("...")]) is
# scanned. Real exceptions (identifiers, wire strings) are in
# scripts/spelling-allow.txt.
#
# POSIX sh, find, grep -E and awk. Run from anywhere:
#   sh scripts/check-spelling.sh
set -eu

cd "$(dirname "$0")/.."
allow=scripts/spelling-allow.txt

# British forms, as word-boundary EREs (matched case-insensitively).
british='\b(colour[a-z]*|(fav|flav|hum|lab|neighb|rum|endeav|vig|rig)our[a-z]*|honour[a-z]*|behaviour[a-z]*|centre[sd]?|licence[sd]?|grey(s|ed|ish)?|cancell(ed|ing)|labell(ed|ing)|travell(ed|ing|er|ers)|signall(ed|ing)|dial(led|ling)|modell(ed|ing)|(lev|fu|chann|tunn)ell(ed|ing)|(tot|marsh)all(ed|ing)|(un|de|re)?(authori|recogni|organi|reali|apologi|customi|initiali|minimi|maximi|normali|optimi|prioriti|seriali|summari|synchroni|utili|categori|finali|visuali|standardi|personali|memori|emphasi|critici|itemi|saniti|anonymi|randomi|tokeni|locali|characteri|capitali|digiti|stabili|speciali|generali|centrali)s(e|ed|es|ing|ation|ations)\b|analys(e|ed|ing)|(paraly|cataly)s(e|ed|es|ing)|catalogue[sd]?|dialogue[s]?|defence[s]?|offence[s]?|pretence[s]?|judgement[s]?|acknowledgement[s]?|whilst|amongst|enrol(s|ment|ments)?|programme[sd]?|(met|lit|fib|theat)re[s]?|cheque[s]?|fulfil(s|ment)?|(skil|wil)ful|instalment[s]?|artefact[s]?|ageing|practis(e|ed|es|ing)|sceptic[a-z]*)\b'

for p in src src-tauri/src src-tauri/crates/vettid-device/src src-tauri/windows index.html src-tauri/tauri.conf.json src-tauri/Info.plist "$allow"; do
  [ -e "$p" ] || { echo "check-spelling: $p is missing" >&2; exit 2; }
done

scan() {
  find src -type f \( -name '*.svelte' -o -name '*.ts' \) -exec grep -HniE "$british" {} + || true
  find src-tauri/src src-tauri/crates/vettid-device/src -type f -name '*.rs' -exec grep -HniE "$british" {} + || true
  find src-tauri/windows -type f -name '*.nsh' -exec grep -HniE "$british" {} + || true
  grep -HniE "$british" index.html src-tauri/tauri.conf.json src-tauri/Info.plist || true
}

hits=$(scan)

# Drop comment-only lines (see the header).
hits=$(printf '%s\n' "$hits" |
  grep -vE '^[^:]+\.nsh:[0-9]+:[[:space:]]*(#|;)' |
  grep -vE '^[^:]+\.(rs|ts|svelte|html|json|plist):[0-9]+:[[:space:]]*(//|/\*|\*([[:space:]/]|$)|<!--)' || true)

# Remove allow-listed tokens (scoped by path), then look again.
# Each allow-list entry is: PATH-ERE TOKEN-ERE  # why
left=$(printf '%s\n' "$hits" | awk -v allow="$allow" '
  function bad_entry(why) {
    print allow ": " why ": " $0 > "/dev/stderr"
    bad = 1
  }
  FILENAME == allow {
    if ($0 ~ /^#/ || $0 ~ /^[[:space:]]*$/) next
    if ($0 ~ /^[[:space:]]/) { bad_entry("entry with leading whitespace"); next }
    if ($0 !~ /[[:space:]]#[[:space:]]*[^[:space:]]/) { bad_entry("entry without a reason"); next }
    line = $0
    sub(/[[:space:]]+#.*$/, "", line)
    if (split(line, f, /[[:space:]]+/) != 2) { bad_entry("entry without exactly 2 fields (PATH-ERE TOKEN-ERE)"); next }
    n++
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
