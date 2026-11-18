#!/usr/bin/env bash
#
# check-oracle-claims.sh — PA-008 citation-integrity lint.
#
# Rule: every comment that asserts what an ORACLE does or permits — i.e. what
# "i2pd" emits/always/never/signs/includes/writes, or what "the spec"
# requires/permits/allows/says/states/mandates/emits — must carry a resolvable
# file:line citation (pattern `Name.ext:NNNN`) somewhere in the same comment
# block. This is the anti-poisoning guard from audit finding PA-008: in this
# repo, every i2pd-citing leniency rationale was found FALSE when opened
# against the real source. Requiring a surviving file:line stops an unverified
# "as i2pd emits" claim from being inherited by the next leniency.
#
# A "file:line" citation is checked two ways:
#   1. FORMAT (always enforced): the citation must match `name.ext:NNNN`.
#   2. RANGE (best-effort): when the cited reference file is locatable on this
#      machine, the cited line number must be within the file's length. This
#      catches fabricated or stale citations whose target line does not exist.
#      If the reference file is not available, the range check is skipped for
#      that citation (format is still required).
#
# Reference sources (override with env vars; defaults match the go-i2p dev
# checkout layout). The lint never fails solely because a reference is absent —
# it only fails on a missing/malformed citation, or on an out-of-range citation
# for a reference that IS present.
#   SSU2_SPEC  -> the ssu2.md spec (default: i2p.website en/docs/specs/ssu2.md)
#   I2PD_SRC   -> the i2pd source root (default: PurpleI2P/i2pd)
#
# Usage: scripts/check-oracle-claims.sh [path ...]   (default: repo root)
# Exit 0 = all oracle claims cited; exit 1 = at least one violation.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Default reference locations for the best-effort range check.
SSU2_SPEC="${SSU2_SPEC:-$HOME/go/src/github.com/i2p/i2p.website/content/en/docs/specs/ssu2.md}"
I2PD_SRC="${I2PD_SRC:-$HOME/go/src/github.com/PurpleI2P/i2pd}"

TARGETS=("$@")
if [ ${#TARGETS[@]} -eq 0 ]; then
	TARGETS=("$REPO_ROOT")
fi

# Trigger: a comment line asserting oracle behavior (case-insensitive).
#   - any mention of i2pd (every i2pd reference in this repo is an oracle claim)
#   - positive spec claims: "spec requires/permits/allows/says/states/mandates/
#     emits/always/never/includes/signs/writes"
TRIGGER_RE='i2pd|spec( is)? (requires|permits|allows|says|states|mandates|emits|always|never|includes|signs|writes)'
# Exempt: negative spec-freedom notes ("the spec does not mandate/require/..."),
# which assert the ABSENCE of a constraint, not an oracle shape.
EXEMPT_RE='spec (does not|doesn.t|do not|dont) (mandate|require|specify|define|say|state|spec)'
# A citation: name.ext:NNNN (optionally a range NNNN-NNNN). `[.]` not `\.` so the
# same pattern is warning-free in both grep -E and awk.
CITE_RE='[A-Za-z0-9_./-]+[.](md|cpp|cc|c|go|h|hpp|java|py|rs|txt|html|rst):[0-9]+(-[0-9]+)?'

OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT

for target in "${TARGETS[@]}"; do
	while IFS= read -r f; do
		awk -v file="$f" -v trig="$TRIGGER_RE" -v exempt="$EXEMPT_RE" -v cite="$CITE_RE" '
		BEGINIGNORECASE = 1
		function flush_block(  i, has_trigger, has_cite, is_exempt) {
			if (blen == 0) return
			has_trigger = 0; has_cite = 0; is_exempt = 0
			for (i = 0; i < blen; i++) {
				if (blines[i] ~ exempt) is_exempt = 1
				if (blines[i] ~ trig) has_trigger = 1
				if (blines[i] ~ cite) has_cite = 1
			}
			if (has_trigger && !has_cite && !is_exempt) {
				printf "UNCITED %s:%d oracle claim (no file:line citation in block)\n", file, bstart
			}
			if (has_trigger) claims++
			blen = 0
		}
		{
			line = $0
			if (line ~ /^[[:space:]]*\/\//) {
				if (blen == 0) bstart = NR
				blines[blen++] = line
			} else {
				flush_block()
			}
		}
		END {
			flush_block()
			printf "STATS %d %d\n", claims+0, (claims+0)
		}
		' "$f" >> "$OUT"
	done < <(find "$target" -type f -name '*.go' -not -path '*/.git/*' -not -path '*/vendor/*' | sort)
done

# Best-effort range check: for each citation in the file set, if its reference
# is locatable, ensure the cited line number is within the file's length.
range_violations=0
while IFS= read -r cite; do
	target="${cite%%:*}"
	after="${cite#*:}"
	lineno="${after%%-*}"
	base="$(basename "$target")"
	ref=""
	case "$base" in
		ssu2.md) [ -f "$SSU2_SPEC" ] && ref="$SSU2_SPEC" ;;
		SSU2Session.cpp) [ -d "$I2PD_SRC" ] && ref="$(find "$I2PD_SRC" -name 'SSU2Session.cpp' -type f 2>/dev/null | head -n1)" ;;
	esac
	[ -z "$ref" ] && continue
	maxlen="$(wc -l < "$ref" 2>/dev/null || echo 0)"
	if [ "${lineno:-0}" -gt "$maxlen" ] 2>/dev/null; then
		printf 'OUT-OF-RANGE cites %s but %s has only %s lines\n' "$cite" "$ref" "$maxlen" >&2
		range_violations=$((range_violations + 1))
	fi
done < <(grep -hoE "$CITE_RE" "${TARGETS[@]}" -r --include='*.go' 2>/dev/null | sort -u)

uncited="$(grep -c '^UNCITED ' "$OUT" 2>/dev/null || true)"
claims="$(awk '/^STATS / {s+=$2} END {print s+0}' "$OUT")"

echo "check-oracle-claims: $claims oracle claim(s); $uncited uncited; $range_violations out-of-range."
grep '^UNCITED ' "$OUT" >&2 || true

if [ "${uncited:-0}" -gt 0 ] || [ "$range_violations" -gt 0 ]; then
	echo "FAIL: every oracle claim (i2pd / spec behavior) must carry a resolvable file:line citation." >&2
	exit 1
fi
exit 0
