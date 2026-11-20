#!/usr/bin/env bash
# mayhem/test.sh — run upstream's C test suites (soter_test, themis_test; built by mayhem/build.sh
# under build/mayhem-test). Both are known-answer / round-trip assertion suites (test vectors,
# encrypt→decrypt equality, protocol outcomes); each prints
#   one "[S:N] test:#K \"desc\" pass|FAIL" line per check, plus a final "==> ..." summary
# which is mapped to CTRF counts. A missing or silent binary counts as a failure.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Every check prints one line: "[S:N]  <test>:#K  "<desc>"  pass|FAIL". Those lines are counted.
# test_rand_with_nist (soter_test) is a statistical NIST STS randomness assessment of the RNG output;
# it fails nondeterministically (about one run in two on the same tree), so it is reported as
# skipped rather than letting a random verdict grade a patch. Every other check counts.
FLAKY='test_rand_with_nist'
passed=0; failed=0; skipped=0
for t in soter_test themis_test; do
  bin="build/mayhem-test/tests/$t"
  if [ ! -x "$bin" ]; then
    echo "missing $bin — mayhem/build.sh did not build it" >&2
    failed=$((failed + 1)); continue
  fi
  out=$("$bin" 2>&1); rc=$?
  printf '%s\n' "$out" | tail -n 3
  checks=$(printf '%s\n' "$out" | grep -E '^\[[0-9]+:[0-9]+\] .* (pass|FAIL)$' || true)
  if [ -z "$checks" ] || ! printf '%s\n' "$out" | grep -q '^==> '; then
    echo "$t: no check results / summary (rc=$rc)" >&2
    failed=$((failed + 1)); continue
  fi
  p=$(printf '%s\n' "$checks" | grep -v " $FLAKY:" | grep -c ' pass$' || true)
  f=$(printf '%s\n' "$checks" | grep -v " $FLAKY:" | grep -c ' FAIL$' || true)
  sk=$(printf '%s\n' "$checks" | grep -c " $FLAKY:" || true)
  printf '%s\n' "$checks" | grep -v " $FLAKY:" | grep ' FAIL$' >&2 || true
  passed=$((passed + p)); failed=$((failed + f)); skipped=$((skipped + sk))
  # A crash/abort after the last check still fails the suite unless it's only the skipped check.
  if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ] && [ "$sk" -eq 0 ]; then failed=$((failed + 1)); fi
done
emit_ctrf "sput" "$passed" "$failed" "$skipped"
