#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
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

# Upstream's `make test` suite, minus the cases that need root/userns/network to start jails:
#  * the four nstun unit tests (assert-based; built by build.sh with normal flags), and
#  * upstream's `test-cmdline` cases: exit codes of nsjail's numeric-option parsing, plus a
#    golden check that --help prints the option list.
passed=0; failed=0
check() { # <name> <expected-exit> <cmd...>
  local name="$1" want="$2"; shift 2
  "$@" >/dev/null 2>&1; local rc=$?
  if [ "$rc" -eq "$want" ]; then passed=$((passed+1)); echo "PASS: $name"
  else failed=$((failed+1)); echo "FAIL: $name (exit $rc, expected $want)"; fi
}

for t in nstun_buffer_budget_test nstun_policy_test nstun_ip_test nstun_udp_peer_test; do
  if [ ! -x "tests/$t" ]; then echo "missing tests/$t — run mayhem/build.sh" >&2; failed=$((failed+1)); continue; fi
  check "$t" 0 "./tests/$t"
done
[ -x ./nsjail ] || { echo "missing ./nsjail — run mayhem/build.sh" >&2; emit_ctrf nsjail-make-test "$passed" $((failed+1)); exit 1; }

check "time_limit 1.5 rejected"            255 ./nsjail --time_limit 1.5 --help
check "time_limit -1 rejected"             255 ./nsjail --time_limit=-1 --help
check "max_cpus 2^32 rejected"             255 ./nsjail --max_cpus 4294967296 --help
check "nice_level 2^31 rejected"           255 ./nsjail --nice_level=2147483648 --help
check "user idmap count 1.5 rejected"      255 ./nsjail --user 1000:1000:1.5 --help
check "rlimit_cpu 1.5 rejected"            255 ./nsjail --rlimit_cpu 1.5 --help
check "valid hex/negative/idmap accepted"  0   ./nsjail --time_limit 0x10 --cgroup_mem_swap_max=-1 --user 1000:1000:1 --help

help="$(./nsjail --help 2>&1)"
for opt in '--config|-C VALUE' '--seccomp_string VALUE' '--rlimit_as VALUE' '--bindmount|-B VALUE'; do
  if grep -qF -- "$opt" <<<"$help"; then passed=$((passed+1)); echo "PASS: --help lists $opt"
  else failed=$((failed+1)); echo "FAIL: --help does not list $opt"; fi
done

emit_ctrf nsjail-make-test "$passed" "$failed"
