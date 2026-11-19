#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# 1) Upstream's own build, NORMAL flags: the nsjail binary + upstream's unit tests (test.sh runs
#    them). This also generates config.pb.{h,cc}, unotify/unotify.pb.{h,cc} and kafel's
#    lexer/parser, all gitignored and recreated here (SPEC §6.2 item 16). make is incremental.
TEST_BINS="tests/nstun_buffer_budget_test tests/nstun_policy_test tests/nstun_ip_test tests/nstun_udp_peer_test"
( unset CFLAGS
  CXXFLAGS="$COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" make -j"$MAYHEM_JOBS" nsjail $TEST_BINS )

# 2) The sanitized fuzz build, out of tree under mayhem/build/ (gitignored by mayhem/.gitignore):
#    every nsjail object except main (nsjail.cc is compiled with main renamed — other objects use
#    its nsjail:: helpers), the protobuf objects, and kafel compiled from its sources, all with
#    $SANITIZER_FLAGS $DEBUG_FLAGS and SanCov.
OUT="$SRC/mayhem/build/fuzz"
mkdir -p "$OUT/unotify" "$OUT/nstun" "$OUT/kafel/syscalls"
NL3_CFLAGS="$(pkg-config --cflags libnl-route-3.0) -DHAVE_LIBNL3"
NL3_LIBS="$(pkg-config --libs libnl-route-3.0)"
PB_CFLAGS="$(pkg-config --cflags protobuf)"
PB_LIBS="$(pkg-config --libs protobuf)"
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1"
NSJ_CXXFLAGS="-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -std=c++20 -fno-exceptions -Wno-c99-designator \
  -I$SRC -I$SRC/kafel/include $PB_CFLAGS $NL3_CFLAGS"

compile() { # <compiler> <src> <obj> <flags...>
  local cc="$1" src="$2" obj="$3"; shift 3
  if [ ! -f "$obj" ] || [ "$src" -nt "$obj" ] || [ "$SRC/mayhem/build.sh" -nt "$obj" ]; then
    "$cc" $FUZZ_CFLAGS "$@" -c "$src" -o "$obj"
  fi
}

NSJ_SRCS="caps.cc cgroup.cc cgroup2.cc cmdline.cc config.cc contain.cc cpu.cc logs.cc mnt.cc mnt_legacy.cc mnt_newapi.cc net.cc nsjail.cc pid.cc sandbox.cc subproc.cc uts.cc user.cc unotify/unotify.cc unotify/stats.cc unotify/syscall.cc util.cc nstun/nstun.cc nstun/policy.cc nstun/encap.cc nstun/iface.cc nstun/tun.cc nstun/ip.cc nstun/icmp.cc nstun/udp.cc nstun/tcp.cc config.pb.cc unotify/unotify.pb.cc"
OBJS=()
pids=()
for s in $NSJ_SRCS; do
  o="$OUT/${s%.cc}.o"; OBJS+=("$o")
  extra=""; [ "$s" = nsjail.cc ] && extra="-Dmain=nsjail_upstream_main"
  compile "$CXX" "$SRC/$s" "$o" $NSJ_CXXFLAGS $extra &
  pids+=($!)
  if [ "${#pids[@]}" -ge "$MAYHEM_JOBS" ]; then wait "${pids[0]}"; pids=("${pids[@]:1}"); fi
done
for p in "${pids[@]}"; do wait "$p"; done

KAFEL_SRCS="kafel.c context.c codegen.c expression.c includes.c parser_types.c policy.c range_rules.c syscall.c lexer.c parser.c syscalls/amd64_syscalls.c syscalls/i386_syscalls.c syscalls/aarch64_syscalls.c syscalls/mipso32_syscalls.c syscalls/mips64_syscalls.c syscalls/riscv64_syscalls.c syscalls/arm_syscalls.c syscalls/m68k_syscalls.c"
for s in $KAFEL_SRCS; do
  o="$OUT/kafel/${s%.c}.o"; OBJS+=("$o")
  compile "$CC" "$SRC/kafel/src/$s" "$o" -std=gnu11 -I"$SRC/kafel/include" -I"$SRC/kafel/src" -fvisibility=hidden
done

compile "$CXX" "$SRC/mayhem/lsan_off.cc" "$OUT/lsan_off.o"
compile "$CC" "$STANDALONE_FUZZ_MAIN" "$OUT/standalone_main.o"

# 3) Each harness twice: libFuzzer binary + run-once -standalone reproducer.
for h in fuzz_nstun_frames fuzz_kafel_policy fuzz_config fuzz_cmdline; do
  compile "$CXX" "$SRC/mayhem/harnesses/$h.cc" "$OUT/$h.o" $NSJ_CXXFLAGS -I"$SRC/mayhem/harnesses"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/$h.o" "${OBJS[@]}" "$OUT/lsan_off.o" \
    -o "$SRC/$h" -lpthread $PB_LIBS $NL3_LIBS
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/$h.o" "$OUT/standalone_main.o" "${OBJS[@]}" "$OUT/lsan_off.o" \
    -o "$SRC/$h-standalone" -lpthread $PB_LIBS $NL3_LIBS
done
echo "built: $(cd "$SRC" && ls fuzz_*)"
