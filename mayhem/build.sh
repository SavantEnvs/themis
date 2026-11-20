#!/usr/bin/env bash
# mayhem/build.sh — build themis (libthemis + libsoter, OpenSSL backend) and its fuzz targets.
#
#   build/mayhem-afl   libs built with afl-clang-fast + sanitizers, for upstream's AFL harnesses
#                      (tools/afl/src, file-input main()s)
#   build/mayhem-fuzz  libs built with clang + sanitizers + fuzzer-no-link, for the libFuzzer
#                      harnesses in mayhem/harnesses
#   build/mayhem-test  normal upstream build of soter_test/themis_test, run by mayhem/test.sh
#   build/mayhem-bin   all fuzz binaries (+ -standalone reproducers)
# Everything lands under build/, which upstream's .gitignore already ignores.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
# The bundled ref10 ed25519 code (src/soter/ed25519, used by Secure Comparator) left-shifts negative
# carries by design (e.g. fe_mul.c `h3 -= carry3 << 25`), which UBSan's shift-base check halts on for
# nearly every input. Relax only that check; the rest of UBSan and ASan stay on and halting.
LIB_RELAX="-fno-sanitize=shift-base"
[ -n "$SANITIZER_FLAGS" ] || LIB_RELAX=""
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
BIN="$SRC/build/mayhem-bin"
mkdir -p "$BIN"

# Upstream's make: CC/CFLAGS must come from the ENVIRONMENT (a make command-line CFLAGS would
# override the Makefile's own `CFLAGS += -Iinclude -Isrc ...`). -gdwarf-3 goes after the Makefile's
# -g via the same CFLAGS (clang keeps the explicit DWARF version).
build_libs() { # <build path> <cc> <cflags>
    BUILD_PATH="$1" CC="$2" CFLAGS="$3" make -j"$MAYHEM_JOBS" BUILD_PATH="$1" themis_static soter_static
}

# 1) Sanitized libs for the AFL harnesses (instrumented by afl-clang-fast).
AFL_LIB=build/mayhem-afl
build_libs "$AFL_LIB" afl-clang-fast "$SANITIZER_FLAGS $LIB_RELAX $DEBUG_FLAGS"
afl-clang-fast $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.c -o "$AFL_LIB/lsan_off.o"
for t in scell_seal_decrypt scell_seal_decrypt_pw scell_seal_roundtrip scell_seal_roundtrip_pw \
         smessage_encrypt_decrypt smessage_encrypt_roundtrip smessage_sign_roundtrip smessage_sign_verify; do
    afl-clang-fast $SANITIZER_FLAGS $DEBUG_FLAGS -Iinclude -Isrc -Itools/afl/src \
        "tools/afl/src/$t.c" tools/afl/src/readline.c "$AFL_LIB/lsan_off.o" \
        "$AFL_LIB/libthemis.a" "$AFL_LIB/libsoter.a" -lcrypto -o "$BIN/$t"
done

# 2) Sanitized libs for the libFuzzer harnesses.
FZ_LIB=build/mayhem-fuzz
build_libs "$FZ_LIB" "$CC" "$SANITIZER_FLAGS $LIB_RELAX -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.c -o "$FZ_LIB/lsan_off.o"
for t in fuzz_asym_key fuzz_scell_token_protect fuzz_scell_context_imprint fuzz_smessage_unwrap \
         fuzz_ssession_server fuzz_ssession_client fuzz_ssession_load fuzz_scomparator; do
    common=(-Wno-deprecated-declarations -Iinclude -Isrc -Itests/themis -Imayhem/harnesses "mayhem/harnesses/$t.c"
            "$FZ_LIB/lsan_off.o" "$FZ_LIB/libthemis.a" "$FZ_LIB/libsoter.a" -lcrypto)
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${common[@]}" -o "$BIN/$t"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$STANDALONE_FUZZ_MAIN" "${common[@]}" -o "$BIN/$t-standalone"
done

# 3) Upstream's own C test suites (soter_test, themis_test), normal flags.
env -u CFLAGS -u LDFLAGS BUILD_PATH=build/mayhem-test CC="$CC" CFLAGS="$COVERAGE_FLAGS" \
    LDFLAGS="$COVERAGE_FLAGS" make -j"$MAYHEM_JOBS" BUILD_PATH=build/mayhem-test prepare_tests_basic
