# vulnlab fuzz toolchain.
#
# Builds the intentionally-vulnerable target for two industry-standard
# coverage-guided fuzzers, both with AddressSanitizer so real memory bugs are
# caught:
#   - libFuzzer (clang, -fsanitize=fuzzer)
#   - AFL++ (afl-clang-fast)
#
# LAB ONLY. These intentionally crash. Run them in the sandboxed container.

CC        ?= clang
CXX       ?= clang++
AFL_CC    ?= afl-clang-fast
CFLAGS     = -g -O1 -I.
SAN        = -fsanitize=address,undefined
AFL_SAN   ?= address

.PHONY: all server libfuzzer afl parse-asan clean

all: server libfuzzer

# Normal (non-fuzzing) server build
server:
	$(CC) $(CFLAGS) -o vulnlab vulnlab.c

# libFuzzer + ASan harness (coverage-guided, finds B1/B2 in ~milliseconds)
libfuzzer: fuzz/parse_fuzzer.c vulnlab.c
	$(CC) $(CFLAGS) $(SAN) -fsanitize=fuzzer -o parse_fuzzer \
		fuzz/parse_fuzzer.c vulnlab.c

# AFL++ + ASan harness (alternative coverage-guided fuzzer)
afl: fuzz/parse_afl.c vulnlab.c
	$(AFL_CC) $(CFLAGS) vulnlab.c -c -o vulnlab_afl.o
	$(AFL_CC) $(CFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
		-fsanitize=$(AFL_SAN) -o parse_afl fuzz/parse_afl.c vulnlab_afl.o

# Minimal ASan build to repro a single input (for triage/minimization)
parse-asan:
	$(CC) $(CFLAGS) $(SAN) -o parse_asan vulnlab.c

clean:
	rm -f vulnlab parse_fuzzer parse_afl parse_asan vulnlab_afl.o
	rm -rf corpus crashes findings
