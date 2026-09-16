/*
 * libFuzzer harness for vulnlab_parse() — coverage-guided fuzzing with ASan.
 *
 * Build (clang + sanitizers):
 *   clang -g -O1 -fsanitize=fuzzer,address -I. -o parse_fuzzer \
 *         fuzz/parse_fuzzer.c vulnlab.c
 *
 * Run:
 *   ./parse_fuzzer -runs=100000 -max_len=512 corpus/
 *
 * The fuzzer will find the stack overflow (and the format-string %n) almost
 * immediately, because it has the source's control-flow to guide it — the
 * advantage of white-box fuzzing over blind HTTP mutation.
 */
#include <stddef.h>
#include <stdint.h>

#include "vulnlab.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* libFuzzer guarantees size>0, but keep the parser's contract honest. */
  (void)vulnlab_parse(data, size);
  return 0; /* Returning non-zero aborts fuzzing; always return 0. */
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
/* Provide a bare main only when NOT compiled as a libFuzzer target, so the
 * file can also be built standalone for a quick check. */
__attribute__((unused)) static int not_main(void) {
  return 0;
}
#endif
