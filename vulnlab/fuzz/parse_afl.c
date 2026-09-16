/*
 * AFL++ stdin harness for vulnlab_parse() — coverage-guided fuzzing with ASan.
 *
 * Build (needs afl-clang-fast; use the Makefile `make afl`):
 *   make afl   (AFL_CC=afl-clang-fast)
 *
 * Run:
 *   mkdir -p corpus && printf AAAA > corpus/seed
 *   afl-fuzz -i corpus -o findings ./parse_afl
 *
 * Same coverage-guided advantage as libFuzzer: it follows the parser's
 * control flow so B1 (stack overflow) and B2 (format string) crash quickly.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vulnlab.h"

#define MAX_IN 262144

int main(void) {
  static uint8_t buf[MAX_IN];
  size_t size = fread(buf, 1, sizeof(buf), stdin);
  vulnlab_parse(buf, size);
  return 0; /* AFL detects crashes via signals, not exit code. */
}
