# vulnlab — an INTENTIONALLY VULNERABLE lab target + fuzzing toolchain.
#
# WARNING: deliberately unsafe code. Exists ONLY as a throwaway, sandboxed
# teaching target for h4k's fuzzer lab. Runs in its own container against
# nothing but itself. Never expose beyond your machine; do not use as a template.
#
# Ships BOTH:
#   - the vulnerable HTTP server (supervisord restarts it after each crash), AND
#   - industry-standard coverage-guided fuzz harnesses:
#         libFuzzer (clang -fsanitize=fuzzer,address)  -> ./parse_fuzzer
#         AFL++     (afl-clang-fast + afl-fuzz)        -> ./parse_afl
#     both with ASan/UBSan so real memory bugs (B1 stack overflow, B2 format
#     string) are caught fast — the modern way to find bugs vs blind mutation.
FROM alpine:3.20

ENV VULNLAB_PORT=8080

# toolchain: compiler, sanitizers, libFuzzer, AFL++, supervisor
RUN apk add --no-cache build-base clang llvm git supervisor bash \
    && apk add --no-cache afl++ 2>/dev/null || true

# build the vulnerable server (no stack protector keeps B1 reliably crashy)
COPY vulnlab.c /opt/vulnlab.c
COPY vulnlab.h /opt/vulnlab.h
RUN cc -O0 -g -fno-stack-protector -I/opt -o /usr/local/bin/vulnlab /opt/vulnlab.c \
    && rm -f /opt/vulnlab.c

# build the libFuzzer/ASan harness (strip vulnlab's main via the fuzz macro)
COPY fuzz/parse_fuzzer.c /opt/fuzz/parse_fuzzer.c
COPY vulnlab.c /opt/vulnlab.c
COPY vulnlab.h /opt/vulnlab.h
RUN clang -g -O1 -I/opt -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
        -fsanitize=address,undefined -fsanitize=fuzzer \
        -o /usr/local/bin/parse_fuzzer /opt/fuzz/parse_fuzzer.c /opt/vulnlab.c \
    && rm -f /opt/vulnlab.c /opt/fuzz/parse_fuzzer.c
RUN mkdir -p /opt/corpus /opt/findings \
    && printf 'AAAA' > /opt/corpus/seed

# supervisor restarts the live server after each fuzz-induced crash
COPY supervisord.conf /etc/supervisord.conf
EXPOSE 8080
CMD ["supervisord", "-c", "/etc/supervisord.conf"]
