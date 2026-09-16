/*
 * vulnlab — an INTENTIONALLY VULNERABLE lab-only HTTP service + fuzz harnesses.
 *
 * Two use-modes:
 *   1) Run as a real server:  ./vulnlab <port>
 *   2) Compile as a fuzz target with a coverage-guided fuzzer (AFL++ or the
 *      clang/libFuzzer) — see fuzz/ and the Dockerfile targets.
 *
 * The vulnerable logic is isolated in `vulnlab_parse()`, which BOTH the server
 * and the harnesses call. That is the whole point: give coverage guidance the
 * same code path the network server actually runs.
 *
 * WARNING: UNBALANCED / UNSOUND ON PURPOSE. This is a teaching target for h4k's
 * fuzzer lab. Run it ONLY inside its own sandboxed container against nothing
 * but itself. Never expose it beyond your machine; it is not a template.
 *
 * Bugs (each reachable from attacker-controlled bytes):
 *   B1 stack buffer overflow — attacker bytes strcpy'd into a 256B stack buf.
 *   B2 format-string        — attacker bytes used as printf format (aborts on %n).
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUF_SIZE 256

#if defined(__has_feature)
#  if __has_feature(address_sanitizer)
#    define VULNLAB_ASAN 1
#  endif
#endif

/* The buggy parser. `in` is attacker-controlled bytes; `in_len` its length.
 * Returns 0 on success. May clobber memory / die on crafted input. */
int vulnlab_parse(const uint8_t *in, size_t in_len) {
  char header[BUF_SIZE];
  char tmp[512];
  size_t i;

  /* B1: stack buffer overflow — copy attacker bytes into a fixed 256B buffer
   * with no length check. Any input longer than BUF_SIZE-1 overflows. */
  for (i = 0; i < in_len; i++) {
    header[i] = (char)in[i];
  }
  header[in_len] = '\0'; /* B1: writes one byte past the buffer when full */

  /* B2: format string — attacker bytes used as a printf format. The fuzzer's
   * "%s%n" input makes printf write through %n, aborting under ASan. */
  snprintf(tmp, sizeof(tmp), "%s", header);
  fprintf(stderr, header); /* UNSOUND: attacker-controlled format */
  fflush(stderr);
  (void)tmp;

  return 0;
}

/* ---------- server mode (not used by harnesses) ---------- */
static void handle(int conn) {
  uint8_t req[4096];
  ssize_t n = recv(conn, req, sizeof(req) - 1, 0);
  if (n <= 0) { close(conn); return; }
  /* copy req into an exact buffer and parse it through the buggy path */
  uint8_t buf[4096];
  memcpy(buf, req, (size_t)n);
  vulnlab_parse(buf, (size_t)n);
  const char *resp =
      "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
      "Content-Length: 13\r\nConnection: close\r\n\r\nvulnlab v1.0\n";
  send(conn, resp, (int)strlen(resp), 0);
  close(conn);
}

static int run_server(int port) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) { perror("socket"); return 1; }
  int one = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons((unsigned short)port);
  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
  if (listen(sock, 16) < 0) { perror("listen"); return 1; }
  fprintf(stderr, "vulnlab listening on 0.0.0.0:%d\n", port);
  fflush(stderr);
  for (;;) {
    int conn = accept(sock, NULL, NULL);
    if (conn < 0) continue;
    handle(conn);
  }
}

/* main() is omitted when fuzzing (libFuzzer/AFL provide their own main). */
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int main(int argc, char **argv) {
  if (argc > 1 && strcmp(argv[1], "parse") == 0) {
    /* CLI test mode: read stdin and run through the buggy parser. */
    uint8_t in[65536];
    size_t got = fread(in, 1, sizeof(in), stdin);
    return vulnlab_parse(in, got);
  }
  int port = argc > 1 ? atoi(argv[1]) : 8080;
  if (port <= 0 || port > 65535) port = 8080;
  return run_server(port);
}
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
