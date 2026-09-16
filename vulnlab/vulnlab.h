#ifndef VULNLAB_H
#define VULNLAB_H

#include <stddef.h>
#include <stdint.h>

/*
 * The intentionally-vulnerable parser shared by the server and the fuzz
 * harnesses. Defined in vulnlab.c. Returns 0 on success; may overflow/abort
 * on crafted input (BUGS B1/B2). LAB ONLY.
 */
int vulnlab_parse(const uint8_t *in, size_t in_len);

#endif /* VULNLAB_H */
