/* Shared helpers for the themis libFuzzer harnesses (mayhem integration). */
#ifndef MAYHEM_FUZZ_COMMON_H
#define MAYHEM_FUZZ_COMMON_H
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Cursor over the fuzz input. Fields are a 2-byte big-endian length followed by that many bytes;
 * a short final field takes whatever is left. */
typedef struct {
    const uint8_t* data;
    size_t size;
} fuzz_cursor_t;

/* Returns a heap copy of exactly the field's length (so ASan sees any over-read), or NULL when the
 * input is exhausted. *out_len receives the length. Caller frees. */
static uint8_t* fuzz_next_field(fuzz_cursor_t* c, size_t* out_len)
{
    size_t len;
    uint8_t* out;
    if (c->size < 2) {
        return NULL;
    }
    len = ((size_t)c->data[0] << 8) | c->data[1];
    c->data += 2;
    c->size -= 2;
    if (len > c->size) {
        len = c->size;
    }
    out = malloc(len ? len : 1);
    if (!out) {
        return NULL;
    }
    memcpy(out, c->data, len);
    c->data += len;
    c->size -= len;
    *out_len = len;
    return out;
}

/* Heap copy of the rest of the input. */
static uint8_t* fuzz_rest(fuzz_cursor_t* c, size_t* out_len)
{
    uint8_t* out = malloc(c->size ? c->size : 1);
    if (!out) {
        return NULL;
    }
    memcpy(out, c->data, c->size);
    *out_len = c->size;
    c->data += c->size;
    c->size = 0;
    return out;
}
#endif
