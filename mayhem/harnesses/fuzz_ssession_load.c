/* Secure Session saved-state restore: secure_session_load on untrusted bytes, then wrap/unwrap on
 * the restored session. Uses the session struct definition as upstream's own tests do. */
#include "session_common.h"
#include "themis/secure_session_t.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz_cursor_t c = {data, size};
    size_t state_len = 0, out_len = 0;
    uint8_t *state, *out = NULL;
    static const uint8_t msg[] = "mayhem";
    secure_session_t* s = calloc(1, sizeof(secure_session_t));
    if (!s) {
        return 0;
    }
    state = fuzz_next_field(&c, &state_len);
    if (state && secure_session_load(s, state, state_len, &fuzz_callbacks) == THEMIS_SUCCESS) {
        /* Wrap into a caller-sized buffer (wrapped length = message + a small fixed header).
         * The NULL size query is avoided: secure_session_wrap computes header pointers from the
         * output buffer before its NULL check, which UBSan flags on every call regardless of the
         * restored state (pointer arithmetic on NULL, secure_session_message.c:42). */
        out_len = 4096;
        out = malloc(out_len);
        if (out) {
            (void)secure_session_wrap(s, msg, sizeof(msg), out, &out_len);
        }
        feed_packets(s, &c);
        secure_session_cleanup(s);
    }
    free(out);
    free(state);
    free(s);
    return 0;
}
