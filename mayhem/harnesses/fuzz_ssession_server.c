/* Secure Session, server side: every input packet is handed to secure_session_unwrap as if it came
 * from a client (handshake messages, then data once established). */
#include "session_common.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz_cursor_t c = {data, size};
    secure_session_t* s = secure_session_create(server_id, sizeof(server_id) - 1, server_priv,
                                                sizeof(server_priv), &fuzz_callbacks);
    if (!s) {
        return 0;
    }
    feed_packets(s, &c);
    secure_session_destroy(s);
    return 0;
}
