/* Secure Session, client side: generate a connect request, then hand every input packet to
 * secure_session_unwrap as if it were the server's reply. */
#include "session_common.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz_cursor_t c = {data, size};
    uint8_t req[4096];
    size_t req_len = sizeof(req);
    secure_session_t* s = secure_session_create(client_id, sizeof(client_id) - 1, client_priv,
                                                sizeof(client_priv), &fuzz_callbacks);
    if (!s) {
        return 0;
    }
    if (secure_session_generate_connect_request(s, req, &req_len) == THEMIS_SUCCESS) {
        feed_packets(s, &c);
    }
    secure_session_destroy(s);
    return 0;
}
