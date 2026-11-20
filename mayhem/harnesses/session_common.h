/* Secure Session harness helpers: fixed identities + key lookup callback (upstream test keys). */
#ifndef MAYHEM_SESSION_COMMON_H
#define MAYHEM_SESSION_COMMON_H
#include <themis/themis.h>
#include "fuzz_common.h"
#include "themis_secure_session_test_keys.h"

static const char client_id[] = "client";
static const char server_id[] = "server";

static int get_public_key_for_id(const void* id, size_t id_length, void* key_buffer,
                                 size_t key_buffer_length, void* user_data)
{
    const uint8_t* key = NULL;
    size_t key_len = 0;
    (void)user_data;
    if (id_length == sizeof(client_id) - 1 && !memcmp(id, client_id, id_length)) {
        key = client_pub;
        key_len = sizeof(client_pub);
    } else if (id_length == sizeof(server_id) - 1 && !memcmp(id, server_id, id_length)) {
        key = server_pub;
        key_len = sizeof(server_pub);
    } else {
        return -1;
    }
    if (key_buffer_length < key_len) {
        return -1;
    }
    memcpy(key_buffer, key, key_len);
    return 0;
}

static secure_session_user_callbacks_t fuzz_callbacks = {NULL, NULL, NULL, get_public_key_for_id, NULL};

/* Feed every remaining length-prefixed packet of the input to secure_session_unwrap. */
static void feed_packets(secure_session_t* s, fuzz_cursor_t* c)
{
    size_t pkt_len = 0;
    uint8_t* pkt;
    while ((pkt = fuzz_next_field(c, &pkt_len)) != NULL) {
        size_t out_len = 0;
        themis_status_t res = secure_session_unwrap(s, pkt, pkt_len, NULL, &out_len);
        if (res == THEMIS_BUFFER_TOO_SMALL) {
            uint8_t* out = malloc(out_len ? out_len : 1);
            if (out) {
                (void)secure_session_unwrap(s, pkt, pkt_len, out, &out_len);
            }
            free(out);
        }
        free(pkt);
    }
}
#endif
