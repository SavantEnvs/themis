/* Secure Comparator (SMP over ed25519): byte 0 picks the role; the rest is a sequence of
 * length-prefixed peer messages fed to secure_comparator_proceed_compare. */
#include <themis/themis.h>
#include "fuzz_common.h"

static const uint8_t secret[] = "mayhem shared secret";

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz_cursor_t c;
    uint8_t* pkt;
    size_t pkt_len = 0;
    secure_comparator_t* comp;

    if (size < 1) {
        return 0;
    }
    comp = secure_comparator_create();
    if (!comp) {
        return 0;
    }
    if (secure_comparator_append_secret(comp, secret, sizeof(secret) - 1) != THEMIS_SUCCESS) {
        goto done;
    }
    if (data[0] & 1) {
        size_t req_len = 0;
        if (secure_comparator_begin_compare(comp, NULL, &req_len) == THEMIS_BUFFER_TOO_SMALL) {
            uint8_t* req = malloc(req_len);
            if (req) {
                (void)secure_comparator_begin_compare(comp, req, &req_len);
            }
            free(req);
        }
    }
    c.data = data + 1;
    c.size = size - 1;
    while ((pkt = fuzz_next_field(&c, &pkt_len)) != NULL) {
        size_t out_len = 0;
        themis_status_t res = secure_comparator_proceed_compare(comp, pkt, pkt_len, NULL, &out_len);
        if (res == THEMIS_BUFFER_TOO_SMALL) {
            uint8_t* out = malloc(out_len ? out_len : 1);
            if (out) {
                res = secure_comparator_proceed_compare(comp, pkt, pkt_len, out, &out_len);
            }
            free(out);
        }
        free(pkt);
        if (res != THEMIS_SUCCESS && res != THEMIS_SCOMPARE_SEND_OUTPUT_TO_PEER) {
            break;
        }
    }
done:
    secure_comparator_destroy(comp);
    return 0;
}
