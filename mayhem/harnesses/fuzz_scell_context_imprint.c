/* Secure Cell context-imprint decryption: fields = context, ciphertext. Fixed key. */
#include <themis/themis.h>
#include "fuzz_common.h"

static const uint8_t master_key[] = "mayhem-fuzz-secure-cell-master-key-32b";

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz_cursor_t c = {data, size};
    size_t ctx_len = 0, msg_len = 0, out_len = 0;
    uint8_t *ctx = NULL, *msg = NULL, *out = NULL;

    ctx = fuzz_next_field(&c, &ctx_len);
    msg = fuzz_rest(&c, &msg_len);
    if (!ctx || !msg) {
        goto done;
    }
    if (themis_secure_cell_decrypt_context_imprint(master_key, sizeof(master_key) - 1, msg, msg_len,
                                                   ctx, ctx_len, NULL, &out_len)
        != THEMIS_BUFFER_TOO_SMALL) {
        goto done;
    }
    out = malloc(out_len ? out_len : 1);
    if (out) {
        (void)themis_secure_cell_decrypt_context_imprint(master_key, sizeof(master_key) - 1, msg,
                                                         msg_len, ctx, ctx_len, out, &out_len);
    }
done:
    free(ctx);
    free(msg);
    free(out);
    return 0;
}
