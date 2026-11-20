/* Secure Cell token-protect decryption: fields = context, auth token, ciphertext. Fixed key. */
#include <themis/themis.h>
#include "fuzz_common.h"

static const uint8_t master_key[] = "mayhem-fuzz-secure-cell-master-key-32b";

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz_cursor_t c = {data, size};
    size_t ctx_len = 0, tok_len = 0, msg_len = 0, out_len = 0;
    uint8_t *ctx = NULL, *tok = NULL, *msg = NULL, *out = NULL;

    ctx = fuzz_next_field(&c, &ctx_len);
    tok = fuzz_next_field(&c, &tok_len);
    msg = fuzz_rest(&c, &msg_len);
    if (!ctx || !tok || !msg) {
        goto done;
    }
    if (themis_secure_cell_decrypt_token_protect(master_key, sizeof(master_key) - 1, ctx, ctx_len,
                                                 msg, msg_len, tok, tok_len, NULL, &out_len)
        != THEMIS_BUFFER_TOO_SMALL) {
        goto done;
    }
    /* Token Protect plaintext is exactly as long as the ciphertext: the library's own decrypt
     * (sym_enc_message.c, "Sanity check of resulting message length") fails any result whose length
     * differs from encrypted_message_length. The size query above is only "a quick guess" read from
     * the token header, so don't allocate a guess larger than the ciphertext. */
    if (out_len > msg_len) {
        goto done;
    }
    out = malloc(out_len ? out_len : 1);
    if (out) {
        (void)themis_secure_cell_decrypt_token_protect(master_key, sizeof(master_key) - 1, ctx,
                                                       ctx_len, msg, msg_len, tok, tok_len, out,
                                                       &out_len);
    }
done:
    free(ctx);
    free(tok);
    free(msg);
    free(out);
    return 0;
}
