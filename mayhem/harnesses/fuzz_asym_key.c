/* Asymmetric key containers on untrusted bytes: themis_is_valid_asym_key / themis_get_asym_key_kind,
 * then the soter key importers (EC and RSA, private and public) that turn the container into an
 * OpenSSL key, via the sign/verify, ECDH and RSA cipher APIs.
 *
 * Input: 1 flag byte, then the key container. When bit 0 of the flag is set the harness rewrites the
 * container's size field to the input length and recomputes its CRC, so mutated key material gets
 * past the checksum and reaches the parsers; with bit 0 clear the bytes are used as given. */
#include <themis/themis.h>
#include <soter/soter.h>
#include <soter/soter_asym_cipher.h>
#include <soter/soter_asym_ka.h>
#include <soter/soter_asym_sign.h>
#include <soter/soter_container.h>
#include "fuzz_common.h"

static const uint8_t message[] = "mayhem fuzz_asym_key fixed message";

static void try_sign(soter_sign_alg_t alg, const uint8_t* key, size_t len, int private_key)
{
    soter_sign_ctx_t* ctx = private_key ? soter_sign_create(alg, key, len, NULL, 0)
                                        : soter_verify_create(alg, NULL, 0, key, len);
    uint8_t sig[2048];
    size_t sig_len = sizeof(sig);
    if (!ctx) {
        return;
    }
    if (private_key) {
        /* EC only: an RSA private sign with a fuzzed (up to 8192-bit) key is too slow per input. */
        if (alg == SOTER_SIGN_ecdsa_none_pkcs8
            && soter_sign_update(ctx, message, sizeof(message)) == SOTER_SUCCESS) {
            (void)soter_sign_final(ctx, sig, &sig_len);
        }
        soter_sign_destroy(ctx);
    } else {
        memset(sig, 0x30, 72);
        if (soter_verify_update(ctx, message, sizeof(message)) == SOTER_SUCCESS) {
            (void)soter_verify_final(ctx, sig, 72);
        }
        soter_verify_destroy(ctx);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz_cursor_t c = {data, size};
    size_t len = 0;
    uint8_t flags;
    uint8_t* key;
    if (size < 1) {
        return 0;
    }
    flags = data[0];
    c.data++;
    c.size--;
    key = fuzz_rest(&c, &len);
    if (!key) {
        return 0;
    }
    if ((flags & 1) && len >= sizeof(soter_container_hdr_t)) {
        soter_container_hdr_t* hdr = (soter_container_hdr_t*)key;
        soter_container_set_data_size(hdr, len - sizeof(soter_container_hdr_t));
        soter_update_container_checksum(hdr);
    }

    themis_key_kind_t kind = themis_get_asym_key_kind(key, len);
    if (themis_is_valid_asym_key(key, len) == THEMIS_SUCCESS) {
        switch (kind) {
        case THEMIS_KEY_EC_PRIVATE:
        case THEMIS_KEY_EC_PUBLIC: {
            int priv = kind == THEMIS_KEY_EC_PRIVATE;
            soter_asym_ka_t* ka;
            try_sign(SOTER_SIGN_ecdsa_none_pkcs8, key, len, priv);
            ka = soter_asym_ka_create(SOTER_ASYM_KA_EC_P256);
            if (ka) {
                (void)soter_asym_ka_import_key(ka, key, len);
                soter_asym_ka_destroy(ka);
            }
            break;
        }
        case THEMIS_KEY_RSA_PRIVATE:
        case THEMIS_KEY_RSA_PUBLIC: {
            int priv = kind == THEMIS_KEY_RSA_PRIVATE;
            soter_asym_cipher_t* cipher;
            try_sign(SOTER_SIGN_rsa_pss_pkcs8, key, len, priv);
            cipher = soter_asym_cipher_create(key, len, SOTER_ASYM_CIPHER_OAEP);
            if (cipher) {
                if (!priv) {
                    uint8_t out[1024];
                    size_t out_len = sizeof(out);
                    (void)soter_asym_cipher_encrypt(cipher, message, sizeof(message), out, &out_len);
                }
                soter_asym_cipher_destroy(cipher);
            }
            break;
        }
        default:
            break;
        }
    }
    free(key);
    return 0;
}
