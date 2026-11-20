/* Legacy auto-detecting Secure Message unwrap (encrypted or signed container, EC or RSA keys).
 * Byte 0 selects the key pair; the rest is the wrapped message. Keys come from upstream's test keys. */
#define THEMIS_NO_DEPRECATION_WARNINGS
#include <themis/themis.h>
#include "fuzz_common.h"
#include "themis_secure_session_test_keys.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz_cursor_t c;
    size_t msg_len = 0, out_len = 0;
    uint8_t *msg = NULL, *out = NULL;
    const uint8_t *priv, *pub;
    size_t priv_len, pub_len;

    if (size < 1) {
        return 0;
    }
    switch (data[0] & 3) {
    case 0: /* sign/verify direction: no private key */
        priv = NULL; priv_len = 0; pub = client_pub; pub_len = sizeof(client_pub);
        break;
    case 1:
        priv = server_priv; priv_len = sizeof(server_priv); pub = client_pub; pub_len = sizeof(client_pub);
        break;
    case 2:
        priv = NULL; priv_len = 0; pub = client_pub_rsa; pub_len = sizeof(client_pub_rsa);
        break;
    default:
        priv = client_priv_rsa; priv_len = sizeof(client_priv_rsa); pub = client_pub_rsa; pub_len = sizeof(client_pub_rsa);
        break;
    }
    c.data = data + 1;
    c.size = size - 1;
    msg = fuzz_rest(&c, &msg_len);
    if (!msg) {
        return 0;
    }
    if (themis_secure_message_unwrap(priv, priv_len, pub, pub_len, msg, msg_len, NULL, &out_len)
        == THEMIS_BUFFER_TOO_SMALL) {
        out = malloc(out_len ? out_len : 1);
        if (out) {
            (void)themis_secure_message_unwrap(priv, priv_len, pub, pub_len, msg, msg_len, out, &out_len);
        }
    }
    free(msg);
    free(out);
    return 0;
}
