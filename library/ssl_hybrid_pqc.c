/*
 *  Hybrid X25519MLKEM768 implementation for TLS 1.3
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "ssl_client.h"
#include "ssl_misc.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/debug.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "psa/crypto.h"
#include "psa_util_internal.h"
/* Local PSA error translation to align with other TLS1.3 files */
static int local_err_translation(psa_status_t status)
{
    return psa_status_to_mbedtls(status, psa_to_ssl_errors,
                                 ARRAY_LENGTH(psa_to_ssl_errors),
                                 psa_generic_status_to_mbedtls);
}
#define PSA_TO_MBEDTLS_ERR(status) local_err_translation(status)
#include <mbedtls/ctr_drbg.h>

#include <string.h>
#include "mlkem768.h"

#define MLKEM768_PUBLIC_KEY_LEN  1184
#define MLKEM768_SECRET_KEY_LEN  2400
#define MLKEM768_CIPHERTEXT_LEN  1088
#define MLKEM768_SHARED_SECRET_LEN 32

#define X25519_PUBLIC_KEY_LEN    32
#define X25519_PRIVATE_KEY_LEN   32
#define X25519_SHARED_SECRET_LEN 32

#define HYBRID_PUBLIC_KEY_LEN    (MLKEM768_PUBLIC_KEY_LEN + X25519_PUBLIC_KEY_LEN)  // 1216
#define HYBRID_CIPHERTEXT_LEN    (MLKEM768_CIPHERTEXT_LEN + X25519_PUBLIC_KEY_LEN)  // 1120
#define HYBRID_SHARED_SECRET_LEN (MLKEM768_SHARED_SECRET_LEN + X25519_SHARED_SECRET_LEN)  // 64

int mbedtls_ssl_tls13_generate_hybrid_x25519mlkem768_key_exchange(
    mbedtls_ssl_context *ssl,
    unsigned char *buf,
    unsigned char *end,
    size_t *out_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ssl_handshake_params *handshake = ssl->handshake;
    mlkem768_ctx_t mlkem_ctx;
    unsigned char *x25519_pk = NULL;
    psa_key_attributes_t x_attrs = PSA_KEY_ATTRIBUTES_INIT;
    size_t x25519_pk_len = 0;

    *out_len = 0;

    printf("*** Generating hybrid X25519MLKEM768 key exchange ***\n");

    /* Check buffer space */
    if ((size_t)(end - buf) < HYBRID_PUBLIC_KEY_LEN) {
        printf("*** Insufficient buffer space for hybrid key exchange ***\n");
        return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }

    /* Initialize ML-KEM-768 */
    ret = mlkem768_init(&mlkem_ctx);
    if (ret != 0) {
        printf("*** Failed to initialize ML-KEM-768 ***\n");
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    /* Generate ML-KEM-768 keypair */
    ret = mlkem768_keypair(&mlkem_ctx);
    if (ret != 0) {
        printf("*** Failed to generate ML-KEM-768 keypair ***\n");
        mlkem768_cleanup(&mlkem_ctx);
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    /* Allocate memory for X25519 public key */
    x25519_pk = mbedtls_calloc(1, X25519_PUBLIC_KEY_LEN);
    if (x25519_pk == NULL) {
        printf("*** Failed to allocate memory for X25519 keys ***\n");
        mlkem768_cleanup(&mlkem_ctx);
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }

    /* Generate X25519 keypair via PSA and export raw public key (32 bytes) */
    psa_status_t status;
    psa_set_key_usage_flags(&x_attrs, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&x_attrs, PSA_ALG_ECDH);
    psa_set_key_type(&x_attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&x_attrs, 255);
    status = psa_generate_key(&x_attrs, &handshake->xxdh_psa_privkey);
    if (status != PSA_SUCCESS) {
        ret = PSA_TO_MBEDTLS_ERR(status);
        printf("*** PSA X25519 keygen failed: %d ***\n", ret);
        goto cleanup;
    }
    status = psa_export_public_key(handshake->xxdh_psa_privkey,
                                   x25519_pk, X25519_PUBLIC_KEY_LEN, &x25519_pk_len);
    if (status != PSA_SUCCESS || x25519_pk_len != X25519_PUBLIC_KEY_LEN) {
        ret = PSA_TO_MBEDTLS_ERR(status);
        printf("*** PSA X25519 export public key failed: %d (len=%zu) ***\n", ret, x25519_pk_len);
        goto cleanup;
    }

    /* Store keys in handshake context */
    handshake->mlx_mlkem_sk = mbedtls_calloc(1, MLKEM768_SECRET_KEY_LEN);
    if (handshake->mlx_mlkem_sk == NULL) {
        printf("*** Failed to allocate memory for ML-KEM secret key ***\n");
        ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto cleanup;
    }

    // For now, we'll store the context and extract the key later
    handshake->mlx_mlkem_sk_len = MLKEM768_SECRET_KEY_LEN;
    handshake->hybrid_state_allocated = 1;

    /* Serialize hybrid public key: ML-KEM pk || X25519 pk */
    // Get ML-KEM public key from context
    memcpy(buf, mlkem_ctx.public_key, MLKEM768_PUBLIC_KEY_LEN);
    memcpy(buf + MLKEM768_PUBLIC_KEY_LEN, x25519_pk, X25519_PUBLIC_KEY_LEN);
    *out_len = HYBRID_PUBLIC_KEY_LEN;

    /* Copy ML-KEM secret key to handshake context */
    memcpy(handshake->mlx_mlkem_sk, mlkem_ctx.secret_key, MLKEM768_SECRET_KEY_LEN);

    printf("*** Generated hybrid key exchange: %zu bytes ***\n", *out_len);

    ret = 0;

cleanup:
    /* Clean up temporary allocations */
    if (x25519_pk != NULL) {
        mbedtls_free(x25519_pk);
    }

    mlkem768_cleanup(&mlkem_ctx);

    return ret;
}

int mbedtls_ssl_tls13_parse_hybrid_x25519mlkem768_key_share(
    mbedtls_ssl_context *ssl,
    const unsigned char *buf,
    size_t buf_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ssl_handshake_params *handshake = ssl->handshake;
    mlkem768_ctx_t mlkem_ctx;
    unsigned char *mlkem_ct = NULL;
    unsigned char *x25519_pk_s = NULL;
    unsigned char *mlkem_ss = NULL;
    unsigned char *x25519_ss = NULL;
    unsigned char *hybrid_ss = NULL;
    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

    printf("*** Parsing hybrid X25519MLKEM768 key share ***\n");

    /* The input buffer starts with a 2-byte key_exchange length, followed by
     * key_exchange bytes: ML-KEM ct (1088) || X25519 pk_s (32) */
    if (buf_len < 2) {
        printf("*** Invalid key_share buffer (too short for length): %zu ***\n", buf_len);
        return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }
    uint16_t key_exchange_len = MBEDTLS_GET_UINT16_BE(buf, 0);
    if (key_exchange_len != HYBRID_CIPHERTEXT_LEN) {
        printf("*** Invalid hybrid key_exchange_len: %u (expected %d) ***\n",
               (unsigned) key_exchange_len, HYBRID_CIPHERTEXT_LEN);
        return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }
    if (buf_len < 2 + key_exchange_len) {
        printf("*** Truncated key_share: buf_len=%zu, need=%u ***\n",
               buf_len, (unsigned) (2 + key_exchange_len));
        return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }
    const unsigned char *key_exchange = buf + 2;

    /* Check if we have the required state */
    if (!handshake->hybrid_state_allocated || handshake->mlx_mlkem_sk == NULL) {
        printf("*** Missing hybrid state for key share parsing ***\n");
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    /* Initialize ML-KEM-768 */
    ret = mlkem768_init(&mlkem_ctx);
    if (ret != 0) {
        printf("*** Failed to initialize ML-KEM-768 ***\n");
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    /* Allocate memory */
    mlkem_ct = mbedtls_calloc(1, MLKEM768_CIPHERTEXT_LEN);
    x25519_pk_s = mbedtls_calloc(1, X25519_PUBLIC_KEY_LEN);
    mlkem_ss = mbedtls_calloc(1, MLKEM768_SHARED_SECRET_LEN);
    x25519_ss = mbedtls_calloc(1, X25519_SHARED_SECRET_LEN);
    hybrid_ss = mbedtls_calloc(1, HYBRID_SHARED_SECRET_LEN);

    if (mlkem_ct == NULL || x25519_pk_s == NULL || mlkem_ss == NULL ||
        x25519_ss == NULL || hybrid_ss == NULL) {
        printf("*** Failed to allocate memory for key share parsing ***\n");
        ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto cleanup;
    }

    /* Parse server key share: ML-KEM ct || X25519 pk_s */
    memcpy(mlkem_ct, key_exchange, MLKEM768_CIPHERTEXT_LEN);
    memcpy(x25519_pk_s, key_exchange + MLKEM768_CIPHERTEXT_LEN, X25519_PUBLIC_KEY_LEN);

    /* Set up ML-KEM context with our secret key */
    memcpy(mlkem_ctx.secret_key, handshake->mlx_mlkem_sk, MLKEM768_SECRET_KEY_LEN);

    /* Decapsulate ML-KEM shared secret */
    ret = mlkem768_decaps(&mlkem_ctx, mlkem_ct);
    if (ret != 0) {
        printf("*** Failed to decapsulate ML-KEM shared secret ***\n");
        ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        goto cleanup;
    }

    /* Copy ML-KEM shared secret */
    memcpy(mlkem_ss, mlkem_ctx.shared_secret, MLKEM768_SHARED_SECRET_LEN);

    /* Compute X25519 shared secret via PSA to match TLS ECDHE path semantics */
    psa_algorithm_t alg = PSA_ALG_ECDH;
    psa_status_t status;
    size_t olen = 0;

    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&key_attributes, alg);
    psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&key_attributes, 255);

    /* Use the PSA private key generated during ClientHello for X25519 */
    if (mbedtls_svc_key_id_is_null(handshake->xxdh_psa_privkey)) {
        printf("*** Missing PSA X25519 private key in handshake ***\n");
        ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        goto cleanup;
    }

    status = psa_raw_key_agreement(alg, handshake->xxdh_psa_privkey,
                                   x25519_pk_s, X25519_PUBLIC_KEY_LEN,
                                   x25519_ss, X25519_SHARED_SECRET_LEN, &olen);
    if (status != PSA_SUCCESS || olen != X25519_SHARED_SECRET_LEN) {
        ret = PSA_TO_MBEDTLS_ERR(status);
        printf("*** PSA X25519 key agreement failed: %d (olen=%zu) ***\n", ret, olen);
        goto cleanup;
    }

    /* Combine shared secrets: ML-KEM ss || X25519 ss */
    memcpy(hybrid_ss, mlkem_ss, MLKEM768_SHARED_SECRET_LEN);
    memcpy(hybrid_ss + MLKEM768_SHARED_SECRET_LEN, x25519_ss, X25519_SHARED_SECRET_LEN);

    /* Store the hybrid shared secret in the handshake context for key derivation */
    memcpy(handshake->hybrid_ss, hybrid_ss, HYBRID_SHARED_SECRET_LEN);
    handshake->hybrid_ss_len = HYBRID_SHARED_SECRET_LEN;
    handshake->hybrid_ss_valid = 1;
    printf("*** Computed hybrid shared secret: %d bytes (stored) ***\n", HYBRID_SHARED_SECRET_LEN);

    ret = 0;

cleanup:
    /* Clean up temporary allocations */
    if (mlkem_ct != NULL) {
        mbedtls_free(mlkem_ct);
    }
    if (x25519_pk_s != NULL) {
        mbedtls_free(x25519_pk_s);
    }
    if (mlkem_ss != NULL) {
        mbedtls_platform_zeroize(mlkem_ss, MLKEM768_SHARED_SECRET_LEN);
        mbedtls_free(mlkem_ss);
    }
    if (x25519_ss != NULL) {
        mbedtls_platform_zeroize(x25519_ss, X25519_SHARED_SECRET_LEN);
        mbedtls_free(x25519_ss);
    }
    if (hybrid_ss != NULL) {
        mbedtls_platform_zeroize(hybrid_ss, HYBRID_SHARED_SECRET_LEN);
        mbedtls_free(hybrid_ss);
    }

    /* Do not destroy handshake->xxdh_psa_privkey here; TLS will manage it. */

    mlkem768_cleanup(&mlkem_ctx);

    return ret;
}

int mbedtls_ssl_tls13_cleanup_hybrid_state(mbedtls_ssl_context *ssl)
{
    mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    if (handshake->hybrid_state_allocated) {
        mbedtls_platform_zeroize(handshake->mlx_mlkem_sk, handshake->mlx_mlkem_sk_len);
        mbedtls_free(handshake->mlx_mlkem_sk);
        handshake->mlx_mlkem_sk = NULL;
        handshake->mlx_mlkem_sk_len = 0;
        mbedtls_platform_zeroize(handshake->x25519_priv, sizeof(handshake->x25519_priv));
        handshake->hybrid_state_allocated = 0;
    }
    return 0;
}
