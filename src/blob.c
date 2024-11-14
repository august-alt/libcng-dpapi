/***********************************************************************************************************************
**
** Copyright (C) 2024 BaseALT Ltd. <org@basealt.ru>
**
** This program is free software; you can redistribute it and/or
** modify it under the terms of the GNU General Public License
** as published by the Free Software Foundation; either version 2
** of the License, or (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**
***********************************************************************************************************************/

#include "blob_p.h"

#include <math.h>
#include <stdbool.h>
#include <string.h>

#include <gkdi/ndr_gkdi.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/ssl.h>

#include "pkcs7_p.h"
#include "pkcs7/KEKRecipientInfo.h"

const uint8_t KDS_SERVICE_LABEL[] = { 0x00, 0x00 };

#define CONTENT_TYPE_ENVELOPED_DATA_OID "1.2.840.113549.1.7.3"
#define MAX_BUFFER_SIZE 16384

blob_t *
blob_unpack(
        TALLOC_CTX *mem_ctx,
        const uint8_t *data,
        const uint32_t size)
{
    if (!mem_ctx)
    {
        printf("%s:%s:%d Passed talloc_ctx is NULL. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, 0, "TALLOC_CTX is NULL!");

        return NULL;
    }

    blob_t *result = talloc(mem_ctx, blob_t);
    enum ndr_err_code ndr_status = NDR_ERR_SUCCESS;
    if (!result)
    {
        printf("%s:%s:%d Failed to allocate blob_t object. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, 0, "Out of memory!");

        goto error_exit;
    }

    KEKRecipientInfo_t *kekInfo = unpack_ContentInfo(data, size);
    if (!kekInfo)
    {
        printf("%s:%s:%d Failed to decode KEKRecipientInfo object. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, 0, "Unable to unpack object!");

        goto error_exit;
    }

    // TODO: Check encrypted content according to blob.py#L310

    DATA_BLOB data_blob;
    data_blob.data = kekInfo->kekid.keyIdentifier.buf;
    data_blob.length = kekInfo->kekid.keyIdentifier.size;
    ndr_status = ndr_pull_struct_blob(&data_blob, mem_ctx, &result->key_identifier, (ndr_pull_flags_fn_t)ndr_pull_KeyEnvelope);
    if (ndr_status != NDR_ERR_SUCCESS)
    {
        printf("%s:%s:%d Failed to decode KeyEnvelope object. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, ndr_status, ndr_errstr(ndr_status));

        goto error_exit;
    }

    const char target_sd[] = { 0x01, 0x00, 0x04, 0x80, 0x54, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x40, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x08, 0x70, 0x66, 0x99, 0x73, 0xf4, 0xc7, 0xf5, 0x08, 0x6e, 0x25, 0x31, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00 };

    uint32_t target_sd_size = sizeof(target_sd);

    result->protection_descriptor.target_sd = talloc_memdup(mem_ctx, target_sd, target_sd_size);
    result->protection_descriptor.target_sd_len = target_sd_size;

    result->enc_cek = talloc_memdup(mem_ctx, kekInfo->encryptedKey.buf, kekInfo->encryptedKey.size);
    result->enc_cek_size = kekInfo->encryptedKey.size;
    result->enc_cek_algorithm = talloc_strndup(mem_ctx, kekInfo->keyEncryptionAlgorithm.algorithm.buf,
                                               kekInfo->keyEncryptionAlgorithm.algorithm.size);
    result->enc_cek_parameters = kekInfo->keyEncryptionAlgorithm.parameters
            ? talloc_memdup(mem_ctx, kekInfo->keyEncryptionAlgorithm.parameters->buf,
                            kekInfo->keyEncryptionAlgorithm.parameters->size)
            : NULL;


    result->enc_content = NULL; // TODO: Implement Enveloped data.
    result->enc_content_algorithm = NULL; // TODO: Implement Enveloped data.
    result->enc_content_parameters = NULL; // TODO: Implement Enveloped data.
    result->enc_content_parameters = 0;

    return result;

error_exit:
    if (kekInfo)
    {
        free(kekInfo);
    }

    if (result)
    {
        talloc_free(result);
    }

    return NULL;
}

static uint32_t
compute_kdf(const uint8_t  *algorithm,
            const uint8_t  *secret,
            const uint32_t secret_size,
            const uint8_t  *label,
            const uint32_t label_size,
            const uint8_t *context,
            const uint32_t context_size,
            const uint32_t length,
            uint8_t **out)
{
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx;
    OSSL_PARAM params[7];
    OSSL_PARAM* p = params;
    int rc = 0;

    kdf = EVP_KDF_fetch(NULL, "KBKDF", NULL);
    if (kdf == NULL)
    {
        printf("%s:%s:%d Failed to perform EVP_KDF_fetch kdf is NULL.",
               __FILE__, __func__, __LINE__);
        return false;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    if (kctx == NULL)
    {
        printf("%s:%s:%d Failed to perform EVP_KDF_CTX_new kctx is NULL.",
               __FILE__, __func__, __LINE__);
        return false;
    }

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char*)algorithm, 0);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, "HMAC", 0);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, "COUNTER", 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (char*)secret, secret_size);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (char*)label, label_size);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (char*)context, context_size);
    *p = OSSL_PARAM_construct_end();


    rc = EVP_KDF_CTX_set_params(kctx, params);
    if (rc <= 0)
    {
        printf("%s:%s:%d Unable to set context parameters. Error = 0x%x\n",
               __FILE__, __func__, __LINE__, rc);
        EVP_KDF_CTX_free(kctx);

        return false;
    }

    rc = EVP_KDF_derive(kctx, *out, length, NULL);

    EVP_KDF_CTX_free(kctx);

    if (rc <= 0)
    {
        SSL_load_error_strings();
        ERR_load_crypto_strings();
        printf("%s:%s:%d Failed to derive key. Error = 0x%x %s\n",
               __FILE__, __func__, __LINE__, rc, ERR_error_string(ERR_get_error(), NULL));
        ERR_free_strings();
        return false;
    }

    return true;
}

static void
calculate_kdf_context(TALLOC_CTX* ctx,
                      uint8_t* uuid,
                      uint32_t l0,
                      uint32_t l1,
                      uint32_t l2,
                      uint8_t** out)
{
    memcpy(*out, uuid, 16);

    uint32_t* l0_ptr = (uint32_t*)(*out + 16);
    *l0_ptr = htole32(l0);

    uint32_t* l1_ptr = (uint32_t*)(*out + 20);
    *l1_ptr = htole32(l1);

    uint32_t* l2_ptr = (uint32_t*)(*out + 24);
    *l2_ptr = htole32(l2);
}

static uint32_t
compute_l2_key(TALLOC_CTX* ctx,
               const char* hash_algorithm,
               uint32_t request_1,
               uint32_t request_2,
               GroupKeyEnvelope *key_envelope,
               uint8_t** out_l2_key)
{
    uint32_t l1 = key_envelope->l1_index;
    uint8_t* l1_key = key_envelope->l1_key;
    uint32_t l2 = key_envelope->l2_index;
    uint8_t* l2_key = key_envelope->l2_key;

    uint32_t rc = 0;

    bool reseed_l2 = l2 == 31 || l1 != request_1;

    if (l2 != 31 && l1 != request_1)
    {
        l1 -= 1;
    }

    while (l1 != request_1)
    {
        reseed_l2 = true;
        l1 -= 1;

        uint32_t kdf_context_size = 32;
        uint8_t* kdf_context = talloc_zero_array(ctx, uint8_t, kdf_context_size);

        calculate_kdf_context(ctx,
                              (uint8_t*)&key_envelope->root_key_id,
                              key_envelope->l0_index,
                              l1,
                              -1,
                              &kdf_context);

        uint32_t new_l1_key_size = 64;
        uint8_t* new_l1_key = talloc_zero_array(ctx, uint8_t, new_l1_key_size);

        rc = compute_kdf(hash_algorithm,
                         l1_key,
                         sizeof(l1_key),
                         KDS_SERVICE_LABEL,
                         sizeof(KDS_SERVICE_LABEL),
                         kdf_context,
                         kdf_context_size,
                         new_l1_key_size,
                         &new_l1_key);
        if (!rc)
        {
            printf("%s:%s:%d Failed to derive l1 key. Error = 0x%x\n",
                   __FILE__, __func__, __LINE__, rc);
            return false;
        }

        l1_key = new_l1_key;
    }

    if (reseed_l2)
    {
        l2 = 31;

        uint32_t kdf_context_size = 32;
        uint8_t* kdf_context = talloc_zero_array(ctx, uint8_t, kdf_context_size);

        calculate_kdf_context(ctx,
                              (uint8_t*)&key_envelope->root_key_id,
                              key_envelope->l0_index,
                              l1,
                              l2,
                              &kdf_context);

        uint32_t new_l2_key_size = 64;
        uint8_t* new_l2_key = talloc_zero_array(ctx, uint8_t, new_l2_key_size);

        rc = compute_kdf(hash_algorithm,
                         l1_key,
                         sizeof(l1_key),
                         KDS_SERVICE_LABEL,
                         sizeof(KDS_SERVICE_LABEL),
                         kdf_context,
                         kdf_context_size,
                         new_l2_key_size,
                         &new_l2_key);
        if (!rc)
        {
            printf("%s:%s:%d Failed to reseed l2 key. Error = 0x%x\n",
                   __FILE__, __func__, __LINE__, rc);
            return false;
        }

        l2_key = new_l2_key;
    }

    while (l2 != request_2)
    {
        l2 -= 1;

        uint32_t kdf_context_size = 32;
        uint8_t* kdf_context = talloc_zero_array(ctx, uint8_t, kdf_context_size);

        calculate_kdf_context(ctx,
                              (uint8_t*)&key_envelope->root_key_id,
                              key_envelope->l0_index,
                              l1,
                              l2,
                              &kdf_context);

        uint32_t new_l2_key_size = 64;
        uint8_t* new_l2_key = talloc_zero_array(ctx, uint8_t, new_l2_key_size);

        rc = compute_kdf(hash_algorithm,
                         l2_key,
                         sizeof(l2_key),
                         KDS_SERVICE_LABEL,
                         sizeof(KDS_SERVICE_LABEL),
                         kdf_context,
                         kdf_context_size,
                         new_l2_key_size,
                         &new_l2_key);
        if (!rc)
        {
            printf("%s:%s:%d Failed to derive l2 key. Error = 0x%x\n",
                   __FILE__, __func__, __LINE__, rc);
            return false;
        }

        l2_key = new_l2_key;
    }

    *out_l2_key = l2_key;

    return true;
}

static uint32_t
compute_kek(TALLOC_CTX* ctx,
            const char* hash_algorithm,
            const char* secret_algorithm,
            const uint32_t secret_algorithm_len,
            const uint8_t* secret_parameters,
            const uint32_t secret_parameters_len,
            const uint8_t* public_key,
            const uint32_t public_key_size,
            const uint8_t* private_key,
            const uint32_t private_key_size,
            const uint32_t key_size,
            uint8_t** out)
{
    return false;
}

static uint32_t
compute_kek_from_public_key(TALLOC_CTX* ctx,
                            const char* hash_algorithm,
                            const uint8_t* seed,
                            const uint32_t seed_size,
                            const char* secret_algorithm,
                            const uint32_t secret_algorithm_len,
                            const uint8_t* secret_parameters,
                            const uint32_t secret_parameters_len,
                            const uint8_t* public_key,
                            const uint32_t public_key_size,
                            const uint32_t private_key_size,
                            const uint32_t key_size,
                            uint8_t** out)
{
    uint8_t* private_key = talloc_zero_array(ctx, uint8_t, private_key_size);

    uint8_t* secret_algorithm_utf16_le = NULL;

    if (!compute_kdf(hash_algorithm,
                     seed,
                     seed_size,
                     KDS_SERVICE_LABEL,
                     sizeof(KDS_SERVICE_LABEL),
                     secret_algorithm_utf16_le,
                     sizeof(secret_algorithm_utf16_le),
                     private_key_size,
                     &private_key))
    {
        printf("%s:%s:%d Failed to derive private key.\n",
               __FILE__, __func__, __LINE__);
        return -1;
    }

    if (!compute_kek(ctx,
                     hash_algorithm,
                     secret_algorithm,
                     secret_algorithm_len,
                     secret_parameters,
                     secret_parameters_len,
                     public_key,
                     public_key_size,
                     private_key,
                     private_key_size,
                     key_size,
                     out))
    {
        printf("%s:%s:%d Failed to derive key encryption key.\n",
               __FILE__, __func__, __LINE__);
        return -1;
    }

    return 0;
}

static uint32_t
get_kek(TALLOC_CTX* ctx,
        GroupKeyEnvelope *key_envelope,
        struct KeyEnvelope *key_identifier,
        gnutls_datum_t *kek)
{
    if (key_envelope->flags & 1)
    {
        return -1;
    }

    if (strcmp(key_envelope->kdf_algorithm, "SP800_108_CTR_HMAC") != 0)
    {
        return -1;
    }

    if (key_identifier->l0_index != key_envelope->l0_index)
    {
        return -1;
    }

    enum ndr_err_code ndr_status = NDR_ERR_SUCCESS;
    struct KdfParameters kdf_parameters;

    DATA_BLOB data_blob;
    data_blob.data = key_envelope->kdf_parameters;
    data_blob.length = key_envelope->kdf_parameters_len;
    ndr_status = ndr_pull_struct_blob(&data_blob, ctx, &kdf_parameters, (ndr_pull_flags_fn_t)ndr_pull_KdfParameters);
    if (ndr_status != NDR_ERR_SUCCESS)
    {
        printf("%s:%s:%d Failed to decode KeyEnvelope object. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, ndr_status, ndr_errstr(ndr_status));

        return -1;
    }

    uint8_t *l2_key = NULL;
    uint32_t l2_key_size = 64;

    if (!compute_l2_key(ctx,
                        kdf_parameters.hash_algorithm,
                        key_identifier->l1_index,
                        key_identifier->l2_index,
                        key_envelope,
                        &l2_key))
    {
        printf("%s:%s:%d Failed to compute l2 key.\n",
               __FILE__, __func__, __LINE__);

        return -1;
    }

    const uint32_t key_size = 32;
    uint8_t* key = talloc_zero_array(ctx, uint8_t, key_size);

    if (!key)
    {
        printf("%s:%s:%d Failed to allocate kek memory.\n",
               __FILE__, __func__, __LINE__);

        return -1;
    }

    if (key_identifier->flags & 1)
    {
        int rc = 0;
        rc = compute_kek_from_public_key(ctx,
                                         kdf_parameters.hash_algorithm,
                                         l2_key,
                                         l2_key_size,
                                         key_envelope->secret_agreement_algorithm,
                                         key_envelope->secret_agreement_algorithm_len,
                                         key_envelope->secret_agreement_parameters,
                                         key_envelope->secret_agreement_parameters_len,
                                         key_identifier->additional_info,
                                         key_identifier->additional_info_len,
                                         ceil(key_envelope->private_key_len / 8),
                                         key_size,
                                         &key);

        if (rc != 0)
        {
            printf("%s:%s:%d Failed to compute kek.\n",
                   __FILE__, __func__, __LINE__);

            return -1;
        }
    }
    else
    {
        if (!compute_kdf(kdf_parameters.hash_algorithm,
                         l2_key,
                         l2_key_size,
                         KDS_SERVICE_LABEL,
                         sizeof(KDS_SERVICE_LABEL),
                         key_identifier->additional_info,
                         key_identifier->additional_info_len,
                         key_size,
                         &key))
        {
            printf("%s:%s:%d Failed to compute kdf.\n",
                   __FILE__, __func__, __LINE__);

            return -1;
        }
    }

    kek->data = key;
    kek->size = key_size;

    return 0;
}

static uint32_t
cek_decrypt(gnutls_datum_t *kek,
            gnutls_datum_t *value,
            gnutls_datum_t *result)
{
    gnutls_cipher_hd_t cipher_handle = { 0 };
    gnutls_cipher_algorithm_t cipher_algo = GNUTLS_CIPHER_AES_256_CBC; // TODO: Implement algorithm selection.
    int rc = 0;

    rc = gnutls_cipher_init(&cipher_handle,
                            cipher_algo,
                            kek,
                            NULL);
    if (rc < 0)
    {
        printf("%s:%s:%d Failed gnutls_cipher_init: Error = 0x%x (%s)\n",
            __FILE__, __func__, __LINE__, rc, gnutls_strerror(rc));
        return -1;
    }

    rc = gnutls_cipher_decrypt2(cipher_handle,
                                value->data,
                                value->size,
                                result->data,
                                result->size);
    gnutls_cipher_deinit(cipher_handle);
    if (rc < 0)
    {
        printf("%s:%s:%d Failed gnutls_cipher_decrypt2: Error = 0x%x (%s)\n",
            __FILE__, __func__, __LINE__, rc, gnutls_strerror(rc));
        return -1;
    }

    return 0;
}

static uint32_t
content_decrypt(gnutls_datum_t *cek,
                gnutls_datum_t *iv,
                gnutls_datum_t *value,
                gnutls_datum_t *result)
{
    gnutls_cipher_hd_t cipher_handle = { 0 };
    gnutls_cipher_algorithm_t cipher_algo = GNUTLS_CIPHER_AES_256_GCM; // TODO: Implement algorithm selection.
    int rc = 0;

    rc = gnutls_cipher_init(&cipher_handle,
                            cipher_algo,
                            cek,
                            iv);
    if (rc < 0)
    {
        printf("%s:%s:%d Failed gnutls_cipher_init: Error = 0x%x (%s)\n",
            __FILE__, __func__, __LINE__, rc, gnutls_strerror(rc));
        return -1;
    }

    rc = gnutls_cipher_decrypt2(cipher_handle,
                                value->data,
                                value->size,
                                result->data,
                                result->size);
    gnutls_cipher_deinit(cipher_handle);
    if (rc < 0)
    {
        printf("%s:%s:%d Failed gnutls_cipher_decrypt2: Error = 0x%x (%s)\n",
            __FILE__, __func__, __LINE__, rc, gnutls_strerror(rc));
        return -1;
    }

    return 0;
}

uint32_t
unpack_response(TALLOC_CTX *mem_ctx,
                const uint8_t* data,
                const uint32_t size,
                blob_t *initial_data,
                uint8_t **decrypted_data,
                uint32_t *decrypted_data_size)
{
    if (!mem_ctx)
    {
        printf("%s:%s:%d Passed talloc_ctx is NULL. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, 0, "TALLOC_CTX is NULL!");

        return -1;
    }

    GroupKeyEnvelope *result = talloc_zero(mem_ctx, GroupKeyEnvelope);
    enum ndr_err_code ndr_status = NDR_ERR_SUCCESS;

    DATA_BLOB data_blob;
    data_blob.data = (uint8_t*)data;
    data_blob.length = size;
    ndr_status = ndr_pull_struct_blob(&data_blob, mem_ctx, result, (ndr_pull_flags_fn_t)ndr_pull_GroupKeyEnvelope);
    if (ndr_status != NDR_ERR_SUCCESS)
    {
        printf("%s:%s:%d Failed to decode GroupKeyEnvelope object. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, ndr_status, ndr_errstr(ndr_status));

        return -1;
    }

    gnutls_datum_t kek = { 0 };
    int rc = 0;

    rc = get_kek(mem_ctx, result, &initial_data->key_identifier, &kek);
    if (rc != 0)
    {
        printf("%s:%s:%d Failed to get key encryption key. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, rc, "Key retrival failed!");

        return -1;
    }

    gnutls_datum_t encrypted_cek_value = { .data = initial_data->enc_cek, .size = initial_data->enc_cek_size };
    gnutls_datum_t decrypted_cek_value = { 0 };

    rc = cek_decrypt(&kek, &encrypted_cek_value, &decrypted_cek_value);
    if (rc != 0)
    {
        printf("%s:%s:%d Failed to decrypt content encryption key. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, rc, "Content key decryption failed!");

        return -1;
    }

    gnutls_datum_t iv =
    {
        .data = initial_data->enc_content_parameters,
        .size = initial_data->enc_content_parameters_size
    };
    gnutls_datum_t encrypted_data_value =
    {
        .data = initial_data->enc_content,
        .size = initial_data->enc_content_size
    };
    gnutls_datum_t decrypted_data_value = { 0 };

    rc = content_decrypt(&decrypted_cek_value, &iv, &encrypted_data_value, &decrypted_data_value);
    if (rc != 0)
    {
        printf("%s:%s:%d Failed to decrypt encrypted content. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, rc, "Content decryption failed!");

        return -1;
    }

    *decrypted_data = decrypted_data_value.data;
    *decrypted_data_size = decrypted_data_value.size;

    return 0;
}
