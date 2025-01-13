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
#include <strings.h>

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
#include "pkcs7/EnvelopedData.h"
#include "pkcs7/MyKeyInfo.h"

const uint8_t KDS_SERVICE_LABEL[] = { 0x4b, 0x00, 0x44, 0x00, 0x53, 0x00, 0x20, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x00, 0x00 };
const uint8_t KDS_PUBLIC_KEY_LABEL[] = { 0x4b, 0x00, 0x44, 0x00, 0x53, 0x00, 0x20, 0x00, 0x70, 0x00, 0x75, 0x00, 0x62, 0x00, 0x6c, 0x00, 0x69, 0x00, 0x63, 0x00, 0x20, 0x00, 0x6b, 0x00, 0x65, 0x00, 0x79, 0x00, 0x00, 0x00 };

const uint8_t SHA512_UTF_16_LE[] = { 0x53, 0x00, 0x48, 0x00, 0x41, 0x00, 0x35, 0x00, 0x31, 0x00, 0x32, 0x00, 0x00, 0x00 };

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

    EnvelopedData_t *envelopedData = unpack_ContentInfo(data, size);
    KEKRecipientInfo_t *kekInfo = malloc(sizeof(KEKRecipientInfo_t));
    *kekInfo = envelopedData->recipientInfos.list.array[0]->choice.kekri;
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


    result->enc_content = envelopedData->encryptedContentInfo.encryptedContent->buf;
    result->enc_content_size = envelopedData->encryptedContentInfo.encryptedContent->size;
    result->enc_content_algorithm = envelopedData->encryptedContentInfo.contentEncryptionAlgorithm.algorithm.buf;
    result->enc_content_algorithm_size = envelopedData->encryptedContentInfo.contentEncryptionAlgorithm.algorithm.size;
    result->enc_content_parameters = envelopedData->encryptedContentInfo.contentEncryptionAlgorithm.parameters->buf;
    result->enc_content_parameters_size = envelopedData->encryptedContentInfo.contentEncryptionAlgorithm.parameters->size;

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
    OSSL_PARAM params[6];
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

        uint32_t kdf_context_size = 28;
        uint8_t* kdf_context = talloc_zero_array(ctx, uint8_t, kdf_context_size);

        calculate_kdf_context(ctx,
                              (uint8_t*)&key_envelope->root_key_id,
                              key_envelope->l0_index,
                              l1,
                              -1,
                              &kdf_context);

        uint32_t new_l1_key_size = key_envelope->l1_key_len;
        uint8_t* new_l1_key = talloc_zero_array(ctx, uint8_t, new_l1_key_size);

        rc = compute_kdf(hash_algorithm,
                         l1_key,
                         key_envelope->l1_key_len,
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

        uint32_t kdf_context_size = 28;
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
                         key_envelope->l1_key_len,
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

        uint32_t kdf_context_size = 28;
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
                         key_envelope->l2_key_len,
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
compute_secret_key(TALLOC_CTX* ctx,
                   const uint8_t* hash_algorithm,
                   const uint8_t* key_mateial,
                   const uint32_t key_mateial_size,
                   const uint8_t* other_info,
                   const uint32_t other_info_size,
                   uint32_t* out_size,
                   uint8_t** out)
{
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;

    uint8_t md_value[EVP_MAX_MD_SIZE];
    uint32_t md_size = 0;

    md = EVP_get_digestbyname(hash_algorithm);
    if (md == NULL)
    {
        printf("%s:%s:%d Unsupported hash algorithm %s.\n",
               __FILE__, __func__, __LINE__, hash_algorithm);

        return false;
    }

    uint32_t length = EVP_MD_size(md);

    uint8_t* result = talloc_zero_array(ctx, uint8_t, length);
    if (!result)
    {
        printf("%s:%s:%d Unable to allocate output buffer.\n",
               __FILE__, __func__, __LINE__);

        return false;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
    {
        printf("%s:%s:%d EVP_MD_CTX_new failed!\n",
               __FILE__, __func__, __LINE__);

        return false;
    }

    uint32_t out_length = 0;
    uint32_t counter = 1;

    while (out_length < length)
    {
        uint32_t counter_be = htobe32(counter);

        if (!EVP_DigestInit_ex2(mdctx, md, NULL))
        {
            printf("%s:%s:%d EVP_DigestInit_ex2 failed!\n",
                   __FILE__, __func__, __LINE__);
            goto error_exit;
        }

        if (!EVP_DigestUpdate(mdctx, &counter_be, 4))
        {
            printf("%s:%s:%d EVP_DigestUpdate failed!\n",
                   __FILE__, __func__, __LINE__);
            goto error_exit;
        }

        if (!EVP_DigestUpdate(mdctx, key_mateial, key_mateial_size))
        {
            printf("%s:%s:%d EVP_DigestUpdate failed!\n",
                   __FILE__, __func__, __LINE__);
            goto error_exit;
        }

        if (!EVP_DigestUpdate(mdctx, other_info, other_info_size))
        {
            printf("%s:%s:%d EVP_DigestUpdate failed!\n",
                   __FILE__, __func__, __LINE__);
            goto error_exit;
        }

        if (!EVP_DigestFinal_ex(mdctx, md_value, &md_size))
        {
            printf("%s:%s:%d EVP_DigestFinal_ex failed!\n",
                   __FILE__, __func__, __LINE__);
            goto error_exit;

        }

        if (out_length + md_size <= length)
        {
            memcpy(result + out_length, md_value, md_size);
        }

        out_length += md_size;
        counter++;
    }

    EVP_MD_CTX_free(mdctx);

    *out_size = length;
    *out = result;

    return true;

error_exit:
    EVP_MD_CTX_free(mdctx);

    return false;
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
    enum ndr_err_code ndr_status = NDR_ERR_SUCCESS;
    char* secret_hash_algorithm = "";
    uint8_t* shared_secret = NULL;

    if (strncasecmp(secret_algorithm, "DH", 2) == 0)
    {
        printf("%s:%s:%d Standard diffie hellman located.\n",
               __FILE__, __func__, __LINE__);

        struct FfcDhKey dh_parameters;

        DATA_BLOB data_blob;
        data_blob.data = (uint8_t*)public_key;
        data_blob.length = public_key_size;
        ndr_status = ndr_pull_struct_blob(&data_blob, ctx, &dh_parameters, (ndr_pull_flags_fn_t)ndr_pull_FfcDhKey);

        if (ndr_status != NDR_ERR_SUCCESS)
        {
            printf("%s:%s:%d Failed to decode FfcDhKey object. Error = 0x%x (%s)\n",
                   __FILE__, __func__, __LINE__, ndr_status, ndr_errstr(ndr_status));

            return false;
        }

        uint32_t secret_shared_int = (uint32_t)pow(*((uint32_t*)dh_parameters.public_key), htobe32(*((uint32_t*)private_key))) % (*(uint32_t*)dh_parameters.field_order);
        shared_secret = (uint8_t*)talloc_zero(ctx, uint32_t);
        if (!shared_secret)
        {
            printf("%s:%s:%d Unable to allocate DH shared secret. Error = 0x%x (%s)\n",
                   __FILE__, __func__, __LINE__, ndr_status, ndr_errstr(ndr_status));

            return false;
        }
        uint32_t* shared_secret_ptr = (uint32_t*)shared_secret;
        *shared_secret_ptr = htobe32(secret_shared_int);
        secret_hash_algorithm = "SHA256";
    }
    else if (strncasecmp(secret_algorithm, "ECDH_P", 6) == 0)
    {
        printf("%s:%s:%d Elliptic curve diffie hellman located.\n",
               __FILE__, __func__, __LINE__);
        // TODO: Implement ECDH_P.
    }
    else
    {
        printf("%s:%s:%d Unsupported type of encryption: %s.\n",
               __FILE__, __func__, __LINE__, secret_algorithm);

        return false;
    }

    uint8_t* secret = NULL;
    uint32_t secret_length = 0;

    size_t other_info_length = sizeof(KDS_SERVICE_LABEL) + sizeof(KDS_PUBLIC_KEY_LABEL) + sizeof(SHA512_UTF_16_LE);
    uint8_t* other_info = talloc_zero_array(ctx, uint8_t, other_info_length);

    memcpy(other_info, SHA512_UTF_16_LE, sizeof(SHA512_UTF_16_LE));
    memcpy(other_info + sizeof(SHA512_UTF_16_LE), KDS_PUBLIC_KEY_LABEL, sizeof(KDS_PUBLIC_KEY_LABEL));
    memcpy(other_info + sizeof(SHA512_UTF_16_LE) + sizeof(KDS_PUBLIC_KEY_LABEL), KDS_SERVICE_LABEL, sizeof(KDS_SERVICE_LABEL));

    if (!compute_secret_key(ctx,
                            secret_hash_algorithm,
                            shared_secret,
                            sizeof(uint32_t),
                            other_info,
                            other_info_length,
                            &secret_length,
                            &secret))
    {
        printf("%s:%s:%d Unable to compute secret key.\n",
               __FILE__, __func__, __LINE__);

        return false;
    }

    if (!compute_kdf(hash_algorithm,
                     secret,
                     secret_length,
                     KDS_SERVICE_LABEL,
                     sizeof(KDS_SERVICE_LABEL),
                     KDS_PUBLIC_KEY_LABEL,
                     sizeof(KDS_PUBLIC_KEY_LABEL),
                     key_size,
                     out))
    {
        printf("%s:%s:%d Unable to derive KEK.\n",
               __FILE__, __func__, __LINE__);

        return false;
    }

    return true;
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
cek_decrypt(TALLOC_CTX* mem_ctx,
            uint8_t* kek,
            uint32_t kek_size,
            uint8_t* value,
            uint32_t value_size,
            uint32_t* result_size,
            uint8_t** result)
{
    EVP_CIPHER_CTX* ctx = NULL;
    int length = 0;
    int rc = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        printf("%s:%s:%d EVP_CIPHER_CTX_new failed!\n",
            __FILE__, __func__, __LINE__);
        return -1;
    }

    EVP_CIPHER* cipher = EVP_CIPHER_fetch(NULL, "AES-256-WRAP", NULL);
    if (!cipher)
    {
        printf("%s:%s:%d EVP_aes_256_wrap failed!\n",
            __FILE__, __func__, __LINE__);
        return -1;
    }

    uint8_t* block = talloc_zero_array(mem_ctx, uint8_t, value_size);
    if (!result)
    {
        printf("%s:%s:%d Unable to allocate output buffer.\n",
               __FILE__, __func__, __LINE__);

        return false;
    }

    rc = EVP_DecryptInit_ex2(ctx, cipher, kek, NULL, NULL);
    if (!rc)
    {
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);

        printf("%s:%s:%d EVP_DecryptInit_ex2 failed!\n",
            __FILE__, __func__, __LINE__);
        return -1;
    }

    rc = EVP_DecryptUpdate(ctx, block, &length, value, value_size);
    if (!rc)
    {
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);

        printf("%s:%s:%d EVP_DecryptUpdate failed!\n",
            __FILE__, __func__, __LINE__);
        return -1;
    }
    *result_size = length;

    rc = EVP_DecryptFinal_ex(ctx, block + length, &length);
    if (!rc)
    {
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);

        printf("%s:%s:%d EVP_DecryptFinal failed!\n",
            __FILE__, __func__, __LINE__);
        return -1;
    }
    *result = block;
    result_size += length;

    return 0;
}

static MyKeyInfo_t *
decode_MyKeyInfo(
    const uint8_t* data,
    const uint32_t size
)
{
    asn_dec_rval_t rval;
    MyKeyInfo_t *my_key_info = NULL;

    rval = ber_decode(0, &asn_DEF_MyKeyInfo, (void**)&my_key_info, data, size);
    if (rval.code != RC_OK)
    {
        printf("%s:%s:%d Failed to decode MyKeyInfo_t object. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, rval.code, "");
    }

    return my_key_info;
}

static uint32_t
content_decrypt(TALLOC_CTX* mem_ctx,
                uint8_t* cek,
                uint32_t cek_size,
                uint8_t* iv,
                uint32_t iv_size,
                uint8_t* value,
                uint32_t value_size,
                uint32_t* result_size,
                uint8_t **result)
{
    const uint32_t tagLength = 16;

    uint8_t* block = talloc_zero_array(mem_ctx, uint8_t, value_size - tagLength);
    if (!block)
    {
        printf("%s:%s:%d Unable to allocate output buffer.\n",
               __FILE__, __func__, __LINE__);

        return -1;
    }

    int length = 0;
    int rc = 0;
    OSSL_PARAM params[3] =
    {
        OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END
    };

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        printf("%s:%s:%d EVP_CIPHER_CTX_new failed!\n",
               __FILE__, __func__, __LINE__);
        return -1;
    }

    EVP_CIPHER* cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    if (!cipher)
    {
        EVP_CIPHER_CTX_free(ctx);
        printf("%s:%s:%d EVP_aes_256_wrap failed!\n",
               __FILE__, __func__, __LINE__);

        return -1;
    }

    rc = EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL);
    if (!rc)
    {
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);

        printf("%s:%s:%d EVP_DecryptInit_ex2 failed!\n",
               __FILE__, __func__, __LINE__);
        return -1;
    }

    MyKeyInfo_t *iv_key_info = decode_MyKeyInfo(iv, iv_size);
    if (!iv_key_info)
    {
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);

        printf("%s:%s:%d decode_IA5String_t failed!\n",
               __FILE__, __func__, __LINE__);
        return -1;
    }

    uint8_t tag[tagLength];
    memcpy(tag, value + value_size - tagLength, tagLength);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (size_t)iv_key_info->iv.size, NULL);

    rc = EVP_DecryptInit_ex(ctx, NULL, NULL, cek, iv_key_info->iv.buf);
    if (!rc)
    {
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);

        printf("%s:%s:%d EVP_DecryptInit_ex2 failed!\n",
               __FILE__, __func__, __LINE__);
        return -1;
    }

    rc = EVP_DecryptUpdate(ctx, block, &length, value, value_size - tagLength);
    if (!rc)
    {
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);

        printf("%s:%s:%d EVP_DecryptUpdate failed!\n",
               __FILE__, __func__, __LINE__);
        return -1;
    }
    *result_size = length;

    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tagLength, tag);
    if (!rc)
    {
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);

        printf("%s:%s:%d EVP_DecryptUpdate failed!\n",
               __FILE__, __func__, __LINE__);
        return -1;
    }

    rc = EVP_DecryptFinal_ex(ctx, block + length, &length);
    if (!rc)
    {
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);

        printf("%s:%s:%d EVP_DecryptFinal failed!\n",
            __FILE__, __func__, __LINE__);
        return -1;
    }
    *result = block;
    *result_size += length;

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

    uint8_t* decrypted_cek_data = NULL;
    uint32_t decrypted_cek_size = 0;

    rc = cek_decrypt(mem_ctx, kek.data, kek.size, initial_data->enc_cek, initial_data->enc_cek_size, &decrypted_cek_size, &decrypted_cek_data);
    if (rc != 0)
    {
        printf("%s:%s:%d Failed to decrypt content encryption key. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, rc, "Content key decryption failed!");

        return -1;
    }

    gnutls_datum_t decrypted_cek_value = { .data = decrypted_cek_data, .size = decrypted_cek_size };
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
    gnutls_datum_t decrypted_data_value =
    {
        .data = NULL,
        .size = 0
    };

    rc = content_decrypt(mem_ctx,
                         decrypted_cek_value.data,
                         decrypted_cek_value.size,
                         iv.data,
                         iv.size,
                         encrypted_data_value.data,
                         encrypted_data_value.size,
                         &decrypted_data_value.size,
                         &decrypted_data_value.data);
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
