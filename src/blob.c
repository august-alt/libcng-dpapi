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

#include <openssl/bio.h>
#include <openssl/param_build.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "pkcs7_p.h"
#include "pkcs7/ContentInfo.h"
#include "pkcs7/KEKRecipientInfo.h"
#include "pkcs7/EnvelopedData.h"
#include "pkcs7/MyKeyInfo.h"

#include "protection_descriptor_p.h"

const uint8_t KDS_SERVICE_LABEL[] = { 0x4b, 0x00, 0x44, 0x00, 0x53, 0x00, 0x20, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x00, 0x00 };
const uint8_t KDS_PUBLIC_KEY_LABEL[] = { 0x4b, 0x00, 0x44, 0x00, 0x53, 0x00, 0x20, 0x00, 0x70, 0x00, 0x75, 0x00, 0x62, 0x00, 0x6c, 0x00, 0x69, 0x00, 0x63, 0x00, 0x20, 0x00, 0x6b, 0x00, 0x65, 0x00, 0x79, 0x00, 0x00, 0x00 };

const uint8_t SHA512_UTF_16_LE[] = { 0x53, 0x00, 0x48, 0x00, 0x41, 0x00, 0x35, 0x00, 0x31, 0x00, 0x32, 0x00, 0x00, 0x00 };

const uint8_t DH_UTF_16_LE[] = { 0x44, 0x00, 0x48, 0x00, 0x00, 0x00 };
const uint8_t ECDH_UTF_16_LE[] = {};

#define CONTENT_TYPE_ENVELOPED_DATA_OID "1.2.840.113549.1.7.3"
#define CONTENT_TYPE_DATA_OID "1.2.840.113549.1.7.1"

#define MICROSOFT_SOFTWARE_OID "1.3.6.1.4.1.311.74.1"

#define AES256_WRAP_OID "2.16.840.1.101.3.4.1.45"
#define AES256_GCM_OID "2.16.840.1.101.3.4.1.46"

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
    if (!envelopedData)
    {
        printf("%s:%s:%d Failed to decode EnvelopedData_t object. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, 0, "Unable to unpack object!");

        goto error_exit;
    }
    KEKRecipientInfo_t *kekInfo = malloc(sizeof(KEKRecipientInfo_t));
    *kekInfo = envelopedData->recipientInfos.list.array[0]->choice.kekri;
    if (!kekInfo)
    {
        printf("%s:%s:%d Failed to decode KEKRecipientInfo object. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, 0, "Unable to unpack object!");

        goto error_exit;
    }

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

    ProtectionDescriptor_t *descriptor = NULL;

    if (unpack_single_protection_descriptor(kekInfo->kekid.other->keyAttr->buf,
                                            kekInfo->kekid.other->keyAttr->size,
                                            &descriptor) != 0)
    {
        printf("%s:%s:%d Failed to decode ProtectionDescriptor_t object!\n",
               __FILE__, __func__, __LINE__);

        goto error_exit;

    }

    uint8_t *target_sd = NULL;
    uint32_t target_sd_size = 0;

    if (create_security_descriptor_from_protection_descriptor(mem_ctx,
                                                              descriptor,
                                                              &target_sd_size,
                                                              &target_sd))
    {
        goto error_exit;
    }

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
        key_envelope->l2_key_len = new_l2_key_size;
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
decode_shared_secret(struct FfcDhKey *dh_parameters,
                     const uint8_t* private_key,
                     const uint32_t private_key_size,
                     uint8_t** shared_secret,
                     size_t *shared_secret_size)
{
    int result = 0;

    BN_CTX *ctx = NULL;
    BIGNUM *shared = NULL;

    ctx = BN_CTX_new_ex(NULL);
    if (ctx == NULL)
    {
        goto error_exit;
    }
    BN_CTX_start(ctx);
    shared = BN_CTX_get(ctx);
    if (shared == NULL)
    {
        goto error_exit;
    }

    BIGNUM *bp = BN_bin2bn(dh_parameters->field_order, dh_parameters->key_length, NULL);
    BIGNUM *bg = BN_bin2bn(dh_parameters->generator, dh_parameters->key_length, NULL);
    BIGNUM *pub_key = BN_bin2bn(dh_parameters->public_key, dh_parameters->key_length, NULL);
    BIGNUM *priv_key = BN_bin2bn(private_key, private_key_size, NULL);

    result = BN_mod_exp(shared, pub_key, priv_key, bp, ctx);
    if (result == 0)
    {
        goto error_exit;
    }

    *shared_secret = OPENSSL_malloc(dh_parameters->key_length);

    result = BN_bn2binpad(shared, *shared_secret, BN_num_bytes(bp));
    *shared_secret_size = dh_parameters->key_length;

    error_exit:
        BN_clear(shared); /* (Step 2) destroy intermediate values */
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        return result;
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
    uint32_t shared_secret_length = 0;

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

        shared_secret_length = dh_parameters.key_length;
        size_t shared_secret_size = 0;
        if (decode_shared_secret(&dh_parameters,
                                 private_key,
                                 private_key_size,
                                 &shared_secret,
                                 &shared_secret_size) == 0)
        {
            printf("%s:%s:%d Unable to decode shared secret!.\n",
                   __FILE__, __func__, __LINE__);

            return false;
        }

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
                            shared_secret_length,
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
    const uint8_t* secret_algorithm_utf16_le = 0;
    uint32_t secret_algorithm_size = 0;

    if (strncmp("DH", secret_algorithm, 2) == 0)
    {
        secret_algorithm_utf16_le = DH_UTF_16_LE;
        secret_algorithm_size = sizeof(DH_UTF_16_LE);
    }
    else if (strncmp("ECDH_P", secret_algorithm, 6) == 0)
    {
        secret_algorithm_utf16_le = ECDH_UTF_16_LE;
        secret_algorithm_size = sizeof(ECDH_UTF_16_LE);
    }
    else
    {
        printf("%s:%s:%d Unsupported type of encryption %s.\n",
               __FILE__, __func__, __LINE__, secret_algorithm);
        return -1;
    }

    if (!compute_kdf(hash_algorithm,
                     seed,
                     seed_size,
                     KDS_SERVICE_LABEL,
                     sizeof(KDS_SERVICE_LABEL),
                     secret_algorithm_utf16_le,
                     secret_algorithm_size,
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

        printf("%s:%s:%d decode_MyKeyInfo failed!\n",
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

const int CEK_LENGTH = 256 / 8;
const int CEK_IV_LENGTH = 12;
const int RAND_OK = 1;

const int DEFAULT_TAG_SIZE = 16;

static int32_t
content_encrypt(TALLOC_CTX* mem_ctx,
                const uint8_t *data,
                const uint32_t data_size,
                const uint8_t *cek,
                const uint32_t cek_size,
                const uint8_t *cek_iv,
                const uint32_t cek_iv_size,
                uint8_t **out,
                uint32_t *out_length)
{
    int32_t rc = -1;

    *out = talloc_array(mem_ctx, uint8_t, data_size + DEFAULT_TAG_SIZE);
    if (!*out)
    {
        printf("%s:%s:%d Unable to allocate encrypted content!\n",
               __FILE__, __func__, __LINE__);
        return rc;
    }

    uint8_t tag[DEFAULT_TAG_SIZE] = {};
    uint32_t tag_length = DEFAULT_TAG_SIZE;

    (void)cek_size;

    OSSL_PARAM params[2] = {
        OSSL_PARAM_END, OSSL_PARAM_END
    };

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        printf("%s:%s:%d EVP_CIPHER_CTX_new failed!\n",
               __FILE__, __func__, __LINE__);
        return rc;
    }

    EVP_CIPHER* cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    if (!cipher)
    {
        EVP_CIPHER_CTX_free(ctx);
        printf("%s:%s:%d EVP_aes_256_wrap failed!\n",
               __FILE__, __func__, __LINE__);

        return rc;
    }

    size_t tmp_iv_size = cek_iv_size;

    /* Set IV length if default 96 bits is not appropriate */
    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                            &tmp_iv_size);

    if (!EVP_EncryptInit_ex2(ctx, cipher, cek, cek_iv, params))
    {
        printf("%s:%s:%d EVP_EncryptInit_ex failed!\n",
               __FILE__, __func__, __LINE__);
        goto error_exit;
    }

    if (!EVP_EncryptUpdate(ctx, *out, out_length, data, data_size))
    {
        printf("%s:%s:%d EVP_EncryptUpdate failed!\n",
               __FILE__, __func__, __LINE__);

        goto error_exit;
    }

    // printf("Ciphertext:\n");
    // BIO_dump_fp(stdout, *out, *out_length);

    uint32_t tmp_length = 0;

    /* Finalise: note get no output for GCM */
    if (!EVP_EncryptFinal_ex(ctx, *out, &tmp_length))
    {
        printf("%s:%s:%d EVP_EncryptFinal_ex failed!\n",
               __FILE__, __func__, __LINE__);

        goto error_exit;
    }

    *out_length += tmp_length;

    /* Get tag */
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                  tag, tag_length);

    if (!EVP_CIPHER_CTX_get_params(ctx, params))
    {
        printf("%s:%s:%d EVP_CIPHER_CTX_get_params failed!\n",
               __FILE__, __func__, __LINE__);

        goto error_exit;
    }

    /* Output tag */
    // printf("Tag:\n");
    // BIO_dump_fp(stdout, tag, tag_length);

    memcpy(*out + *out_length, tag, tag_length);

    *out_length += tag_length;

    rc = 0;

error_exit:
    if (rc)
    {
        ERR_print_errors_fp(stderr);
    }

    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return rc;
}

static int32_t
cek_encrypt(TALLOC_CTX *mem_ctx,
            const uint8_t *cek,
            const uint32_t cek_size,
            const uint8_t *kek,
            const uint32_t kek_size,
            uint8_t **encrypted_cek,
            uint32_t *encrypted_cek_size)
{
    (void)kek_size;

    int32_t rc = -1;
    int32_t tmplen = 0;

    *encrypted_cek = talloc_array(mem_ctx, uint8_t, cek_size);
    if (!*encrypted_cek)
    {
        goto error_exit;
    }

    /* Create a context for the encrypt operation */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        goto error_exit;
    }

    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    // TODO: Add global library context and other parameters to EVP_CIPHER_fetch.
    /* Fetch the cipher implementation */
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-256-WRAP", NULL);
    if (!cipher)
    {
        goto error_exit;
    }

    /*
     * Initialise an encrypt operation with the cipher/mode, key and IV.
     * We are not setting any custom params so let params be just NULL.
     */
    if (!EVP_EncryptInit_ex2(ctx, cipher, kek, NULL /* iv */, /* params */ NULL))
    {
        goto error_exit;
    }

    /* Encrypt plaintext */
    if (!EVP_EncryptUpdate(ctx, *encrypted_cek, encrypted_cek_size, cek, cek_size))
    {
        goto error_exit;
    }

    /* Finalise: there can be some additional output from padding */
    if (!EVP_EncryptFinal_ex(ctx, *encrypted_cek + *encrypted_cek_size, &tmplen))
    {
        goto error_exit;
    }
    *encrypted_cek_size += tmplen;

    /* Output encrypted block */
    // printf("Ciphertext (outlen:%d):\n", *encrypted_cek_size);
    // BIO_dump_fp(stdout, *encrypted_cek, *encrypted_cek_size);

    rc = 0;

error_exit:
    if (rc)
    {
        ERR_print_errors_fp(stderr);
    }

    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return rc;
}

static int32_t
compute_peer_public_key(TALLOC_CTX *parent_ctx,
                        const char* secret_algorithm,
                        const uint32_t secret_algorithm_len,
                        const uint8_t* secret_parameters,
                        const uint32_t secret_parameters_len,
                        const uint8_t* private_key,
                        const uint32_t private_key_len,
                        const uint8_t* peer_public_key,
                        const uint32_t peer_public_key_len,
                        uint32_t *size,
                        uint8_t **out)
{
    int32_t rc = -1;

    TALLOC_CTX *mem_ctx = talloc_named(NULL, 0, "create_kek");
    if (!mem_ctx)
    {
        printf("%s:%s:%d Failed to create talloc context.\n",
               __FILE__, __func__, __LINE__);

        goto error_exit;
    }

    if (strncmp(secret_algorithm, "DH", secret_algorithm_len) == 0)
    {
        enum ndr_err_code ndr_status = NDR_ERR_SUCCESS;
        struct FfcDhKey ffc_dh_key;

        DATA_BLOB data_blob;
        data_blob.data = (uint8_t*)peer_public_key;
        data_blob.length = peer_public_key_len;
        ndr_status = ndr_pull_struct_blob(&data_blob, mem_ctx, &ffc_dh_key, (ndr_pull_flags_fn_t)ndr_pull_FfcDhKey);
        if (ndr_status != NDR_ERR_SUCCESS)
        {
            printf("%s:%s:%d Failed to decode FfcDhKey object. Error = 0x%x (%s)\n",
                   __FILE__, __func__, __LINE__, ndr_status, ndr_errstr(ndr_status));
            goto error_exit;
        }
        struct FfcDhKey *target_key = talloc_zero(mem_ctx, struct FfcDhKey);
        if (!target_key)
        {
            printf("%s:%s:%d Failed to allocate FfcDhKey.\n",
                   __FILE__, __func__, __LINE__);

            goto error_exit;
        }

        uint8_t* shared_secret = NULL;
        size_t shared_secret_size = 0;
        if (decode_shared_secret(&ffc_dh_key, private_key, private_key_len, &shared_secret, &shared_secret_size) == 0)
        {
            printf("%s:%s:%d Failed to compute shared secret.\n",
                   __FILE__, __func__, __LINE__);

            goto error_exit;
        }

        target_key->magic = ffc_dh_key.magic;
        target_key->field_order = talloc_memdup(target_key, ffc_dh_key.field_order, ffc_dh_key.key_length);
        target_key->generator = talloc_memdup(target_key, ffc_dh_key.generator, ffc_dh_key.key_length);
        target_key->key_length = ffc_dh_key.key_length;
        target_key->public_key = talloc_memdup(target_key, shared_secret, shared_secret_size);

        OPENSSL_free(shared_secret);

        if (!target_key->field_order || !target_key->generator || !target_key->public_key)
        {
            printf("%s:%s:%d Failed to allocate target key.\n",
                   __FILE__, __func__, __LINE__);

            goto error_exit;
        }

        *size = sizeof(struct FfcDhKey);
        *out = talloc_reparent(mem_ctx, parent_ctx, target_key);
    }
    else if (strncmp(secret_algorithm, "ECDH_P", secret_algorithm_len) == 0)
    {
        enum ndr_err_code ndr_status = NDR_ERR_SUCCESS;
        struct ECDHKey ecdh_key;

        DATA_BLOB data_blob;
        data_blob.data = (uint8_t*)peer_public_key;
        data_blob.length = peer_public_key_len;
        ndr_status = ndr_pull_struct_blob(&data_blob, mem_ctx, &ecdh_key, (ndr_pull_flags_fn_t)ndr_pull_ECDHKey);
        if (ndr_status != NDR_ERR_SUCCESS)
        {
            printf("%s:%s:%d Failed to decode ECDHKey object. Error = 0x%x (%s)\n",
                   __FILE__, __func__, __LINE__, ndr_status, ndr_errstr(ndr_status));
            goto error_exit;
        }
        struct ECDHKey *target_key = talloc_zero(mem_ctx, struct ECDHKey);
        if (!target_key)
        {
            printf("%s:%s:%d Failed to allocate ECDHKey.\n",
                   __FILE__, __func__, __LINE__);

            goto error_exit;
        }

        // TODO: compute ecdh key.
        // Derive private key.

        *size = sizeof(struct ECDHKey);
        *out = talloc_reparent(mem_ctx, parent_ctx, target_key);
    }
    else
    {
        printf("%s:%s:%d Unsupported secret algorithm.\n",
               __FILE__, __func__, __LINE__);

        goto error_exit;
    }

    rc = 0;

error_exit:
    talloc_free(mem_ctx);

    return rc;
}

static int32_t
create_kek(TALLOC_CTX *parent_ctx,
           const uint8_t *key_envelope_data,
           const uint32_t key_envelope_data_size,
           uint8_t **kek,
           uint32_t *kek_size,
           struct KeyEnvelope **key_id)
{
    int32_t rc = -1;

    TALLOC_CTX *mem_ctx = talloc_named(NULL, 0, "create_kek");
    if (!mem_ctx)
    {
        printf("%s:%s:%d Failed to create talloc context.\n",
               __FILE__, __func__, __LINE__);

        goto error_exit;
    }

    GroupKeyEnvelope *key_envelope = talloc_zero(mem_ctx, GroupKeyEnvelope);
    enum ndr_err_code ndr_status = NDR_ERR_SUCCESS;

    DATA_BLOB data_blob;
    data_blob.data = (uint8_t*)key_envelope_data;
    data_blob.length = key_envelope_data_size;
    ndr_status = ndr_pull_struct_blob(&data_blob, mem_ctx, key_envelope, (ndr_pull_flags_fn_t)ndr_pull_GroupKeyEnvelope);
    if (ndr_status != NDR_ERR_SUCCESS)
    {
        printf("%s:%s:%d Failed to decode GroupKeyEnvelope object. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, ndr_status, ndr_errstr(ndr_status));

        goto error_exit;
    }

    if (strcmp(key_envelope->kdf_algorithm, "SP800_108_CTR_HMAC") != 0)
    {
        printf("%s:%s:%d Unsupported KDF algorithm.\n",
               __FILE__, __func__, __LINE__);

        goto error_exit;
    }

    struct KdfParameters kdf_parameters;

    data_blob.data = key_envelope->kdf_parameters;
    data_blob.length = key_envelope->kdf_parameters_len;
    ndr_status = ndr_pull_struct_blob(&data_blob, mem_ctx, &kdf_parameters, (ndr_pull_flags_fn_t)ndr_pull_KdfParameters);
    if (ndr_status != NDR_ERR_SUCCESS)
    {
        printf("%s:%s:%d Failed to decode KdfParameters object. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, ndr_status, ndr_errstr(ndr_status));
        goto error_exit;
    }

    *kek_size = 32; // TODO: Set proper key size for now using educated guess.
    *kek = talloc_array(mem_ctx, uint8_t, *kek_size);
    if (!kek)
    {
        printf("%s:%s:%d Failed to allocate kek.\n",
               __FILE__, __func__, __LINE__);
        goto error_exit;
    }

    uint8_t *key_info = NULL;
    uint32_t key_info_size = 0;

    if (key_envelope->flags & 1) // Is public.
    {
        uint32_t private_key_size = key_envelope->private_key_len / 8;
        uint8_t *private_key = talloc_array(mem_ctx, uint8_t, private_key_size);
        if (!private_key || RAND_bytes(private_key, private_key_size) != RAND_OK)
        {
            printf("%s:%s:%d Failed to create private key. Error = 0x%x (%s)\n",
                   __FILE__, __func__, __LINE__, rc, "Content encryption failed!");

            goto error_exit;
        }

        // TODO: Cleanup or allocate random bytes.

        if (!compute_kek(mem_ctx,
                         kdf_parameters.hash_algorithm,
                         key_envelope->secret_agreement_algorithm,
                         key_envelope->secret_agreement_algorithm_len,
                         key_envelope->secret_agreement_parameters,
                         key_envelope->secret_agreement_parameters_len,
                         key_envelope->l2_key,
                         key_envelope->l2_key_len,
                         private_key,
                         private_key_size,
                         *kek_size,
                         kek))
        {
            printf("%s:%s:%d Failed to derive key encryption key.\n",
                   __FILE__, __func__, __LINE__);

            goto error_exit;
        }

        if (compute_peer_public_key(mem_ctx,
                                    key_envelope->secret_agreement_algorithm,
                                    key_envelope->secret_agreement_algorithm_len,
                                    key_envelope->secret_agreement_parameters,
                                    key_envelope->secret_agreement_parameters_len,
                                    private_key,
                                    private_key_size,
                                    key_envelope->l2_key,
                                    key_envelope->l2_key_len,
                                    &key_info_size,
                                    &key_info) != 0)
        {
            printf("%s:%s:%d Failed to compute public key.\n",
                   __FILE__, __func__, __LINE__);

            goto error_exit;
        }
    }
    else
    {
        uint32_t public_key_size = *kek_size;
        uint8_t *public_key = talloc_array(mem_ctx, uint8_t, public_key_size);
        if (!public_key || RAND_bytes(public_key, public_key_size) != RAND_OK)
        {
            printf("%s:%s:%d Failed to create cek iv. Error = 0x%x (%s)\n",
                   __FILE__, __func__, __LINE__, rc, "Content encryption failed!");

            goto error_exit;
        }
        if (!compute_kdf(kdf_parameters.hash_algorithm,
                         key_envelope->l2_key,
                         key_envelope->l2_key_len,
                         KDS_SERVICE_LABEL,
                         sizeof(KDS_SERVICE_LABEL),
                         public_key,
                         public_key_size,
                         public_key_size,
                         kek))
        {
            printf("%s:%s:%d Failed to compute kdf.\n",
                   __FILE__, __func__, __LINE__);

            goto error_exit;
        }

        key_info = public_key;
        key_info_size = public_key_size;
        // TODO: Cleanup or allocate random bytes.
    }

    struct KeyEnvelope *key_identifier = talloc_zero(mem_ctx, struct KeyEnvelope);
    if (!key_identifier)
    {
        printf("%s:%s:%d Unable to allocate key identifier.\n",
               __FILE__, __func__, __LINE__);

        goto error_exit;
    }

    key_identifier->version = 1;
    key_identifier->magic = 0x4b53444b;
    key_identifier->flags = key_envelope->flags;
    key_identifier->l0_index = key_envelope->l0_index;
    key_identifier->l1_index = key_envelope->l1_index;
    key_identifier->l2_index = key_envelope->l2_index;
    key_identifier->root_key_id = key_envelope->root_key_id;
    key_identifier->additional_info = talloc_memdup(key_identifier, key_info, key_info_size);
    key_identifier->additional_info_len = key_info_size;
    key_identifier->domain_name = talloc_strndup(key_identifier, key_envelope->domain_name, key_envelope->domain_name_len);
    key_identifier->forest_name = talloc_strndup(key_identifier, key_envelope->forest_name, key_envelope->forest_name_len);

    if (!key_identifier->additional_info
    || !key_identifier->domain_name
    || !key_identifier->forest_name)
    {
        printf("%s:%s:%d Unable to allocate key identifier fields.\n",
               __FILE__, __func__, __LINE__);

        goto error_exit;
    }

    *kek = talloc_reparent(mem_ctx, parent_ctx, *kek);
    *key_id = talloc_reparent(mem_ctx, parent_ctx, key_identifier);

    rc = 0;

error_exit:
    talloc_free(mem_ctx);

    return rc;
}

#define ALLOC_OR_ERROR_EXIT(ctx, type, var, msg) \
    type *var = talloc_zero(ctx, type); \
    if (!var) { \
        printf("%s:%s:%d Unable to allocate %s. Error = 0x%x (%s)\n", \
               __FILE__, __func__, __LINE__, #type, errno, msg); \
        goto error_exit; \
    }

uint8_t * encode_type(TALLOC_CTX *mem_ctx,
                      asn_TYPE_descriptor_t *type_descriptor,
                      void *struct_ptr,
                      ssize_t *encoded)
{
    asn_enc_rval_t erval = {};
    uint8_t *buffer = NULL;
    *encoded = 0;

    erval = der_encode(type_descriptor, struct_ptr, 0, 0);
    if (erval.encoded == -1)
    {
        printf("%s:%s:%d Cannot encode. Type = %s (%s)\n",
               __FILE__, __func__, __LINE__, erval.failed_type->name, strerror(errno));

        goto error_exit;
    }
    buffer = talloc_array(mem_ctx, uint8_t, erval.encoded);
    if (!buffer)
    {
        printf("%s:%s:%d Cannot allocate buffer!\n",
               __FILE__, __func__, __LINE__);

        goto error_exit;
    }
    erval = der_encode_to_buffer(type_descriptor, struct_ptr, buffer, erval.encoded);
    if (erval.encoded == -1)
    {
        printf("%s:%s:%d Cannot encode. Type = %s (%s)\n",
               __FILE__, __func__, __LINE__, erval.failed_type->name, strerror(errno));

        goto error_exit;
    }

    *encoded = erval.encoded;

error_exit:
    talloc_free(buffer);

    return buffer;
}

int32_t
pack_blob(const struct KeyEnvelope *key_identifier,
          const ProtectionDescriptor_t *descriptor,
          const uint8_t *encrypted_cek,
          const uint32_t encrypted_cek_size,
          const uint8_t *encrypted_content,
          const uint32_t encrypted_content_size,
          const uint8_t *cek_iv,
          const uint32_t cek_iv_size,
          uint32_t *size,
          uint8_t **out)
{
    int32_t rc = -1;
    ssize_t encoded = 0;

    TALLOC_CTX *mem_ctx = talloc_named(NULL, 0, "create_blob");
    if (!mem_ctx)
    {
        printf("%s:%s:%d Unable to create new talloc named context. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, rc, "Content packing failed!");
        goto error_exit;
    }

    ALLOC_OR_ERROR_EXIT(mem_ctx, RecipientInfo_t, recInfo, "Content packing failed!");

    KEKRecipientInfo_t *kekInfo = &recInfo->choice.kekri;
    recInfo->present = RecipientInfo_PR_kekri;

    ALLOC_OR_ERROR_EXIT(mem_ctx, ANY_t, key_attribute, "Content packing failed!");

    ALLOC_OR_ERROR_EXIT(mem_ctx, OtherKeyAttribute_t, other_key_attribute, "Content packing failed!");
    other_key_attribute->keyAttr = key_attribute; // TODO: View content of descriptor here!

    uint8_t *descriptor_encoded = encode_type(mem_ctx,
                                              &asn_DEF_ProtectionDescriptor,
                                              (void*)descriptor,
                                              &encoded);
    other_key_attribute->keyAttr->size = (int)encoded;
    if (!descriptor_encoded)
    {
        printf("%s:%s:%d Failed to encode ProtectionDescriptor_t object.\n",
               __FILE__, __func__, __LINE__);
        goto error_exit;
    }

    other_key_attribute->keyAttr->buf = talloc_memdup(mem_ctx, descriptor_encoded, encoded);

    other_key_attribute->keyAttrId.buf = talloc_strdup(mem_ctx, MICROSOFT_SOFTWARE_OID);
    other_key_attribute->keyAttrId.size = strlen(MICROSOFT_SOFTWARE_OID);

    enum ndr_err_code ndr_status = NDR_ERR_SUCCESS;
    DATA_BLOB data_blob = {};
    ndr_status = ndr_push_struct_blob(&data_blob, mem_ctx, key_identifier, (ndr_push_flags_fn_t)ndr_push_KeyEnvelope);
    if (ndr_status != NDR_ERR_SUCCESS)
    {
        printf("%s:%s:%d Failed to encode KeyEnvelope object. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, ndr_status, ndr_errstr(ndr_status));

        goto error_exit;
    }

    ALLOC_OR_ERROR_EXIT(mem_ctx, KEKIdentifier_t, kek_identifier, "Content packing failed!");

    time_t timer = time(NULL);
    const struct tm *current_local_time = localtime(&timer);

    ALLOC_OR_ERROR_EXIT(mem_ctx, GeneralizedTime_t, current_time, "Content packing failed!");
    kek_identifier->date = asn_time2GT(current_time, current_local_time, true);
    if (!kek_identifier->date)
    {
        printf("%s:%s:%d Unable to convert time.\n",
               __FILE__, __func__, __LINE__);

        goto error_exit;
    }
    kek_identifier->keyIdentifier.buf = data_blob.data;
    kek_identifier->keyIdentifier.size = data_blob.length;
    kek_identifier->other = other_key_attribute;

    ALLOC_OR_ERROR_EXIT(mem_ctx, AlgorithmIdentifier_t, algorithm_identifier, "Content packing failed!");

    algorithm_identifier->algorithm.buf = talloc_strdup(mem_ctx, AES256_WRAP_OID);
    algorithm_identifier->algorithm.size = strlen(AES256_WRAP_OID);
    algorithm_identifier->parameters = NULL;

    kekInfo->version = CMSVersion_v4;
    kekInfo->kekid = *kek_identifier;
    kekInfo->keyEncryptionAlgorithm = *algorithm_identifier;
    kekInfo->encryptedKey.buf = talloc_memdup(mem_ctx, encrypted_cek, encrypted_cek_size); // TODO: Check for results of memory and string duplication.
    kekInfo->encryptedKey.size = encrypted_cek_size;

    // asn_fprint(stdout, &asn_DEF_KEKRecipientInfo, kekInfo);

    ALLOC_OR_ERROR_EXIT(mem_ctx, MyKeyInfo_t, my_key_info, "Content packing failed!");
    my_key_info->modulus = 16;
    my_key_info->iv.buf = (uint8_t*)cek_iv;
    my_key_info->iv.size = cek_iv_size;

    // asn_fprint(stdout, &asn_DEF_MyKeyInfo, my_key_info);

    // asn_fprint(stdout, &asn_DEF_RecipientInfo, recInfo);

    ALLOC_OR_ERROR_EXIT(mem_ctx, EnvelopedData_t, enveloped_data, "Content packing failed!");
    enveloped_data->version = CMSVersion_v2;
    if (ASN_SET_ADD(&enveloped_data->recipientInfos.list, recInfo) != 0)
    {
        printf("%s:%s:%d Failed to add RecipientInfo_t to list.\n",
               __FILE__, __func__, __LINE__);
        goto error_exit;
    }

    ALLOC_OR_ERROR_EXIT(mem_ctx, EncryptedContent_t, encrypted_content_s, "Content packing failed!");
    encrypted_content_s->buf = talloc_memdup(mem_ctx, encrypted_content, encrypted_content_size);
    encrypted_content_s->size = encrypted_content_size;

    EncryptedContentInfo_t *encrypted_content_info = &enveloped_data->encryptedContentInfo;
    encrypted_content_info->contentEncryptionAlgorithm.algorithm.buf = talloc_strdup(mem_ctx, AES256_GCM_OID);
    encrypted_content_info->contentEncryptionAlgorithm.algorithm.size = strlen(AES256_GCM_OID);
    encrypted_content_info->contentType.buf = talloc_strdup(mem_ctx, CONTENT_TYPE_DATA_OID);
    encrypted_content_info->contentType.size = strlen(CONTENT_TYPE_DATA_OID);
    encrypted_content_info->encryptedContent = encrypted_content_s;


    ALLOC_OR_ERROR_EXIT(mem_ctx, ANY_t, content_encryption_algorithm_parameters, "Content packing failed!");
    encrypted_content_info->contentEncryptionAlgorithm.parameters = content_encryption_algorithm_parameters;

    uint8_t *buffer = encode_type(mem_ctx, &asn_DEF_MyKeyInfo, my_key_info, &encoded);
    if (!buffer)
    {
        printf("%s:%s:%d Cannot encode. Type = %s\n",
               __FILE__, __func__, __LINE__, "MyKeyInfo");

        goto error_exit;
    }
    content_encryption_algorithm_parameters->buf = talloc_memdup(mem_ctx, buffer, encoded);
    content_encryption_algorithm_parameters->size = (int)encoded;

    buffer = encode_type(mem_ctx, &asn_DEF_RecipientInfo, recInfo, &encoded);
    if (!buffer)
    {
        printf("%s:%s:%d Cannot encode. Type = %s\n",
               __FILE__, __func__, __LINE__, "RecipientInfo");

        goto error_exit;
    }

    // for (ssize_t i = 0; i < encoded; i++)
    // {
    //     printf("%02x ", buffer[i]);
    // }
    // printf("\n");

    ALLOC_OR_ERROR_EXIT(mem_ctx, ContentInfo_t, content_info, "Content packing failed!");
    content_info->contentType.buf = talloc_strdup(mem_ctx, CONTENT_TYPE_ENVELOPED_DATA_OID);
    content_info->contentType.size = strlen(CONTENT_TYPE_ENVELOPED_DATA_OID);

    char error[1024] = {};
    size_t error_size = 1024;

    // asn_fprint(stdout, &asn_DEF_EnvelopedData, enveloped_data);

    asn_check_constraints(&asn_DEF_EnvelopedData, enveloped_data, error, &error_size);
    printf("%s\n", error);

    buffer = encode_type(mem_ctx, &asn_DEF_EnvelopedData, enveloped_data, &encoded);
    if (!buffer)
    {
        printf("%s:%s:%d Cannot encode. Type = %s\n",
               __FILE__, __func__, __LINE__, "EnvelopedData");

        goto error_exit;
    }

    // for (ssize_t i = 0; i < encoded; i++)
    // {
    //     printf("%02x ", buffer[i]);
    // }
    // printf("\n");

    content_info->content.buf = talloc_memdup(mem_ctx, buffer, encoded);
    content_info->content.size = encoded;

    buffer = encode_type(mem_ctx, &asn_DEF_ContentInfo, content_info, &encoded);
    if (!buffer)
    {
        printf("%s:%s:%d Cannot encode. Type = %s\n",
               __FILE__, __func__, __LINE__, "ContentInfo");

        goto error_exit;
    }

    // asn_fprint(stdout, &asn_DEF_ContentInfo, content_info);

    uint8_t *mbuffer = malloc(encoded);
    memcpy(mbuffer, buffer, encoded);

    // for (ssize_t i = 0; i < encoded; i++)
    // {
    //     printf("%02x ", buffer[i]);
    // }
    // printf("\n");

    *size = encoded;
    *out = mbuffer;

    rc = 0;

error_exit:
    talloc_free(mem_ctx);

    return rc;
}

uint32_t
create_blob(const uint8_t *data,
            const uint32_t data_size,
            const uint8_t *key_envelope,
            const uint32_t key_envelope_size,
            ProtectionDescriptor_t *descriptor,
            uint8_t **encrypted_data,
            uint32_t *encrypted_data_size)
{
    int32_t rc = -1;

    uint8_t cek[CEK_LENGTH] = {};
    uint8_t cek_iv[CEK_IV_LENGTH] = {};

    TALLOC_CTX *mem_ctx = talloc_named(NULL, 0, "create_blob");
    if (!mem_ctx)
    {
        printf("%s:%s:%d Unable to create new talloc named context. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, rc, "Content encryption failed!");
        goto error_exit;
    }

    if (RAND_bytes(cek_iv, CEK_IV_LENGTH) != RAND_OK)
    {
        printf("%s:%s:%d Failed to create cek iv. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, rc, "Content encryption failed!");
        goto error_exit;
    }

    if (RAND_bytes(cek, CEK_LENGTH) != RAND_OK)
    {
        printf("%s:%s:%d Failed to create cek. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, rc, "Content encryption failed!");
        goto error_exit;
    }

    uint8_t *encrypted_content = NULL;
    uint32_t encrypted_content_size = 0;

    if (content_encrypt(mem_ctx,
                        data,
                        data_size,
                        cek,
                        CEK_LENGTH,
                        cek_iv,
                        CEK_IV_LENGTH,
                        &encrypted_content,
                        &encrypted_content_size) != 0)
    {
        printf("%s:%s:%d Failed to encrypt data. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, rc, "Content encryption failed!");

        goto error_exit;
    }

    uint8_t *kek = NULL;
    uint32_t kek_size = 0;
    struct KeyEnvelope *key_id = NULL;

    if (create_kek(mem_ctx, key_envelope, key_envelope_size, &kek, &kek_size, &key_id) != 0)
    {
        printf("%s:%s:%d Failed to create kek. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, rc, "Content encryption failed!");

        goto error_exit;
    }

    uint8_t *encrypted_cek = NULL;
    uint32_t encrypted_cek_size = 0;

    if (cek_encrypt(mem_ctx,
                    cek,
                    CEK_LENGTH,
                    kek,
                    kek_size,
                    &encrypted_cek,
                    &encrypted_cek_size))
    {
        printf("%s:%s:%d Failed to encrypt cek. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, rc, "Content encryption failed!");

        goto error_exit;
    }

    if (pack_blob(key_id,
                  descriptor,
                  encrypted_cek,
                  encrypted_cek_size,
                  encrypted_content,
                  encrypted_content_size,
                  cek_iv,
                  CEK_IV_LENGTH,
                  encrypted_data_size,
                  encrypted_data))
    {
        printf("%s:%s:%d Failed to pack content. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, rc, "Content encryption failed!");

        goto error_exit;
    }

    rc = 0;

error_exit:
    OPENSSL_cleanse(cek, CEK_LENGTH);
    OPENSSL_cleanse(cek_iv, CEK_IV_LENGTH);

    talloc_free(mem_ctx);

    return rc;
}
