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

#include <gkdi/ndr_gkdi.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>

#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

#include "pkcs7_p.h"
#include "pkcs7/KEKRecipientInfo.h"


#define CONTENT_TYPE_ENVELOPED_DATA_OID "1.2.840.113549.1.7.3"
#define MAX_BUFFER_SIZE 16384

// TODO: to refine napilnikom
struct ProtectionDescriptor*
unpack_protection_descriptor_sid(
        TALLOC_CTX *mem_ctx,
        KEKRecipientInfo_t *kekInfo
)
{
    // TODO: Add to ASN.1 ProtectionDescriptor.
    // TODO: Add function for OIDs(validation too).
    // 1.3.6.1.4.1.311.74.1 - MICROSOFT_SOFTWARE_OID

/*
    reader = ASN1Reader(data).read_sequence()
    content_type = reader.read_object_identifier()

    reader = reader.read_sequence().read_sequence().read_sequence()
    value_type = reader.read_utf8_string()
    value = reader.read_utf8_string()
*/

    // TEMPORARY
    if (!mem_ctx)
    {
        printf("%s:%s:%d Passed talloc_ctx is NULL. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, 0, "TALLOC_CTX is NULL!");

        return NULL;
    }

    struct ProtectionDescriptor* descriptor = NULL;

    if (kekInfo->kekid.other->keyAttr->size <= 27 || 
        strncmp(&kekInfo->kekid.other->keyAttr->buf[22], "SID", 3) != 0)
    {
        return NULL;
    }

    descriptor = talloc(mem_ctx, struct ProtectionDescriptor);
    descriptor->value = strndup(&kekInfo->kekid.other->keyAttr->buf[27], kekInfo->kekid.other->keyAttr->size - 27);
    descriptor->type = SID;

    return descriptor;
}

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

    char target_sd[] =
    {
        0x01, 0x00, 0x04, 0x80, 0x54, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x40, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x24, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0xCC, 0x48, 0x40, 0x3E, 0x05, 0xFD, 0xE0, 0x01,
        0x57, 0xE4, 0x28, 0xB4, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00
    };
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

uint32_t
compute_kdf(const uint8_t  *algorithm,
            uint8_t  *secret,
            uint32_t secret_size,
            uint8_t  *label,
            uint32_t label_size,
            uint8_t *context,
            uint32_t context_size,
            uint32_t length,
            uint8_t **out)
{
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx;
    int result = 0;
    int KBKDF_use_l = 0;
    char* _algorithm = strdup(algorithm);
    OSSL_PARAM params[6], *p = params;

    kdf = EVP_KDF_fetch(NULL, "KBKDF", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            _algorithm, strlen(_algorithm));
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC,
                                            "HMAC", strlen("HMAC"));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                            secret, strlen(secret));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                            label, strlen(label));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                            context, strlen(context));
    // *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_KBKDF_USE_L,
    //                                          &KBKDF_use_l);
    *p = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, *out, length, params) <= 0)
    {
        result = -1;
    }


    // if (result == 0) {
    //     printf("%s'0x%02x'", "grep \"[", (*out)[0]);
    //     bool firstOutput = true;
    //     for (int i = 1; i < length; ++i)
    //     {
    //         if(firstOutput)
    //         {
    //             printf(", '0x%02x'", (*out)[i]);
    //         }
    //     }
    //     printf("%s", "]\"");
    // }

    EVP_KDF_CTX_free(kctx);
    free(_algorithm);

    return result;
}

static uint32_t
get_kek(GroupKeyEnvelope *key_envelope, struct KeyEnvelope *key_identifier, gnutls_datum_t *kek)
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
    ndr_status = ndr_pull_struct_blob(&data_blob, NULL, &kdf_parameters, (ndr_pull_flags_fn_t)ndr_pull_KdfParameters);
    if (ndr_status != NDR_ERR_SUCCESS)
    {
        printf("%s:%s:%d Failed to decode KeyEnvelope object. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, ndr_status, ndr_errstr(ndr_status));

        return -1;
    }

    uint8_t *l2_key = key_envelope->l2_key;
    uint32_t l2_key_size = key_envelope->l2_key_len;
    uint8_t *KDS_SERVICE_LABEL = "KDS service";
    uint32_t KDS_SERVICE_LABEL_SIZE = strlen(KDS_SERVICE_LABEL);

    if (false)
    {
        printf("%s:%s:%d Failed to compute_kek_from_public_key. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, ndr_status, ndr_errstr(ndr_status));

        return -1;
    }
    else
    {

        uint32_t status = 0;
        kek->size = 32;
        kek->data = malloc(32);     // Rewrite with talloc

        status = compute_kdf(kdf_parameters.hash_algorithm,
                             l2_key,
                             l2_key_size,
                             KDS_SERVICE_LABEL,
                             KDS_SERVICE_LABEL_SIZE,
                             key_identifier->additional_info,
                             key_identifier->additional_info_len,
                             kek->size,
                             &kek->data);
        if (status != 0)
        {
            printf("%s:%s:%d Failed to compute_kdf. Error = 0x%x (%s)\n",
                   __FILE__, __func__, __LINE__, status, "Failed to compute kdf!");

            return -1;
        }
    }

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

    GroupKeyEnvelope *group_key_envelope = talloc_zero(mem_ctx, GroupKeyEnvelope);
    enum ndr_err_code ndr_status = NDR_ERR_SUCCESS;

    DATA_BLOB data_blob;
    data_blob.data = (uint8_t*)data;
    data_blob.length = size;
    ndr_status = ndr_pull_struct_blob(&data_blob, mem_ctx, group_key_envelope, (ndr_pull_flags_fn_t)ndr_pull_GroupKeyEnvelope);
    if (ndr_status != NDR_ERR_SUCCESS)
    {
        printf("%s:%s:%d Failed to decode GroupKeyEnvelope object. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, ndr_status, ndr_errstr(ndr_status));

        return -1;
    }

    gnutls_datum_t kek = { 0 };
    int rc = 0;

    rc = get_kek(group_key_envelope, &initial_data->key_identifier, &kek);
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
