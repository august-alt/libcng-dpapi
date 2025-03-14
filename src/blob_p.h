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

#ifndef CNG_DPAPI_BLOB_H
#define CNG_DPAPI_BLOB_H

#include <stdint.h>
#include <gkdi/ndr_gkdi.h>

#include "pkcs7/ProtectionDescriptor.h"

enum ProtectionDescriptorType
{
    SID,
    KEY_FILE,
    SDDL,
    LOCAL,
};

struct MyProtectionDescriptor
{
    enum ProtectionDescriptorType type;
    char* value;
    uint8_t* target_sd;
    uint32_t target_sd_len;
};

struct KeyEnvelope;

typedef struct blob
{
    struct KeyEnvelope key_identifier;
    struct MyProtectionDescriptor protection_descriptor;
    uint8_t* enc_cek;
    uint32_t enc_cek_size;
    char* enc_cek_algorithm;
    uint8_t* enc_cek_parameters;
    uint8_t* enc_content;
    uint32_t enc_content_size;
    char* enc_content_algorithm;
    uint32_t enc_content_algorithm_size;
    uint8_t* enc_content_parameters;
    uint32_t enc_content_parameters_size;
} blob_t;

struct GroupKeyEnvelope;
typedef struct GroupKeyEnvelope GroupKeyEnvelope;

uint32_t
create_blob(const uint8_t* data,
            const uint32_t data_size,
            const uint8_t* key_envelope,
            const uint32_t key_envelope_size,
            ProtectionDescriptor_t *descriptor,
            uint8_t **encrypted_data,
            uint32_t *encrypted_data_size);

blob_t*
blob_unpack(TALLOC_CTX *mem_ctx, const uint8_t* data, const uint32_t size);

uint32_t
unpack_response(
        TALLOC_CTX *mem_ctx,
        const uint8_t* data,
        const uint32_t size,
        blob_t *initial_data,
        uint8_t **decrypted_data,
        uint32_t *decrypted_data_size
);

#endif//CNG_DPAPI_BLOB_H
