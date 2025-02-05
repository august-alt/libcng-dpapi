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

#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <ndr.h>
#include <talloc.h>

#include <regex.h>

#include "pkcs7/ProtectionDescriptor.h"

#define MESSAGE_BUFFER_SIZE 1024
#define SID_DESCRIPTOR_OID "1.3.6.1.4.1.311.74.1.1"
#define SID_PROVIDER "SID"
#define SID_REGEXP "^SID=S-1-[0-59]-"
//#define SID_REGEXP "^SID=S-1-[0-59]-\\d{2}-\\d{8,10}-\\d{8,10}-\\d{8,10}-[1-9]?\\d{3}$"

#define MAX_SID_PARTS 20

#define SYSTEM_BUILTIN_SID "S-1-5-18"

static int32_t
check_regexp(const char* regexp, const char *string)
{
    regex_t regex = {};
    int32_t rc = REG_NOMATCH;
    char message_buffer[MESSAGE_BUFFER_SIZE] = {};

    rc = regcomp(&regex, regexp, 0);
    if (rc)
    {
        printf("%s:%s:%d Could not compile regular expression %s.\n",
               __FILE__, __func__, __LINE__, regexp);
        return rc;
    }

    rc = regexec(&regex, string, 0, NULL, 0);
    if (!rc)
    {
        goto exit;
    }
    else if (rc == REG_NOMATCH)
    {
        goto exit;
    }
    else
    {
        regerror(rc, &regex, message_buffer, sizeof(message_buffer));
        printf("%s:%s:%d Regex match failed: %s.\n",
               __FILE__, __func__, __LINE__, message_buffer);
    }

exit:
    regfree(&regex);

    return rc;
}

int32_t
create_protection_descriptor(const char* descriptor_string,
                             ProtectionDescriptor_t **descriptor)
{
    int32_t rc = -1;
    if (check_regexp(SID_REGEXP, descriptor_string) != _REG_NOERROR)
    {
        printf("%s:%s:%d Not a SID this is currently unsupported!\n",
               __FILE__, __func__, __LINE__);
        return rc;
    }

    *descriptor = malloc(sizeof(ProtectionDescriptor_t));
    if (!(*descriptor))
    {
        goto error_exit;
    }
    memset(*descriptor, 0, sizeof(ProtectionDescriptor_t));

    size_t type_size = strlen(SID_DESCRIPTOR_OID);
    (*descriptor)->descriptorType.buf = strndup(SID_DESCRIPTOR_OID, type_size);
    (*descriptor)->descriptorType.size = type_size;
    if (!(*descriptor)->descriptorType.buf)
    {
        printf("%s:%s:%d Failed to allocate descriptor type.\n",
               __FILE__, __func__, __LINE__);
        goto error_exit;
    }

    ProviderAttributes_t *attributes = malloc(sizeof(ProviderAttributes_t));
    if (!attributes)
    {
        printf("%s:%s:%d Failed to allocate ProviderAttributes_t.\n",
               __FILE__, __func__, __LINE__);
        goto error_exit;
    }
    memset(attributes, 0, sizeof(ProviderAttributes_t));

    ProviderAttribute_t *attribute = malloc(sizeof(ProviderAttribute_t));
    if (!attribute)
    {
        printf("%s:%s:%d Failed to allocate ProviderAttribute_t.\n",
               __FILE__, __func__, __LINE__);
        goto error_exit;
    }
    memset(attribute, 0, sizeof(ProviderAttribute_t));

    attribute->providerName.buf = strdup(SID_PROVIDER);
    attribute->providerName.size = strlen(SID_PROVIDER);
    if (!attribute->providerName.buf)
    {
        printf("%s:%s:%d Failed to allocate provider name.\n",
               __FILE__, __func__, __LINE__);
        goto error_exit;
    }

    attribute->providerValue.buf = strdup(descriptor_string + 4);
    attribute->providerValue.size = strlen(descriptor_string) - 4;
    if (!attribute->providerValue.buf)
    {
        printf("%s:%s:%d Failed to allocate provider value.\n",
               __FILE__, __func__, __LINE__);
        goto error_exit;
    }

    if (ASN_SET_ADD(&attributes->list, attribute) != 0)
    {
        printf("%s:%s:%d Failed to add ProviderAttribute_t to list.\n",
               __FILE__, __func__, __LINE__);
        goto error_exit;
    }

    if (ASN_SET_ADD(&(*descriptor)->attrs.list, attributes) != 0)
    {
        printf("%s:%s:%d Failed to add ProviderAttributes_t to list.\n",
               __FILE__, __func__, __LINE__);
        goto error_exit;
    }

    rc = 0;

error_exit:
    if (rc != 0)
    {
        if (attribute)
        {
            free(attribute);
        }
        if (attributes)
        {
            free(attributes);
        }
        free(*descriptor);
    }

    return rc;
}

int32_t
unpack_single_protection_descriptor(uint8_t *data,
                                    uint32_t size,
                                    ProtectionDescriptor_t **descriptor)
{
    int32_t rc = -1;
    asn_dec_rval_t rval;

    rval = ber_decode(0, &asn_DEF_ProtectionDescriptor, (void**)descriptor, data, size);
    if (rval.code != RC_OK)
    {
        printf("%s:%s:%d Failed to decode ContentInfo object. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, rval.code, strerror(errno));
        return rc;
    }

    rc = 0;

    return rc;
}

static void
replace_char(char* str, char old_value, char new_value)
{
    char *current_char = strchr(str, old_value);
    while (current_char)
    {
        *current_char = new_value;
        current_char = strchr(current_char, old_value);
    }
}

static bool
sid_to_bytes(TALLOC_CTX *parent_ctx,
             const char *sid,
             uint32_t *bytes_size,
             uint8_t **bytes)
{
    bool rc = false;
    TALLOC_CTX *ctx =talloc_named(NULL, 0, "sid_to_bytes");
    if (!ctx)
    {
        printf("%s:%s:%d Failed to create talloc context.\n",
               __FILE__, __func__, __LINE__);
        return false;
    }
    char *current_sid = talloc_strdup(ctx, sid);
    if (!current_sid)
    {
        printf("%s:%s:%d Failed to duplicate sid.\n",
               __FILE__, __func__, __LINE__);
        return false;
    }
    replace_char(current_sid, '-', ' ');

    uint32_t sid_parts[MAX_SID_PARTS] = {};
    size_t sid_part_index = 0;
\
    char *p = current_sid + 2; // Skip S- from SID.

    for (;;)
    {
        // errno can be set to any non-zero value by a library function call
        // regardless of whether there was an error, so it needs to be cleared
        // in order to check the error set by strtol
        errno = 0;
        char* end = current_sid;
        const long i = strtol(p, &end, 10);
        if (p == end)
        {
            break;
        }

        const bool range_error = errno == ERANGE;
        // printf("Extracted '%.*s', strtol returned %ld.", (int)(end - p), p, i);
        p = end;

        if (range_error)
        {
            printf("%s:%s:%d Failed to duplicate sid.\n",
                   __FILE__, __func__, __LINE__);
            goto error_exit;
        }

        if (sid_part_index >= MAX_SID_PARTS)
        {
            printf("%s:%s:%d Sid is too long.\n",
                   __FILE__, __func__, __LINE__);
            goto error_exit;
        }

        sid_parts[sid_part_index++] = i;
    }

    if (sid_part_index < 3)
    {
        printf("%s:%s:%d Sid is too small.\n",
               __FILE__, __func__, __LINE__);
        goto error_exit;
    }

    uint8_t revision = sid_parts[0];
    uint64_t authority = htobe64(sid_parts[1]);
    uint8_t num_of_parts = (sid_part_index - 2);

    uint32_t result_size = 8 + num_of_parts * sizeof(uint32_t);

    uint8_t *sid_bytes = talloc_zero_array(ctx, uint8_t, result_size);

    memcpy(sid_bytes, &authority, sizeof(uint64_t));

    sid_bytes[0] = revision;
    sid_bytes[1] = num_of_parts;

    for (size_t i = 2; i < sid_part_index; i++)
    {
        uint32_t part = htole32(sid_parts[i]);
        memcpy(sid_bytes + i * sizeof(uint32_t), &part, sizeof(uint32_t));
    }

    *bytes = talloc_steal(parent_ctx, sid_bytes);
    *bytes_size = result_size;

    rc = true;

error_exit:
    talloc_free(ctx);

    return rc;
}

static bool
ace_to_bytes(TALLOC_CTX *parent_ctx,
             const char *ace,
             uint32_t access_mask,
             uint32_t *bytes_size,
             uint8_t **bytes)
{
    bool rc = false;

    uint32_t sid_size = 0;
    uint8_t *sid = NULL;

    if (!sid_to_bytes(parent_ctx, ace, &sid_size, &sid))
    {
        return rc;
    }

    uint32_t result_size = sizeof(uint32_t) + sizeof(uint32_t) + sid_size;

    uint8_t *ace_bytes = talloc_zero_array(parent_ctx, uint8_t, result_size);
    if (!ace_bytes)
    {
        return rc;
    }

    uint32_t access_mask_le = htole32(access_mask);
    uint16_t sid_length = htole16(sid_size + 8);

    memcpy(ace_bytes + sizeof(uint16_t), &sid_length, sizeof(uint16_t));
    memcpy(ace_bytes + sizeof(uint32_t), &access_mask_le, sizeof(uint32_t));
    memcpy(ace_bytes + sizeof(uint32_t) * 2, sid, sid_size);

    *bytes = ace_bytes;
    *bytes_size = result_size;

    return true;
}

static bool
construct_dacl(TALLOC_CTX *parent_ctx,
               uint8_t *ace1,
               uint32_t ace1_size,
               uint8_t *ace2,
               uint32_t ace2_size,
               uint32_t *bytes_size,
               uint8_t **bytes)
{
    uint32_t result_size = 2 * sizeof(uint32_t) + ace1_size + ace2_size;
    uint8_t *acl = talloc_zero_array(parent_ctx, uint8_t, result_size);
    if (!acl)
    {
        return false;
    }

    uint16_t ace_data_size_le = htole16(ace1_size + ace2_size + 8);
    uint16_t ace_count = htole16(2);

    acl[0] = 0x02; // ACL revision.

    memcpy(acl + sizeof(uint16_t), &ace_data_size_le, sizeof(uint16_t));
    memcpy(acl + sizeof(uint16_t) * 2, &ace_count, sizeof(uint16_t));

    memcpy(acl + sizeof(uint32_t) * 2, ace1, ace1_size);
    memcpy(acl + sizeof(uint32_t) * 2 + ace1_size, ace2, ace2_size);

    *bytes_size = result_size;
    *bytes = acl;

    return true;
}

typedef struct packed_descriptor_header
{
   uint16_t header;
   uint16_t control;
   uint32_t owner_offset;
   uint32_t group_offset;
   uint32_t sacl_offset;
   uint32_t dacl_offset;
} packed_descriptor_header_t;

int32_t
create_security_descriptor_from_protection_descriptor(TALLOC_CTX *parent_ctx,
                                                      const ProtectionDescriptor_t *descriptor,
                                                      uint32_t *size,
                                                      uint8_t **out)
{
    int32_t rc = -1;

    TALLOC_CTX *ctx = talloc_named(NULL, 0, "create_encryption_sid_from_descriptor");
    if (!ctx)
    {
        printf("%s:%s:%d Failed to create talloc ctx.)\n",
               __FILE__, __func__, __LINE__);
        goto error_exit;
    }

    if (descriptor->attrs.list.count <= 0 || descriptor->attrs.list.array[0]->list.count <= 0)
    {
        printf("%s:%s:%d Invalid protection descriptor.\n",
               __FILE__, __func__, __LINE__);
        goto error_exit;
    }

    uint32_t current_offset = sizeof(packed_descriptor_header_t);
    uint32_t owner_offset = 0;
    uint32_t group_offset = 0;
    uint32_t dacl_offset = 0;

    uint8_t *user_ace = NULL;
    uint32_t user_ace_size = 0;

    ace_to_bytes(ctx, descriptor->attrs.list.array[0]->list.array[0]->providerValue.buf, 3, &user_ace_size, &user_ace);

    uint8_t *world_ace = NULL;
    uint32_t world_ace_size = 0;

    ace_to_bytes(ctx, "S-1-1-0", 2, &world_ace_size, &world_ace);

    uint8_t *dacl = NULL;
    uint32_t dacl_size = 0;

    construct_dacl(ctx, user_ace, user_ace_size, world_ace, world_ace_size, &dacl_size, &dacl);
    dacl_offset = current_offset;
    current_offset += dacl_size;

    uint8_t *owner_data = NULL;
    uint32_t owner_size = 0;

    sid_to_bytes(ctx, SYSTEM_BUILTIN_SID, &owner_size, &owner_data);
    owner_offset = current_offset;
    current_offset += owner_size;

    uint8_t *group_data = NULL;
    uint32_t group_size = 0;

    sid_to_bytes(ctx, SYSTEM_BUILTIN_SID, &group_size, &group_data);
    group_offset = current_offset;

    packed_descriptor_header_t *header = talloc_zero(ctx, packed_descriptor_header_t);
    if (!header)
    {
        goto error_exit;
    }

    header->header = 0x0001;
    header->control = 0x8000 | 0x0004; // Relative SID and DACL present.
    header->owner_offset = owner_offset;
    header->group_offset = group_offset;
    header->dacl_offset = dacl_offset;

    uint32_t result_size = current_offset + group_size;
    uint8_t *result = talloc_zero_array(ctx, uint8_t, result_size);
    if (!result)
    {
        goto error_exit;
    }

    memcpy(result, header, sizeof(packed_descriptor_header_t));
    memcpy(result + dacl_offset, dacl, dacl_size);
    memcpy(result + owner_offset, owner_data, owner_size);
    memcpy(result + group_offset, group_data, group_size);

    result = talloc_steal(parent_ctx, result);

    *out = result;
    *size = result_size;

    rc = 0;

error_exit:
    talloc_free(ctx);

    return rc;
}
