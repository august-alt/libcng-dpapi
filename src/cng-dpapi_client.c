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

#include "cng-dpapi_client.h"
#include <gkdi/gkdi_client.h>
#include <gkdi/gkdi.h>
#include <gkdi/ndr_gkdi.h>
#include <gkdi/ndr_gkdi_c.h>

#include "blob_p.h"
#include "protection_descriptor_p.h"

static uint32_t
create_rpc_binding(TALLOC_CTX *parent_ctx,
                   struct dcerpc_pipe **pipe,
                   const char *server,
                   const char *domain,
                   const char *username)
{
    TALLOC_CTX *mem_ctx = talloc_named(NULL, 0, "create_rpc_binding");
    NTSTATUS status = {0};

    char *server_name = server ? talloc_strdup(mem_ctx, server) : NULL;
    char *domain_name = domain ? talloc_strdup(mem_ctx, domain) : NULL;
    char *user_name = username ? talloc_strdup(mem_ctx, username) : NULL;

    if (!server_name)
    {
        // TODO: Implement server lookup.
    }

    status = get_client_rpc_binding(
                parent_ctx,
                pipe,
                server_name,
                domain_name,
                user_name);

    if (!NT_STATUS_IS_OK(status))
    {
        printf("Failed to establish RPC connection: %s\n", nt_errstr(status));

        talloc_free(mem_ctx);
        return -1;
    }

    talloc_free(mem_ctx);

    return 0;
}

uint32_t
ncrypt_unprotect_secret(const uint8_t *data,
                        const uint32_t data_size,
                        uint8_t **unpacked_data,
                        uint32_t *unpacked_data_size,
                        const char *server,
                        const char *domain,
                        const char *username)
{
    TALLOC_CTX *mem_ctx = talloc_named(NULL, 0, "create_rpc_client");

    blob_t *blob = blob_unpack(mem_ctx, data, data_size);

    if (!blob)
    {
        return -1;
    }

    struct dcerpc_pipe* pipe = NULL;
    NTSTATUS status = {0};

    if (create_rpc_binding(mem_ctx, &pipe, server, domain ? domain : blob->key_identifier.domain_name, username) == -1)
    {
        return -1;
    }

    uint8_t *key_envelope = NULL;
    uint32_t key_envelope_size = 0;

    HRESULT result;

    status = dcerpc_GetKey(pipe->binding_handle,
                           mem_ctx,
                           blob->protection_descriptor.target_sd_len,
                           blob->protection_descriptor.target_sd,
                           &blob->key_identifier.root_key_id,
                           blob->key_identifier.l0_index,
                           blob->key_identifier.l1_index,
                           blob->key_identifier.l2_index,
                           &key_envelope_size,
                           &key_envelope,
                           &result);

    if (!NT_STATUS_IS_OK(status))
    {
        printf("Failed to perform RPC call: %s\n", nt_errstr(status));
        return 0;
    }

    if (!HRES_IS_OK(result))
    {
        printf("Failed to perform operation GetKey: %s\n", hresult_errstr(result));
        return 0;
    }

    int rc = 0;

    rc = unpack_response(mem_ctx,
                         key_envelope,
                         key_envelope_size,
                         blob,
                         unpacked_data,
                         unpacked_data_size);

    if (rc != 0)
    {
        printf("Failed to unpack response!\n");
        return 0;
    }

    // Cleanup
    TALLOC_FREE(pipe);
    TALLOC_FREE(mem_ctx);

    return 0;
}

uint32_t
ncrypt_protect_secret(const ProtectionDescriptor_p protection_descriptor,
                      const uint8_t* data,
                      const uint32_t data_size,
                      uint8_t **encrypted_data,
                      uint32_t *encrypted_data_size,
                      const char* server,
                      const char* domain,
                      const char* username)
{
    uint32_t rc = 0;
    TALLOC_CTX *mem_ctx = talloc_named(NULL, 0, "ncrypt_protect_secret");
    struct dcerpc_pipe* pipe = NULL;
    NTSTATUS status = {0};    

    if (create_rpc_binding(mem_ctx, &pipe, server, domain, username) == -1)
    {
        rc = -1;
        goto cleanup;
    }

    uint8_t *key_envelope = NULL;
    uint32_t key_envelope_size = 0;

    HRESULT operation_result = {0};

    // TODO: Write explanation about -1 indices and NULL root_key_id.
    const int32_t l0_index = -1, l1_index = -1, l2_index = -1;
    struct GUID *root_key_id = NULL;

    uint8_t *target_sd = NULL;
    uint32_t target_sd_len = 0;

    if (create_security_descriptor_from_protection_descriptor(mem_ctx,
                                                              protection_descriptor,
                                                              &target_sd_len,
                                                              &target_sd))
    {
        rc = -1;
        goto cleanup;
    }

    status = dcerpc_GetKey(pipe->binding_handle,
                           mem_ctx,
                           target_sd_len,
                           target_sd,
                           root_key_id,
                           l0_index,
                           l1_index,
                           l2_index,
                           &key_envelope_size,
                           &key_envelope,
                           &operation_result);

    if (!NT_STATUS_IS_OK(status))
    {
        printf("Failed to perform RPC call: %s\n", nt_errstr(status));
        rc = -1;
        goto cleanup;
    }

    if (!HRES_IS_OK(operation_result))
    {
        printf("Failed to perform operation GetKey: %s\n", hresult_errstr(operation_result));
        rc = -1;
        goto cleanup;
    }

    rc = create_blob(data,
                     data_size,
                     key_envelope,
                     key_envelope_size,
                     protection_descriptor,
                     encrypted_data,
                     encrypted_data_size);

cleanup:
    talloc_free(mem_ctx);

    return rc;
}

uint32_t
ncrypt_create_protection_descriptor(const char *desciptor_string,
                                    uint32_t flags,
                                    ProtectionDescriptor_p *desciptor)
{
    (void)flags;
    uint32_t rc = 0;

    if (create_protection_descriptor(desciptor_string, desciptor) || !*desciptor)
    {
        rc = -1;
    }

    return rc;
}
