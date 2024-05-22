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
    NTSTATUS status;

    char *server_name = server ? talloc_strdup(mem_ctx, server) : NULL;
    char *domain_name = domain ? talloc_strdup(mem_ctx, domain)
                               : talloc_strndup(mem_ctx, blob->key_identifier.domain_name,
                                                blob->key_identifier.domain_name_len);
    char *user_name = talloc_strdup(mem_ctx, username);

    if (!server_name)
    {
        // TODO: Implement server lookup.
    }

    status = get_client_rpc_binding(
                mem_ctx,
                &pipe,
                server_name,
                domain_name,
                user_name);

    if (!NT_STATUS_IS_OK(status))
    {
        printf("Failed to establish RPC connection: %u\n", status.v);
        return 0;
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
