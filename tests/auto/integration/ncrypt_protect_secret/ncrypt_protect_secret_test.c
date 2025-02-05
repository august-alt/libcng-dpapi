#include "cng-dpapi/cng-dpapi_client.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define SERVER_FQDN "dc01.domain2.alt"
#define DOMAIN_NAME "DOMAIN2.ALT"
#define USER_NAME "administrator"

int main(int argc, char ** argv)
{
    (void)argc;
    (void)argv;

    uint32_t status = 0;

    uint8_t *unprotected_secret = NULL;
    uint32_t unprotected_secret_size = 0;

    uint8_t *protected_secret = NULL;
    uint32_t protected_secret_size = 0;

    const uint8_t test_data_bytes[] = { 0x48, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00, 0x20, 0x00, 0x57, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x6c, 0x00, 0x64, 0x00, 0x21, 0x00, 0x00, 0x00 };
    const uint32_t test_data_size = sizeof(test_data_bytes);

    ProtectionDescriptor_p descriptor = NULL;

    status = ncrypt_create_protection_descriptor("SID=S-1-5-21-2573627400-4123522163-824536584-500",
                                                 0,
                                                 &descriptor);
    if (status != 0)
    {
        printf("Failed to create descriptor: %d\n", status);
        goto error_exit;
    }

    status = ncrypt_protect_secret(descriptor,
                                   test_data_bytes,
                                   test_data_size,
                                   &protected_secret,
                                   &protected_secret_size,
                                   SERVER_FQDN,
                                   DOMAIN_NAME,
                                   USER_NAME);

    if (status != 0)
    {
        printf("Failed to protect secret: %d\n", status);
        goto error_exit;
    }

    status = ncrypt_unprotect_secret(protected_secret,
                                     protected_secret_size,
                                     &unprotected_secret,
                                     &unprotected_secret_size,
                                     SERVER_FQDN,
                                     DOMAIN_NAME,
                                     USER_NAME);

    if (status != 0)
    {
        printf("Failed to unprotect secret: %d\n", status);
        goto error_exit;
    }

    if (unprotected_secret_size != test_data_size)
    {
        printf("Unprotected secret size mismatch\n");
        goto error_exit;
    }

    for (uint32_t i = 0; i < test_data_size; i++)
    {
        if (unprotected_secret[i] != test_data_bytes[i])
        {
            printf("Unprotected secret data mismatch\n");
            goto error_exit;
        }
    }

    printf("Secret protection and unprotection successful\n");

error_exit:
    return unprotected_secret ? EXIT_SUCCESS : EXIT_FAILURE;
}
