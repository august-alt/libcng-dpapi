#include <errno.h>
#include <stdint.h>
#include <ndr.h>
#include <talloc.h>

#include "pkcs7/ProtectionDescriptor.h"

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

int32_t
create_security_descriptor_from_protection_descriptor(const ProtectionDescriptor_t *descriptor,
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

error_exit:
    talloc_free(ctx);

    return rc;
}
