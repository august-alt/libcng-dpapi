#ifndef PROTECTION_DESCRIPTOR_H
#define PROTECTION_DESCRIPTOR_H

#include <stdint.h>

typedef struct ProtectionDescriptor ProtectionDescriptor_t;

int32_t
unpack_single_protection_descriptor(uint8_t *data,
                                    uint32_t *size,
                                    ProtectionDescriptor_t **descriptor);

int32_t
create_security_descriptor_from_protection_descriptor(const ProtectionDescriptor_t *descriptor,
                                                      uint32_t *size,
                                                      uint8_t **out);

#endif//PROTECTION_DESCRIPTOR_H
