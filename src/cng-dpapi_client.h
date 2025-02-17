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

#ifndef CNG_DPAPI_CLIENT_H
#define CNG_DPAPI_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef struct ProtectionDescriptor *ProtectionDescriptor_p;

uint32_t
ncrypt_create_protection_descriptor(const char *desciptor_string,
                                    uint32_t flags,
                                    ProtectionDescriptor_p *desciptor);

uint32_t
ncrypt_unprotect_secret(const uint8_t* data,
                        const uint32_t data_size,
                        uint8_t **unpacked_data,
                        uint32_t *unpacked_data_size,
                        const char* server,
                        const char *domain,
                        const char* username);

uint32_t
ncrypt_protect_secret(const ProtectionDescriptor_p protection_descriptor,
                      const uint8_t* data,
                      const uint32_t data_size,
                      uint8_t **encrypted_data,
                      uint32_t *encrypted_data_size,
                      const char* server,
                      const char* domain,
                      const char* username);

#ifdef __cplusplus
}
#endif

#endif//CNG_DPAPI_CLIENT_H
