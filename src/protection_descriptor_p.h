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

#ifndef PROTECTION_DESCRIPTOR_H
#define PROTECTION_DESCRIPTOR_H

#include <talloc.h>
#include <stdint.h>

#include "pkcs7/ProtectionDescriptor.h"

int32_t
create_protection_descriptor(const char* descriptor_string,
                             ProtectionDescriptor_t **descriptor);

int32_t
unpack_single_protection_descriptor(uint8_t *data,
                                    uint32_t size,
                                    ProtectionDescriptor_t **descriptor);

int32_t
create_security_descriptor_from_protection_descriptor(TALLOC_CTX *parent_ctx,
                                                      const ProtectionDescriptor_t *descriptor,
                                                      uint32_t *size,
                                                      uint8_t **out);

#endif//PROTECTION_DESCRIPTOR_H
