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

#include <stdint.h>
#include <errno.h>

#include "pkcs7/ContentInfo.h"
#include "pkcs7/EnvelopedData.h"
#include "pkcs7/ber_decoder.h"

#define CONTENT_TYPE_ENVELOPED_DATA_OID "1.2.840.113549.1.7.3"

#define MAX_ERROR_STRING_LENGTH 1024

EnvelopedData_t *unpack_ContentInfo(
        const uint8_t* data,
        const uint32_t size
        )
{
    asn_dec_rval_t rval;
    ContentInfo_t *contentInfo = NULL;
    EnvelopedData_t *envelopedData = NULL;

    rval = ber_decode(0, &asn_DEF_ContentInfo, (void**)&contentInfo, data, size);
    if (rval.code != RC_OK)
    {
        printf("%s:%s:%d Failed to decode ContentInfo object. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, rval.code, strerror(errno));
        return NULL;
    }

    uint32_t consumed_first = rval.consumed;

    rval = ber_decode(0, &asn_DEF_EnvelopedData, (void**)&envelopedData,
                      contentInfo->content.buf, contentInfo->content.size);
    if (rval.code != RC_OK)
    {
        printf("%s:%s:%d Failed to decode EnvelopedData object. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, rval.code, strerror(errno));
    }

    if (envelopedData->recipientInfos.list.count != 1
        || envelopedData->version != 2
        || envelopedData->recipientInfos.list.array[0]->present != RecipientInfo_PR_kekri
        || envelopedData->recipientInfos.list.array[0]->choice.kekri.version != 4)
    {
        printf("%s:%s:%d Unexpected data format. Error = 0x%x (%s)\n",
               __FILE__, __func__, __LINE__, envelopedData->recipientInfos.list.count, "");
        return NULL;
    }

    if (!envelopedData->encryptedContentInfo.encryptedContent)
    {
        envelopedData->encryptedContentInfo.encryptedContent = malloc(sizeof(EncryptedContent_t));
        envelopedData->encryptedContentInfo.encryptedContent->buf = (uint8_t*)(data + consumed_first);
        envelopedData->encryptedContentInfo.encryptedContent->size = (uint32_t)(size - consumed_first);
    }

    return envelopedData;
}
