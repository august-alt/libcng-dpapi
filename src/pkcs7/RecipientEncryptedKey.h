/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#ifndef	_RecipientEncryptedKey_H_
#define	_RecipientEncryptedKey_H_


#include <asn_application.h>

/* Including external dependencies */
#include "KeyAgreeRecipientIdentifier.h"
#include "EncryptedKey.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RecipientEncryptedKey */
typedef struct RecipientEncryptedKey {
	KeyAgreeRecipientIdentifier_t	 rid;
	EncryptedKey_t	 encryptedKey;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RecipientEncryptedKey_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RecipientEncryptedKey;

#ifdef __cplusplus
}
#endif

#endif	/* _RecipientEncryptedKey_H_ */
#include <asn_internal.h>
