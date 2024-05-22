/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#ifndef	_OriginatorIdentifierOrKey_H_
#define	_OriginatorIdentifierOrKey_H_


#include <asn_application.h>

/* Including external dependencies */
#include "IssuerAndSerialNumber.h"
#include "SubjectKeyIdentifier.h"
#include "OriginatorPublicKey.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum OriginatorIdentifierOrKey_PR {
	OriginatorIdentifierOrKey_PR_NOTHING,	/* No components present */
	OriginatorIdentifierOrKey_PR_issuerAndSerialNumber,
	OriginatorIdentifierOrKey_PR_subjectKeyIdentifier,
	OriginatorIdentifierOrKey_PR_originatorKey
} OriginatorIdentifierOrKey_PR;

/* OriginatorIdentifierOrKey */
typedef struct OriginatorIdentifierOrKey {
	OriginatorIdentifierOrKey_PR present;
	union OriginatorIdentifierOrKey_u {
		IssuerAndSerialNumber_t	 issuerAndSerialNumber;
		SubjectKeyIdentifier_t	 subjectKeyIdentifier;
		OriginatorPublicKey_t	 originatorKey;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} OriginatorIdentifierOrKey_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_OriginatorIdentifierOrKey;

#ifdef __cplusplus
}
#endif

#endif	/* _OriginatorIdentifierOrKey_H_ */
#include <asn_internal.h>
