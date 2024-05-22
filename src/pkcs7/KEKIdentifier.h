/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#ifndef	_KEKIdentifier_H_
#define	_KEKIdentifier_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>
#include <GeneralizedTime.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct OtherKeyAttribute;

/* KEKIdentifier */
typedef struct KEKIdentifier {
	OCTET_STRING_t	 keyIdentifier;
	GeneralizedTime_t	*date	/* OPTIONAL */;
	struct OtherKeyAttribute	*other	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} KEKIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_KEKIdentifier;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "OtherKeyAttribute.h"

#endif	/* _KEKIdentifier_H_ */
#include <asn_internal.h>