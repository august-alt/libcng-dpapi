/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#ifndef	_RevocationInfoChoices_H_
#define	_RevocationInfoChoices_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SET_OF.h>
#include <constr_SET_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RevocationInfoChoice;

/* RevocationInfoChoices */
typedef struct RevocationInfoChoices {
	A_SET_OF(struct RevocationInfoChoice) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RevocationInfoChoices_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RevocationInfoChoices;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "RevocationInfoChoice.h"

#endif	/* _RevocationInfoChoices_H_ */
#include <asn_internal.h>