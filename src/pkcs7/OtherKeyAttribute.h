/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#ifndef	_OtherKeyAttribute_H_
#define	_OtherKeyAttribute_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OBJECT_IDENTIFIER.h>
#include <ANY.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* OtherKeyAttribute */
typedef struct OtherKeyAttribute {
	OBJECT_IDENTIFIER_t	 keyAttrId;
	ANY_t	*keyAttr	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} OtherKeyAttribute_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_OtherKeyAttribute;

#ifdef __cplusplus
}
#endif

#endif	/* _OtherKeyAttribute_H_ */
#include <asn_internal.h>
