/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#ifndef	_ExtensionAttribute_H_
#define	_ExtensionAttribute_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include <ANY.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ExtensionAttribute */
typedef struct ExtensionAttribute {
	long	 extension_attribute_type;
	ANY_t	 extension_attribute_value;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ExtensionAttribute_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ExtensionAttribute;

#ifdef __cplusplus
}
#endif

#endif	/* _ExtensionAttribute_H_ */
#include <asn_internal.h>
