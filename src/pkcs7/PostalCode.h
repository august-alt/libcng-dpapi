/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#ifndef	_PostalCode_H_
#define	_PostalCode_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NumericString.h>
#include <PrintableString.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PostalCode_PR {
	PostalCode_PR_NOTHING,	/* No components present */
	PostalCode_PR_numeric_code,
	PostalCode_PR_printable_code
} PostalCode_PR;

/* PostalCode */
typedef struct PostalCode {
	PostalCode_PR present;
	union PostalCode_u {
		NumericString_t	 numeric_code;
		PrintableString_t	 printable_code;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PostalCode_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PostalCode;

#ifdef __cplusplus
}
#endif

#endif	/* _PostalCode_H_ */
#include <asn_internal.h>
