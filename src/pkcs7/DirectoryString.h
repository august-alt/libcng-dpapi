/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#ifndef	_DirectoryString_H_
#define	_DirectoryString_H_


#include <asn_application.h>

/* Including external dependencies */
#include <TeletexString.h>
#include <PrintableString.h>
#include <UniversalString.h>
#include <UTF8String.h>
#include <BMPString.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum DirectoryString_PR {
	DirectoryString_PR_NOTHING,	/* No components present */
	DirectoryString_PR_teletexString,
	DirectoryString_PR_printableString,
	DirectoryString_PR_universalString,
	DirectoryString_PR_utf8String,
	DirectoryString_PR_bmpString
} DirectoryString_PR;

/* DirectoryString */
typedef struct DirectoryString {
	DirectoryString_PR present;
	union DirectoryString_u {
		TeletexString_t	 teletexString;
		PrintableString_t	 printableString;
		UniversalString_t	 universalString;
		UTF8String_t	 utf8String;
		BMPString_t	 bmpString;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DirectoryString_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DirectoryString;

#ifdef __cplusplus
}
#endif

#endif	/* _DirectoryString_H_ */
#include <asn_internal.h>
