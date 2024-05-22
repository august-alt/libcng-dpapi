/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#ifndef	_CertificateSet_H_
#define	_CertificateSet_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SET_OF.h>
#include <constr_SET_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct CertificateChoices;

/* CertificateSet */
typedef struct CertificateSet {
	A_SET_OF(struct CertificateChoices) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CertificateSet_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CertificateSet;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "CertificateChoices.h"

#endif	/* _CertificateSet_H_ */
#include <asn_internal.h>
