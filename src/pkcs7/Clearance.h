/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#ifndef	_Clearance_H_
#define	_Clearance_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OBJECT_IDENTIFIER.h>
#include "ClassList.h"
#include <asn_SET_OF.h>
#include <constr_SET_OF.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct SecurityCategory;

/* Clearance */
typedef struct Clearance {
	OBJECT_IDENTIFIER_t	 policyId;
	ClassList_t	 classList;
	struct securityCategories {
		A_SET_OF(struct SecurityCategory) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *securityCategories;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Clearance_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Clearance;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "SecurityCategory.h"

#endif	/* _Clearance_H_ */
#include <asn_internal.h>
