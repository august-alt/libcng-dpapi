/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#ifndef	_IssuerSerial_H_
#define	_IssuerSerial_H_


#include <asn_application.h>

/* Including external dependencies */
#include "GeneralNames.h"
#include "CertificateSerialNumber.h"
#include "UniqueIdentifier.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* IssuerSerial */
typedef struct IssuerSerial {
	GeneralNames_t	 issuer;
	CertificateSerialNumber_t	 serial;
	UniqueIdentifier_t	*issuerUID	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} IssuerSerial_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_IssuerSerial;

#ifdef __cplusplus
}
#endif

#endif	/* _IssuerSerial_H_ */
#include <asn_internal.h>
