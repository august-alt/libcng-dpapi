/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#ifndef	_AttributeCertificateInfo_H_
#define	_AttributeCertificateInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include "AttCertVersion.h"
#include "Holder.h"
#include "AttCertIssuer.h"
#include "AlgorithmIdentifier.h"
#include "CertificateSerialNumber.h"
#include "AttCertValidityPeriod.h"
#include "UniqueIdentifier.h"
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Extensions;
struct Attribute;

/* AttributeCertificateInfo */
typedef struct AttributeCertificateInfo {
	AttCertVersion_t	 version;
	Holder_t	 holder;
	AttCertIssuer_t	 issuer;
	AlgorithmIdentifier_t	 signature;
	CertificateSerialNumber_t	 serialNumber;
	AttCertValidityPeriod_t	 attrCertValidityPeriod;
    struct attributes_s {
		A_SEQUENCE_OF(struct Attribute) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
    } attributes_s;
	UniqueIdentifier_t	*issuerUniqueID	/* OPTIONAL */;
	struct Extensions	*extensions	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} AttributeCertificateInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_AttributeCertificateInfo;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "Extensions.h"
#include "Attribute.h"

#endif	/* _AttributeCertificateInfo_H_ */
#include <asn_internal.h>
