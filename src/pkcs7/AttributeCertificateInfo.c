/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#include "AttributeCertificateInfo.h"

static asn_TYPE_member_t asn_MBR_attributes_8[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Attribute,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		""
		},
};
static const ber_tlv_tag_t asn_DEF_attributes_tags_8[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_attributes_specs_8 = {
    sizeof(struct attributes_s),
    offsetof(struct attributes_s, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_attributes_8 = {
	"attributes",
	"attributes",
	SEQUENCE_OF_free,
	SEQUENCE_OF_print,
	SEQUENCE_OF_constraint,
	SEQUENCE_OF_decode_ber,
	SEQUENCE_OF_encode_der,
	SEQUENCE_OF_decode_xer,
	SEQUENCE_OF_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_attributes_tags_8,
	sizeof(asn_DEF_attributes_tags_8)
		/sizeof(asn_DEF_attributes_tags_8[0]), /* 1 */
	asn_DEF_attributes_tags_8,	/* Same as above */
	sizeof(asn_DEF_attributes_tags_8)
		/sizeof(asn_DEF_attributes_tags_8[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_attributes_8,
	1,	/* Single element */
	&asn_SPC_attributes_specs_8	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_AttributeCertificateInfo_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct AttributeCertificateInfo, version),
		(ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
		0,
		&asn_DEF_AttCertVersion,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"version"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct AttributeCertificateInfo, holder),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Holder,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"holder"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct AttributeCertificateInfo, issuer),
		-1 /* Ambiguous tag (CHOICE?) */,
		0,
		&asn_DEF_AttCertIssuer,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"issuer"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct AttributeCertificateInfo, signature),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_AlgorithmIdentifier,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"signature"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct AttributeCertificateInfo, serialNumber),
		(ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
		0,
		&asn_DEF_CertificateSerialNumber,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"serialNumber"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct AttributeCertificateInfo, attrCertValidityPeriod),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_AttCertValidityPeriod,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"attrCertValidityPeriod"
		},
    { ATF_NOFLAGS, 0, offsetof(struct AttributeCertificateInfo, attributes_s),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_attributes_8,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"attributes"
		},
	{ ATF_POINTER, 2, offsetof(struct AttributeCertificateInfo, issuerUniqueID),
		(ASN_TAG_CLASS_UNIVERSAL | (3 << 2)),
		0,
		&asn_DEF_UniqueIdentifier,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"issuerUniqueID"
		},
	{ ATF_POINTER, 1, offsetof(struct AttributeCertificateInfo, extensions),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Extensions,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"extensions"
		},
};
static const ber_tlv_tag_t asn_DEF_AttributeCertificateInfo_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_AttributeCertificateInfo_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 0, 0, 1 }, /* version */
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 4, -1, 0 }, /* serialNumber */
    { (ASN_TAG_CLASS_UNIVERSAL | (3 << 2)), 7, 0, 0 }, /* issuerUniqueID */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, 0, 5 }, /* holder */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 2, -1, 4 }, /* v1Form */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 3, -2, 3 }, /* signature */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 5, -3, 2 }, /* attrCertValidityPeriod */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 6, -4, 1 }, /* attributes */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 8, -5, 0 }, /* extensions */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 2, 0, 0 } /* v2Form */
};
static asn_SEQUENCE_specifics_t asn_SPC_AttributeCertificateInfo_specs_1 = {
	sizeof(struct AttributeCertificateInfo),
	offsetof(struct AttributeCertificateInfo, _asn_ctx),
	asn_MAP_AttributeCertificateInfo_tag2el_1,
	10,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_AttributeCertificateInfo = {
	"AttributeCertificateInfo",
	"AttributeCertificateInfo",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_AttributeCertificateInfo_tags_1,
	sizeof(asn_DEF_AttributeCertificateInfo_tags_1)
		/sizeof(asn_DEF_AttributeCertificateInfo_tags_1[0]), /* 1 */
	asn_DEF_AttributeCertificateInfo_tags_1,	/* Same as above */
	sizeof(asn_DEF_AttributeCertificateInfo_tags_1)
		/sizeof(asn_DEF_AttributeCertificateInfo_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_AttributeCertificateInfo_1,
	9,	/* Elements count */
	&asn_SPC_AttributeCertificateInfo_specs_1	/* Additional specs */
};

