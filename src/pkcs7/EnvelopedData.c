/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#include "EnvelopedData.h"

static asn_TYPE_member_t asn_MBR_EnvelopedData_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct EnvelopedData, version),
		(ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
		0,
		&asn_DEF_CMSVersion,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"version"
		},
	{ ATF_POINTER, 1, offsetof(struct EnvelopedData, originatorInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_OriginatorInfo,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"originatorInfo"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct EnvelopedData, recipientInfos),
		(ASN_TAG_CLASS_UNIVERSAL | (17 << 2)),
		0,
		&asn_DEF_RecipientInfos,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"recipientInfos"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct EnvelopedData, encryptedContentInfo),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_EncryptedContentInfo,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"encryptedContentInfo"
		},
	{ ATF_POINTER, 1, offsetof(struct EnvelopedData, unprotectedAttrs),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UnprotectedAttributes,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"unprotectedAttrs"
		},
};
static const ber_tlv_tag_t asn_DEF_EnvelopedData_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_EnvelopedData_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 0, 0, 0 }, /* version */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 3, 0, 0 }, /* encryptedContentInfo */
    { (ASN_TAG_CLASS_UNIVERSAL | (17 << 2)), 2, 0, 0 }, /* recipientInfos */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 1, 0, 0 }, /* originatorInfo */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 4, 0, 0 } /* unprotectedAttrs */
};
static asn_SEQUENCE_specifics_t asn_SPC_EnvelopedData_specs_1 = {
	sizeof(struct EnvelopedData),
	offsetof(struct EnvelopedData, _asn_ctx),
	asn_MAP_EnvelopedData_tag2el_1,
	5,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_EnvelopedData = {
	"EnvelopedData",
	"EnvelopedData",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_EnvelopedData_tags_1,
	sizeof(asn_DEF_EnvelopedData_tags_1)
		/sizeof(asn_DEF_EnvelopedData_tags_1[0]), /* 1 */
	asn_DEF_EnvelopedData_tags_1,	/* Same as above */
	sizeof(asn_DEF_EnvelopedData_tags_1)
		/sizeof(asn_DEF_EnvelopedData_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_EnvelopedData_1,
	5,	/* Elements count */
	&asn_SPC_EnvelopedData_specs_1	/* Additional specs */
};

