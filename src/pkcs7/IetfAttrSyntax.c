/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#include "IetfAttrSyntax.h"

static asn_TYPE_member_t asn_MBR_Member_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct Member, choice.octets),
		(ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
		0,
		&asn_DEF_OCTET_STRING,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"octets"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Member, choice.oid),
		(ASN_TAG_CLASS_UNIVERSAL | (6 << 2)),
		0,
		&asn_DEF_OBJECT_IDENTIFIER,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"oid"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Member, choice.string),
		(ASN_TAG_CLASS_UNIVERSAL | (12 << 2)),
		0,
		&asn_DEF_UTF8String,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"string"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_Member_tag2el_4[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 0, 0, 0 }, /* octets */
    { (ASN_TAG_CLASS_UNIVERSAL | (6 << 2)), 1, 0, 0 }, /* oid */
    { (ASN_TAG_CLASS_UNIVERSAL | (12 << 2)), 2, 0, 0 } /* string */
};
static asn_CHOICE_specifics_t asn_SPC_Member_specs_4 = {
	sizeof(struct Member),
	offsetof(struct Member, _asn_ctx),
	offsetof(struct Member, present),
	sizeof(((struct Member *)0)->present),
	asn_MAP_Member_tag2el_4,
	3,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_Member_4 = {
	"CHOICE",
	"CHOICE",
	CHOICE_free,
	CHOICE_print,
	CHOICE_constraint,
	CHOICE_decode_ber,
	CHOICE_encode_der,
	CHOICE_decode_xer,
	CHOICE_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	CHOICE_outmost_tag,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	0,	/* No PER visible constraints */
	asn_MBR_Member_4,
	3,	/* Elements count */
	&asn_SPC_Member_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_values_3[] = {
	{ ATF_POINTER, 0, 0,
		-1 /* Ambiguous tag (CHOICE?) */,
		0,
		&asn_DEF_Member_4,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		""
		},
};
static const ber_tlv_tag_t asn_DEF_values_tags_3[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_values_specs_3 = {
	sizeof(struct values),
	offsetof(struct values, _asn_ctx),
	2,	/* XER encoding is XMLValueList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_values_3 = {
	"values",
	"values",
	SEQUENCE_OF_free,
	SEQUENCE_OF_print,
	SEQUENCE_OF_constraint,
	SEQUENCE_OF_decode_ber,
	SEQUENCE_OF_encode_der,
	SEQUENCE_OF_decode_xer,
	SEQUENCE_OF_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_values_tags_3,
	sizeof(asn_DEF_values_tags_3)
		/sizeof(asn_DEF_values_tags_3[0]), /* 1 */
	asn_DEF_values_tags_3,	/* Same as above */
	sizeof(asn_DEF_values_tags_3)
		/sizeof(asn_DEF_values_tags_3[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_values_3,
	1,	/* Single element */
	&asn_SPC_values_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_IetfAttrSyntax_1[] = {
	{ ATF_POINTER, 1, offsetof(struct IetfAttrSyntax, policyAuthority),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GeneralNames,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"policyAuthority"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct IetfAttrSyntax, values),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_values_3,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"values"
		},
};
static const ber_tlv_tag_t asn_DEF_IetfAttrSyntax_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_IetfAttrSyntax_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, 0, 0 }, /* values */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* policyAuthority */
};
static asn_SEQUENCE_specifics_t asn_SPC_IetfAttrSyntax_specs_1 = {
	sizeof(struct IetfAttrSyntax),
	offsetof(struct IetfAttrSyntax, _asn_ctx),
	asn_MAP_IetfAttrSyntax_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_IetfAttrSyntax = {
	"IetfAttrSyntax",
	"IetfAttrSyntax",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_IetfAttrSyntax_tags_1,
	sizeof(asn_DEF_IetfAttrSyntax_tags_1)
		/sizeof(asn_DEF_IetfAttrSyntax_tags_1[0]), /* 1 */
	asn_DEF_IetfAttrSyntax_tags_1,	/* Same as above */
	sizeof(asn_DEF_IetfAttrSyntax_tags_1)
		/sizeof(asn_DEF_IetfAttrSyntax_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_IetfAttrSyntax_1,
	2,	/* Elements count */
	&asn_SPC_IetfAttrSyntax_specs_1	/* Additional specs */
};

