/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#include "AttCertIssuer.h"

static asn_TYPE_member_t asn_MBR_AttCertIssuer_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct AttCertIssuer, choice.v1Form),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_GeneralNames,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"v1Form"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct AttCertIssuer, choice.v2Form),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_V2Form,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"v2Form"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_AttCertIssuer_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 0 }, /* v1Form */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 1, 0, 0 } /* v2Form */
};
static asn_CHOICE_specifics_t asn_SPC_AttCertIssuer_specs_1 = {
	sizeof(struct AttCertIssuer),
	offsetof(struct AttCertIssuer, _asn_ctx),
	offsetof(struct AttCertIssuer, present),
	sizeof(((struct AttCertIssuer *)0)->present),
	asn_MAP_AttCertIssuer_tag2el_1,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_AttCertIssuer = {
	"AttCertIssuer",
	"AttCertIssuer",
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
	asn_MBR_AttCertIssuer_1,
	2,	/* Elements count */
	&asn_SPC_AttCertIssuer_specs_1	/* Additional specs */
};
