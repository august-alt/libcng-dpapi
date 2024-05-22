/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#include "ORAddress.h"

static asn_TYPE_member_t asn_MBR_ORAddress_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct ORAddress, built_in_standard_attributes),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_BuiltInStandardAttributes,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"built-in-standard-attributes"
		},
	{ ATF_POINTER, 2, offsetof(struct ORAddress, built_in_domain_defined_attributes),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_BuiltInDomainDefinedAttributes,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"built-in-domain-defined-attributes"
		},
	{ ATF_POINTER, 1, offsetof(struct ORAddress, extension_attributes),
		(ASN_TAG_CLASS_UNIVERSAL | (17 << 2)),
		0,
		&asn_DEF_ExtensionAttributes,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"extension-attributes"
		},
};
static const ber_tlv_tag_t asn_DEF_ORAddress_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_ORAddress_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 1 }, /* built-in-standard-attributes */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, -1, 0 }, /* built-in-domain-defined-attributes */
    { (ASN_TAG_CLASS_UNIVERSAL | (17 << 2)), 2, 0, 0 } /* extension-attributes */
};
static asn_SEQUENCE_specifics_t asn_SPC_ORAddress_specs_1 = {
	sizeof(struct ORAddress),
	offsetof(struct ORAddress, _asn_ctx),
	asn_MAP_ORAddress_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_ORAddress = {
	"ORAddress",
	"ORAddress",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_ORAddress_tags_1,
	sizeof(asn_DEF_ORAddress_tags_1)
		/sizeof(asn_DEF_ORAddress_tags_1[0]), /* 1 */
	asn_DEF_ORAddress_tags_1,	/* Same as above */
	sizeof(asn_DEF_ORAddress_tags_1)
		/sizeof(asn_DEF_ORAddress_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_ORAddress_1,
	3,	/* Elements count */
	&asn_SPC_ORAddress_specs_1	/* Additional specs */
};

