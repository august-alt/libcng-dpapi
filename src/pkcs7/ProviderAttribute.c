/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "ProtectionDescriptorModule"
 * 	found in "protection_descriptor.asn1"
 */

#include "ProviderAttribute.h"

static asn_TYPE_member_t asn_MBR_ProviderAttribute_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct ProviderAttribute, providerName),
		(ASN_TAG_CLASS_UNIVERSAL | (12 << 2)),
		0,
		&asn_DEF_UTF8String,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"providerName"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct ProviderAttribute, providerValue),
		(ASN_TAG_CLASS_UNIVERSAL | (12 << 2)),
		0,
		&asn_DEF_UTF8String,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"providerValue"
		},
};
static const ber_tlv_tag_t asn_DEF_ProviderAttribute_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_ProviderAttribute_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (12 << 2)), 0, 0, 1 }, /* providerName */
    { (ASN_TAG_CLASS_UNIVERSAL | (12 << 2)), 1, -1, 0 } /* providerValue */
};
static asn_SEQUENCE_specifics_t asn_SPC_ProviderAttribute_specs_1 = {
	sizeof(struct ProviderAttribute),
	offsetof(struct ProviderAttribute, _asn_ctx),
	asn_MAP_ProviderAttribute_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_ProviderAttribute = {
	"ProviderAttribute",
	"ProviderAttribute",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_ProviderAttribute_tags_1,
	sizeof(asn_DEF_ProviderAttribute_tags_1)
		/sizeof(asn_DEF_ProviderAttribute_tags_1[0]), /* 1 */
	asn_DEF_ProviderAttribute_tags_1,	/* Same as above */
	sizeof(asn_DEF_ProviderAttribute_tags_1)
		/sizeof(asn_DEF_ProviderAttribute_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_ProviderAttribute_1,
	2,	/* Elements count */
	&asn_SPC_ProviderAttribute_specs_1	/* Additional specs */
};

