/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#include "SubjectAltName.h"

int
SubjectAltName_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	/* Determine the number of elements */
	size = _A_CSEQUENCE_FROM_VOID(sptr)->count;
	
	if((size >= 1)) {
		/* Perform validation of the inner elements */
		return td->check_constraints(td, sptr, ctfailcb, app_key);
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

/*
 * This type is implemented using GeneralNames,
 * so here we adjust the DEF accordingly.
 */
static void
SubjectAltName_1_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td) {
	td->free_struct    = asn_DEF_GeneralNames.free_struct;
	td->print_struct   = asn_DEF_GeneralNames.print_struct;
	td->check_constraints = asn_DEF_GeneralNames.check_constraints;
	td->ber_decoder    = asn_DEF_GeneralNames.ber_decoder;
	td->der_encoder    = asn_DEF_GeneralNames.der_encoder;
	td->xer_decoder    = asn_DEF_GeneralNames.xer_decoder;
	td->xer_encoder    = asn_DEF_GeneralNames.xer_encoder;
	td->uper_decoder   = asn_DEF_GeneralNames.uper_decoder;
	td->uper_encoder   = asn_DEF_GeneralNames.uper_encoder;
	if(!td->per_constraints)
		td->per_constraints = asn_DEF_GeneralNames.per_constraints;
	td->elements       = asn_DEF_GeneralNames.elements;
	td->elements_count = asn_DEF_GeneralNames.elements_count;
	td->specifics      = asn_DEF_GeneralNames.specifics;
}

void
SubjectAltName_free(asn_TYPE_descriptor_t *td,
		void *struct_ptr, int contents_only) {
	SubjectAltName_1_inherit_TYPE_descriptor(td);
	td->free_struct(td, struct_ptr, contents_only);
}

int
SubjectAltName_print(asn_TYPE_descriptor_t *td, const void *struct_ptr,
		int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
	SubjectAltName_1_inherit_TYPE_descriptor(td);
	return td->print_struct(td, struct_ptr, ilevel, cb, app_key);
}

asn_dec_rval_t
SubjectAltName_decode_ber(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const void *bufptr, size_t size, int tag_mode) {
	SubjectAltName_1_inherit_TYPE_descriptor(td);
	return td->ber_decoder(opt_codec_ctx, td, structure, bufptr, size, tag_mode);
}

asn_enc_rval_t
SubjectAltName_encode_der(asn_TYPE_descriptor_t *td,
		void *structure, int tag_mode, ber_tlv_tag_t tag,
		asn_app_consume_bytes_f *cb, void *app_key) {
	SubjectAltName_1_inherit_TYPE_descriptor(td);
	return td->der_encoder(td, structure, tag_mode, tag, cb, app_key);
}

asn_dec_rval_t
SubjectAltName_decode_xer(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const char *opt_mname, const void *bufptr, size_t size) {
	SubjectAltName_1_inherit_TYPE_descriptor(td);
	return td->xer_decoder(opt_codec_ctx, td, structure, opt_mname, bufptr, size);
}

asn_enc_rval_t
SubjectAltName_encode_xer(asn_TYPE_descriptor_t *td, void *structure,
		int ilevel, enum xer_encoder_flags_e flags,
		asn_app_consume_bytes_f *cb, void *app_key) {
	SubjectAltName_1_inherit_TYPE_descriptor(td);
	return td->xer_encoder(td, structure, ilevel, flags, cb, app_key);
}

static const ber_tlv_tag_t asn_DEF_SubjectAltName_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_TYPE_descriptor_t asn_DEF_SubjectAltName = {
	"SubjectAltName",
	"SubjectAltName",
	SubjectAltName_free,
	SubjectAltName_print,
	SubjectAltName_constraint,
	SubjectAltName_decode_ber,
	SubjectAltName_encode_der,
	SubjectAltName_decode_xer,
	SubjectAltName_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_SubjectAltName_tags_1,
	sizeof(asn_DEF_SubjectAltName_tags_1)
		/sizeof(asn_DEF_SubjectAltName_tags_1[0]), /* 1 */
	asn_DEF_SubjectAltName_tags_1,	/* Same as above */
	sizeof(asn_DEF_SubjectAltName_tags_1)
		/sizeof(asn_DEF_SubjectAltName_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	0, 0,	/* Defined elsewhere */
	0	/* No specifics */
};

