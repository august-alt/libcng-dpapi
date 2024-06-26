/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#ifndef	_AttCertVersion_H_
#define	_AttCertVersion_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AttCertVersion {
	AttCertVersion_v2	= 1
} e_AttCertVersion;

/* AttCertVersion */
typedef long	 AttCertVersion_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_AttCertVersion;
asn_struct_free_f AttCertVersion_free;
asn_struct_print_f AttCertVersion_print;
asn_constr_check_f AttCertVersion_constraint;
ber_type_decoder_f AttCertVersion_decode_ber;
der_type_encoder_f AttCertVersion_encode_der;
xer_type_decoder_f AttCertVersion_decode_xer;
xer_type_encoder_f AttCertVersion_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _AttCertVersion_H_ */
#include <asn_internal.h>
