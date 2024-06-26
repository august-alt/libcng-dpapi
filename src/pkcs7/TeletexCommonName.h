/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#ifndef	_TeletexCommonName_H_
#define	_TeletexCommonName_H_


#include <asn_application.h>

/* Including external dependencies */
#include <TeletexString.h>

#ifdef __cplusplus
extern "C" {
#endif

/* TeletexCommonName */
typedef TeletexString_t	 TeletexCommonName_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TeletexCommonName;
asn_struct_free_f TeletexCommonName_free;
asn_struct_print_f TeletexCommonName_print;
asn_constr_check_f TeletexCommonName_constraint;
ber_type_decoder_f TeletexCommonName_decode_ber;
der_type_encoder_f TeletexCommonName_encode_der;
xer_type_decoder_f TeletexCommonName_decode_xer;
xer_type_encoder_f TeletexCommonName_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _TeletexCommonName_H_ */
#include <asn_internal.h>
