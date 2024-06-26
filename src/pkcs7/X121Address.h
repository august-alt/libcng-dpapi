/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#ifndef	_X121Address_H_
#define	_X121Address_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NumericString.h>

#ifdef __cplusplus
extern "C" {
#endif

/* X121Address */
typedef NumericString_t	 X121Address_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_X121Address;
asn_struct_free_f X121Address_free;
asn_struct_print_f X121Address_print;
asn_constr_check_f X121Address_constraint;
ber_type_decoder_f X121Address_decode_ber;
der_type_encoder_f X121Address_encode_der;
xer_type_decoder_f X121Address_decode_xer;
xer_type_encoder_f X121Address_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _X121Address_H_ */
#include <asn_internal.h>
