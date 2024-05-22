/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#ifndef	_EncryptedContent_H_
#define	_EncryptedContent_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* EncryptedContent */
typedef OCTET_STRING_t	 EncryptedContent_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_EncryptedContent;
asn_struct_free_f EncryptedContent_free;
asn_struct_print_f EncryptedContent_print;
asn_constr_check_f EncryptedContent_constraint;
ber_type_decoder_f EncryptedContent_decode_ber;
der_type_encoder_f EncryptedContent_encode_der;
xer_type_decoder_f EncryptedContent_decode_xer;
xer_type_encoder_f EncryptedContent_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _EncryptedContent_H_ */
#include <asn_internal.h>
