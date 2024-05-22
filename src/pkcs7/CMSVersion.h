/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#ifndef	_CMSVersion_H_
#define	_CMSVersion_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CMSVersion {
	CMSVersion_v0	= 0,
	CMSVersion_v1	= 1,
	CMSVersion_v2	= 2,
	CMSVersion_v3	= 3,
	CMSVersion_v4	= 4,
	CMSVersion_v5	= 5
} e_CMSVersion;

/* CMSVersion */
typedef long	 CMSVersion_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CMSVersion;
asn_struct_free_f CMSVersion_free;
asn_struct_print_f CMSVersion_print;
asn_constr_check_f CMSVersion_constraint;
ber_type_decoder_f CMSVersion_decode_ber;
der_type_encoder_f CMSVersion_encode_der;
xer_type_decoder_f CMSVersion_decode_xer;
xer_type_encoder_f CMSVersion_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _CMSVersion_H_ */
#include <asn_internal.h>
