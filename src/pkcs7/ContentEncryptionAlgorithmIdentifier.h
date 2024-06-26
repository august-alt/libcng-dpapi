/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#ifndef	_ContentEncryptionAlgorithmIdentifier_H_
#define	_ContentEncryptionAlgorithmIdentifier_H_


#include <asn_application.h>

/* Including external dependencies */
#include "AlgorithmIdentifier.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ContentEncryptionAlgorithmIdentifier */
typedef AlgorithmIdentifier_t	 ContentEncryptionAlgorithmIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ContentEncryptionAlgorithmIdentifier;
asn_struct_free_f ContentEncryptionAlgorithmIdentifier_free;
asn_struct_print_f ContentEncryptionAlgorithmIdentifier_print;
asn_constr_check_f ContentEncryptionAlgorithmIdentifier_constraint;
ber_type_decoder_f ContentEncryptionAlgorithmIdentifier_decode_ber;
der_type_encoder_f ContentEncryptionAlgorithmIdentifier_encode_der;
xer_type_decoder_f ContentEncryptionAlgorithmIdentifier_decode_xer;
xer_type_encoder_f ContentEncryptionAlgorithmIdentifier_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _ContentEncryptionAlgorithmIdentifier_H_ */
#include <asn_internal.h>
