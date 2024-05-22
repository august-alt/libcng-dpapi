/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "CryptographicMessageSyntax2004"
 * 	found in "pkcs7.asn1"
 */

#ifndef	_PhysicalDeliveryPersonalName_H_
#define	_PhysicalDeliveryPersonalName_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PDSParameter.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PhysicalDeliveryPersonalName */
typedef PDSParameter_t	 PhysicalDeliveryPersonalName_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PhysicalDeliveryPersonalName;
asn_struct_free_f PhysicalDeliveryPersonalName_free;
asn_struct_print_f PhysicalDeliveryPersonalName_print;
asn_constr_check_f PhysicalDeliveryPersonalName_constraint;
ber_type_decoder_f PhysicalDeliveryPersonalName_decode_ber;
der_type_encoder_f PhysicalDeliveryPersonalName_encode_der;
xer_type_decoder_f PhysicalDeliveryPersonalName_decode_xer;
xer_type_encoder_f PhysicalDeliveryPersonalName_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _PhysicalDeliveryPersonalName_H_ */
#include <asn_internal.h>