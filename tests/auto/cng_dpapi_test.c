#include "cng-dpapi/cng-dpapi_client.h"
#include <errno.h>
#include <iconv.h>
#include <openldap.h>
#include <sasl/sasl.h>
#include <stdbool.h>
#include <talloc.h>
#include <wchar.h>

#define SERVER_FQDN "dc01.domain2.alt"
#define DOMAIN_NAME "DOMAIN2.ALT"
#define USER_NAME "administrator"
#define LDAP_SEARCH_BASE "OU=LAPSManaged,DC=domain2,DC=alt"
#define LDAP_SEARCH_FILTER "(objectClass=computer)"

char* LDAP_DIRECTORY_ATTRS[] = { "msLAPS-EncryptedPassword", NULL };

typedef struct ldap_sasl_defaults_t
{
    char *realm;
    char *authcid;
    char *authzid;

    char *passwd;
} ldap_sasl_defaults_t;

int sasl_interact_gssapi(LDAP *ld, unsigned flags, void *indefaults, void *in)
{
    (void)(flags);

    sasl_interact_t *interact = (sasl_interact_t *) in;

    if (ld == NULL)
    {
        return LDAP_PARAM_ERROR;
    }

    while (interact->id != SASL_CB_LIST_END)
    {
        const char *dflt = interact->defresult;

        if (dflt && !*dflt)
        {
            dflt = NULL;
        }

        /* input must be empty */
        interact->result = (dflt && *dflt) ? dflt : "";
        interact->len = strlen((const char *) interact->result);
        interact++;
    }

    return LDAP_SUCCESS;
}

bool
get_attribute_value(TALLOC_CTX *mem_ctx,
                    char *server,
                    char *domain,
                    char *username,
                    uint8_t **attribute_value,
                    uint32_t *attribute_size)
{
    (void)(domain);
    (void)(username);

    if (!attribute_value || !attribute_size)
    {
        return false;
    }

    uint32_t result = 0;
    LDAP *ld = NULL;

    char *ldap_server = talloc_asprintf(mem_ctx, "ldap://%s:389", server);
    if (!ldap_server)
    {
        printf("Unable to allocate ldap_server");
        return false;
    }

    result = ldap_initialize(&ld, ldap_server);
    if (result != LDAP_SUCCESS)
    {
        ldap_memfree(ld);
        printf("Failed to initialize LDAP library %s.\n", strerror(errno));
        return false;
    }

    const int version = LDAP_VERSION3;
    result = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (result != LDAP_OPT_SUCCESS)
    {
        printf("Unable to set ldap option: LDAP_OPT_PROTOCOL_VERSION\n");
        return false;
    }

    result = ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    if (result != LDAP_OPT_SUCCESS)
    {
        printf("Unable to set ldap option: LDAP_OPT_REFERRALS\n");
        return false;
    }

    const char *sasl_secprops = "maxssf=56";
    result = ldap_set_option(ld, LDAP_OPT_X_SASL_SECPROPS, sasl_secprops);
    if (result != LDAP_SUCCESS)
    {
        printf("Unable to set ldap option: LDAP_OPT_X_SASL_SECPROPS\n");
        return false;
    }

    result = ldap_set_option(ld, LDAP_OPT_X_SASL_NOCANON, LDAP_OPT_ON);
    if (result != LDAP_SUCCESS)
    {
        printf("Unable to set ldap option: LDAP_OPT_X_SASL_NOCANON\n");
        return false;
    }

    result = ldap_sasl_interactive_bind_s(ld, NULL, "GSSAPI", NULL, NULL, LDAP_SASL_QUIET,
                                          sasl_interact_gssapi, NULL);
    if (result != LDAP_SUCCESS)
    {
        int error_code = 0;
        char *diagnostic_message = NULL;

        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, (void*)&error_code);
        ldap_get_option(ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, (void*)&diagnostic_message);

        printf("Unable to bind to server! %s %s.\n", ldap_err2string(result), diagnostic_message);
        return false;
    }

    LDAPMessage *messages = NULL;

    result = ldap_search_ext_s(ld, LDAP_SEARCH_BASE, LDAP_SCOPE_SUB, LDAP_SEARCH_FILTER,
                               LDAP_DIRECTORY_ATTRS, false, NULL, NULL, 0, LDAP_NO_LIMIT, &messages);
    if (result != LDAP_SUCCESS)
    {
        printf("Unable to find test data server! %s.\n", ldap_err2string(result));
        return false;
    }

    BerElement *ber_element = NULL;
    char *attribute   = NULL;

    struct berval **values  = NULL;
    int values_count = 0;

    LDAPMessage *message = messages;

    while (message)
    {
        attribute = ldap_first_attribute(ld, message, &ber_element);
        while (attribute != NULL)
        {
            printf("Current attribute: %s\n", attribute);

            values = ldap_get_values_len(ld, message, attribute);
            values_count = ldap_count_values_len(values);

            if (values_count != 1)
            {
                printf("Attributes value count:  %d, expected value 1!\n", values_count);
                return false;
            }

            *attribute_value = talloc_memdup(mem_ctx, values[0]->bv_val + 16, values[0]->bv_len - 16);
            *attribute_size = values[0]->bv_len - 16;

            ldap_value_free_len(values);

            ldap_memfree(attribute);
            attribute = ldap_next_attribute(ld, message, ber_element);
        };
        ber_free(ber_element, 0);

        message = ldap_next_message(ld, message);
    }

    return true;
}

int main(int argc, char ** argv)
{
    (void)argc;
    (void)argv;

    TALLOC_CTX *mem_ctx = talloc_named(NULL, 0, "create_rpc_client");
    uint32_t attribute_size = 0;
    uint8_t *attribute_value = NULL;
    uint8_t *unprotected_secret = NULL;
    uint32_t unprotected_secret_size = 0;
    uint32_t status = 0;

    if (!get_attribute_value(mem_ctx,
                             SERVER_FQDN,
                             DOMAIN_NAME,
                             USER_NAME,
                             &attribute_value,
                             &attribute_size))
    {
        goto error_exit;
    }

    status = ncrypt_unprotect_secret(attribute_value,
                                     attribute_size,
                                     &unprotected_secret,
                                     &unprotected_secret_size,
                                     SERVER_FQDN,
                                     DOMAIN_NAME,
                                     USER_NAME);

    if (!unprotected_secret)
    {
        goto error_exit;
    }

error_exit:
    TALLOC_FREE(mem_ctx);

    return EXIT_FAILURE;
}
