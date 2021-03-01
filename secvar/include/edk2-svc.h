// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#ifndef EDK2_SVC_SECVAR_H
#define EDK2_SVC_SECVAR_H
#include <stdint.h> //for uint_16 stuff like that
#include <mbedtls/x509_crt.h> // for printCertInfo
#include "external/skiboot/include/secvar.h" //for secvar struct
#include "err.h"
#include "prlog.h"
#include "generic.h"
#include "external/extraMbedtls/include/generate-pkcs7.h"
#include "external/skiboot/include/edk2.h" //include last or else problems from pragma pack(1)

#define variables  (char* []){ "PK", "KEK", "db", "dbx", "TS" }
#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))
#define uuid_equals(a,b) (!memcmp(a, b, UUID_SIZE))

// array holding different hash function information
static const struct hash_funct {
    char name[8];
    size_t size;
    int mbedtls_funct;
    uuid_t const* guid;
} hash_functions[] = {
    { .name = "SHA1", .size = 20 , .mbedtls_funct = MBEDTLS_MD_SHA1, .guid = &EFI_CERT_SHA1_GUID },
    { .name = "SHA224", .size = 28 , .mbedtls_funct = MBEDTLS_MD_SHA224, .guid = &EFI_CERT_SHA224_GUID },
    { .name = "SHA256", .size = 32, .mbedtls_funct = MBEDTLS_MD_SHA256, .guid = &EFI_CERT_SHA256_GUID },
    { .name = "SHA384", .size = 48, .mbedtls_funct = MBEDTLS_MD_SHA384, .guid = &EFI_CERT_SHA384_GUID },
    { .name = "SHA512", .size = 64, .mbedtls_funct = MBEDTLS_MD_SHA512, .guid = &EFI_CERT_SHA512_GUID },
};

int performValidation(int argc, char* argv[]); 
int performGenerateCommand(int argc, char* argv[]);

int printReadable(const char *c , size_t size, const char * key);


int printCertInfo(mbedtls_x509_crt *x509);
void printESLInfo(EFI_SIGNATURE_LIST *sigList);
void printTimestamp(struct efi_time t);
void printGuidSig(const void *sig);

EFI_SIGNATURE_LIST* get_esl_signature_list(const char *buf, size_t buflen);
ssize_t get_esl_cert( const char *c,EFI_SIGNATURE_LIST *list ,char **cert);
size_t get_pkcs7_len(const struct efi_variable_authentication_2 *auth);
int parseX509(mbedtls_x509_crt *x509, const unsigned char *certBuf, size_t buflen);
const char* getSigType(const uuid_t);

int isVariable(const char *var);

int validateAuth(const unsigned char *authBuf, size_t buflen, const char *key);
int validateESL(const unsigned char *eslBuf, size_t buflen, const char *key);
int validateCert(const unsigned char *authBuf, size_t buflen, const char *varName);
int validatePKCS7(const unsigned char *cert_data, size_t len);
int validateTS(const unsigned char *data, size_t size);
int validateTime(struct efi_time *time);


#endif
