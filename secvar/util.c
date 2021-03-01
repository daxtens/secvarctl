#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "secvar/include/edk2-svc.h"

#define CERT_BUFFER_SIZE 2048

/*
 *prints human readable data in of ESL buffer
 *@param c , buffer containing ESL data
 *@param size , length of buffer
 *@param key, variable name {"db","dbx","KEK", "PK"} b/c dbx is a different format
 *@return SUCCESS or error number if failure
 */
int printReadable(const char *c, size_t size, const char *key) 
{
	ssize_t eslvarsize = size, cert_size;
	size_t  eslsize = 0;
	int count = 0, offset = 0, rc;
	unsigned char *cert = NULL;
	EFI_SIGNATURE_LIST *sigList;
	mbedtls_x509_crt *x509 = NULL;

	while (eslvarsize > 0) {
		if (eslvarsize < sizeof(EFI_SIGNATURE_LIST)) { 
			prlog(PR_ERR, "ERROR: ESL has %zd bytes and is smaller than an ESL (%zd bytes), remaining data not parsed\n", eslvarsize, sizeof(EFI_SIGNATURE_LIST));
			break;
		}
		// Get sig list
		sigList = get_esl_signature_list(c + offset, eslvarsize);
		// check size info is logical 
		if (sigList->SignatureListSize > 0) {
			if ((sigList->SignatureSize <= 0 && sigList->SignatureHeaderSize <= 0) 
				|| sigList->SignatureListSize < sigList->SignatureHeaderSize + sigList->SignatureSize) {
				/*printf("Sig List : %d , sig Header: %d, sig Size: %d\n",list.SignatureListSize,list.SignatureHeaderSize,list.SignatureSize);*/
				prlog(PR_ERR,"ERROR: Sig List is not structured correctly, defined size and actual sizes are mismatched\n");
				break;
			}	
		}
		if (sigList->SignatureListSize  > eslvarsize || sigList->SignatureHeaderSize > eslvarsize || sigList->SignatureSize > eslvarsize) {
			prlog(PR_ERR, "ERROR: Expected Sig List Size %d + Header size %d + Signature Size is %d larger than actual size %zd\n", sigList->SignatureListSize, sigList->SignatureHeaderSize, sigList->SignatureSize, eslvarsize);
			break;
		}
		eslsize = sigList->SignatureListSize;
		printESLInfo(sigList);
		// puts sig data in cert
		cert_size = get_esl_cert(c + offset, sigList, (char **)&cert); 
		if (cert_size <= 0) {
			prlog(PR_ERR, "\tERROR: Signature Size was too small, no data \n");
			break;
		}
		if (key && !strcmp(key, "dbx")) {
			printf("\tHash: ");
			printHex(cert, cert_size);
		}
		else {
			x509 = malloc(sizeof(*x509));
			if (!x509) {
				prlog(PR_ERR, "ERROR: failed to allocate memory\n");
				return ALLOC_FAIL;
			}
			rc = parseX509(x509, cert, (size_t) cert_size);
			if (rc)
				break;
			rc = printCertInfo(x509);
			if (rc)
				break;
			free(cert);
			cert = NULL;
			mbedtls_x509_crt_free(x509);
			free(x509);
			x509 = NULL;
		}
		
		count++;	
		 // we read all eslsize bytes so iterate to next esl	
		offset += eslsize;
		// size left of total file
		eslvarsize -= eslsize;	
	}
	printf("\tFound %d ESL's\n\n", count);
	if (x509) {
		mbedtls_x509_crt_free(x509);
		free(x509);
	}
	if (cert) 
		free(cert);

	if (!count)
		return ESL_FAIL;

	return SUCCESS;
}

//prints info on ESL, nothing on ESL data
void printESLInfo(EFI_SIGNATURE_LIST *sigList) 
{
	printf("\tESL SIG LIST SIZE: %d\n", sigList->SignatureListSize);
	printf("\tGUID is : ");
	printGuidSig(&sigList->SignatureType);
	printf("\tSignature type is: %s\n", getSigType(sigList->SignatureType));
}

//prints info on x509
int printCertInfo(mbedtls_x509_crt *x509)
{
	char *x509_info;
	int failures;

	x509_info = malloc(CERT_BUFFER_SIZE);
	if (!x509_info){
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return CERT_FAIL;
	}
	// failures = number of bytes written, x509_info now has string of ascii data
	failures = mbedtls_x509_crt_info(x509_info, CERT_BUFFER_SIZE, "\t\t", x509); 
	if (failures <= 0) {
		prlog(PR_ERR, "\tERROR: Failed to get cert info, wrote %d bytes when getting info\n", failures);
		return CERT_FAIL;
	}
	printf("\tFOUND %d bytes of certificate info:\n %s", failures, x509_info);
	free(x509_info);

	return SUCCESS;
 }

/** 
 *inspired by secvar/backend/edk2-compat-process.c by Nayna Jain
 *@param c  pointer to start of esl file
 *@param cert empty buffer 
 *@param list current siglist
 *@return size of memory allocated to cert or negative number if allocation fails
 */
ssize_t get_esl_cert(const char *c, EFI_SIGNATURE_LIST *list , char **cert) 
{
	ssize_t size, dataOffset;
	size = list->SignatureSize - sizeof(uuid_t);
	dataOffset = sizeof(EFI_SIGNATURE_LIST) + list->SignatureHeaderSize + 16 * sizeof(uint8_t);
	*cert = malloc(size);
	if (!*cert){
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return ALLOC_FAIL;
	}
	// copies size bytes from eslfile-headerstuff and guid into cert
	memcpy(*cert, c + dataOffset, size); 

	return size;
}

/**
 *finds format type given by guid
 *@param type uuid_t of guid of file
 *@return string of format type, "UNKNOWN" if type doesnt match any known formats
 */
const char* getSigType(const uuid_t type) 
{
	//loop through all known hashes
	for (int i = 0; i < sizeof(hash_functions) / sizeof(struct hash_funct); i++) {
		if (uuid_equals(&type, hash_functions[i].guid)) 
			return hash_functions[i].name;	
	}
	//try other known guids
	if (uuid_equals(&type, &EFI_CERT_X509_GUID)) return "X509";
	else if (uuid_equals(&type, &EFI_CERT_RSA2048_GUID)) return "RSA2048";
	else if (uuid_equals(&type, &EFI_CERT_TYPE_PKCS7_GUID))return "PKCS7";
	
	return "UNKNOWN";
}

/**
 *prints guid id
 *@param sig pointer to uuid_t
 */
void printGuidSig(const void *sig) 
{
	const unsigned char *p = sig;
	for (int i = 0; i < 16; i++)
		printf("%02hhx", p[i]);
	printf("\n");
}

/**
 *parses buffer into a EFI_SIG_LIST
 *@param buf pointer to sig list buffer
 *@param buflen length of buffer
 *@return NULL if buflen is smaller than size of sig list stuct or if buff is empty
 *@return EFI_SIG_LIST struct
 */ 
EFI_SIGNATURE_LIST* get_esl_signature_list(const char *buf, size_t buflen)
{
	EFI_SIGNATURE_LIST *list = NULL;
	if (buflen < sizeof(EFI_SIGNATURE_LIST) || !buf) {
		prlog(PR_ERR,"ERROR: SigList does not have enough data to be valid\n");
		return NULL;
	}
	list = (EFI_SIGNATURE_LIST *)buf;

	return list;
}

/**
 *checks to see if string is a valid variable name {db,dbx,pk,kek, TS}
 *@param var variable name
 *@return SUCCESS or error code
 */
int isVariable(const char * var)
{
	for (int i = 0; i < ARRAY_SIZE(variables); i++) {
		if (strcmp(var,variables[i]) == 0)
			return SUCCESS;
	}

	return INVALID_VAR_NAME;
}
