// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#include <sys/stat.h> // needed for stat struct for file info
#include <sys/types.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>// for exit
#include "secvarctl.h"
#include "backends/powernv/include/edk2-svc.h"// import last!!

void edk2_write_usage()
{
	printf("USAGE:\n\t' $ secvarctl write [OPTIONS] <variable> <authFile>'"
		"\n\tOPTIONS:\n"
		"\t\t--help/--usage\n"
		"\t\t-v\t\tverbose, print process info"
		"\n\t\t-f\t\tforce update, skips validation of file\n\t\t"
		"-p <path>\tlooks for .../<var>/update file in <path>,\n"
		"\t\t\t\tshould contain expected var subdirectories {'PK','KEK','db','dbx'},\n"
		"\t\t\t\tdefault is " SECVARPATH "\n"
		"\tVariable:\n\t\tone of the following {PK, KEK, db, dbx}\n\n");
}

void edk2_write_help()
{
	printf("HELP:\n\tThis function updates a given secure variable with a new key contained in an auth file\n"
		"It is recommended that 'secvarctl verify' is tried on the update file before submitting.\n"
		"\tThis will ensure that the submission will be successful upon reboot.\n");
	edk2_write_usage();
}


/**
 *ensures updating variable is a valid variable, creates full path to ...../update file, verifies auth file is valid
 *@param varName string to varName {PK,KEK,db,dbx}
 *@param authfile string of auth file name
 *@param path string of path to directory containing <varName>/update file
 *@param force 1 for no validation of auth, 0 for validate
 *@return error if variable given is unkown, or issue validating or writing
 */
int edk2_updateSecVar(const char *varName, const char *authFile, const char *path, int force)
{	
	int rc;
	unsigned char *buff = NULL;
	size_t size;

	if (isVariable(varName)) {
		prlog(PR_ERR, "ERROR: Unrecognized variable name %s\n", varName);
		edk2_write_usage();
		return INVALID_VAR_NAME;
	}
	if (strcmp(varName, "TS") == 0) {
		prlog(PR_ERR, "ERROR: Cannot update TimeStamp (TS) variable\n");
		edk2_write_usage();
		return INVALID_VAR_NAME;
	}
		
	if (!path) {
		path = SECVARPATH;
	} 

	// get data to write, if force flag then validate the data is an auth file
	buff = (unsigned char *)getDataFromFile(authFile, &size); 
	// if we are validating and validating fails, quit
	if (!force) { 
		rc = validateAuth(buff, size, varName);
		if (rc) {
			prlog(PR_ERR, "ERROR: validating update file (Signed Auth) failed, not updating\n");
			free(buff);
			return rc;
		}
	}
	rc = updateVar(path, varName, buff, size);

	if (rc) 
		prlog(PR_ERR, "ERROR: issue writing to file: %s\n", strerror(errno));
	free(buff);

	return rc;
}

/*
 *updates a secure variable by writing data in buf to the <path>/<var>/update
 *@param path, path to sec vars
 *@param var, one of  {db,dbx, KEK, Pk}
 *@param buff , auth file data
 *@param size , size of buff
 *@return whatever returned by writeData, SUCCESS or errno
 */
int updateVar(const char *path, const char *var, const unsigned char *buff, size_t size)
{	
	int commandLength, rc; 
	char *fullPathWithCommand = NULL;

	commandLength = strlen(path) + strlen(var) + strlen("/update ");
	fullPathWithCommand = malloc(commandLength);
	if (!fullPathWithCommand) { 
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return ALLOC_FAIL;
	}

	strcpy(fullPathWithCommand, path);
	strcat(fullPathWithCommand, var);
	strcat(fullPathWithCommand, "/update");

	rc = writeData(fullPathWithCommand, (const char *)buff, size);
	free(fullPathWithCommand);

	return rc;

}


