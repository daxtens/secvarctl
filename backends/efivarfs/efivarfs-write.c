// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#include <sys/stat.h> // needed for stat struct for file info
#include <sys/types.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>// for exit
#include <unistd.h>
#include <fcntl.h>
#include "prlog.h"
#include "backends/efivarfs/include/efivarfs.h"
#include "backends/include/backends.h"
#include "external/skiboot/include/endian.h"

void evfs_write_usage()
{
	printf("USAGE:\n\t' $ secvarctl write [OPTIONS] <variable> <authFile>'"
		"\n\tOPTIONS:\n"
		"\t\t--help/--usage\n"
		"\t\t-v\t\tverbose, print process info"
		"\n\t\t-f\t\tforce update, skips validation of file\n\t\t"
		"-p <path>\tlooks for .../<var>-<UUID> file in <path>,\n"
		"\t\t\t\tdefault is " SECVARPATH "\n"
		"\tVariable:\n\t\tone of the following {PK, KEK, db, dbx}\n\n");
}

void evfs_write_help()
{
	printf("HELP:\n\tThis function updates a given secure variable with a new key contained in an auth file\n"
		"It is recommended that 'secvarctl verify' is tried on the update file before submitting.\n"
		"\tThis will ensure that the submission will be successful upon reboot.\n");
	evfs_write_usage();
}

/**
 *ensures updating variable is a valid variable, creates full path to ...../update file, verifies auth file is valid
 *@param varName string to varName {PK,KEK,db,dbx}
 *@param authfile string of auth file name
 *@param path string of path to directory containing <varName>/update file
 *@param force 1 for no validation of auth, 0 for validate
 *@return error if variable given is unkown, or issue validating or writing
 */
int evfs_updateSecVar(const char *varName, const char *authFile, const char *path, int force)
{	
	int rc;
	unsigned char *buff = NULL;
	size_t size;

	// todo factor this out to be backend specific.
	if (isVariable(varName)) {
		prlog(PR_ERR, "ERROR: Unrecognized variable name %s\n", varName);
		evfs_write_usage();
		return INVALID_VAR_NAME;
	}
		
	if (!path) {
		path = SECVARPATH;
	} 

	// get data to write, if force flag then validate the data is an auth file
	buff = (unsigned char *)getDataFromFile(authFile, &size); 
	// if we are validating and validating fails, quit
	if (!force) { 
		rc = SUCCESS; //not yet defined for efivarfs FIXME: validateAuth(buff, size, varName);
		if (rc) {
			prlog(PR_ERR, "ERROR: validating update file (Signed Auth) failed, not updating\n");
			free(buff);
			return rc;
		}
	}
	rc = evfs_updateVar(path, varName, buff, size);

	if (rc) 
		prlog(PR_ERR, "ERROR: issue writing to file: %s\n", strerror(errno));
	free(buff);

	return rc;
}

/*
 *updates a secure variable by writing data in buf to the <path>/<var>
 *@param path, path to sec vars
 *@param var, one of  {db,dbx, KEK, Pk}
 *@param buff , auth file data
 *@param size , size of buff
 *@return whatever returned by writeData, SUCCESS or errno
 */
int evfs_updateVar(const char *path, const char *var, const unsigned char *buff, size_t size)
{	
	int commandLength, rc, i;
	char *fullPathWithCommand = NULL;
	unsigned char *newbuff;
	char *rename = NULL;
	int fptr;

	for (i = 0; i < ARRAY_SIZE(variable_renames); i++) {
		if (strcmp(var, variable_renames[i].from) == 0) {
			rename = variable_renames[i].to;
			break;
		}
	}
	if (!rename) {
		prlog(PR_ERR, "don't know the GUID for %s, giving up\n", var);
		return INVALID_VAR_NAME;
	}

	commandLength = strlen(path) + strlen(rename) + 1;
	fullPathWithCommand = malloc(commandLength);
	if (!fullPathWithCommand) { 
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return ALLOC_FAIL;
	}

	strcpy(fullPathWithCommand, path);
	strcat(fullPathWithCommand, rename);

	// adjust for efivarfs
	newbuff = malloc(size + 4);
	if (!newbuff) {
		rc = ALLOC_FAIL;
		prlog(PR_ERR, "couldn't allocate space for buffer");
		goto out;
	}

	memcpy(newbuff + 4, buff, size);
	((le32 *)newbuff)[0] = cpu_to_le32(EVFS_SECVAR_ATTRIBUTES);
	size += 4;

	// can't use writeData, we need O_CREAT
	fptr = open(fullPathWithCommand, O_WRONLY|O_CREAT, 0644);
	if (fptr == -1) {
		prlog(PR_ERR, "ERROR: Opening %s failed: %s\n", fullPathWithCommand, strerror(errno));
		rc = INVALID_FILE;
		goto out_newbuf;
	}
	rc = write(fptr, newbuff, size);
	if (rc < 0) {
		prlog(PR_ERR,"ERROR: Writing data to %s failed\n", fullPathWithCommand);
		rc =  FILE_WRITE_FAIL;
	}
	else if (rc != size) {
		prlog(PR_WARNING,"End of file reached, not all of file was written to %s\n", fullPathWithCommand);	
	}
	else prlog(PR_NOTICE,"%d/%zd bytes successfully written from file to %s\n", rc, size, fullPathWithCommand);
	rc = SUCCESS;
	close(fptr);
out_newbuf:
	free(newbuff);
out:
	free(fullPathWithCommand);

	return rc;
}


