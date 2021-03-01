// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#include <sys/stat.h> // needed for stat struct for file info
#include <sys/types.h>
#include <fcntl.h> // O_RDONLY
#include <unistd.h> // has read/open funcitons
#include <mbedtls/x509_crt.h> // for reading certdata
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "external/skiboot/include/secvar.h" // for secvar struct
#include "backends/efivarfs/include/efivarfs.h"
#include "backends/include/backends.h"

static void usage();
static void help();
static int readFileFromSecVar(const char * path, const char *variable, int hrFlag);
static int readFileFromPath(const char *path, int hrFlag);

static struct translation_table {
	char *from;
	char *to;
} variable_renames[] = {
	{ .from = "PK", .to = "PK-8be4df61-93ca-11d2-aa0d-00e098032b8c" },
	{ .from = "db", .to = "db-d719b2cb-3d3a-4596-a3bc-dad00e67656f" },
	{ .from = "dbx", .to = "dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f" },
	{ .from = "KEK", .to = "KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c" },
};

/**
 *Does the appropriate read command depending on hrFlag on the file <path>/<var>/data
 *@param path , the path to the file with ending '/'
 *@param variable , variable name one of {db,dbx,KEK,PK}
 *@param hrFlag, 1 for human readable 0 for raw data
 *@return SUCCESS or error number
 */
static int readFileFromSecVar(const char *path, const char *variable, int hrFlag)
{
	int rc, i;
	struct secvar *var = NULL;
	char *fullPath = NULL;
	char *rename = NULL;

	for (i = 0; i < ARRAY_SIZE(variable_renames); i++) {
		if (strcmp(variable, variable_renames[i].from) == 0) {
			rename = variable_renames[i].to;
			break;
		}
	}
	if (!rename) {
		prlog(PR_ERR, "don't know the GUID for %s, giving up\n", variable);
		return INVALID_VAR_NAME;
	}

	fullPath = malloc(strlen(path) + strlen(rename));
	if (!fullPath) { 
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return ALLOC_FAIL;
	}

	strcpy(fullPath, path);
	strcat(fullPath, rename);

	rc = getEVFSSecVar(&var, variable, fullPath);
	
	free(fullPath);

	if (rc) {
		goto out;
	}
	if (hrFlag) {
		if (var->data_size == 0) {
			printf("%s is empty\n", var->key);
			rc = SUCCESS;
		}
		else
			rc = printReadable(var->data, var->data_size, var->key);

		if (rc)
			prlog(PR_WARNING, "ERROR: Could not parse file, continuing...\n");
	}
	else {
		printRaw(var->data, var->data_size);
		rc = SUCCESS;
	}
	
out:
	dealloc_secvar(var);
	
	return rc;
}

/**
 *Does the appropriate read command depending on hrFlag on the file 
 *@param file , the path to the file 
 *@param hrFlag, 1 for human readable 0 for raw data
 *@return SUCCESS or error number
 */
static int readFileFromPath(const char *file, int hrFlag)
{
	int rc;
	size_t size = 0;
	char *c = NULL;
	c = getDataFromFile(file, &size);
	if (!c) {
		return INVALID_FILE;
	}
	// efivarfs
	c += 4;
	size -= 4;
	if (hrFlag) {
		rc = printReadable(c, size, NULL);
		if(rc)
			prlog(PR_WARNING,"ERROR: Could not parse file\n");
		else
			rc = SUCCESS; 		
	}
	else {
		printRaw(c, size);
		rc = SUCCESS;
	}
	c -= 4;
	free(c);

	return rc;
}

/**
 *gets the secvar struct from a file
 *@param var , returned secvar
 *@param name , secure variable name {db,dbx,KEK,PK}
 *@param fullPath, file and path <path>/<varname>
 *NOTE: THIS IS ALLOCATING DATA AND var STILL NEEDS TO BE DEALLOCATED
 */
int getEVFSSecVar(struct secvar **var, const char* name, const char *fullPath){
	int rc, fptr;
	size_t size;
	ssize_t read_size;
	char *c = NULL;
	struct stat fileInfo;
	rc = isFile(fullPath);
	if (rc) {
		printf("dja: %s not a file?\n", fullPath);
		return rc;
	}

	fptr = open(fullPath, O_RDONLY);			
	if (fptr < 0) {
		prlog(PR_WARNING, "----opening %s failed : %s----\n", fullPath, strerror(errno));
		return INVALID_FILE;
	}
	if (fstat(fptr, &fileInfo) < 0) {
		return INVALID_FILE;
	}

	// we use efivarfs here, so no /data, /size
	size = fileInfo.st_size;
	prlog(PR_NOTICE,"---opening %s is success: reading %zd bytes---- \n", fullPath, size);
	c = malloc(size);
	if (!c) {
		prlog(PR_ERR, "ERROR: failed to allocate memory\n");
		return ALLOC_FAIL;	
	}

	read_size = read(fptr, c, size);
	if (read_size != size) {
		prlog(PR_ERR, "ERROR: did not read all variable data in one read\n");
		return INVALID_FILE;
	}
	close(fptr);

	// efivarfs uses the first 4 bytes to encode the attributes
	// skip it.
	*var = new_secvar(name, strlen(name) + 1, c + 4, size - 4, 0);
	if (*var == NULL) {
		prlog(PR_ERR, "ERROR: Could not convert data to secvar\n");
		free(c);
		return INVALID_FILE;
	}
	free(c);

	return SUCCESS;
}

static void help() 
{
	printf("HELP:\n\t"
		"This program command is created to easily view secure variables. The current variables\n" 
		"\tthat are able to be observed are the PK, KEK, db, db, dbx. If no options are\n" 
		"\tgiven, then the information for the keys in the default path will be printed."
		"\n\tIf the user would like to print the information for another ESL file,\n"
		"\tthen the '-f' command would be appropriate.\n");
	usage();
}

static void usage() 
{
	printf("USAGE:\n\t' $ secvarctl read [OPTIONS] [VARIABLES] '\nOPTIONS:"
		"\n\t--usage/--help"
		"\n\t-r\t\t\tprints raw data, default is human readable information"
		"\n\t-f <filename>\t\tnavigates to ESL file from working directiory"
		"\n\t-p <path to vars>\tlooks for key directories {'PK','KEK','db','dbx'} in <path>,\n"
		"\t\t\t\tdefault is " SECVARPATH "\n"
		"VARIABLES:\n\t{'PK','KEK','db','dbx'}\ttype one of the following to get info on that key,\n"
		"\t\t\t\t\tNOTE does not work when -f option is present\n\n");
}

static const char * evfs_variables[] = { "PK", "KEK", "db", "dbx" };

const struct secvarctl_backend efivarfs_backend = {
	.name = "efivarfs",
	.default_secvar_path = SECVARPATH,
	.sb_variables = evfs_variables,
	.sb_var_count = 4,
	.read_help = help,
	.read_usage = usage,
	.readFileFromPath = readFileFromPath,
	.readFileFromSecVar = readFileFromSecVar,
};
