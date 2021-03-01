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

static int readFiles(const char* var, const char* file, int hrFlag, const  char* path);
static void usage();
static void help();
static int readFileFromSecVar(const char * path, const char *variable, int hrFlag);
static int readFileFromPath(const char *path, int hrFlag);

struct Arguments {
	int helpFlag, printRaw;
	const char *pathToSecVars, *varName, *inFile;
}; 
static int parseArgs(int argc, char *argv[], struct Arguments *args);

static struct translation_table {
	char *from;
	char *to;
} variable_renames[] = {
	{ .from = "PK", .to = "PK-8be4df61-93ca-11d2-aa0d-00e098032b8c" },
	{ .from = "db", .to = "db-d719b2cb-3d3a-4596-a3bc-dad00e67656f" },
	{ .from = "dbx", .to = "dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f" },
	{ .from = "KEK", .to = "KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c" },
};

/*
 *called from main()
 *handles argument parsing for read command
 *@param argc, number of argument
 *@param arv, array of params
 *@return SUCCESS or err number 
 */
int efivarfsReadCommand(int argc, char* argv[]) 
{
	int rc;
	struct Arguments args = {	
		.helpFlag = 0, .printRaw = 0, 
		.pathToSecVars = NULL, .inFile = NULL, .varName = NULL
	};

	rc = parseArgs(argc, argv, &args);
	if (rc || args.helpFlag)
		return rc;

	rc = readFiles(args.varName, args.inFile, !args.printRaw, args.pathToSecVars);

	return rc;	
}

/**
 *@param argv , array of command line arguments
 *@param argc, length of argv
 *@param args, struct that will be filled with data from argv
 *@return success or errno
 */
static int parseArgs( int argc, char *argv[], struct Arguments *args) {
	int rc = SUCCESS;
	for (int i = 0; i < argc; i++) {
		if (argv[i][0] != '-') {
			args->varName = argv[i];
			rc = isVariable(args->varName);
			if (rc) {
				prlog(PR_ERR, "ERROR: Invalid variable name %s\n", args->varName);
				goto out;
			}
			continue;
		}
		if (!strcmp(argv[i], "--usage")) {
			usage();
			args->helpFlag = 1;
			goto out;
		}
		else if (!strcmp(argv[i], "--help")) {
			help();
			args->helpFlag = 1;
			goto out;
		}
		switch (argv[i][1]) {
			case 'v':
				verbose = PR_DEBUG;
				break;
			//set path
			case 'p':
				if (i + 1 >= argc || argv[i + 1][0] == '-') {
					prlog(PR_ERR, "ERROR: Incorrect value for '-p', see usage...\n");
					rc = ARG_PARSE_FAIL;
					goto out;
				}
				else {
					i++;
					args->pathToSecVars= argv[i];
				}
				break;
			//set file path
			case 'f':
				if (i + 1 >= argc || argv[i + 1][0] == '-') {
					prlog(PR_ERR, "ERROR: Incorrect value for file flag, use '-f <file>', see usage...\n");
					rc = ARG_PARSE_FAIL;
					goto out;
				}
				else {
					i++;
					args->inFile = argv[i];
				}	
				break;
			case 'r':
				args->printRaw = 1;
				break;
			default:
				prlog(PR_ERR, "ERROR: Unknown argument: %s\n", argv[i]);
				rc = ARG_PARSE_FAIL;
				goto out;
		}
		
	}
		
out:
	if (rc) {
		prlog(PR_ERR, "Failed during argument parsing\n");
		usage();
	}

	return rc;
}


/**
 *Function that recieves arguments to read command and handles getting data, finding paths, iterating through variables to read
 *@param var  string to variable wanted if <variable> option is given, NULL if not
 *@param file string to filename with path if -f option, NULL if not
 *@param hrFLag 1 if -hr for human readable output, 0 for raw data
 *@param path string to path where {PK,KEK,db,dbx,TS} subdirectories are, default SECVARPATH if none given
 *@return succcess if at least one file was successfully read
 */
static int readFiles(const char* var, const char* file, int hrFlag, const char *path) 
{  
	// program is successful if at least one var was able to be read
	int rc, successCount = 0;

	if (file) prlog(PR_NOTICE, "Looking in file %s for ESL's\n", file); 
	else prlog(PR_NOTICE, "Looking in %s for %s variable with %s format\n", path ? path : SECVARPATH, var ? var : "ALL", hrFlag ? "ASCII" : "raw_data");
	
	// set default path if no path chosen
	if (!path) { 
		path = SECVARPATH;
	}

	if (!file) {
		for (int i = 0; i < ARRAY_SIZE(variables); i++) {
			// if var is defined and it is not the current one then skip
			if (var && strcmp(var, variables[i]) != 0) {	
				continue;
			}
			printf("READING %s :\n", variables[i]);
			rc = readFileFromSecVar(path, variables[i], hrFlag);
			if (rc == SUCCESS) successCount++;
		}
	}
	else {
		rc = readFileFromPath(file, hrFlag);
		if (rc == SUCCESS) successCount++;
	} 
	// if no good files read then count it as a failure
	if (successCount < 1) {
		prlog(PR_ERR, "No valid files to print, returning failure\n");
		return INVALID_FILE;
	}

	return SUCCESS;
}

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

struct command efivarfs_command_table[1] = {
	{ .name = "read", .func = efivarfsReadCommand },
	//{ .name = "verify", .func = efivarfsVerificationCommand },
};
