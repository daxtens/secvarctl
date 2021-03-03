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
#include "secvar/include/edk2-svc.h"
#include "backends/include/backends.h"
#include "err.h"
#include "prlog.h"
#include "secvarctl.h"

static int readFiles(const char* var, const char* file, int hrFlag, const  char* path);

struct readArguments {
	int helpFlag, printRaw;
	const char *pathToSecVars, *varName, *inFile;
}; 
static int parseReadArgs(int argc, char *argv[], struct readArguments *args);

/*
 *called from main()
 *handles argument parsing for read command
 *@param argc, number of argument
 *@param arv, array of params
 *@return SUCCESS or err number 
 */
int readCommand(int argc, char* argv[])
{
	int rc;
	struct readArguments args = {	
		.helpFlag = 0, .printRaw = 0, 
		.pathToSecVars = NULL, .inFile = NULL, .varName = NULL
	};

	rc = parseReadArgs(argc, argv, &args);
	if (rc || args.helpFlag)
		return rc;

	rc = readFiles(args.varName, args.inFile, !args.printRaw, args.pathToSecVars);

	return rc;	
}

/**
 *@param argv , array of command line readArguments
 *@param argc, length of argv
 *@param args, struct that will be filled with data from argv
 *@return success or errno
 */
static int parseReadArgs( int argc, char *argv[], struct readArguments *args) {
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
			secvarctl_backend->read_usage();
			args->helpFlag = 1;
			goto out;
		}
		else if (!strcmp(argv[i], "--help")) {
			secvarctl_backend->read_help();
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
		secvarctl_backend->read_usage();
	}

	return rc;
}


/**
 *Function that recieves readArguments to read command and handles getting data, finding paths, iterating through variables to read
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
	else prlog(PR_NOTICE, "Looking in %s for %s variable with %s format\n", path ? path : secvarctl_backend->default_secvar_path, var ? var : "ALL", hrFlag ? "ASCII" : "raw_data");
	
	// set default path if no path chosen
	if (!path) { 
		path = secvarctl_backend->default_secvar_path;
	}

	if (!file) {
		for (int i = 0; i < secvarctl_backend->sb_var_count; i++) {
			// if var is defined and it is not the current one then skip
			if (var && strcmp(var, secvarctl_backend->sb_variables[i]) != 0) {	
				continue;
			}
			printf("READING %s :\n", secvarctl_backend->sb_variables[i]);
			rc = secvarctl_backend->readFileFromSecVar(path, secvarctl_backend->sb_variables[i], hrFlag);
			if (rc == SUCCESS) successCount++;
		}
	}
	else {
		rc = secvarctl_backend->readFileFromPath(file, hrFlag);
		if (rc == SUCCESS) successCount++;
	} 
	// if no good files read then count it as a failure
	if (successCount < 1) {
		prlog(PR_ERR, "No valid files to print, returning failure\n");
		return INVALID_FILE;
	}

	return SUCCESS;
}

struct writeArguments {
	int helpFlag, inpValid;
	const char *pathToSecVars, *varName, *inFile;
}; 
static int parseWriteArgs(int argc, char *argv[], struct writeArguments *args);

/*
 *called from main()
 *handles argument parsing for write command
 *@param argc, number of argument
 *@param arv, array of params
 *@return SUCCESS or err number
*/
int performWriteCommand(int argc, char* argv[])
{
	int rc;
	struct writeArguments args = {	
		.helpFlag = 0, .inpValid = 0, 
		.pathToSecVars = NULL, .inFile = NULL, .varName = NULL
	};

	rc = parseWriteArgs(argc, argv, &args);
	if (rc || args.helpFlag)
		goto out;

	if (!args.inFile || !args.varName ) {
		secvarctl_backend->write_usage();
		rc = ARG_PARSE_FAIL;
		goto out;
	}

	rc = secvarctl_backend->updateSecVar(args.varName, args.inFile, args.pathToSecVars, args.inpValid);	
out:
	if (rc) 
		printf("RESULT: FAILURE\n");
	else 
		printf("RESULT: SUCCESS\n");

	return rc;	
}

/**
 *@param argv , array of command line writeArguments
 *@param argc, length of argv
 *@param args, struct that will be filled with data from argv
 *@return success or errno
 */
static int parseWriteArgs( int argc, char *argv[], struct writeArguments *args) 
{
	int rc = SUCCESS;
	for (int i = 0; i < argc; i++) {
		if (argv[i][0] == '-') {
			if (!strcmp(argv[i], "--usage")) {
				secvarctl_backend->write_usage();
				args->helpFlag = 1;
				goto out;
			}
			else if (!strcmp(argv[i], "--help")) {
				secvarctl_backend->write_help();
				args->helpFlag = 1;
				goto out;
			}
			// set verbose flag
			else if (!strcmp(argv[i], "-v")) {
				verbose = PR_DEBUG; 
			}
			// set path
			else if (!strcmp(argv[i], "-p")) {
				if (i + 1 >= argc || argv[i + 1][0] == '-') {
					prlog(PR_ERR, "ERROR: Incorrect value for '-p', see usage...\n");
					rc = ARG_PARSE_FAIL;
					goto out;
				}
				else {
					i++;
					args->pathToSecVars= argv[i];
				}
			}
			// set force flag
			else if (!strcmp(argv[i], "-f"))
				args->inpValid = 1;	
		}
		else {
			if (i + 1 >= argc || argv[i + 1][0] == '-') {		
				prlog(PR_ERR, "ERROR: Incorrect '<var> <authFile>', see usage\n");
				rc = ARG_PARSE_FAIL;
				goto out;
			}
			args-> varName = argv[i++];			
			args-> inFile = argv[i];
		}
	}
		
out:
	if (rc) {
		prlog(PR_ERR, "Failed during argument parsing\n");
		secvarctl_backend->write_usage();
	}

	return rc;
}

struct verifyArguments {
	int helpFlag, writeFlag, currVarCount, updateVarCount;
	const char *pathToSecVars, **updateVars;
	char **currentVars;
}; 

static int parseVerifyArgs(int argc, char *argv[], struct verifyArguments *args);

/**
*performs verification command, called from main
*@param argc number of items in arg command
*@param argv arguments array
*@return SUCCESS if everything works, error code if not
*/
int performVerificationCommand(int argc, char* argv[])
{
	int rc;
	struct verifyArguments args = {	
		.helpFlag = 0, .writeFlag = 0, .currVarCount = 0, .updateVarCount = 0,
		.pathToSecVars = NULL, .updateVars = NULL, .currentVars = 0
	};

	rc = parseVerifyArgs(argc, argv, &args);
	if (rc || args.helpFlag) {
		goto out;
	}
	if (args.currVarCount && args.writeFlag) {
		prlog(PR_ERR, "ERROR: Cannot update files if current variable files are given. remove -w\n");
		secvarctl_backend->verify_usage();
		rc = ARG_PARSE_FAIL;
		goto out;
	}

	rc = secvarctl_backend->verify(args.currentVars, args.currVarCount, args.updateVars, args.updateVarCount, args.pathToSecVars, args.writeFlag);
	
out:
	if (rc) 
		printf("RESULT: FAILURE\n");
	else 
		printf("RESULT: SUCCESS\n");
	if (args.currentVars) 
		free(args.currentVars);
	if (args.updateVars) 
		free(args.updateVars);
	
	return rc;
}

/**
 *@param argv , array of command line verifyArguments
 *@param argc, length of argv
 *@param args, struct that will be filled with data from argv
 *@return success or errno
 */
static int parseVerifyArgs( int argc, char *argv[], struct verifyArguments *args) {
	int rc = SUCCESS;
	for (int i = 0; i < argc; i++) {
		if (argv[i][0] == '-') {
			if (!strcmp(argv[i], "--usage")) {
				secvarctl_backend->verify_usage();
				args->helpFlag = 1;
				goto out;
			}
			else if (!strcmp(argv[i], "--help")) {
				secvarctl_backend->verify_help();
				args->helpFlag = 1;
				goto out;
			}
			// set verbose flag
			else if (!strcmp(argv[i], "-v")) {
				verbose = PR_DEBUG; 
			}
			
			// set current vars
			else if(!strcmp(argv[i], "-c")) {	
				if (args->currentVars) {
					prlog(PR_ERR, "ERROR: Current variables defined twice, see usage...\n");
					rc = ARG_PARSE_FAIL;
					goto out;
				}
				i++;
				// until next option is approached, add argument to array
				while (i < argc && argv[i][0] != '-') { 
					args->currVarCount++;
					i++;
				}
				if (args->currVarCount > 0) {
					args->currentVars = malloc(sizeof(char*) * args->currVarCount);
					if (!args->currentVars) {
						prlog(PR_ERR, "ERROR: failed to allocate memory\n");
						rc = ALLOC_FAIL;
						goto out;
					}
					memcpy(args->currentVars, &argv[i - args->currVarCount], args->currVarCount * sizeof(char*));
				}
				// to iterate back to the -" " arg
				i--;	
				//make sure format was correct
				if (validateVarsArg((const char **) args->currentVars, args->currVarCount)) {
					prlog(PR_ERR,"ERROR: Current vars list not in right format: "
						"<varName_1> <eslFileForVar_1> <varName_2> <eslFileForVar_2> ...\n\t\t"
						"Where <varName> is one of {'PK','KEK','db','dbx', 'TS'} and <eslFileForVar> is an EFI Signature List file (unless TS variable)\n");
					rc = ARG_PARSE_FAIL;
					goto out;
				}

			}
			// set updateVars array
			else if (!strcmp(argv[i], "-u")) {	
				if (args->updateVars) {
					prlog(PR_ERR, "ERROR: Update variables defined twice, see usage...\n");
					rc = ARG_PARSE_FAIL;
					goto out;
				}
				i++;
				while(i < argc && argv[i][0] != '-'){
					args->updateVarCount++;
					i++;
				}
				if (args->updateVarCount > 0) {
					args->updateVars = malloc(sizeof(char*) * args->updateVarCount);
					if (!args->updateVars) {
						prlog(PR_ERR, "ERROR: failed to allocate memory\n");
						rc = ALLOC_FAIL;
						goto out;
					}
					memcpy(args->updateVars, &argv[i - args->updateVarCount], args->updateVarCount * sizeof(char*));
				}
				i--;
				//make sure format was correct
				if (validateVarsArg(args->updateVars, args->updateVarCount)) {
					prlog(PR_ERR,"ERROR: Update vars list not in right format: "
					"<varName_1> <authFileForVar_1> <varName_2> <authFileForVar_2> ...\n\t\t"
					"Where <varName> is one of {'PK','KEK','db','dbx'} and <authFileForVar> is an authenticated file)\n");
					rc = ARG_PARSE_FAIL;
					goto out;
				}
			}
			else if (!strcmp(argv[i], "-p")) {
				if (i + 1 >= argc || argv[i + 1][0] == '-') {
					prlog(PR_ERR, "ERROR: Incorrect value for '-p', see usage...\n");
					rc = ARG_PARSE_FAIL;
					goto out;
				}
				else {
					i++;
					args->pathToSecVars= argv[i];
				}
			}
			else if (!strcmp(argv[i], "-w"))
				args->writeFlag = 1;
		}
	}
		
out:
	if (rc) {
		prlog(PR_ERR, "Failed during argument parsing\n");
		secvarctl_backend->verify_usage();
	}

	return rc;
}
/**
 *ensures the strings are in right format: <key> <file> <key> <file>
 *@param vars , array of strings from argument -c/-u
 *@param size, size of vars array
 *@return SUCCESS or error code if ordering or format is wrong
 */
int validateVarsArg(const char *vars[], int size)
{
	if (size % 2) {
		prlog(PR_ERR,"ERROR: when parsing variable list, expected every variable name to have exactly one corresponding file\n");
		return ARG_PARSE_FAIL;
	}
	for (int i = 0; i < size; i++) {
		// if odd number expect file name, not a var name
		if (i % 2) { 
			if (!isVariable(vars[i])) {
				prlog(PR_ERR, "ERROR: when parsing variable list argument, found variable name %s, when file name was expected\n", vars[i]);
				return ARG_PARSE_FAIL;		
			}
		}
		// if even number, expect variable name
		else {
			if (isVariable(vars[i])) {
				prlog(PR_ERR, "ERROR: when parsing variable list argument, found unrecognized variable name %s, when variable name was expected\n", vars[i]);
				return ARG_PARSE_FAIL;
			}
		}
	}

	return SUCCESS;
}
