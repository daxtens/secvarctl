// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "prlog.h"
#include "secvarctl.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "backends/include/backends.h"

int verbose = PR_WARNING;
static void getBackend();

static struct command generic_commands[] = {
#ifndef NO_CRYPTO
	{ .name = "generate", .func = performGenerateCommand },
#endif
	{ .name = "validate", .func = performValidation },
	{ .name = "read", .func = readCommand },
	{ .name = "write", .func = performWriteCommand },
	{ .name = "verify", .func = performVerificationCommand },
};

void usage() 
{
	printf("USAGE: \n\t$ secvarctl [COMMAND]\n"
		"COMMANDs:\n"
		"\t--help/--usage\n\t"
		"read\t\tprints info on secure variables,\n\t\t\t"
		"use 'secvarctl read --usage/help' for more information\n\t"
		"write\t\tupdates secure variable with new auth,\n\t\t\t"
		"use 'secvarctl write --usage/help' for more information"
		"\n\tvalidate\tvalidates format of given esl/cert/auth,\n\t\t\t"
		"use 'secvarctl validate --usage/help' for more information\n\t"
		"verify\t\tcompares proposed variable to the current variables,\n\t\t\t"
		"use 'secvarctl verify --usage/help' for more information\n"
#ifndef NO_CRYPTO
		"\tgenerate\tcreates relevant files for secure variable management,\n\t\t\t"
		"use 'secvarctl generate --usage/help' for more information\n"
#endif
		);
}
void help()
{
	printf("HELP:\n\t"
	   "A command line tool for simplifying the reading and writing of secure boot variables.\n\t"
       "Commands are:\n\t\t"
       "read - print out information on their current secure vaiables\n\t\t"
       "write - update the given variable's key value, committed upon reboot\n\t\t"
       "validate  -  checks format requirements are met for the given file type\n\t\t"
       "verify - checks that the given files are correctly signed by the current variables\n"
#ifndef NO_CRYPTO
       "\t\tgenerate - create files that are relevant to the secure variable management process\n"
#endif
       );
	usage();

}

 
int main(int argc, char *argv[])
{
	int rc, i;
	char *subcommand = NULL;
	
	if (argc < 2) {
		usage();
		return ARG_PARSE_FAIL;
	}
	argv++;
	argc--;
	for (; argc > 0 && *argv[0] == '-'; argc--, argv++) {
		if (!strcmp(*argv, "--usage")) {
			usage();
			return SUCCESS;
		}
		else if (!strcmp(*argv, "--help")) {
			help();
			return SUCCESS;
		}
		if (!strcmp(*argv, "-v")) {
			verbose = PR_DEBUG;
		}
	}
	if (argc <= 0) {
		prlog(PR_ERR,"ERROR: No command found\n");
		return ARG_PARSE_FAIL;
	} 

	// next command should be one of main subcommands
	subcommand = *argv; 
	argv++;
	argc--;

	// if backend is not edk2-compat print continuing despite some funtionality not working 
	getBackend();
	if (!secvarctl_backend) { 
		prlog(PR_WARNING, "WARNING: Unsupported backend detected, assuming ibm,edk2-compat-v1 backend\nRead/write may not work as expected\n");
		secvarctl_backend = &edk2_backend;
	}


	// first try the generic commands, then try a backend
	rc = UNKNOWN_COMMAND;
	for (i = 0; i < ARRAY_SIZE(generic_commands); i++) {
		if (!strncmp(subcommand, generic_commands[i].name, 32)) {
			rc = generic_commands[i].func(argc, argv);
			goto out;
		}
	}

out:
	if (rc == UNKNOWN_COMMAND) {
		prlog(PR_ERR, "ERROR:Unknown command %s\n", subcommand);
		usage();
	}
	
	return rc;
}

static void getPowerNVBackend()
{
	char *buff = NULL, *secVarFormatLocation = "/sys/firmware/secvar/format";
	size_t buffSize;
	// if file doesnt exist then print warning and keep going
	if (isFile(secVarFormatLocation)) {
		prlog(PR_WARNING, "WARNING!! Platform does not support PowerNV secure variables\n");
		goto out;
	}
	buff = getDataFromFile(secVarFormatLocation, &buffSize);
	if (!buff) {
		prlog(PR_WARNING, "WARNING!! Could not extract data from %s , assuming platform does not support secure variables\n", secVarFormatLocation);
		goto out;
	}

	if (!strncmp(buff, edk2_backend.name, strlen(edk2_backend.name))) {
		prlog(PR_NOTICE, "Found Backend %s\n", edk2_backend.name);
		secvarctl_backend = &edk2_backend;
		goto out;
	}
	prlog(PR_WARNING, "WARNING!! %s  does not contain known backend format.\n", secVarFormatLocation);

out:
	if (buff) 
		free(buff);
}

/*
 *Checks what backend the platform is running, CURRENTLY ONLY KNOWS EDK2
 *@return type of backend, or NULL if file could not be found or contained wrong contents,
 */
static void getBackend()
{
	struct stat statbuf;
	int rc;

	// a hack, efivarfs can be anywhere.
	// test for dir, not PK, as PK could be absent.
	rc = stat("/sys/firmware/efi/efivars/", &statbuf);

	if (rc == 0 && (statbuf.st_mode & S_IFMT) == S_IFDIR) {
		secvarctl_backend = &efivarfs_backend;
	} else {
		getPowerNVBackend();
	}
}
