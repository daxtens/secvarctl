// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "prlog.h"
#include "secvarctl.h"

int verbose = PR_WARNING;
static const struct backend *getBackend();

static const struct backend powernv_backends [] = {
	{ .name = "ibm,edk2-compat-v1", .countCmds = ARRAY_SIZE(edk2_compat_command_table), .commands = edk2_compat_command_table },
};

static const struct backend efivarfs_backend = {
	.name = "efivarfs",
	.countCmds = ARRAY_SIZE(efivarfs_command_table),
	.commands = efivarfs_command_table
};

static struct command generic_commands[] = {
#ifndef NO_CRYPTO
	{ .name = "generate", .func = performGenerateCommand },
#endif
	{ .name = "validate", .func = performValidation },
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
	const struct backend *backend = NULL;
	
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

	// first try the generic commands, then try a backend
	rc = UNKNOWN_COMMAND;
	for (i = 0; i < ARRAY_SIZE(generic_commands); i++) {
		if (!strncmp(subcommand, generic_commands[i].name, 32)) {
			rc = generic_commands[i].func(argc, argv);
			break;
		}
	}

	// if backend is not edk2-compat print continuing despite some funtionality not working 
	backend = getBackend();
	if (!backend) { 
		prlog(PR_WARNING, "WARNING: Unsupported backend detected, assuming ibm,edk2-compat-v1 backend\nRead/write may not work as expected\n");
		backend = &powernv_backends[0];
	}

	for (i = 0; i < backend->countCmds; i++) {
		if (!strncmp(subcommand, backend->commands[i].name, 32)) {
			rc = backend->commands[i].func(argc, argv);
			break;
		}
	}
	if (rc == UNKNOWN_COMMAND) {
		prlog(PR_ERR, "ERROR:Unknown command %s\n", subcommand);
		usage();
	}
	
	return rc;
}

static const struct backend *getPowerNVBackend()
{
	char *buff = NULL, *secVarFormatLocation = "/sys/firmware/secvar/format";
	size_t buffSize;
	const struct backend *result = NULL;
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
	//loop through all known backends
	for (int i = 0; i < ARRAY_SIZE(powernv_backends); i++) {
		if (!strncmp(buff, powernv_backends[i].name, strlen(powernv_backends[i].name))) {
			prlog(PR_NOTICE, "Found Backend %s\n", powernv_backends[i].name);
			result = &powernv_backends[i];
			goto out;
		}
	}
	prlog(PR_WARNING, "WARNING!! %s  does not contain known backend format.\n", secVarFormatLocation);

out:
	if (buff) 
		free(buff);

	return result;

}

/*
 *Checks what backend the platform is running, CURRENTLY ONLY KNOWS EDK2
 *@return type of backend, or NULL if file could not be found or contained wrong contents,
 */
static const struct backend *getBackend()
{
	// hack, I was too lazy to do better
	if (isFile("/sys/firmware/efi/efivars/PK-8be4df61-93ca-11d2-aa0d-00e098032b8c") == SUCCESS)
		return &efivarfs_backend;

	return getPowerNVBackend();
}
