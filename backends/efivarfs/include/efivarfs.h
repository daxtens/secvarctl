// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#ifndef BACKENDS_EFIVARFS_H
#define BACKENDS_EFIVARFS_H
#include "secvar/include/edk2-svc.h"

#define CERT_BUFFER_SIZE        2048

#ifndef SECVARPATH
#define SECVARPATH "/sys/firmware/efi/efivars/"
#endif

#define EVFS_SECVAR_ATTRIBUTES (EFI_VARIABLE_APPEND_WRITE | \
				EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS | \
				EFI_VARIABLE_RUNTIME_ACCESS | \
				EFI_VARIABLE_BOOTSERVICE_ACCESS | \
				EFI_VARIABLE_NON_VOLATILE)

struct translation_table {
	char *from;
	char *to;
};

extern struct translation_table variable_renames[4];

int getEVFSSecVar(struct secvar **var, const char* name, const char *fullPath);
void evfs_read_usage();
void evfs_read_help();
int evfs_readFileFromSecVar(const char * path, const char *variable, int hrFlag);
int evfs_readFileFromPath(const char *path, int hrFlag);
void evfs_write_usage();
void evfs_write_help();
int evfs_updateSecVar(const char *var, const char *authFile, const char *path, int force);
int evfs_updateVar(const char *path, const char *var, const unsigned char *buff, size_t size);


#endif
