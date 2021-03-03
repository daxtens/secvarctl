// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#ifndef EDK2_SVC_SKIBOOT_H
#define EDK2_SVC_SKIBOOT_H
#include "secvar/include/edk2-svc.h"

#define CERT_BUFFER_SIZE        2048

#ifndef SECVARPATH
#define SECVARPATH "/sys/firmware/secvar/vars/"
#endif

int getSecVar(struct secvar **var, const char* name, const char *fullPath);
int updateVar(const char *path, const char *var, const unsigned char *buff, size_t size);

void edk2_read_usage();
void edk2_read_help();
int edk2_readFileFromSecVar(const char * path, const char *variable, int hrFlag);
int edk2_readFileFromPath(const char *path, int hrFlag);
void edk2_write_usage();
void edk2_write_help();
int edk2_updateSecVar(const char *var, const char *authFile, const char *path, int force);
void edk2_verify_usage();
void edk2_verify_help();
int edk2_verify(char **currentVars, int currCount, const char **updateVars, int updateCount, const char *path, int writeFlag);

#endif
