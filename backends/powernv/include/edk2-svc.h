// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#ifndef EDK2_SVC_SKIBOOT_H
#define EDK2_SVC_SKIBOOT_H
#include "secvar/include/edk2-svc.h"

#define CERT_BUFFER_SIZE        2048

#ifndef SECVARPATH
#define SECVARPATH "/sys/firmware/secvar/vars/"
#endif

int performReadCommand(int argc, char *argv[]);
int performVerificationCommand(int argc, char *argv[]); 

int getSecVar(struct secvar **var, const char* name, const char *fullPath);
int updateVar(const char* path, const char* var, const unsigned char* buff, size_t size);

void edk2_read_usage();
void edk2_read_help();
int edk2_readFileFromSecVar(const char * path, const char *variable, int hrFlag);
int edk2_readFileFromPath(const char *path, int hrFlag);


extern struct command edk2_compat_command_table[1];
#endif
