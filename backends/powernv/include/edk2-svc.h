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
int performWriteCommand(int argc, char *argv[]);

int getSecVar(struct secvar **var, const char* name, const char *fullPath);
int updateVar(const char* path, const char* var, const unsigned char* buff, size_t size);

extern struct command edk2_compat_command_table[3];
#endif
