// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#ifndef BACKENDS_UEFI_H
#define BACKENDS_UEFI_H
#include "secvar/include/edk2-svc.h"

#define CERT_BUFFER_SIZE        2048

#ifndef SECVARPATH
#define SECVARPATH "/sys/firmware/efi/efivars/"
#endif

int getEVFSSecVar(struct secvar **var, const char* name, const char *fullPath);

#endif
