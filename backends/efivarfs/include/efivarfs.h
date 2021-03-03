// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#ifndef BACKENDS_UEFI_H
#define BACKENDS_UEFI_H
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


int getEVFSSecVar(struct secvar **var, const char* name, const char *fullPath);

#endif
