// SPDX-License-Identifier: Apache-2.0
/* Copyright 2021 IBM Corp.*/
#ifndef SECVARCTL_H
#define SECVARCTL_H
#include <stdint.h> //for uint_16 stuff like that
#include "err.h"
#include "prlog.h"
#include "backends/powernv/include/edk2-svc.h"
#include "backends/efivarfs/include/efivarfs.h"
#include "secvar/include/edk2-svc.h"


enum backends {
	UNKNOWN_BACKEND = 0,
	EDK2_COMPAT
};

extern int verbose;

int readCommand(int argc, char* argv[]);
int performWriteCommand(int argc, char* argv[]);
int performVerificationCommand(int argc, char* argv[]);

int validateVarsArg(const char *vars[], int size);

#endif
