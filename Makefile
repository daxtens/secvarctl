# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 IBM Corp.
#_*_MakeFile_*_
CC = gcc 
_CFLAGS = -s -O2 -std=gnu99 -I./ -Iinclude/ -Wall -Werror -g
LFLAGS = -lmbedtls -lmbedx509 -lmbedcrypto

_DEPEN = secvarctl.h prlog.h err.h generic.h 
DEPDIR = include
DEPEN = $(patsubst %,$(DEPDIR)/%, $(_DEPEN))

_EDK2_DEPEN = edk2-svc.h 
EDK2DEPDIR = backends/powernv/include
EDK2_DEPEN = $(patsubst %,$(EDK2DEPDIR)/%, $(_EDK2_DEPEN))
DEPEN += $(EDK2_DEPEN)

EDK2OBJDIR = backends/powernv
_EDK2_OBJ =  edk2-svc-read.o edk2-svc-write.o edk2-svc-verify.o
EDK2_OBJ = $(patsubst %,$(EDK2OBJDIR)/%, $(_EDK2_OBJ))

_EVFS_DEPEN = efivarfs.h 
EVFSDEPDIR = backends/efivarfs/include
EVFS_DEPEN = $(patsubst %,$(EVFSDEPDIR)/%, $(_EVFS_DEPEN))
DEPEN += $(EVFS_DEPEN)

EVFSOBJDIR = backends/efivarfs
_EVFS_OBJ =  efivarfs-read.o
EVFS_OBJ = $(patsubst %,$(EVFSOBJDIR)/%, $(_EVFS_OBJ))

_SECVAR_DEPEN = edk2-svc.h 
SECVARDEPDIR = backends/powernv/include
SECVAR_DEPEN = $(patsubst %,$(SECVARDEPDIR)/%, $(_SECVAR_DEPEN))
DEPEN += $(SECVAR_DEPEN)

SECVAROBJDIR = secvar
_SECVAR_OBJ =  edk2-svc-validate.o edk2-svc-generate.o util.o
SECVAR_OBJ = $(patsubst %,$(SECVAROBJDIR)/%, $(_SECVAR_OBJ))

_SKIBOOT_DEPEN =list.h config.h container_of.h check_type.h secvar.h opal-api.h endian.h short_types.h edk2.h edk2-compat-process.h
SKIBOOTDEPDIR = external/skiboot/include
SKIBOOT_DEPEN = $(patsubst %,$(SKIBOOTDEPDIR)/%, $(_SKIBOOT_DEPEN))
DEPEN += $(SKIBOOT_DEPEN)

_EXTRAMBEDTLS_DEPEN = pkcs7.h generate-pkcs7.h 
EXTRAMBEDTLSDEPDIR = external/extraMbedtls/include
EXTRAMBEDTLSDEPEN = $(patsubst %,$(EXTRAMBEDTLSDEPDIR)/%, $(_EXTRAMBEDTLS_DEPEN))
DEPEN += $(EXTRAMBEDTLSDEPEN)

SKIBOOTOBJDIR = external/skiboot/
_SKIBOOT_OBJ = secvar_util.o edk2-compat.o edk2-compat-process.o
SKIBOOT_OBJ = $(patsubst %,$(SKIBOOTOBJDIR)/%, $(_SKIBOOT_OBJ))

EXTRAMBEDTLSDIR = external/extraMbedtls
_EXTRAMBEDTLS = generate-pkcs7.o pkcs7.o 
EXTRAMBEDTLS = $(patsubst %,$(EXTRAMBEDTLSDIR)/%, $(_EXTRAMBEDTLS))

OBJ =secvarctl.o  generic.o commands.o backends/backends.o
OBJ +=$(SKIBOOT_OBJ) $(EXTRAMBEDTLS) $(EDK2_OBJ) $(EVFS_OBJ) $(SECVAR_OBJ)

OBJCOV = $(patsubst %.o, %.cov.o,$(OBJ))

MANDIR=usr/local/share/man
#use STATIC=1 for static build
STATIC = 0
ifeq ($(STATIC),1)
	STATICFLAG=-static
	LFLAGS +=-lpthread
else 
	STATICFLAG=
endif

#use NO_CRYPTO for smaller executable but limited functionality
NO_CRYPTO = 0 
ifeq ($(NO_CRYPTO),1)
	_CFLAGS+=-DNO_CRYPTO
endif


secvarctl: $(OBJ) 
	$(CC) $(CFLAGS) $(_CFLAGS) $(STATICFLAG) $^  -o $@ $(LFLAGS)



%.o: %.c $(DEPEN)
	$(CC) $(CFLAGS) $(_CFLAGS) -c  $< -o $@

clean:
	rm -f $(OBJ) secvarctl 
	rm -f ./*/*.cov.* secvarctl-cov ./*.cov.* ./backends/*/*.cov.* ./external/*/*.cov.* ./html*


%.cov.o: %.c $(DEPEN)
	$(CC) $(CFLAGS) $(_CFLAGS) -c  --coverage $< -o $@



secvarctl-cov: $(OBJCOV) 
	$(CC) $(CFLAGS) $(_CFLAGS) $^  $(STATICFLAG) -fprofile-arcs -ftest-coverage -o $@ $(LFLAGS)

install: secvarctl
	mkdir -p $(DESTDIR)/usr/bin
	install -m 0755 secvarctl $(DESTDIR)/usr/bin/secvarctl
	mkdir -p $(DESTDIR)/$(MANDIR)/man1
	install -m 0644 secvarctl.1 $(DESTDIR)/$(MANDIR)/man1
