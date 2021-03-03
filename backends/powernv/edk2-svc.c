#include "backends/include/backends.h"
#include "include/edk2-svc.h"

static const char * edk2_variables[] = {"PK", "KEK", "db", "dbx", "TS"};

const struct secvarctl_backend edk2_backend = {
	.name = "ibm,edk2-compat-v1",
	.default_secvar_path = SECVARPATH,
	.sb_variables = edk2_variables,
	.sb_var_count = 5,
	.read_help = edk2_read_help,
	.read_usage = edk2_read_usage,
	.readFileFromPath = edk2_readFileFromPath,
	.readFileFromSecVar = edk2_readFileFromSecVar,
	.write_help = edk2_write_help,
	.write_usage = edk2_write_usage,
	.updateSecVar = edk2_updateSecVar,
	.verify_help = edk2_verify_help,
	.verify_usage = edk2_write_usage,
	.verify = edk2_verify,
};