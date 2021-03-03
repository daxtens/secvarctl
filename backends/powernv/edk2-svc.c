#include "backends/include/backends.h"
#include "include/edk2-svc.h"

struct command edk2_compat_command_table[] = {
	{ .name = "verify", .func = performVerificationCommand },
};

static const char * edk2_variables[] = {"PK", "KEK", "db", "dbx", "TS"};

const struct secvarctl_backend edk2_backend = {
	.name = "edk2-compat",
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

};