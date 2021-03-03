#include "backends/efivarfs/include/efivarfs.h"
#include "backends/include/backends.h"

struct translation_table variable_renames[] = {
	{ .from = "PK", .to = "PK-8be4df61-93ca-11d2-aa0d-00e098032b8c" },
	{ .from = "db", .to = "db-d719b2cb-3d3a-4596-a3bc-dad00e67656f" },
	{ .from = "dbx", .to = "dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f" },
	{ .from = "KEK", .to = "KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c" },
};

static const char * evfs_variables[] = { "PK", "KEK", "db", "dbx" };

const struct secvarctl_backend efivarfs_backend = {
	.name = "efivarfs",
	.default_secvar_path = SECVARPATH,
	.sb_variables = evfs_variables,
	.sb_var_count = 4,
	.read_help = evfs_read_help,
	.read_usage = evfs_read_usage,
	.readFileFromPath = evfs_readFileFromPath,
	.readFileFromSecVar = evfs_readFileFromSecVar,
	.quirks = QUIRK_TIME_MINUS_1900 | QUIRK_PKCS2_SIGNEDDATA_ONLY,
	.default_attributes = EVFS_SECVAR_ATTRIBUTES,
};
