#define QUIRK_TIME_MINUS_1900		0x1
#define QUIRK_PKCS2_SIGNEDDATA_ONLY	0x2

struct secvarctl_backend {
	const char * name;
	const char * default_secvar_path;
	const char ** sb_variables;
	const int sb_var_count;
	unsigned long long quirks;
	unsigned long default_attributes;

	// read name from file
	int (*readFileFromPath) (const char *file, int hrFlag);
	// read name from var dir
	int (*readFileFromSecVar) (const char *path, const char *variable, int hrFlag);
	// read usage
	void (*read_usage) (void);
	// read help
	void (*read_help) (void);

	// write
	int (*updateSecVar) (const char *varName, const char *authFile, const char *path, int force);
	// write usage
	void (*write_usage) (void);
	// write help
	void (*write_help) (void);
};

extern const struct secvarctl_backend efivarfs_backend;
extern const struct secvarctl_backend edk2_backend;

extern const struct secvarctl_backend *secvarctl_backend;