#include "builtin.h"
#include "cache.h"
#include "config.h"
#include "git-compat-util.h"
#include "parse-options.h"

static char const * const builtin_midx_usage[] ={
	N_("git midx [--object-dir <dir>]"),
	NULL
};

static struct opts_midx {
	const char *object_dir;
} opts;

int cmd_midx(int argc, const char **argv, const char *prefix)
{
	static struct option builtin_midx_options[] = {
		{ OPTION_STRING, 0, "object-dir", &opts.object_dir,
		  N_("dir"),
		  N_("The object directory containing set of packfile and pack-index pairs.") },
		OPT_END(),
	};

	if (argc == 2 && !strcmp(argv[1], "-h"))
		usage_with_options(builtin_midx_usage, builtin_midx_options);

	git_config(git_default_config, NULL);

	argc = parse_options(argc, argv, prefix,
			     builtin_midx_options,
			     builtin_midx_usage, 0);

	if (!opts.object_dir)
		opts.object_dir = get_object_directory();

	return 0;
}
