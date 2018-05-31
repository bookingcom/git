#include "builtin.h"
#include "cache.h"
#include "config.h"
#include "git-compat-util.h"
#include "parse-options.h"
#include "midx.h"

static char const * const builtin_midx_usage[] ={
	N_("git midx [--object-dir <dir>] [read|write]"),
	NULL
};

static struct opts_midx {
	const char *object_dir;
} opts;

static int read_midx_file(const char *object_dir)
{
	struct midxed_git *m = load_midxed_git(object_dir);

	if (!m)
		return 0;

	printf("header: %08x %d %d %d %d\n",
	       m->signature,
	       m->version,
	       m->hash_version,
	       m->num_chunks,
	       m->num_packs);

	printf("chunks:");

	if (m->chunk_pack_names)
		printf(" pack_names");

	printf("\n");

	printf("object_dir: %s\n", m->object_dir);

	return 0;
}

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

	if (argc == 0)
		return 0;

	if (!strcmp(argv[0], "read"))
		return read_midx_file(opts.object_dir);
	if (!strcmp(argv[0], "write"))
		return write_midx_file(opts.object_dir);

	return 0;
}
