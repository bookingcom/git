#include "git-compat-util.h"
#include "test-tool.h"

struct test_cmd {
	const char *name;
	int (*main)(int argc, const char **argv);
};

static struct test_cmd cmds[] = {
	{ "chmtime", cmd__chmtime },
	{ "config", cmd__config },
	{ "ctype", cmd__ctype },
	{ "date", cmd__date },
	{ "delta", cmd__delta },
	{ "drop-caches", cmd__drop_caches },
	{ "dump-cache-tree", cmd__dump_cache_tree },
	{ "dump-split-index", cmd__dump_split_index },
	{ "lazy-init-name-hash", cmd__lazy_init_name_hash },
	{ "sha1", cmd__sha1 },
};

int cmd_main(int argc, const char **argv)
{
	int i;

	if (argc < 2)
		die("I need a test name!");

	for (i = 0; i < ARRAY_SIZE(cmds); i++) {
		if (!strcmp(cmds[i].name, argv[1])) {
			argv++;
			argc--;
			return cmds[i].main(argc, argv);
		}
	}
	die("There is no test named '%s'", argv[1]);
}
