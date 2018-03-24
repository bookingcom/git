#include "git-compat-util.h"
#include "test-tool.h"

struct test_cmd {
	const char *name;
	int (*main)(int argc, const char **argv);
};

static struct test_cmd cmds[] = {
	{ "chmtime", cmd__chmtime },
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
