#ifndef MIDX_H
#define MIDX_H

#include "git-compat-util.h"
#include "cache.h"
#include "object-store.h"
#include "packfile.h"
#include "repository.h"

struct midxed_git *load_midxed_git(const char *object_dir);
int prepare_midxed_git_one(struct repository *r, const char *object_dir);

int write_midx_file(const char *object_dir);

#endif
