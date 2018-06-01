#ifndef MIDX_H
#define MIDX_H

#include "git-compat-util.h"
#include "cache.h"
#include "object-store.h"
#include "packfile.h"
#include "repository.h"

struct midxed_git *load_midxed_git(const char *object_dir);
int bsearch_midx(const struct object_id *oid, struct midxed_git *m, uint32_t *result);
int fill_midx_entry(const struct object_id *oid, struct pack_entry *e, struct midxed_git *m);
int prepare_midxed_git_one(struct repository *r, const char *object_dir);

int write_midx_file(const char *object_dir);

#endif
