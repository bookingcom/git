#ifndef CHECKOUT_H
#define CHECKOUT_H

#include "cache.h"

struct tracking_name_data {
	/* const */ char *src_ref;
	char *dst_ref;
	struct object_id *dst_oid;
	int num_matches;
	const char *default_remote;
	char *default_dst_ref;
	struct object_id *default_dst_oid;
};

#define TRACKING_NAME_DATA_INIT { NULL, NULL, NULL, 0, NULL, NULL, NULL }

/*
 * Check if the branch name uniquely matches a branch name on a remote
 * tracking branch.  Return the name of the remote if such a branch
 * exists, NULL otherwise.
 */
extern const char *unique_tracking_name(const char *name,
					struct object_id *oid,
					int *dwim_remotes_matched);

#endif /* CHECKOUT_H */
