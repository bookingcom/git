#ifndef PACK_OBJECTS_H
#define PACK_OBJECTS_H

#define OE_DFS_STATE_BITS 2
#define OE_DEPTH_BITS 12
#define OE_IN_PACK_BITS 14

#define IN_PACK_POS(to_pack, obj) \
	(to_pack)->in_pack_pos[(struct object_entry *)(obj) - (to_pack)->objects]

#define IN_PACK(to_pack, obj) \
	(to_pack)->in_pack[(obj)->in_pack_idx]

/*
 * State flags for depth-first search used for analyzing delta cycles.
 *
 * The depth is measured in delta-links to the base (so if A is a delta
 * against B, then A has a depth of 1, and B a depth of 0).
 */
enum dfs_state {
	DFS_NONE = 0,
	DFS_ACTIVE,
	DFS_DONE,
	DFS_NUM_STATES
};

/*
 * The size of struct nearly determines pack-objects's memory
 * consumption. This struct is packed tight for that reason. When you
 * add or reorder something in this struct, think a bit about this.
 */
struct object_entry {
	struct pack_idx_entry idx;
	unsigned long size;	/* uncompressed size */
	off_t in_pack_offset;
	uint32_t delta_idx;	/* delta base object */
	uint32_t delta_child_idx; /* deltified objects who bases me */
	uint32_t delta_sibling_idx; /* other deltified objects who
				     * uses the same base as me
				     */
	uint32_t hash;			/* name hint hash */
	void *delta_data;	/* cached delta (uncompressed) */
	unsigned long delta_size;	/* delta data size (uncompressed) */
	unsigned long z_delta_size;	/* delta data size (compressed) */
	unsigned char in_pack_header_size; /* note: spare bits available! */
	unsigned in_pack_idx:OE_IN_PACK_BITS;	/* already in pack */
	unsigned type:TYPE_BITS;
	unsigned in_pack_type:TYPE_BITS; /* could be delta */
	unsigned preferred_base:1; /*
				    * we do not pack this, but is available
				    * to be used as the base object to delta
				    * objects against.
				    */
	unsigned no_try_delta:1;
	unsigned tagged:1; /* near the very tip of refs */
	unsigned filled:1; /* assigned write-order */
	unsigned dfs_state:OE_DFS_STATE_BITS;

	/* XXX 8 bits hole, try to pack */

	unsigned depth:OE_DEPTH_BITS;

	/* size: 96, bit_padding: 18 bits */
};

struct packing_data {
	struct object_entry *objects;
	uint32_t nr_objects, nr_alloc;

	int32_t *index;
	uint32_t index_size;

	unsigned int *in_pack_pos;
	int in_pack_count;
	struct packed_git *in_pack[1 << OE_IN_PACK_BITS];
};

struct object_entry *packlist_alloc(struct packing_data *pdata,
				    const unsigned char *sha1,
				    uint32_t index_pos);

struct object_entry *packlist_find(struct packing_data *pdata,
				   const unsigned char *sha1,
				   uint32_t *index_pos);

static inline uint32_t pack_name_hash(const char *name)
{
	uint32_t c, hash = 0;

	if (!name)
		return 0;

	/*
	 * This effectively just creates a sortable number from the
	 * last sixteen non-whitespace characters. Last characters
	 * count "most", so things that end in ".c" sort together.
	 */
	while ((c = *name++) != 0) {
		if (isspace(c))
			continue;
		hash = (hash >> 2) + (c << 24);
	}
	return hash;
}

#endif
