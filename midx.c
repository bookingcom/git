#include "git-compat-util.h"
#include "cache.h"
#include "dir.h"
#include "csum-file.h"
#include "lockfile.h"
#include "sha1-lookup.h"
#include "object-store.h"
#include "packfile.h"
#include "midx.h"

#define MIDX_SIGNATURE 0x4d494458 /* "MIDX" */
#define MIDX_VERSION 1
#define MIDX_HASH_VERSION 1 /* SHA-1 */
#define MIDX_HEADER_SIZE 12
#define MIDX_HASH_LEN 20
#define MIDX_MIN_SIZE (MIDX_HEADER_SIZE + MIDX_HASH_LEN)

#define MIDX_MAX_CHUNKS 6
#define MIDX_CHUNK_ALIGNMENT 4
#define MIDX_CHUNKID_PACKLOOKUP 0x504c4f4f /* "PLOO" */
#define MIDX_CHUNKID_PACKNAMES 0x504e414d /* "PNAM" */
#define MIDX_CHUNKID_OIDFANOUT 0x4f494446 /* "OIDF" */
#define MIDX_CHUNKID_OIDLOOKUP 0x4f49444c /* "OIDL" */
#define MIDX_CHUNKID_OBJECTOFFSETS 0x4f4f4646 /* "OOFF" */
#define MIDX_CHUNKID_LARGEOFFSETS 0x4c4f4646 /* "LOFF" */
#define MIDX_CHUNKLOOKUP_WIDTH (sizeof(uint32_t) + sizeof(uint64_t))
#define MIDX_CHUNK_FANOUT_SIZE (sizeof(uint32_t) * 256)
#define MIDX_CHUNK_OFFSET_WIDTH (2 * sizeof(uint32_t))
#define MIDX_CHUNK_LARGE_OFFSET_WIDTH (sizeof(uint64_t))
#define MIDX_LARGE_OFFSET_NEEDED 0x80000000

static char *get_midx_filename(const char *object_dir)
{
	struct strbuf midx_name = STRBUF_INIT;
	strbuf_addstr(&midx_name, object_dir);
	strbuf_addstr(&midx_name, "/pack/multi-pack-index");
	return strbuf_detach(&midx_name, NULL);
}

struct midxed_git *load_midxed_git(const char *object_dir)
{
	struct midxed_git *m;
	int fd;
	struct stat st;
	size_t midx_size;
	void *midx_map;
	const char *midx_name = get_midx_filename(object_dir);
	uint32_t i;

	fd = git_open(midx_name);
	if (fd < 0)
		return NULL;
	if (fstat(fd, &st)) {
		close(fd);
		return NULL;
	}
	midx_size = xsize_t(st.st_size);

	if (midx_size < MIDX_MIN_SIZE) {
		close(fd);
		die("multi-pack-index file %s is too small", midx_name);
	}

	midx_map = xmmap(NULL, midx_size, PROT_READ, MAP_PRIVATE, fd, 0);

	m = xcalloc(1, sizeof(*m) + strlen(object_dir) + 1);
	strcpy(m->object_dir, object_dir);
	m->data = (const unsigned char*)midx_map;

	m->signature = get_be32(m->data);
	if (m->signature != MIDX_SIGNATURE) {
		error("multi-pack-index signature %X does not match signature %X",
		      m->signature, MIDX_SIGNATURE);
		goto cleanup_fail;
	}

	m->version = *(m->data + 4);
	if (m->version != MIDX_VERSION) {
		error("multi-pack-index version %d not recognized",
		      m->version);
		goto cleanup_fail;
	}

	m->hash_version = *(m->data + 5);
	if (m->hash_version != MIDX_HASH_VERSION) {
		error("hash version %d not recognized", m->hash_version);
		goto cleanup_fail;
	}
	m->hash_len = MIDX_HASH_LEN;

	m->num_chunks = *(m->data + 6);
	m->num_packs = get_be32(m->data + 8);

	for (i = 0; i < m->num_chunks; i++) {
		uint32_t chunk_id = get_be32(m->data + 12 + MIDX_CHUNKLOOKUP_WIDTH * i);
		uint64_t chunk_offset = get_be64(m->data + 16 + MIDX_CHUNKLOOKUP_WIDTH * i);

		switch (chunk_id) {
			case MIDX_CHUNKID_PACKLOOKUP:
				m->chunk_pack_lookup = (uint32_t *)(m->data + chunk_offset);
				break;

			case MIDX_CHUNKID_PACKNAMES:
				m->chunk_pack_names = m->data + chunk_offset;
				break;

			case MIDX_CHUNKID_OIDFANOUT:
				m->chunk_oid_fanout = (uint32_t *)(m->data + chunk_offset);
				break;

			case MIDX_CHUNKID_OIDLOOKUP:
				m->chunk_oid_lookup = m->data + chunk_offset;
				break;

			case MIDX_CHUNKID_OBJECTOFFSETS:
				m->chunk_object_offsets = m->data + chunk_offset;
				break;

			case MIDX_CHUNKID_LARGEOFFSETS:
				m->chunk_large_offsets = m->data + chunk_offset;
				break;

			case 0:
				die("terminating MIDX chunk id appears earlier than expected");
				break;

			default:
				/*
				 * Do nothing on unrecognized chunks, allowing future
				 * extensions to add optional chunks.
				 */
				break;
		}
	}

	if (!m->chunk_pack_lookup)
		die("MIDX missing required pack lookup chunk");
	if (!m->chunk_pack_names)
		die("MIDX missing required pack-name chunk");
	if (!m->chunk_oid_fanout)
		die("MIDX missing required OID fanout chunk");
	if (!m->chunk_oid_lookup)
		die("MIDX missing required OID lookup chunk");
	if (!m->chunk_object_offsets)
		die("MIDX missing required object offsets chunk");

	m->num_objects = ntohl(m->chunk_oid_fanout[255]);

	m->packs = xcalloc(m->num_packs, sizeof(*m->packs));

	ALLOC_ARRAY(m->pack_names, m->num_packs);
	for (i = 0; i < m->num_packs; i++) {
		if (i) {
			if (ntohl(m->chunk_pack_lookup[i]) <= ntohl(m->chunk_pack_lookup[i - 1])) {
				error("MIDX pack lookup value %d before %d",
				      ntohl(m->chunk_pack_lookup[i - 1]),
				      ntohl(m->chunk_pack_lookup[i]));
				goto cleanup_fail;
			}
		}

		m->pack_names[i] = (const char *)(m->chunk_pack_names + ntohl(m->chunk_pack_lookup[i]));

		if (i && strcmp(m->pack_names[i], m->pack_names[i - 1]) <= 0) {
			error("MIDX pack names out of order: '%s' before '%s'",
			      m->pack_names[i - 1],
			      m->pack_names[i]);
			goto cleanup_fail;
		}
	}

	return m;

cleanup_fail:
	FREE_AND_NULL(m);
	munmap(midx_map, midx_size);
	close(fd);
	exit(1);
}

static int prepare_midx_pack(struct midxed_git *m, uint32_t pack_int_id)
{
	struct strbuf pack_name = STRBUF_INIT;

	if (pack_int_id >= m->num_packs)
		BUG("bad pack-int-id");

	if (m->packs[pack_int_id])
		return 0;

	strbuf_addstr(&pack_name, m->object_dir);
	strbuf_addstr(&pack_name, "/pack/");
	strbuf_addstr(&pack_name, m->pack_names[pack_int_id]);

	m->packs[pack_int_id] = add_packed_git(pack_name.buf, pack_name.len, 1);
	strbuf_release(&pack_name);
	return !m->packs[pack_int_id];
}

int bsearch_midx(const struct object_id *oid, struct midxed_git *m, uint32_t *result)
{
	return bsearch_hash(oid->hash, m->chunk_oid_fanout, m->chunk_oid_lookup,
			    MIDX_HASH_LEN, result);
}

struct object_id *nth_midxed_object_oid(struct object_id *oid,
					struct midxed_git *m,
					uint32_t n)
{
	if (n >= m->num_objects)
		return NULL;

	hashcpy(oid->hash, m->chunk_oid_lookup + m->hash_len * n);
	return oid;
}

static off_t nth_midxed_offset(struct midxed_git *m, uint32_t pos)
{
        const unsigned char *offset_data;
        uint32_t offset32;

        offset_data = m->chunk_object_offsets + pos * MIDX_CHUNK_OFFSET_WIDTH;
        offset32 = get_be32(offset_data + sizeof(uint32_t));

        if (m->chunk_large_offsets && offset32 & MIDX_LARGE_OFFSET_NEEDED) {
                if (sizeof(offset32) < sizeof(uint64_t))
                        die(_("multi-pack-index stores a 64-bit offset, but off_t is too small"));

                offset32 ^= MIDX_LARGE_OFFSET_NEEDED;
                return get_be64(m->chunk_large_offsets + sizeof(uint64_t) * offset32);
        }

        return offset32;
}

static uint32_t nth_midxed_pack_int_id(struct midxed_git *m, uint32_t pos)
{
        return get_be32(m->chunk_object_offsets + pos * MIDX_CHUNK_OFFSET_WIDTH);
}

static int nth_midxed_pack_entry(struct midxed_git *m, struct pack_entry *e, uint32_t pos)
{
        uint32_t pack_int_id;
        struct packed_git *p;

        if (pos >= m->num_objects)
                return 0;

        pack_int_id = nth_midxed_pack_int_id(m, pos);

        if (prepare_midx_pack(m, pack_int_id))
                die(_("error preparing packfile from multi-pack-index"));
        p = m->packs[pack_int_id];

        /*
        * We are about to tell the caller where they can locate the
        * requested object.  We better make sure the packfile is
        * still here and can be accessed before supplying that
        * answer, as it may have been deleted since the MIDX was
        * loaded!
        */
        if (!is_pack_valid(p))
                return 0;

        e->offset = nth_midxed_offset(m, pos);
        e->p = p;

        return 1;
}

int fill_midx_entry(const struct object_id *oid, struct pack_entry *e, struct midxed_git *m)
{
	uint32_t pos;

	if (!bsearch_midx(oid, m, &pos))
		return 0;

	return nth_midxed_pack_entry(m, e, pos);
}

int prepare_midxed_git_one(struct repository *r, const char *object_dir)
{
	struct midxed_git *m = r->objects->midxed_git;
	struct midxed_git *m_search;

	if (!core_midx)
		return 0;

	for (m_search = m; m_search; m_search = m_search->next)
		if (!strcmp(object_dir, m_search->object_dir))
			return 1;

	r->objects->midxed_git = load_midxed_git(object_dir);

	if (r->objects->midxed_git) {
		r->objects->midxed_git->next = m;
		return 1;
	}

	return 0;
}

static size_t write_midx_header(struct hashfile *f,
				unsigned char num_chunks,
				uint32_t num_packs)
{
	char byte_values[4];
	hashwrite_be32(f, MIDX_SIGNATURE);
	byte_values[0] = MIDX_VERSION;
	byte_values[1] = MIDX_HASH_VERSION;
	byte_values[2] = num_chunks;
	byte_values[3] = 0; /* unused */
	hashwrite(f, byte_values, sizeof(byte_values));
	hashwrite_be32(f, num_packs);

	return MIDX_HEADER_SIZE;
}

struct pack_pair {
	uint32_t pack_int_id;
	char *pack_name;
};

static int pack_pair_compare(const void *_a, const void *_b)
{
	struct pack_pair *a = (struct pack_pair *)_a;
	struct pack_pair *b = (struct pack_pair *)_b;
	return strcmp(a->pack_name, b->pack_name);
}

static void sort_packs_by_name(char **pack_names, uint32_t nr_packs, uint32_t *perm)
{
	uint32_t i;
	struct pack_pair *pairs;

	ALLOC_ARRAY(pairs, nr_packs);

	for (i = 0; i < nr_packs; i++) {
		pairs[i].pack_int_id = i;
		pairs[i].pack_name = pack_names[i];
	}

	QSORT(pairs, nr_packs, pack_pair_compare);

	for (i = 0; i < nr_packs; i++) {
		pack_names[i] = pairs[i].pack_name;
		perm[pairs[i].pack_int_id] = i;
	}
}

static uint32_t get_pack_fanout(struct packed_git *p, uint32_t value)
{
	const uint32_t *level1_ofs = p->index_data;

	if (!level1_ofs) {
		if (open_pack_index(p))
			return 0;
		level1_ofs = p->index_data;
	}

	if (p->index_version > 1) {
		level1_ofs += 2;
	}

	return ntohl(level1_ofs[value]);
}

struct pack_midx_entry {
	struct object_id oid;
	uint32_t pack_int_id;
	time_t pack_mtime;
	uint64_t offset;
};

static int midx_oid_compare(const void *_a, const void *_b)
{
	struct pack_midx_entry *a = (struct pack_midx_entry *)_a;
	struct pack_midx_entry *b = (struct pack_midx_entry *)_b;
	int cmp = oidcmp(&a->oid, &b->oid);

	if (cmp)
		return cmp;

	if (a->pack_mtime > b->pack_mtime)
		return -1;
	else if (a->pack_mtime < b->pack_mtime)
		return 1;

	return a->pack_int_id - b->pack_int_id;
}

static void fill_pack_entry(uint32_t pack_int_id,
			    struct packed_git *p,
			    uint32_t cur_object,
			    struct pack_midx_entry *entry)
{
	if (!nth_packed_object_oid(&entry->oid, p, cur_object))
		die("failed to located object %d in packfile", cur_object);

	entry->pack_int_id = pack_int_id;
	entry->pack_mtime = p->mtime;

	entry->offset = nth_packed_object_offset(p, cur_object);
}

/*
 * It is possible to artificially get into a state where there are many
 * duplicate copies of objects. That can create high memory pressure if
 * we are to create a list of all objects before de-duplication. To reduce
 * this memory pressure without a significant performance drop, automatically
 * group objects by the first byte of their object id. Use the IDX fanout
 * tables to group the data, copy to a local array, then sort.
 *
 * Copy only the de-duplicated entries (selected by most-recent modified time
 * of a packfile containing the object).
 */
static struct pack_midx_entry *get_sorted_entries(struct packed_git **p,
						  uint32_t *perm,
						  uint32_t nr_packs,
						  uint32_t *nr_objects)
{
	uint32_t cur_fanout, cur_pack, cur_object;
	uint32_t nr_fanout, alloc_fanout, alloc_objects, total_objects = 0;
	struct pack_midx_entry *entries_by_fanout = NULL;
	struct pack_midx_entry *deduplicated_entries = NULL;

	for (cur_pack = 0; cur_pack < nr_packs; cur_pack++) {
		if (open_pack_index(p[cur_pack]))
			continue;

		total_objects += p[cur_pack]->num_objects;
	}

	/*
	 * As we de-duplicate by fanout value, we expect the fanout
	 * slices to be evenly distributed, with some noise. Hence,
	 * allocate slightly more than one 256th.
	 */
	alloc_objects = alloc_fanout = total_objects > 3200 ? total_objects / 200 : 16;

	ALLOC_ARRAY(entries_by_fanout, alloc_fanout);
	ALLOC_ARRAY(deduplicated_entries, alloc_objects);
	*nr_objects = 0;

	for (cur_fanout = 0; cur_fanout < 256; cur_fanout++) {
		nr_fanout = 0;

		for (cur_pack = 0; cur_pack < nr_packs; cur_pack++) {
			uint32_t start = 0, end;

			if (cur_fanout)
				start = get_pack_fanout(p[cur_pack], cur_fanout - 1);
			end = get_pack_fanout(p[cur_pack], cur_fanout);

			for (cur_object = start; cur_object < end; cur_object++) {
				ALLOC_GROW(entries_by_fanout, nr_fanout + 1, alloc_fanout);
				fill_pack_entry(perm[cur_pack], p[cur_pack], cur_object, &entries_by_fanout[nr_fanout]);
				nr_fanout++;
			}
		}

		QSORT(entries_by_fanout, nr_fanout, midx_oid_compare);

		/*
		 * The batch is now sorted by OID and then mtime (descending).
		 * Take only the first duplicate.
		 */
		for (cur_object = 0; cur_object < nr_fanout; cur_object++) {
			if (cur_object && !oidcmp(&entries_by_fanout[cur_object - 1].oid,
						  &entries_by_fanout[cur_object].oid))
				continue;

			ALLOC_GROW(deduplicated_entries, *nr_objects + 1, alloc_objects);
			memcpy(&deduplicated_entries[*nr_objects],
			       &entries_by_fanout[cur_object],
			       sizeof(struct pack_midx_entry));
			(*nr_objects)++;
		}
	}

	FREE_AND_NULL(entries_by_fanout);
	return deduplicated_entries;
}

static size_t write_midx_pack_lookup(struct hashfile *f,
				     char **pack_names,
				     uint32_t nr_packs)
{
	uint32_t i, cur_len = 0;

	for (i = 0; i < nr_packs; i++) {
		hashwrite_be32(f, cur_len);
		cur_len += strlen(pack_names[i]) + 1;
	}

	return sizeof(uint32_t) * (size_t)nr_packs;
}

static size_t write_midx_pack_names(struct hashfile *f,
				    char **pack_names,
				    uint32_t num_packs)
{
	uint32_t i;
	unsigned char padding[MIDX_CHUNK_ALIGNMENT];
	size_t written = 0;

	for (i = 0; i < num_packs; i++) {
		size_t writelen = strlen(pack_names[i]) + 1;

		if (i && strcmp(pack_names[i], pack_names[i - 1]) <= 0)
			BUG("incorrect pack-file order: %s before %s",
			    pack_names[i - 1],
			    pack_names[i]);

		hashwrite(f, pack_names[i], writelen);
		written += writelen;
	}

	/* add padding to be aligned */
	i = MIDX_CHUNK_ALIGNMENT - (written % MIDX_CHUNK_ALIGNMENT);
	if (i < MIDX_CHUNK_ALIGNMENT) {
		bzero(padding, sizeof(padding));
		hashwrite(f, padding, i);
		written += i;
	}

	return written;
}

static size_t write_midx_oid_fanout(struct hashfile *f,
				    struct pack_midx_entry *objects,
				    uint32_t nr_objects)
{
	struct pack_midx_entry *list = objects;
	struct pack_midx_entry *last = objects + nr_objects;
	uint32_t count = 0;
	uint32_t i;

	/*
	* Write the first-level table (the list is sorted,
	* but we use a 256-entry lookup to be able to avoid
	* having to do eight extra binary search iterations).
	*/
	for (i = 0; i < 256; i++) {
		struct pack_midx_entry *next = list;

		while (next < last && next->oid.hash[0] == i) {
			count++;
			next++;
		}

		hashwrite_be32(f, count);
		list = next;
	}

	return MIDX_CHUNK_FANOUT_SIZE;
}

static size_t write_midx_oid_lookup(struct hashfile *f, unsigned char hash_len,
				    struct pack_midx_entry *objects,
				    uint32_t nr_objects)
{
	struct pack_midx_entry *list = objects;
	uint32_t i;
	size_t written = 0;

	for (i = 0; i < nr_objects; i++) {
		struct pack_midx_entry *obj = list++;

		if (i < nr_objects - 1) {
			struct pack_midx_entry *next = list;
			if (oidcmp(&obj->oid, &next->oid) >= 0)
				BUG("OIDs not in order: %s >= %s",
				oid_to_hex(&obj->oid),
				oid_to_hex(&next->oid));
		}

		hashwrite(f, obj->oid.hash, (int)hash_len);
		written += hash_len;
	}

	return written;
}

static size_t write_midx_object_offsets(struct hashfile *f, int large_offset_needed,
					struct pack_midx_entry *objects, uint32_t nr_objects)
{
	struct pack_midx_entry *list = objects;
	uint32_t i, nr_large_offset = 0;
	size_t written = 0;

	for (i = 0; i < nr_objects; i++) {
		struct pack_midx_entry *obj = list++;

		hashwrite_be32(f, obj->pack_int_id);

		if (large_offset_needed && obj->offset >> 31)
			hashwrite_be32(f, MIDX_LARGE_OFFSET_NEEDED | nr_large_offset++);
		else if (!large_offset_needed && obj->offset >> 32)
			BUG("object %s requires a large offset (%"PRIx64") but the MIDX is not writing large offsets!",
			    oid_to_hex(&obj->oid),
			    obj->offset);
		else
			hashwrite_be32(f, (uint32_t)obj->offset);

		written += MIDX_CHUNK_OFFSET_WIDTH;
	}

	return written;
}

static size_t write_midx_large_offsets(struct hashfile *f, uint32_t nr_large_offset,
				       struct pack_midx_entry *objects, uint32_t nr_objects)
{
	struct pack_midx_entry *list = objects;
	size_t written = 0;

	while (nr_large_offset) {
		struct pack_midx_entry *obj = list++;
		uint64_t offset = obj->offset;

		if (!(offset >> 31))
			continue;

		hashwrite_be32(f, offset >> 32);
		hashwrite_be32(f, offset & 0xffffffff);
		written += 2 * sizeof(uint32_t);

		nr_large_offset--;
	}

	return written;
}

int write_midx_file(const char *object_dir)
{
	unsigned char cur_chunk, num_chunks = 0;
	char *midx_name;
	struct hashfile *f;
	struct lock_file lk;
	struct packed_git **packs = NULL;
	char **pack_names = NULL;
	uint32_t *pack_perm;
	uint32_t i, nr_packs = 0, alloc_packs = 0;
	uint32_t alloc_pack_names = 0;
	DIR *dir;
	struct dirent *de;
	struct strbuf pack_dir = STRBUF_INIT;
	size_t pack_dir_len;
	uint64_t pack_name_concat_len = 0;
	uint64_t written = 0;
	uint32_t chunk_ids[MIDX_MAX_CHUNKS + 1];
	uint64_t chunk_offsets[MIDX_MAX_CHUNKS + 1];
	struct pack_midx_entry *entries;
	uint32_t nr_entries, num_large_offsets = 0;
	int large_offsets_needed = 0;

	midx_name = get_midx_filename(object_dir);
	if (safe_create_leading_directories(midx_name)) {
		UNLEAK(midx_name);
		die_errno(_("unable to create leading directories of %s"),
			  midx_name);
	}

	strbuf_addf(&pack_dir, "%s/pack", object_dir);
	dir = opendir(pack_dir.buf);

	if (!dir) {
		error_errno("unable to open pack directory: %s",
			    pack_dir.buf);
		strbuf_release(&pack_dir);
		return 1;
	}

	strbuf_addch(&pack_dir, '/');
	pack_dir_len = pack_dir.len;
	ALLOC_ARRAY(packs, alloc_packs);
	ALLOC_ARRAY(pack_names, alloc_pack_names);
	while ((de = readdir(dir)) != NULL) {
		if (is_dot_or_dotdot(de->d_name))
			continue;

		if (ends_with(de->d_name, ".idx")) {
			ALLOC_GROW(packs, nr_packs + 1, alloc_packs);
			ALLOC_GROW(pack_names, nr_packs + 1, alloc_pack_names);

			strbuf_setlen(&pack_dir, pack_dir_len);
			strbuf_addstr(&pack_dir, de->d_name);

			packs[nr_packs] = add_packed_git(pack_dir.buf,
							 pack_dir.len,
							 0);
			if (!packs[nr_packs]) {
				warning("failed to add packfile '%s'",
					pack_dir.buf);
				continue;
			}

			pack_names[nr_packs] = xstrdup(de->d_name);
			pack_name_concat_len += strlen(de->d_name) + 1;
			nr_packs++;
		}
	}

	closedir(dir);
	strbuf_release(&pack_dir);

	if (pack_name_concat_len % MIDX_CHUNK_ALIGNMENT)
		pack_name_concat_len += MIDX_CHUNK_ALIGNMENT -
					(pack_name_concat_len % MIDX_CHUNK_ALIGNMENT);

	ALLOC_ARRAY(pack_perm, nr_packs);
	sort_packs_by_name(pack_names, nr_packs, pack_perm);

	entries = get_sorted_entries(packs, pack_perm, nr_packs, &nr_entries);
	for (i = 0; i < nr_entries; i++) {
		if (entries[i].offset > 0x7fffffff)
			num_large_offsets++;
		if (entries[i].offset > 0xffffffff)
			large_offsets_needed = 1;
	}

	hold_lock_file_for_update(&lk, midx_name, LOCK_DIE_ON_ERROR);
	f = hashfd(lk.tempfile->fd, lk.tempfile->filename.buf);
	FREE_AND_NULL(midx_name);

	cur_chunk = 0;
	num_chunks = large_offsets_needed ? 6 : 5;

	written = write_midx_header(f, num_chunks, nr_packs);

	chunk_ids[cur_chunk] = MIDX_CHUNKID_PACKLOOKUP;
	chunk_offsets[cur_chunk] = written + (num_chunks + 1) * MIDX_CHUNKLOOKUP_WIDTH;

	cur_chunk++;
	chunk_ids[cur_chunk] = MIDX_CHUNKID_PACKNAMES;
	chunk_offsets[cur_chunk] = chunk_offsets[cur_chunk - 1] + nr_packs * sizeof(uint32_t);

	cur_chunk++;
	chunk_ids[cur_chunk] = MIDX_CHUNKID_OIDFANOUT;
	chunk_offsets[cur_chunk] = chunk_offsets[cur_chunk - 1] + pack_name_concat_len;

	cur_chunk++;
	chunk_ids[cur_chunk] = MIDX_CHUNKID_OIDLOOKUP;
	chunk_offsets[cur_chunk] = chunk_offsets[cur_chunk - 1] + MIDX_CHUNK_FANOUT_SIZE;

	cur_chunk++;
	chunk_ids[cur_chunk] = MIDX_CHUNKID_OBJECTOFFSETS;
	chunk_offsets[cur_chunk] = chunk_offsets[cur_chunk - 1] + nr_entries * MIDX_HASH_LEN;

	cur_chunk++;
	chunk_offsets[cur_chunk] = chunk_offsets[cur_chunk - 1] + nr_entries * MIDX_CHUNK_OFFSET_WIDTH;
	if (large_offsets_needed) {
		chunk_ids[cur_chunk] = MIDX_CHUNKID_LARGEOFFSETS;

		cur_chunk++;
		chunk_offsets[cur_chunk] = chunk_offsets[cur_chunk - 1] +
					   num_large_offsets * MIDX_CHUNK_LARGE_OFFSET_WIDTH;
	}

	chunk_ids[cur_chunk] = 0;

	for (i = 0; i <= num_chunks; i++) {
		if (i && chunk_offsets[i] < chunk_offsets[i - 1])
			BUG("incorrect chunk offsets: %"PRIu64" before %"PRIu64,
			    chunk_offsets[i - 1],
			    chunk_offsets[i]);

		if (chunk_offsets[i] % MIDX_CHUNK_ALIGNMENT)
			BUG("chunk offset %"PRIu64" is not properly aligned",
			    chunk_offsets[i]);

		hashwrite_be32(f, chunk_ids[i]);
		hashwrite_be32(f, chunk_offsets[i] >> 32);
		hashwrite_be32(f, chunk_offsets[i]);

		written += MIDX_CHUNKLOOKUP_WIDTH;
	}

	for (i = 0; i < num_chunks; i++) {
		if (written != chunk_offsets[i])
			BUG("inccrrect chunk offset (%"PRIu64" != %"PRIu64") for chunk id %"PRIx32,
			    chunk_offsets[i],
			    written,
			    chunk_ids[i]);

		switch (chunk_ids[i]) {
			case MIDX_CHUNKID_PACKLOOKUP:
				written += write_midx_pack_lookup(f, pack_names, nr_packs);
				break;

			case MIDX_CHUNKID_PACKNAMES:
				written += write_midx_pack_names(f, pack_names, nr_packs);
				break;

			case MIDX_CHUNKID_OIDFANOUT:
				written += write_midx_oid_fanout(f, entries, nr_entries);
				break;

			case MIDX_CHUNKID_OIDLOOKUP:
				written += write_midx_oid_lookup(f, MIDX_HASH_LEN, entries, nr_entries);
				break;

			case MIDX_CHUNKID_OBJECTOFFSETS:
				written += write_midx_object_offsets(f, large_offsets_needed, entries, nr_entries);
				break;

			case MIDX_CHUNKID_LARGEOFFSETS:
				written += write_midx_large_offsets(f, num_large_offsets, entries, nr_entries);
				break;

			default:
				BUG("trying to write unknown chunk id %"PRIx32,
				    chunk_ids[i]);
		}
	}

	if (written != chunk_offsets[num_chunks])
		BUG("incorrect final offset %"PRIu64" != %"PRIu64,
		    written,
		    chunk_offsets[num_chunks]);

	finalize_hashfile(f, NULL, CSUM_FSYNC | CSUM_HASH_IN_STREAM);
	commit_lock_file(&lk);

	for (i = 0; i < nr_packs; i++) {
		close_pack(packs[i]);
		FREE_AND_NULL(packs[i]);
	}

	FREE_AND_NULL(packs);
	FREE_AND_NULL(pack_names);
	return 0;
}
