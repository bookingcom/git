#include "git-compat-util.h"
#include "cache.h"
#include "dir.h"
#include "csum-file.h"
#include "lockfile.h"
#include "object-store.h"
#include "midx.h"

#define MIDX_SIGNATURE 0x4d494458 /* "MIDX" */
#define MIDX_VERSION 1
#define MIDX_HASH_VERSION 1 /* SHA-1 */
#define MIDX_HEADER_SIZE 12
#define MIDX_HASH_LEN 20
#define MIDX_MIN_SIZE (MIDX_HEADER_SIZE + MIDX_HASH_LEN)

#define MIDX_MAX_CHUNKS 2
#define MIDX_CHUNK_ALIGNMENT 4
#define MIDX_CHUNKID_PACKLOOKUP 0x504c4f4f /* "PLOO" */
#define MIDX_CHUNKID_PACKNAMES 0x504e414d /* "PNAM" */
#define MIDX_CHUNKLOOKUP_WIDTH (sizeof(uint32_t) + sizeof(uint64_t))

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
	m->data = midx_map;

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

	m->pack_names = xcalloc(m->num_packs, sizeof(const char *));
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

	hold_lock_file_for_update(&lk, midx_name, LOCK_DIE_ON_ERROR);
	f = hashfd(lk.tempfile->fd, lk.tempfile->filename.buf);
	FREE_AND_NULL(midx_name);

	cur_chunk = 0;
	num_chunks = 2;

	written = write_midx_header(f, num_chunks, nr_packs);

	chunk_ids[cur_chunk] = MIDX_CHUNKID_PACKLOOKUP;
	chunk_offsets[cur_chunk] = written + (num_chunks + 1) * MIDX_CHUNKLOOKUP_WIDTH;

	cur_chunk++;
	chunk_ids[cur_chunk] = MIDX_CHUNKID_PACKNAMES;
	chunk_offsets[cur_chunk] = chunk_offsets[cur_chunk - 1] + nr_packs * sizeof(uint32_t);

	cur_chunk++;
	chunk_ids[cur_chunk] = 0;
	chunk_offsets[cur_chunk] = chunk_offsets[cur_chunk - 1] + pack_name_concat_len;

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
