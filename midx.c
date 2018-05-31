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

int write_midx_file(const char *object_dir)
{
	unsigned char num_chunks = 0;
	uint32_t num_packs = 0;
	char *midx_name;
	struct hashfile *f;
	struct lock_file lk;

	midx_name = get_midx_filename(object_dir);
	if (safe_create_leading_directories(midx_name)) {
		UNLEAK(midx_name);
		die_errno(_("unable to create leading directories of %s"),
			  midx_name);
	}

	hold_lock_file_for_update(&lk, midx_name, LOCK_DIE_ON_ERROR);
	f = hashfd(lk.tempfile->fd, lk.tempfile->filename.buf);
	FREE_AND_NULL(midx_name);

	write_midx_header(f, num_chunks, num_packs);

	finalize_hashfile(f, NULL, CSUM_FSYNC | CSUM_HASH_IN_STREAM);
	commit_lock_file(&lk);

	return 0;
}
