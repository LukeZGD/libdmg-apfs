/*
 * extents.c
 * apfs-tool
 *
 * Data streams: file extents in the file-system tree (or the fext tree of a
 * sealed volume) and the physical extent records of the extent reference
 * tree.
 */

#include <stdlib.h>
#include <string.h>

#include "apfs/apfs.h"

#define MAX_EXTENT_BLOCKS 0x100000ULL /* 4 GiB with 4 KiB blocks */

typedef struct {
	uint64_t logical;
	uint64_t len;
	paddr_t phys;
	uint8_t flags;
	uint64_t crypto;
} fext_t;

static int read_fext_rec(apfs_vol_t* vol, const apfs_kv_t* kv, uint64_t id, fext_t* e) {
	if(vol->sealed && vol->fext.loaded) {
		if(kv->klen != 16 || kv->vlen != 16 || apfs_get64(kv->k) != id)
			return APFS_ENOENT;
		e->logical = apfs_get64(kv->k + 8);
		e->len = apfs_get64(kv->v) & J_FILE_EXTENT_LEN_MASK;
		e->flags = (uint8_t)(apfs_get64(kv->v) >> J_FILE_EXTENT_FLAG_SHIFT);
		e->phys = apfs_get64(kv->v + 8);
		e->crypto = 0;
		return APFS_OK;
	}
	if(kv->klen != 16 || kv->vlen < 24 || apfs_key_id(kv->k) != id || apfs_key_type(kv->k) != APFS_TYPE_FILE_EXTENT)
		return APFS_ENOENT;
	e->logical = apfs_get64(kv->k + 8);
	e->len = apfs_get64(kv->v) & J_FILE_EXTENT_LEN_MASK;
	e->flags = (uint8_t)(apfs_get64(kv->v) >> J_FILE_EXTENT_FLAG_SHIFT);
	e->phys = apfs_get64(kv->v + 8);
	e->crypto = apfs_get64(kv->v + 16);
	return APFS_OK;
}

static apfs_btree_t* extent_tree(apfs_vol_t* vol) {
	return (vol->sealed && vol->fext.loaded) ? &vol->fext : &vol->fs;
}

static void extent_key(apfs_vol_t* vol, uint8_t* key, uint64_t id, uint64_t off) {
	if(vol->sealed && vol->fext.loaded) {
		apfs_put64(key, id);
		apfs_put64(key + 8, off);
	} else {
		apfs_key_hdr(key, id, APFS_TYPE_FILE_EXTENT);
		apfs_put64(key + 8, off);
	}
}

/* Finds the extent containing `off`, or else the first one after it.
 * Returns APFS_ENOENT when there is none. */
static int find_extent(apfs_vol_t* vol, uint64_t id, uint64_t off, fext_t* e) {
	apfs_btree_t* bt = extent_tree(vol);
	uint8_t key[16];
	apfs_kv_t kv;
	apfs_btiter_t it;
	int ret;

	extent_key(vol, key, id, off);
	ret = apfs_bt_lookup_le(bt, key, sizeof(key), &kv);
	if(ret == APFS_OK && read_fext_rec(vol, &kv, id, e) == APFS_OK && off < e->logical + e->len)
		return APFS_OK;
	if(ret < 0 && ret != APFS_ENOENT)
		return ret;

	ret = apfs_bt_iter_seek(&it, bt, key, sizeof(key));
	if(ret < 0)
		return ret;
	while(it.valid) {
		apfs_bt_iter_get(&it, &kv);
		if(read_fext_rec(vol, &kv, id, e) < 0)
			return APFS_ENOENT;
		if(e->logical + e->len > off)
			return APFS_OK;
		ret = apfs_bt_iter_next(&it);
		if(ret < 0)
			return ret;
	}
	return APFS_ENOENT;
}

int apfs_dstream_read(apfs_vol_t* vol, uint64_t id, uint64_t size, uint64_t off, void* buf, size_t len) {
	apfs_nx_t* nx = vol->nx;
	uint8_t* out = (uint8_t*)buf;
	uint64_t pos, end;

	if(off >= size)
		return APFS_OK;
	if(len > size - off)
		len = (size_t)(size - off);
	pos = off;
	end = off + len;

	while(pos < end) {
		fext_t e;
		int ret = find_extent(vol, id, pos, &e);
		uint64_t n;

		if(ret == APFS_ENOENT || (ret == APFS_OK && e.logical > pos)) {
			/* hole */
			uint64_t hole_end = (ret == APFS_ENOENT) ? end : (e.logical < end ? e.logical : end);
			memset(out + (pos - off), 0, (size_t)(hole_end - pos));
			pos = hole_end;
			continue;
		}
		if(ret < 0)
			return ret;

		n = e.logical + e.len - pos;
		if(n > end - pos)
			n = end - pos;
		if(e.phys == 0) {
			memset(out + (pos - off), 0, (size_t)n);
		} else {
			uint64_t byte = nx->base + e.phys * nx->bs + (pos - e.logical);
			if(e.phys + (e.len + nx->bs - 1) / nx->bs > LE64(nx->sb->nx_block_count))
				return APFS_ECORRUPT;
			if(!nx->io->read(nx->io, (off_t)byte, (size_t)n, out + (pos - off)))
				return APFS_EIO;
		}
		pos += n;
	}
	return APFS_OK;
}

int apfs_dstream_extents(apfs_vol_t* vol, uint64_t id, apfs_extent_t** out, size_t* count, uint64_t** logical) {
	apfs_btree_t* bt = extent_tree(vol);
	uint8_t key[16];
	apfs_btiter_t it;
	apfs_kv_t kv;
	apfs_extent_t* list = NULL;
	uint64_t* lg = NULL;
	size_t n = 0;
	int ret;

	extent_key(vol, key, id, 0);
	ret = apfs_bt_iter_seek(&it, bt, key, sizeof(key));
	while(ret == APFS_OK && it.valid) {
		fext_t e;
		apfs_bt_iter_get(&it, &kv);
		if(read_fext_rec(vol, &kv, id, &e) < 0)
			break;
		list = (apfs_extent_t*)apfs_realloc(list, (n + 1) * sizeof(apfs_extent_t));
		lg = (uint64_t*)apfs_realloc(lg, (n + 1) * sizeof(uint64_t));
		list[n].start = e.phys;
		list[n].count = (e.len + vol->nx->bs - 1) / vol->nx->bs;
		list[n].owner = NULL;
		lg[n] = e.logical;
		n++;
		ret = apfs_bt_iter_next(&it);
	}
	if(ret < 0) {
		free(list);
		free(lg);
		return ret;
	}
	*out = list;
	*count = n;
	if(logical)
		*logical = lg;
	else
		free(lg);
	return APFS_OK;
}

/* Physical extent records (extent reference tree) */

static void pext_key(uint8_t* key, paddr_t paddr) {
	apfs_key_hdr(key, paddr, APFS_TYPE_EXTENT);
}

static void pext_val(uint8_t* val, uint64_t len, uint8_t kind, uint64_t owner, int32_t refcnt) {
	apfs_put64(val, (len & PEXT_LEN_MASK) | ((uint64_t)kind << PEXT_KIND_SHIFT));
	apfs_put64(val + 8, owner);
	apfs_put32(val + 16, (uint32_t)refcnt);
}

int apfs_phys_extent_add(apfs_vol_t* vol, paddr_t start, uint64_t count, uint64_t owner) {
	uint8_t key[8], val[20];
	int ret = apfs_vol_mark_dirty(vol);
	if(ret < 0)
		return ret;
	pext_key(key, start);
	pext_val(val, count, APFS_KIND_NEW, owner, 1);
	return apfs_bt_insert(&vol->extref, key, sizeof(key), val, sizeof(val));
}

typedef struct {
	paddr_t start;
	uint64_t len;
	uint8_t kind;
	uint64_t owner;
	int32_t refcnt;
} pext_t;

static int pext_find(apfs_vol_t* vol, paddr_t bno, pext_t* p) {
	uint8_t key[8];
	apfs_kv_t kv;
	int ret;

	pext_key(key, bno);
	ret = apfs_bt_lookup_le(&vol->extref, key, sizeof(key), &kv);
	if(ret < 0)
		return ret;
	if(kv.klen != 8 || kv.vlen < 20 || apfs_key_type(kv.k) != APFS_TYPE_EXTENT)
		return APFS_ENOENT;
	p->start = apfs_key_id(kv.k);
	p->len = apfs_get64(kv.v) & PEXT_LEN_MASK;
	p->kind = (uint8_t)(apfs_get64(kv.v) >> PEXT_KIND_SHIFT);
	p->owner = apfs_get64(kv.v + 8);
	p->refcnt = (int32_t)apfs_get32(kv.v + 16);
	return APFS_OK;
}

static int pext_write(apfs_vol_t* vol, const pext_t* p) {
	uint8_t key[8], val[20];
	pext_key(key, p->start);
	pext_val(val, p->len, p->kind, p->owner, p->refcnt);
	return apfs_bt_insert(&vol->extref, key, sizeof(key), val, sizeof(val));
}

/* Drops one reference to the physical blocks [start, start + count). Blocks
 * whose last reference goes away are freed; blocks that belong to a snapshot
 * get a reference-count update record instead. */
int apfs_phys_extent_put(apfs_vol_t* vol, paddr_t start, uint64_t count) {
	int ret = apfs_vol_mark_dirty(vol);
	if(ret < 0)
		return ret;

	while(count > 0) {
		paddr_t end = start + count;
		pext_t p;

		ret = pext_find(vol, end - 1, &p);
		if(ret < 0 && ret != APFS_ENOENT)
			return ret;

		if(ret == APFS_ENOENT || p.start + p.len <= start || p.start + p.len < end) {
			/* the tail of the range is not tracked by the live tree */
			paddr_t lo = start;
			pext_t u;
			if(ret == APFS_OK && p.start + p.len > start)
				lo = p.start + p.len;
			if(LE64(vol->sb->apfs_num_snapshots) == 0) {
				APFS_WARN("blocks 0x%llx+%llu have no extent reference; freeing them", (unsigned long long)lo,
					(unsigned long long)(end - lo));
				ret = apfs_sm_free(vol->nx, vol, lo, end - lo);
				if(ret < 0)
					return ret;
			} else {
				u.start = lo;
				u.len = end - lo;
				u.kind = APFS_KIND_UPDATE;
				u.owner = OWNING_OBJ_ID_INVALID;
				u.refcnt = -1;
				ret = pext_write(vol, &u);
				if(ret < 0)
					return ret;
			}
			count = lo - start;
			continue;
		}

		/* p covers [max(p.start, start), end): split off the parts outside */
		{
			paddr_t lo = p.start > start ? p.start : start;
			paddr_t pend = p.start + p.len;
			uint8_t key[8];

			if(pend > end) {
				pext_t tail = p;
				tail.start = end;
				tail.len = pend - end;
				ret = pext_write(vol, &tail);
				if(ret < 0)
					return ret;
			}
			if(p.start < lo) {
				pext_t head = p;
				head.len = lo - p.start;
				ret = pext_write(vol, &head);
				if(ret < 0)
					return ret;
			} else {
				pext_key(key, p.start);
				ret = apfs_bt_delete(&vol->extref, key, sizeof(key));
				if(ret < 0)
					return ret;
			}

			p.start = lo;
			p.len = end - lo;
			p.refcnt--;
			if(p.refcnt != 0) {
				ret = pext_write(vol, &p);
				if(ret < 0)
					return ret;
			} else if(p.kind == APFS_KIND_NEW) {
				ret = apfs_sm_free(vol->nx, vol, p.start, p.len);
				if(ret < 0)
					return ret;
			}
			count = lo - start;
		}
	}
	return APFS_OK;
}

/* Data stream writes */

static void fext_key(uint8_t* key, uint64_t id, uint64_t logical) {
	apfs_key_hdr(key, id, APFS_TYPE_FILE_EXTENT);
	apfs_put64(key + 8, logical);
}

static int fext_insert(apfs_vol_t* vol, uint64_t id, uint64_t logical, uint64_t len, paddr_t phys) {
	uint8_t key[16], val[24];
	fext_key(key, id, logical);
	apfs_put64(val, len & J_FILE_EXTENT_LEN_MASK);
	apfs_put64(val + 8, phys);
	apfs_put64(val + 16, 0);
	return apfs_bt_insert(&vol->fs, key, sizeof(key), val, sizeof(val));
}

static int all_zero(const uint8_t* p, size_t n) {
	size_t i;
	for(i = 0; i < n; i++)
		if(p[i])
			return 0;
	return 1;
}

/* Writes `size` bytes from `src` as the contents of a data stream that has no
 * extents yet. With `sparse`, all-zero blocks become holes. */
static int dstream_write_internal(apfs_vol_t* vol, uint64_t id, uint64_t size, apfs_source_fn src, void* ctx,
		apfs_dstream_t* ds, int sparse, uint64_t* sparse_bytes) {
	apfs_nx_t* nx = vol->nx;
	uint32_t bs = nx->bs;
	uint64_t nblocks = (size + bs - 1) / bs;
	uint64_t logical = 0, remaining = size;
	size_t bufsize = 256 * bs;
	uint8_t* buf;
	int ret;

	ret = apfs_vol_mark_dirty(vol);
	if(ret < 0)
		return ret;
	if(sparse_bytes)
		*sparse_bytes = 0;
	buf = (uint8_t*)apfs_malloc(bufsize);

	while(nblocks > 0) {
		uint64_t chunk_blocks = nblocks > bufsize / bs ? bufsize / bs : nblocks;
		size_t want = (size_t)(remaining < chunk_blocks * bs ? remaining : chunk_blocks * bs);
		size_t have = 0;
		uint64_t b = 0;

		while(have < want) {
			size_t n = src(ctx, buf + have, want - have);
			if(n == 0)
				break;
			have += n;
		}
		if(have < want) {
			free(buf);
			APFS_ERR("unexpected end of input data");
			return APFS_EIO;
		}
		memset(buf + have, 0, (size_t)(chunk_blocks * bs - have));

		while(b < chunk_blocks) {
			uint64_t run = 1;
			if(sparse && all_zero(buf + b * bs, bs)) {
				while(b + run < chunk_blocks && all_zero(buf + (b + run) * bs, bs))
					run++;
				ret = fext_insert(vol, id, logical, run * bs, 0);
				if(ret < 0) {
					free(buf);
					return ret;
				}
				if(sparse_bytes)
					*sparse_bytes += run * bs;
			} else {
				paddr_t start;
				uint64_t got;
				while(b + run < chunk_blocks && !(sparse && all_zero(buf + (b + run) * bs, bs)))
					run++;
				ret = apfs_sm_alloc(nx, vol, run, 0, &start, &got);
				if(ret < 0) {
					free(buf);
					return ret;
				}
				run = got;
				ret = apfs_write_blocks(nx, start, got, buf + b * bs);
				if(ret == APFS_OK)
					ret = fext_insert(vol, id, logical, got * bs, start);
				if(ret == APFS_OK)
					ret = apfs_phys_extent_add(vol, start, got, id);
				if(ret < 0) {
					free(buf);
					return ret;
				}
			}
			logical += run * bs;
			b += run;
		}
		nblocks -= chunk_blocks;
		remaining -= want;
	}
	free(buf);

	memset(ds, 0, sizeof(*ds));
	ds->size = size;
	ds->alloced_size = logical;
	ds->bytes_written = size;
	return APFS_OK;
}

int apfs_dstream_write(apfs_vol_t* vol, uint64_t id, uint64_t size, apfs_source_fn src, void* ctx, apfs_dstream_t* ds) {
	return dstream_write_internal(vol, id, size, src, ctx, ds, 0, NULL);
}

int apfs_dstream_write_sparse(apfs_vol_t* vol, uint64_t id, uint64_t size, apfs_source_fn src, void* ctx,
		apfs_dstream_t* ds, uint64_t* sparse_bytes) {
	return dstream_write_internal(vol, id, size, src, ctx, ds, 1, sparse_bytes);
}

/* Removes every extent of a data stream, releasing its blocks */
int apfs_dstream_release(apfs_vol_t* vol, uint64_t id) {
	apfs_extent_t* ext;
	uint64_t* logical;
	size_t n, i;
	int ret;

	if(vol->sealed)
		return APFS_EROFS;
	ret = apfs_vol_mark_dirty(vol);
	if(ret < 0)
		return ret;
	ret = apfs_dstream_extents(vol, id, &ext, &n, &logical);
	if(ret < 0)
		return ret;
	for(i = 0; i < n && ret == APFS_OK; i++) {
		uint8_t key[16];
		fext_key(key, id, logical[i]);
		ret = apfs_bt_delete(&vol->fs, key, sizeof(key));
		if(ret == APFS_OK && ext[i].start)
			ret = apfs_phys_extent_put(vol, ext[i].start, ext[i].count);
	}
	free(ext);
	free(logical);
	return ret;
}
