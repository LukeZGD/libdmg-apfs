/*
 * spaceman.c
 * apfs-tool
 *
 * Space manager: tracks block allocation for the container. The whole
 * allocation bitmap is kept in memory while the container is writable. Freed
 * blocks only become available once the transaction is committed, so the
 * previous checkpoint stays intact until the new one is written.
 */

#include <stdlib.h>
#include <string.h>

#include "apfs/apfs.h"

#define SM_PHYS(nx) ((spaceman_phys_t*)apfs_nx_eph((nx), LE64((nx)->sb->nx_spaceman_oid))->data)

static inline int bit_get(const uint8_t* bm, uint64_t i) {
	return (bm[i >> 3] >> (i & 7)) & 1;
}

static inline void bit_set(uint8_t* bm, uint64_t i) {
	bm[i >> 3] |= (uint8_t)(1 << (i & 7));
}

static inline void bit_clear(uint8_t* bm, uint64_t i) {
	bm[i >> 3] &= (uint8_t)~(1 << (i & 7));
}

static uint64_t popcount_bytes(const uint8_t* p, size_t n) {
	uint64_t c = 0;
	size_t i;
	for(i = 0; i < n; i++) {
		uint8_t b = p[i];
		while(b) {
			b &= (uint8_t)(b - 1);
			c++;
		}
	}
	return c;
}

static apfs_eph_t* sm_eph(apfs_nx_t* nx) {
	return apfs_nx_eph(nx, LE64(nx->sb->nx_spaceman_oid));
}

static uint64_t sm_val(apfs_eph_t* e, uint32_t off) {
	return apfs_get64(e->data + off);
}

static int load_cib(apfs_nx_t* nx, apfs_sm_t* sm, uint32_t index, paddr_t addr, uint64_t* expected_start) {
	uint8_t* buf = (uint8_t*)apfs_malloc(nx->bs);
	chunk_info_block_t* cib = (chunk_info_block_t*)buf;
	uint32_t type, count, i;
	int ret;

	ret = apfs_read_obj(nx, addr, buf, &type, NULL, NULL, NULL);
	if(ret < 0) {
		free(buf);
		return ret;
	}
	if((type & OBJECT_TYPE_MASK) != OBJECT_TYPE_SPACEMAN_CIB) {
		APFS_ERR("block 0x%llx is not a chunk-info block", (unsigned long long)addr);
		free(buf);
		return APFS_ECORRUPT;
	}
	count = LE32(cib->cib_chunk_info_count);
	if(count > sm->chunks_per_cib) {
		free(buf);
		return APFS_ECORRUPT;
	}
	for(i = 0; i < count; i++) {
		chunk_info_t* ci = &cib->cib_chunk_info[i];
		uint64_t caddr = LE64(ci->ci_addr);
		uint64_t chunk = caddr / sm->blocks_per_chunk;
		paddr_t bmaddr = LE64(ci->ci_bitmap_addr);

		if(caddr != *expected_start || chunk >= sm->nchunks) {
			APFS_ERR("chunk-info block %u is inconsistent", index);
			free(buf);
			return APFS_ECORRUPT;
		}
		if(bmaddr) {
			ret = apfs_read_blocks(nx, bmaddr, 1, sm->bitmap + chunk * nx->bs);
			if(ret < 0) {
				free(buf);
				return ret;
			}
		}
		*expected_start += LE32(ci->ci_block_count) & CI_COUNT_MASK;
	}
	sm->cib[index] = buf;
	sm->cib_addr[index] = addr;
	return APFS_OK;
}

int apfs_sm_load(apfs_nx_t* nx) {
	apfs_sm_t* sm = &nx->sm;
	apfs_eph_t* e = sm_eph(nx);
	spaceman_phys_t* p;
	uint64_t start = 0, i;
	uint32_t addr_off;
	int ret;

	if(sm->loaded)
		return APFS_OK;
	if(!e) {
		APFS_ERR("space manager is missing from the checkpoint");
		return APFS_ECORRUPT;
	}
	p = (spaceman_phys_t*)e->data;
	if(LE64(p->sm_dev[SD_TIER2].sm_block_count)) {
		APFS_ERR("Fusion containers are not supported for writing");
		return APFS_EUNSUPP;
	}
	if(LE32(p->sm_block_size) != nx->bs) {
		APFS_ERR("space manager block size mismatch");
		return APFS_ECORRUPT;
	}

	memset(sm, 0, sizeof(*sm));
	sm->blocks_per_chunk = LE32(p->sm_blocks_per_chunk);
	sm->chunks_per_cib = LE32(p->sm_chunks_per_cib);
	sm->cibs_per_cab = LE32(p->sm_cibs_per_cab);
	sm->nblocks = LE64(p->sm_dev[SD_MAIN].sm_block_count);
	sm->nchunks = LE64(p->sm_dev[SD_MAIN].sm_chunk_count);
	sm->ncib = LE32(p->sm_dev[SD_MAIN].sm_cib_count);
	sm->ncab = LE32(p->sm_dev[SD_MAIN].sm_cab_count);
	sm->free_count = LE64(p->sm_dev[SD_MAIN].sm_free_count);
	addr_off = LE32(p->sm_dev[SD_MAIN].sm_addr_offset);

	if(sm->blocks_per_chunk != nx->bs * 8 || sm->nblocks > LE64(nx->sb->nx_block_count) || !sm->nchunks) {
		APFS_ERR("space manager geometry is invalid");
		return APFS_ECORRUPT;
	}

	sm->bitmap = (uint8_t*)apfs_calloc(sm->nchunks, nx->bs);
	sm->chunk_dirty = (uint8_t*)apfs_calloc(sm->nchunks, 1);
	sm->cib_addr = (paddr_t*)apfs_calloc(sm->ncib, sizeof(paddr_t));
	sm->cib = (uint8_t**)apfs_calloc(sm->ncib, sizeof(uint8_t*));

	if(sm->ncab == 0) {
		for(i = 0; i < sm->ncib; i++) {
			if(addr_off + (i + 1) * 8 > e->size)
				return APFS_ECORRUPT;
			ret = load_cib(nx, sm, (uint32_t)i, sm_val(e, addr_off + (uint32_t)i * 8), &start);
			if(ret < 0)
				return ret;
		}
	} else {
		uint32_t cibn = 0;
		sm->cab_addr = (paddr_t*)apfs_calloc(sm->ncab, sizeof(paddr_t));
		sm->cab = (uint8_t**)apfs_calloc(sm->ncab, sizeof(uint8_t*));
		for(i = 0; i < sm->ncab; i++) {
			uint8_t* buf = (uint8_t*)apfs_malloc(nx->bs);
			cib_addr_block_t* cab = (cib_addr_block_t*)buf;
			uint32_t type, j, count;
			if(addr_off + (i + 1) * 8 > e->size) {
				free(buf);
				return APFS_ECORRUPT;
			}
			sm->cab_addr[i] = sm_val(e, addr_off + (uint32_t)i * 8);
			ret = apfs_read_obj(nx, sm->cab_addr[i], buf, &type, NULL, NULL, NULL);
			if(ret < 0 || (type & OBJECT_TYPE_MASK) != OBJECT_TYPE_SPACEMAN_CAB) {
				free(buf);
				return ret < 0 ? ret : APFS_ECORRUPT;
			}
			sm->cab[i] = buf;
			count = LE32(cab->cab_cib_count);
			for(j = 0; j < count; j++) {
				if(cibn >= sm->ncib)
					return APFS_ECORRUPT;
				ret = load_cib(nx, sm, cibn, LE64(cab->cab_cib_addr[j]), &start);
				if(ret < 0)
					return ret;
				cibn++;
			}
		}
	}

	if(start != sm->nblocks) {
		APFS_ERR("space manager chunks do not cover the container");
		return APFS_ECORRUPT;
	}

	/* blocks past the end of the device are never allocatable */
	for(i = sm->nblocks; i < sm->nchunks * sm->blocks_per_chunk; i++)
		bit_set(sm->bitmap, i);

	/* internal pool */
	sm->ip_base = LE64(p->sm_ip_base);
	sm->ip_blocks = LE64(p->sm_ip_block_count);
	{
		uint32_t bm_blocks = LE32(p->sm_ip_bm_size_in_blocks);
		uint32_t ring = LE32(p->sm_ip_bm_block_count);
		paddr_t bm_base = LE64(p->sm_ip_bm_base);
		uint32_t off = LE32(p->sm_ip_bitmap_offset);
		sm->ip_bitmap = (uint8_t*)apfs_calloc(bm_blocks ? bm_blocks : 1, nx->bs);
		for(i = 0; i < bm_blocks; i++) {
			uint16_t slot;
			if(off + (i + 1) * 2 > e->size || !ring)
				return APFS_ECORRUPT;
			slot = apfs_get16(e->data + off + i * 2);
			ret = apfs_read_blocks(nx, bm_base + slot % ring, 1, sm->ip_bitmap + i * nx->bs);
			if(ret < 0)
				return ret;
		}
	}

	sm->hint = 0;
	sm->meta_hint = 0;
	sm->loaded = 1;
	return APFS_OK;
}

void apfs_sm_close(apfs_nx_t* nx) {
	apfs_sm_t* sm = &nx->sm;
	uint32_t i;
	if(!sm->loaded)
		return;
	for(i = 0; i < sm->ncib; i++)
		free(sm->cib[i]);
	for(i = 0; i < sm->ncab; i++)
		free(sm->cab[i]);
	free(sm->cib);
	free(sm->cib_addr);
	free(sm->cab);
	free(sm->cab_addr);
	free(sm->bitmap);
	free(sm->chunk_dirty);
	free(sm->ip_bitmap);
	free(sm->pend);
	memset(sm, 0, sizeof(*sm));
}

static void account(apfs_vol_t* owner, int64_t delta) {
	apfs_superblock_t* vsb;
	if(!owner)
		return;
	vsb = owner->sb;
	vsb->apfs_fs_alloc_count = LE64(LE64(vsb->apfs_fs_alloc_count) + (uint64_t)delta);
	if(delta > 0)
		vsb->apfs_total_blocks_alloced = LE64(LE64(vsb->apfs_total_blocks_alloced) + (uint64_t)delta);
	else
		vsb->apfs_total_blocks_freed = LE64(LE64(vsb->apfs_total_blocks_freed) + (uint64_t)(-delta));
	owner->dirty = 1;
}

/* Finds the first free block at or after `from`, or returns nblocks */
static uint64_t find_free(apfs_sm_t* sm, uint64_t from) {
	uint64_t i = from;
	while(i < sm->nblocks) {
		if((i & 7) == 0 && i + 8 <= sm->nblocks && sm->bitmap[i >> 3] == 0xff) {
			i += 8;
			continue;
		}
		if(!bit_get(sm->bitmap, i))
			return i;
		i++;
	}
	return sm->nblocks;
}

int apfs_sm_alloc(apfs_nx_t* nx, apfs_vol_t* owner, uint64_t want, int metadata, paddr_t* start, uint64_t* got) {
	apfs_sm_t* sm = &nx->sm;
	uint64_t b, n, pass;
	paddr_t* hint;
	int ret;

	ret = apfs_nx_begin(nx);
	if(ret < 0)
		return ret;
	if(!sm->loaded) {
		ret = apfs_sm_load(nx);
		if(ret < 0)
			return ret;
	}
	if(want == 0)
		return APFS_EINVAL;

	hint = metadata ? &sm->meta_hint : &sm->hint;
	for(pass = 0; pass < 2; pass++) {
		b = find_free(sm, pass == 0 ? *hint : 0);
		if(b < sm->nblocks)
			break;
	}
	if(b >= sm->nblocks)
		return APFS_ENOSPC;

	n = 0;
	while(n < want && b + n < sm->nblocks && !bit_get(sm->bitmap, b + n))
		n++;

	for(pass = 0; pass < n; pass++) {
		bit_set(sm->bitmap, b + pass);
		sm->chunk_dirty[(b + pass) / sm->blocks_per_chunk] = 1;
	}
	sm->free_count -= n;
	*hint = b + n;
	*start = b;
	*got = n;
	account(owner, (int64_t)n);
	nx->dirty = 1;
	return APFS_OK;
}

int apfs_sm_alloc_block(apfs_nx_t* nx, apfs_vol_t* owner, paddr_t* paddr) {
	uint64_t got;
	return apfs_sm_alloc(nx, owner, 1, 1, paddr, &got);
}

int apfs_sm_free(apfs_nx_t* nx, apfs_vol_t* owner, paddr_t start, uint64_t count) {
	apfs_sm_t* sm = &nx->sm;
	int ret;

	if(!count)
		return APFS_OK;
	ret = apfs_nx_begin(nx);
	if(ret < 0)
		return ret;
	if(!sm->loaded) {
		ret = apfs_sm_load(nx);
		if(ret < 0)
			return ret;
	}
	if(start + count > sm->nblocks || start + count < start) {
		APFS_ERR("attempt to free blocks 0x%llx+%llu outside the container", (unsigned long long)start, (unsigned long long)count);
		return APFS_ECORRUPT;
	}
	if(sm->npend == sm->cappend) {
		sm->cappend = sm->cappend ? sm->cappend * 2 : 64;
		sm->pend = (apfs_extent_t*)apfs_realloc(sm->pend, sm->cappend * sizeof(apfs_extent_t));
	}
	sm->pend[sm->npend].start = start;
	sm->pend[sm->npend].count = count;
	sm->pend[sm->npend].owner = owner;
	sm->npend++;
	account(owner, -(int64_t)count);
	nx->dirty = 1;
	return APFS_OK;
}

int apfs_sm_is_free(apfs_nx_t* nx, paddr_t start, uint64_t count) {
	apfs_sm_t* sm = &nx->sm;
	uint64_t i;
	for(i = 0; i < count; i++)
		if(start + i >= sm->nblocks || bit_get(sm->bitmap, start + i))
			return 0;
	return 1;
}

int apfs_sm_mark_used(apfs_nx_t* nx, paddr_t start, uint64_t count) {
	apfs_sm_t* sm = &nx->sm;
	uint64_t i;
	for(i = 0; i < count; i++) {
		if(start + i >= sm->nblocks)
			return APFS_ERANGE;
		if(!bit_get(sm->bitmap, start + i)) {
			bit_set(sm->bitmap, start + i);
			sm->free_count--;
			sm->chunk_dirty[(start + i) / sm->blocks_per_chunk] = 1;
		}
	}
	return APFS_OK;
}

uint64_t apfs_sm_free_blocks(apfs_nx_t* nx) {
	apfs_sm_t* sm = &nx->sm;
	if(sm->loaded)
		return sm->free_count;
	{
		apfs_eph_t* e = sm_eph(nx);
		if(!e)
			return 0;
		return LE64(((spaceman_phys_t*)e->data)->sm_dev[SD_MAIN].sm_free_count);
	}
}

/* Allocates a block of the internal pool, which holds the space manager's
 * own bitmaps and chunk-info blocks */
static int ip_alloc(apfs_nx_t* nx, paddr_t* out) {
	apfs_sm_t* sm = &nx->sm;
	uint64_t i;
	for(i = 0; i < sm->ip_blocks; i++) {
		if(!bit_get(sm->ip_bitmap, i)) {
			bit_set(sm->ip_bitmap, i);
			sm->ip_dirty = 1;
			*out = sm->ip_base + i;
			return APFS_OK;
		}
	}
	APFS_ERR("the space manager's internal pool is full");
	return APFS_ENOSPC;
}

static chunk_info_t* chunk_info(apfs_sm_t* sm, uint64_t chunk, uint32_t* cibn) {
	uint32_t c = (uint32_t)(chunk / sm->chunks_per_cib);
	chunk_info_block_t* cib = (chunk_info_block_t*)sm->cib[c];
	*cibn = c;
	return &cib->cib_chunk_info[chunk % sm->chunks_per_cib];
}

/* The space manager totals the block reservations of the volumes, and how
 * much of each reservation is in use */
static int update_reserves(apfs_nx_t* nx, spaceman_phys_t* p) {
	uint64_t total = 0, used = 0;
	uint8_t* buf = NULL;
	int i, ret;

	for(i = 0; i < NX_MAX_FILE_SYSTEMS; i++) {
		const apfs_superblock_t* vsb;
		uint64_t reserve, alloc;
		oid_t oid = LE64(nx->sb->nx_fs_oid[i]);
		paddr_t paddr;

		if(!oid)
			continue;
		if(nx->vols[i]) {
			vsb = nx->vols[i]->sb;
		} else {
			if(!buf)
				buf = (uint8_t*)apfs_malloc(nx->bs);
			ret = apfs_omap_lookup(&nx->omap, oid, 0, &paddr, NULL, NULL);
			if(ret == APFS_OK)
				ret = apfs_read_obj(nx, paddr, buf, NULL, NULL, NULL, NULL);
			if(ret < 0) {
				free(buf);
				return ret;
			}
			vsb = (const apfs_superblock_t*)buf;
		}
		reserve = LE64(vsb->apfs_fs_reserve_block_count);
		alloc = LE64(vsb->apfs_fs_alloc_count);
		total += reserve;
		used += alloc < reserve ? alloc : reserve;
	}
	free(buf);
	p->sm_fs_reserve_block_count = LE64(total);
	p->sm_fs_reserve_alloc_count = LE64(used);
	return APFS_OK;
}

int apfs_sm_flush(apfs_nx_t* nx) {
	apfs_sm_t* sm = &nx->sm;
	apfs_eph_t* e;
	spaceman_phys_t* p;
	uint8_t* cib_dirty;
	uint64_t i;
	size_t k;
	int ret;

	if(!sm->loaded)
		return APFS_OK;

	/* release the blocks freed by this transaction */
	for(k = 0; k < sm->npend; k++) {
		uint64_t b;
		for(b = sm->pend[k].start; b < sm->pend[k].start + sm->pend[k].count; b++) {
			if(!bit_get(sm->bitmap, b)) {
				APFS_WARN("block 0x%llx freed twice", (unsigned long long)b);
				continue;
			}
			bit_clear(sm->bitmap, b);
			sm->free_count++;
			sm->chunk_dirty[b / sm->blocks_per_chunk] = 1;
		}
	}
	sm->npend = 0;

	cib_dirty = (uint8_t*)apfs_calloc(sm->ncib, 1);
	for(i = 0; i < sm->nchunks; i++) {
		uint32_t cibn;
		chunk_info_t* ci;
		uint8_t* bm;
		uint32_t blocks;
		uint64_t used;
		paddr_t bmaddr;

		if(!sm->chunk_dirty[i])
			continue;
		ci = chunk_info(sm, i, &cibn);
		bm = sm->bitmap + i * nx->bs;
		blocks = LE32(ci->ci_block_count) & CI_COUNT_MASK;
		used = popcount_bytes(bm, nx->bs);
		if(i == sm->nchunks - 1)
			used -= (uint64_t)sm->blocks_per_chunk - blocks; /* bits past the end are set in memory only */
		bmaddr = LE64(ci->ci_bitmap_addr);

		if(!bmaddr && used) {
			ret = ip_alloc(nx, &bmaddr);
			if(ret < 0) {
				free(cib_dirty);
				return ret;
			}
			ci->ci_bitmap_addr = LE64(bmaddr);
		}
		if(bmaddr) {
			uint8_t* out = bm;
			uint8_t* tmp = NULL;
			if(i == sm->nchunks - 1 && blocks < sm->blocks_per_chunk) {
				uint32_t b;
				tmp = (uint8_t*)apfs_malloc(nx->bs);
				memcpy(tmp, bm, nx->bs);
				for(b = blocks; b < sm->blocks_per_chunk; b++)
					bit_clear(tmp, b);
				out = tmp;
			}
			ret = apfs_write_blocks(nx, bmaddr, 1, out);
			free(tmp);
			if(ret < 0) {
				free(cib_dirty);
				return ret;
			}
		}
		ci->ci_free_count = LE32((uint32_t)(blocks - used));
		ci->ci_xid = LE64(nx->txn);
		cib_dirty[cibn] = 1;
		sm->chunk_dirty[i] = 0;
	}

	for(i = 0; i < sm->ncib; i++) {
		chunk_info_block_t* cib;
		if(!cib_dirty[i])
			continue;
		cib = (chunk_info_block_t*)sm->cib[i];
		cib->cib_o.o_xid = LE64(nx->txn);
		ret = apfs_write_obj(nx, sm->cib_addr[i], sm->cib[i]);
		if(ret < 0) {
			free(cib_dirty);
			return ret;
		}
		if(sm->ncab) {
			uint32_t cabn = (uint32_t)(i / sm->cibs_per_cab);
			cib_addr_block_t* cab = (cib_addr_block_t*)sm->cab[cabn];
			cab->cab_o.o_xid = LE64(nx->txn);
		}
	}
	if(sm->ncab) {
		for(i = 0; i < sm->ncab; i++) {
			cib_addr_block_t* cab = (cib_addr_block_t*)sm->cab[i];
			if(LE64(cab->cab_o.o_xid) != nx->txn)
				continue;
			ret = apfs_write_obj(nx, sm->cab_addr[i], sm->cab[i]);
			if(ret < 0) {
				free(cib_dirty);
				return ret;
			}
		}
	}
	free(cib_dirty);

	e = sm_eph(nx);
	p = (spaceman_phys_t*)e->data;
	p->sm_dev[SD_MAIN].sm_free_count = LE64(sm->free_count);
	ret = update_reserves(nx, p);
	if(ret < 0)
		return ret;

	if(sm->ip_dirty) {
		uint32_t bm_blocks = LE32(p->sm_ip_bm_size_in_blocks);
		uint32_t ring = LE32(p->sm_ip_bm_block_count);
		paddr_t bm_base = LE64(p->sm_ip_bm_base);
		uint32_t off = LE32(p->sm_ip_bitmap_offset);
		uint32_t xoff = LE32(p->sm_ip_bm_xid_offset);
		for(i = 0; i < bm_blocks; i++) {
			uint16_t slot = apfs_get16(e->data + off + i * 2);
			ret = apfs_write_blocks(nx, bm_base + slot % ring, 1, sm->ip_bitmap + i * nx->bs);
			if(ret < 0)
				return ret;
			apfs_put64(e->data + xoff + i * 8, nx->txn);
		}
		sm->ip_dirty = 0;
	}
	return APFS_OK;
}
