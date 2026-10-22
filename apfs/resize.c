/*
 * resize.c
 * apfs-tool
 *
 * Growing a container. The space manager's chunk-info blocks, chunk-info
 * address blocks and bitmaps are laid out again for the new size; when the
 * internal pool that holds them has to get bigger, it moves to a free
 * contiguous range, usually the space that was just added.
 */

#include <stdlib.h>
#include <string.h>

#include "apfs/apfs.h"

uint16_t apfs_ip_fq_node_limit(uint64_t chunks);
uint16_t apfs_main_fq_node_limit(uint64_t blocks);

static int bget(const uint8_t* bm, uint64_t i) {
	return (bm[i >> 3] >> (i & 7)) & 1;
}

static void bset(uint8_t* bm, uint64_t i) {
	bm[i >> 3] |= (uint8_t)(1 << (i & 7));
}

static uint64_t popcount_range(const uint8_t* bm, uint64_t start, uint64_t count) {
	uint64_t n = 0, i;
	for(i = start; i < start + count; i++)
		n += bget(bm, i);
	return n;
}

static uint32_t max_volumes_for(uint64_t bytes) {
	uint64_t v = (bytes + 512ULL * 1024 * 1024 - 1) / (512ULL * 1024 * 1024);
	if(v > NX_MAX_FILE_SYSTEMS)
		v = NX_MAX_FILE_SYSTEMS;
	return v ? (uint32_t)v : 1;
}

/* Finds `count` contiguous free blocks, preferring `hint` */
static int find_free_run(apfs_sm_t* sm, uint64_t count, uint64_t hint, paddr_t* out) {
	uint64_t start, run = 0, i;
	if(hint + count <= sm->nblocks) {
		for(i = 0; i < count && !bget(sm->bitmap, hint + i); i++)
			;
		if(i == count) {
			*out = hint;
			return APFS_OK;
		}
	}
	start = 0;
	for(i = 1; i < sm->nblocks; i++) {
		if(bget(sm->bitmap, i)) {
			run = 0;
			start = i + 1;
			continue;
		}
		if(++run == count) {
			*out = start;
			return APFS_OK;
		}
	}
	return APFS_ENOSPC;
}

int apfs_nx_resize(apfs_nx_t* nx, uint64_t new_size) {
	apfs_sm_t* sm = &nx->sm;
	apfs_eph_t* e;
	spaceman_phys_t* p;
	uint32_t bs = nx->bs;
	uint64_t newblocks = new_size / bs, oldblocks;
	uint64_t nchunks, ncib, ncab, ip_blocks, i;
	uint32_t bpc, cpc, cpcab, ipbm, ring, addr_off, sm_size;
	paddr_t ip_base, slot;
	uint8_t* ipbitmap;
	uint8_t** cibs;
	uint8_t** cabs;
	paddr_t* cib_addr;
	paddr_t* cab_addr;
	int ret;

	ret = apfs_nx_begin(nx);
	if(ret < 0)
		return ret;
	oldblocks = LE64(nx->sb->nx_block_count);
	if(newblocks < oldblocks) {
		APFS_ERR("shrinking containers is not supported");
		return APFS_EUNSUPP;
	}
	if(newblocks == oldblocks)
		return APFS_OK;

	e = apfs_nx_eph(nx, LE64(nx->sb->nx_spaceman_oid));
	p = (spaceman_phys_t*)e->data;
	bpc = sm->blocks_per_chunk;
	cpc = sm->chunks_per_cib;
	cpcab = sm->cibs_per_cab;
	nchunks = (newblocks + bpc - 1) / bpc;
	ncib = (nchunks + cpc - 1) / cpc;
	ncab = (ncib + cpcab - 1) / cpcab;
	if(ncab == 1)
		ncab = 0;
	ip_blocks = (nchunks + ncib + ncab) * 3;
	ipbm = (uint32_t)((ip_blocks + bpc - 1) / bpc);
	ring = LE32(p->sm_ip_bm_block_count);
	if(ipbm != LE32(p->sm_ip_bm_size_in_blocks)) {
		APFS_ERR("growing this much would need a bigger internal pool bitmap, which is not supported");
		return APFS_EUNSUPP;
	}
	if(LE64(p->sm_fq[SFQ_IP].sfq_count)) {
		apfs_eph_t* fq = apfs_nx_eph(nx, LE64(p->sm_fq[SFQ_IP].sfq_tree_oid));
		/* the queued blocks belong to the old internal pool, which is released wholesale */
		if(!fq || !(apfs_get16(fq->data + 32) & BTNODE_LEAF)) {
			APFS_ERR("the internal pool free queue is too large to reset");
			return APFS_EUNSUPP;
		}
	}

	/* extend the in-memory bitmap; the new blocks are free */
	nx->sb->nx_block_count = LE64(newblocks);
	sm->bitmap = (uint8_t*)apfs_realloc(sm->bitmap, (size_t)nchunks * bs);
	if(nchunks > sm->nchunks)
		memset(sm->bitmap + sm->nchunks * bs, 0, (size_t)((nchunks - sm->nchunks) * bs));
	for(i = oldblocks; i < sm->nchunks * bpc && i < newblocks; i++)
		sm->bitmap[i >> 3] &= (uint8_t)~(1 << (i & 7));
	for(i = newblocks; i < nchunks * bpc; i++)
		bset(sm->bitmap, i);
	sm->free_count += newblocks - oldblocks;
	sm->nblocks = newblocks;
	sm->chunk_dirty = (uint8_t*)apfs_realloc(sm->chunk_dirty, (size_t)nchunks);
	memset(sm->chunk_dirty, 0, (size_t)nchunks);

	/* blocks freed earlier in this transaction stay allocated until commit;
	 * apply them now so the layout below sees the real usage */
	{
		size_t k;
		for(k = 0; k < sm->npend; k++) {
			uint64_t b;
			for(b = sm->pend[k].start; b < sm->pend[k].start + sm->pend[k].count; b++) {
				if(bget(sm->bitmap, b)) {
					sm->bitmap[b >> 3] &= (uint8_t)~(1 << (b & 7));
					sm->free_count++;
				}
			}
		}
		sm->npend = 0;
	}

	/* place the internal pool */
	ip_base = sm->ip_base;
	if(ip_blocks != sm->ip_blocks) {
		uint64_t b;
		ret = find_free_run(sm, ip_blocks, oldblocks, &ip_base);
		if(ret < 0) {
			APFS_ERR("no room for the space manager's internal pool");
			return ret;
		}
		for(b = ip_base; b < ip_base + ip_blocks; b++)
			bset(sm->bitmap, b);
		sm->free_count -= ip_blocks;
		/* release the old pool */
		for(b = sm->ip_base; b < sm->ip_base + sm->ip_blocks; b++) {
			if(bget(sm->bitmap, b)) {
				sm->bitmap[b >> 3] &= (uint8_t)~(1 << (b & 7));
				sm->free_count++;
			}
		}
		/* an emptied internal pool free queue */
		{
			apfs_eph_t* fq = apfs_nx_eph(nx, LE64(p->sm_fq[SFQ_IP].sfq_tree_oid));
			if(fq) {
				uint8_t* d = fq->data;
				uint16_t toc = apfs_get16(d + 42);
				apfs_put32(d + 36, 0);
				apfs_put16(d + 44, 0);
				apfs_put16(d + 46, (uint16_t)(bs - 56 - toc - 40));
				apfs_put16(d + 48, BTOFF_INVALID);
				apfs_put16(d + 50, 0);
				apfs_put16(d + 52, BTOFF_INVALID);
				apfs_put16(d + 54, 0);
				memset(d + 56 + toc, 0, bs - 56 - toc - 40);
				apfs_put64(d + bs - 40 + 24, 0);
			}
			p->sm_fq[SFQ_IP].sfq_count = 0;
			p->sm_fq[SFQ_IP].sfq_oldest_xid = 0;
		}
	}

	/* lay out the pool: CABs, CIBs, then bitmaps of the chunks in use */
	cibs = (uint8_t**)apfs_calloc((size_t)ncib, sizeof(uint8_t*));
	cib_addr = (paddr_t*)apfs_calloc((size_t)ncib, sizeof(paddr_t));
	cabs = (uint8_t**)apfs_calloc(ncab ? (size_t)ncab : 1, sizeof(uint8_t*));
	cab_addr = (paddr_t*)apfs_calloc(ncab ? (size_t)ncab : 1, sizeof(paddr_t));
	ipbitmap = (uint8_t*)apfs_calloc(ipbm, bs);
	slot = 0;
	for(i = 0; i < ncab; i++) {
		cab_addr[i] = ip_base + slot;
		bset(ipbitmap, slot++);
	}
	for(i = 0; i < ncib; i++) {
		cib_addr[i] = ip_base + slot;
		bset(ipbitmap, slot++);
	}

	for(i = 0; i < ncib && ret == APFS_OK; i++) {
		chunk_info_block_t* cib;
		uint64_t first = i * cpc, c;
		uint32_t count = (uint32_t)((nchunks - first) > cpc ? cpc : (nchunks - first));
		cibs[i] = (uint8_t*)apfs_calloc(1, bs);
		cib = (chunk_info_block_t*)cibs[i];
		cib->cib_o.o_oid = LE64(cib_addr[i]);
		cib->cib_o.o_xid = LE64(nx->txn);
		cib->cib_o.o_type = LE32(OBJ_PHYSICAL | OBJECT_TYPE_SPACEMAN_CIB);
		cib->cib_index = LE32((uint32_t)i);
		cib->cib_chunk_info_count = LE32(count);
		for(c = 0; c < count && ret == APFS_OK; c++) {
			uint64_t chunk = first + c;
			uint64_t cstart = chunk * bpc;
			uint32_t blocks = (uint32_t)((newblocks - cstart) > bpc ? bpc : (newblocks - cstart));
			uint64_t used = popcount_range(sm->bitmap, cstart, blocks);
			chunk_info_t* ci = &cib->cib_chunk_info[c];
			ci->ci_xid = LE64(nx->txn);
			ci->ci_addr = LE64(cstart);
			ci->ci_block_count = LE32(blocks);
			ci->ci_free_count = LE32((uint32_t)(blocks - used));
			if(used) {
				uint8_t* out = (uint8_t*)apfs_malloc(bs);
				uint32_t b;
				memcpy(out, sm->bitmap + chunk * bs, bs);
				for(b = blocks; b < bpc; b++)
					out[b >> 3] &= (uint8_t)~(1 << (b & 7));
				ci->ci_bitmap_addr = LE64(ip_base + slot);
				bset(ipbitmap, slot);
				ret = apfs_write_blocks(nx, ip_base + slot, 1, out);
				free(out);
				slot++;
			}
		}
		if(ret == APFS_OK)
			ret = apfs_write_obj(nx, cib_addr[i], cibs[i]);
	}
	for(i = 0; i < ncab && ret == APFS_OK; i++) {
		cib_addr_block_t* cab;
		uint64_t first = i * cpcab, c;
		uint32_t count = (uint32_t)((ncib - first) > cpcab ? cpcab : (ncib - first));
		cabs[i] = (uint8_t*)apfs_calloc(1, bs);
		cab = (cib_addr_block_t*)cabs[i];
		cab->cab_o.o_oid = LE64(cab_addr[i]);
		cab->cab_o.o_xid = LE64(nx->txn);
		cab->cab_o.o_type = LE32(OBJ_PHYSICAL | OBJECT_TYPE_SPACEMAN_CAB);
		cab->cab_index = LE32((uint32_t)i);
		cab->cab_cib_count = LE32(count);
		for(c = 0; c < count; c++)
			cab->cab_cib_addr[c] = LE64(cib_addr[first + c]);
		ret = apfs_write_obj(nx, cab_addr[i], cabs[i]);
	}
	if(slot > ip_blocks)
		ret = APFS_ENOSPC;

	/* the space manager object, which may need more blocks for the address array */
	if(ret == APFS_OK) {
		uint32_t off_free_next = LE32(p->sm_ip_bm_free_next_offset);
		addr_off = off_free_next + ((2 * ring + 7) & ~7U);
		sm_size = addr_off + 8 * (uint32_t)(ncab ? ncab : ncib) + 8;
		sm_size = (sm_size + bs - 1) / bs * bs;
		if(sm_size > e->size) {
			e->data = (uint8_t*)apfs_realloc(e->data, sm_size);
			memset(e->data + e->size, 0, sm_size - e->size);
			e->size = sm_size;
			p = (spaceman_phys_t*)e->data;
		}
		memset(e->data + addr_off, 0, e->size - addr_off);
		for(i = 0; i < (ncab ? ncab : ncib); i++)
			apfs_put64(e->data + addr_off + i * 8, ncab ? cab_addr[i] : cib_addr[i]);
		p->sm_dev[SD_MAIN].sm_block_count = LE64(newblocks);
		p->sm_dev[SD_MAIN].sm_chunk_count = LE64(nchunks);
		p->sm_dev[SD_MAIN].sm_cib_count = LE32((uint32_t)ncib);
		p->sm_dev[SD_MAIN].sm_cab_count = LE32((uint32_t)ncab);
		p->sm_dev[SD_MAIN].sm_addr_offset = LE32(addr_off);
		p->sm_dev[SD_TIER2].sm_addr_offset = LE32(addr_off + 8 * (uint32_t)(ncab ? ncab : ncib));
		p->sm_ip_base = LE64(ip_base);
		p->sm_ip_block_count = LE64(ip_blocks);
		p->sm_fq[SFQ_IP].sfq_tree_node_limit = LE16(apfs_ip_fq_node_limit(nchunks));
		p->sm_fq[SFQ_MAIN].sfq_tree_node_limit = LE16(apfs_main_fq_node_limit(newblocks));

		/* write the pool bitmap into the current ring slots */
		{
			uint32_t bmoff = LE32(p->sm_ip_bitmap_offset), xoff = LE32(p->sm_ip_bm_xid_offset);
			paddr_t ring_base = LE64(p->sm_ip_bm_base);
			for(i = 0; i < ipbm && ret == APFS_OK; i++) {
				uint16_t s = apfs_get16(e->data + bmoff + i * 2);
				ret = apfs_write_blocks(nx, ring_base + s % ring, 1, ipbitmap + i * bs);
				apfs_put64(e->data + xoff + i * 8, nx->txn);
			}
		}
	}

	if(ret == APFS_OK) {
		uint64_t minblk;
		/* replace the in-memory space manager state */
		for(i = 0; i < sm->ncib; i++)
			free(sm->cib[i]);
		for(i = 0; i < sm->ncab; i++)
			free(sm->cab[i]);
		free(sm->cib);
		free(sm->cib_addr);
		free(sm->cab);
		free(sm->cab_addr);
		free(sm->ip_bitmap);
		sm->cib = cibs;
		sm->cib_addr = cib_addr;
		sm->cab = ncab ? cabs : NULL;
		sm->cab_addr = ncab ? cab_addr : NULL;
		if(!ncab) {
			free(cabs);
			free(cab_addr);
		}
		sm->ncib = (uint32_t)ncib;
		sm->ncab = (uint32_t)ncab;
		sm->nchunks = nchunks;
		sm->ip_base = ip_base;
		sm->ip_blocks = ip_blocks;
		sm->ip_bitmap = ipbitmap;
		sm->ip_dirty = 0;

		nx->sb->nx_max_file_systems = LE32(max_volumes_for(newblocks * bs));
		minblk = (newblocks * bs < 128ULL * 1024 * 1024) ? apfs_main_fq_node_limit(newblocks) : NX_EPH_MIN_BLOCK_COUNT;
		nx->sb->nx_ephemeral_info[0] = LE64((minblk << 32) | ((uint64_t)NX_MAX_FILE_SYSTEM_EPH_STRUCTS << 16) | NX_EPH_INFO_VERSION_1);
		nx->dirty = 1;
		return APFS_OK;
	}

	for(i = 0; i < ncib; i++)
		free(cibs[i]);
	for(i = 0; i < ncab; i++)
		free(cabs[i]);
	free(cibs);
	free(cabs);
	free(cib_addr);
	free(cab_addr);
	free(ipbitmap);
	return ret;
}
