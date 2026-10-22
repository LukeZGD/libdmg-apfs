/*
 * container.c
 * apfs-tool
 *
 * Container mounting (checkpoint selection), block I/O and transaction
 * commit, which writes a new checkpoint.
 */

#include <stdlib.h>
#include <string.h>

#include "apfs/apfs.h"

int apfs_read_blocks(apfs_nx_t* nx, paddr_t bno, uint64_t count, void* buf) {
	if(!count)
		return APFS_OK;
	if(nx->sb && (bno + count > LE64(nx->sb->nx_block_count) || bno + count < bno)) {
		APFS_ERR("read of block 0x%llx beyond the end of the container", (unsigned long long)bno);
		return APFS_EIO;
	}
	if(!nx->io->read(nx->io, (off_t)(nx->base + bno * nx->bs), (size_t)(count * nx->bs), buf)) {
		APFS_ERR("cannot read block 0x%llx", (unsigned long long)bno);
		return APFS_EIO;
	}
	return APFS_OK;
}

int apfs_write_blocks(apfs_nx_t* nx, paddr_t bno, uint64_t count, const void* buf) {
	if(!count)
		return APFS_OK;
	if(!nx->writable)
		return APFS_EROFS;
	if(nx->sb && bno + count > LE64(nx->sb->nx_block_count)) {
		APFS_ERR("write of block 0x%llx beyond the end of the container", (unsigned long long)bno);
		return APFS_EIO;
	}
	if(!nx->io->write(nx->io, (off_t)(nx->base + bno * nx->bs), (size_t)(count * nx->bs), (void*)buf)) {
		APFS_ERR("cannot write block 0x%llx", (unsigned long long)bno);
		return APFS_EIO;
	}
	nx->blocks_written += count;
	return APFS_OK;
}

int apfs_read_obj(apfs_nx_t* nx, paddr_t bno, void* buf, uint32_t* type, uint32_t* subtype, oid_t* oid, xid_t* xid) {
	obj_phys_t* o = (obj_phys_t*)buf;
	int ret = apfs_read_blocks(nx, bno, 1, buf);
	if(ret < 0)
		return ret;
	if(!apfs_obj_verify(buf, nx->bs)) {
		APFS_ERR("bad checksum in object at block 0x%llx", (unsigned long long)bno);
		return APFS_ECORRUPT;
	}
	if(type)
		*type = LE32(o->o_type);
	if(subtype)
		*subtype = LE32(o->o_subtype);
	if(oid)
		*oid = LE64(o->o_oid);
	if(xid)
		*xid = LE64(o->o_xid);
	return APFS_OK;
}

int apfs_write_obj(apfs_nx_t* nx, paddr_t bno, void* buf) {
	apfs_obj_set_cksum(buf, nx->bs);
	return apfs_write_blocks(nx, bno, 1, buf);
}

apfs_eph_t* apfs_nx_eph(apfs_nx_t* nx, oid_t oid) {
	uint32_t i;
	for(i = 0; i < nx->neph; i++)
		if(nx->eph[i].oid == oid)
			return &nx->eph[i];
	return NULL;
}

oid_t apfs_nx_new_oid(apfs_nx_t* nx) {
	oid_t oid = LE64(nx->sb->nx_next_oid);
	nx->sb->nx_next_oid = LE64(oid + 1);
	nx->dirty = 1;
	return oid;
}

int apfs_nx_volume_count(apfs_nx_t* nx) {
	int i, n = 0;
	for(i = 0; i < NX_MAX_FILE_SYSTEMS; i++)
		if(nx->sb->nx_fs_oid[i])
			n++;
	return n;
}

int apfs_nx_begin(apfs_nx_t* nx) {
	if(!nx->writable)
		return APFS_EROFS;
	if(!nx->txn) {
		nx->txn = LE64(nx->sb->nx_next_xid);
		if(!nx->sm.loaded) {
			int ret = apfs_sm_load(nx);
			if(ret < 0) {
				nx->txn = 0;
				return ret;
			}
		}
	}
	return APFS_OK;
}

static void free_eph(apfs_nx_t* nx) {
	uint32_t i;
	for(i = 0; i < nx->neph; i++)
		free(nx->eph[i].data);
	free(nx->eph);
	nx->eph = NULL;
	nx->neph = 0;
}

/* Reads the checkpoint maps of a checkpoint and its ephemeral objects */
static int load_checkpoint(apfs_nx_t* nx, const nx_superblock_t* sb) {
	uint32_t desc_blocks = LE32(sb->nx_xp_desc_blocks);
	uint32_t data_blocks = LE32(sb->nx_xp_data_blocks);
	paddr_t desc_base = LE64(sb->nx_xp_desc_base);
	paddr_t data_base = LE64(sb->nx_xp_data_base);
	uint32_t index = LE32(sb->nx_xp_desc_index);
	uint32_t len = LE32(sb->nx_xp_desc_len);
	uint8_t* buf = (uint8_t*)apfs_malloc(nx->bs);
	uint32_t i;
	int ret = APFS_OK;

	free_eph(nx);
	if(len < 1 || len > desc_blocks || !data_blocks) {
		free(buf);
		return APFS_ECORRUPT;
	}

	for(i = 0; i + 1 < len; i++) {
		checkpoint_map_phys_t* cpm = (checkpoint_map_phys_t*)buf;
		uint32_t type, count, j;
		xid_t xid;

		ret = apfs_read_obj(nx, desc_base + (index + i) % desc_blocks, buf, &type, NULL, NULL, &xid);
		if(ret < 0)
			break;
		if((type & OBJECT_TYPE_MASK) != OBJECT_TYPE_CHECKPOINT_MAP || xid != LE64(sb->nx_o.o_xid)) {
			ret = APFS_ECORRUPT;
			break;
		}
		count = LE32(cpm->cpm_count);
		if(sizeof(checkpoint_map_phys_t) + count * sizeof(checkpoint_mapping_t) > nx->bs) {
			ret = APFS_ECORRUPT;
			break;
		}
		for(j = 0; j < count; j++) {
			checkpoint_mapping_t* m = &cpm->cpm_map[j];
			apfs_eph_t* e;
			uint32_t size = LE32(m->cpm_size);
			uint32_t nblk = size / nx->bs, b;
			paddr_t paddr = LE64(m->cpm_paddr);

			if(!size || size % nx->bs || paddr < data_base || paddr >= data_base + data_blocks) {
				ret = APFS_ECORRUPT;
				break;
			}
			nx->eph = (apfs_eph_t*)apfs_realloc(nx->eph, (nx->neph + 1) * sizeof(apfs_eph_t));
			e = &nx->eph[nx->neph];
			e->oid = LE64(m->cpm_oid);
			e->type = LE32(m->cpm_type);
			e->subtype = LE32(m->cpm_subtype);
			e->size = size;
			e->fs_oid = LE64(m->cpm_fs_oid);
			e->data = (uint8_t*)apfs_malloc(size);
			nx->neph++;
			for(b = 0; b < nblk && ret == APFS_OK; b++) {
				paddr_t blk = data_base + ((paddr - data_base) + b) % data_blocks;
				ret = apfs_read_blocks(nx, blk, 1, e->data + (size_t)b * nx->bs);
			}
			if(ret < 0)
				break;
			if(!apfs_obj_verify(e->data, size)) {
				APFS_ERR("bad checksum in ephemeral object 0x%llx", (unsigned long long)e->oid);
				ret = APFS_ECORRUPT;
				break;
			}
		}
		if(ret < 0)
			break;
		if(LE32(cpm->cpm_flags) & CHECKPOINT_MAP_LAST)
			break;
	}
	free(buf);
	if(ret < 0)
		free_eph(nx);
	return ret;
}

int apfs_nx_open(apfs_nx_t** out, io_func* io, uint64_t base, int writable) {
	apfs_nx_t* nx = (apfs_nx_t*)apfs_calloc(1, sizeof(apfs_nx_t));
	nx_superblock_t* sb0;
	uint8_t* buf;
	uint8_t* best = NULL;
	xid_t best_xid = 0;
	uint32_t desc_blocks, i, bs;
	paddr_t desc_base;
	int ret;

	nx->io = io;
	nx->base = base;
	nx->writable = writable;
	nx->bs = NX_DEFAULT_BLOCK_SIZE;

	buf = (uint8_t*)apfs_malloc(NX_MAXIMUM_BLOCK_SIZE);
	if(!io->read(io, (off_t)base, NX_DEFAULT_BLOCK_SIZE, buf)) {
		APFS_ERR("cannot read the container superblock");
		free(buf);
		free(nx);
		return APFS_EIO;
	}
	sb0 = (nx_superblock_t*)buf;
	if(LE32(sb0->nx_magic) != NX_MAGIC) {
		free(buf);
		free(nx);
		return APFS_EINVAL;
	}
	bs = LE32(sb0->nx_block_size);
	if(bs < NX_MINIMUM_BLOCK_SIZE || bs > NX_MAXIMUM_BLOCK_SIZE || (bs & (bs - 1))) {
		APFS_ERR("unsupported block size %u", bs);
		free(buf);
		free(nx);
		return APFS_ECORRUPT;
	}
	nx->bs = bs;
	if(bs != NX_DEFAULT_BLOCK_SIZE && !io->read(io, (off_t)base, bs, buf)) {
		free(buf);
		free(nx);
		return APFS_EIO;
	}
	if(!apfs_obj_verify(buf, bs))
		APFS_WARN("the superblock copy in block zero has a bad checksum");
	if(LE64(sb0->nx_incompatible_features) & NX_INCOMPAT_FUSION) {
		APFS_ERR("Fusion containers are not supported");
		free(buf);
		free(nx);
		return APFS_EUNSUPP;
	}

	desc_blocks = LE32(sb0->nx_xp_desc_blocks);
	desc_base = LE64(sb0->nx_xp_desc_base);
	if(desc_blocks & 0x80000000U || desc_base >> 63) {
		APFS_ERR("non-contiguous checkpoint descriptor areas are not supported");
		free(buf);
		free(nx);
		return APFS_EUNSUPP;
	}

	/* Find the newest valid checkpoint superblock in the descriptor area */
	{
		uint8_t* cand = (uint8_t*)apfs_malloc(bs);
		xid_t tried_below = ~0ULL;
		for(;;) {
			best_xid = 0;
			free(best);
			best = NULL;
			for(i = 0; i < desc_blocks; i++) {
				nx_superblock_t* s = (nx_superblock_t*)cand;
				xid_t x;
				if(!io->read(io, (off_t)(base + (desc_base + i) * bs), bs, cand))
					continue;
				if(!apfs_obj_verify(cand, bs))
					continue;
				if((LE32(s->nx_o.o_type) & OBJECT_TYPE_MASK) != OBJECT_TYPE_NX_SUPERBLOCK || LE32(s->nx_magic) != NX_MAGIC)
					continue;
				x = LE64(s->nx_o.o_xid);
				if(x >= tried_below || x <= best_xid)
					continue;
				best_xid = x;
				if(!best)
					best = (uint8_t*)apfs_malloc(bs);
				memcpy(best, cand, bs);
			}
			if(!best)
				break;
			nx->sbraw = best;
			nx->sb = (nx_superblock_t*)best;
			ret = load_checkpoint(nx, nx->sb);
			if(ret == APFS_OK)
				break;
			APFS_WARN("checkpoint %llu is damaged, trying an older one", (unsigned long long)best_xid);
			nx->sbraw = NULL;
			nx->sb = NULL;
			tried_below = best_xid;
		}
		free(cand);
	}
	free(buf);

	if(!best) {
		APFS_ERR("no valid checkpoint found");
		free(nx);
		return APFS_ECORRUPT;
	}
	best = NULL;
	nx->xid = LE64(nx->sb->nx_o.o_xid);

	ret = apfs_omap_open(&nx->omap, nx, NULL, LE64(nx->sb->nx_omap_oid));
	if(ret < 0) {
		free_eph(nx);
		free(nx->sbraw);
		free(nx);
		return ret;
	}

	*out = nx;
	return APFS_OK;
}

/* Writes the ephemeral objects, the checkpoint maps and the superblock */
static int write_checkpoint(apfs_nx_t* nx) {
	nx_superblock_t* sb = nx->sb;
	uint32_t bs = nx->bs;
	uint32_t desc_blocks = LE32(sb->nx_xp_desc_blocks);
	uint32_t data_blocks = LE32(sb->nx_xp_data_blocks);
	paddr_t desc_base = LE64(sb->nx_xp_desc_base);
	paddr_t data_base = LE64(sb->nx_xp_data_base);
	uint32_t data_start = LE32(sb->nx_xp_data_next) % data_blocks;
	uint32_t desc_start = LE32(sb->nx_xp_desc_next) % desc_blocks;
	uint32_t per_map = (bs - sizeof(checkpoint_map_phys_t)) / sizeof(checkpoint_mapping_t);
	uint32_t nmaps = nx->neph ? (nx->neph + per_map - 1) / per_map : 1;
	uint32_t data_len = 0, off, i, m;
	uint8_t* buf;
	int ret;

	for(i = 0; i < nx->neph; i++)
		data_len += nx->eph[i].size / bs;
	if(data_len > data_blocks || nmaps + 1 > desc_blocks) {
		APFS_ERR("checkpoint areas are too small");
		return APFS_ENOSPC;
	}

	/* ephemeral objects */
	off = 0;
	for(i = 0; i < nx->neph; i++) {
		apfs_eph_t* e = &nx->eph[i];
		obj_phys_t* o = (obj_phys_t*)e->data;
		uint32_t b, nblk = e->size / bs;
		o->o_xid = LE64(nx->txn);
		apfs_obj_set_cksum(e->data, e->size);
		for(b = 0; b < nblk; b++) {
			paddr_t blk = data_base + (data_start + off + b) % data_blocks;
			ret = apfs_write_blocks(nx, blk, 1, e->data + (size_t)b * bs);
			if(ret < 0)
				return ret;
		}
		off += nblk;
	}

	/* checkpoint maps */
	buf = (uint8_t*)apfs_malloc(bs);
	off = 0;
	for(m = 0; m < nmaps; m++) {
		checkpoint_map_phys_t* cpm = (checkpoint_map_phys_t*)buf;
		paddr_t blk = desc_base + (desc_start + m) % desc_blocks;
		uint32_t first = m * per_map, count = 0;

		memset(buf, 0, bs);
		cpm->cpm_o.o_oid = LE64(blk);
		cpm->cpm_o.o_xid = LE64(nx->txn);
		cpm->cpm_o.o_type = LE32(OBJ_PHYSICAL | OBJECT_TYPE_CHECKPOINT_MAP);
		cpm->cpm_o.o_subtype = 0;
		for(i = first; i < nx->neph && count < per_map; i++, count++) {
			apfs_eph_t* e = &nx->eph[i];
			checkpoint_mapping_t* map = &cpm->cpm_map[count];
			map->cpm_type = LE32(e->type);
			map->cpm_subtype = LE32(e->subtype);
			map->cpm_size = LE32(e->size);
			map->cpm_pad = 0;
			map->cpm_fs_oid = LE64(e->fs_oid);
			map->cpm_oid = LE64(e->oid);
			map->cpm_paddr = LE64(data_base + (data_start + off) % data_blocks);
			off += e->size / bs;
		}
		cpm->cpm_count = LE32(count);
		cpm->cpm_flags = LE32(m == nmaps - 1 ? CHECKPOINT_MAP_LAST : 0);
		ret = apfs_write_obj(nx, blk, buf);
		if(ret < 0) {
			free(buf);
			return ret;
		}
	}
	free(buf);

	/* superblock */
	sb->nx_o.o_oid = LE64(OID_NX_SUPERBLOCK);
	sb->nx_o.o_xid = LE64(nx->txn);
	sb->nx_o.o_type = LE32(OBJ_EPHEMERAL | OBJECT_TYPE_NX_SUPERBLOCK);
	sb->nx_o.o_subtype = 0;
	sb->nx_next_xid = LE64(nx->txn + 1);
	sb->nx_xp_desc_index = LE32(desc_start);
	sb->nx_xp_desc_len = LE32(nmaps + 1);
	sb->nx_xp_desc_next = LE32((desc_start + nmaps + 1) % desc_blocks);
	sb->nx_xp_data_index = LE32(data_start);
	sb->nx_xp_data_len = LE32(data_len);
	sb->nx_xp_data_next = LE32((data_start + data_len) % data_blocks);
	sb->nx_omap_oid = LE64(nx->omap.paddr);

	ret = apfs_write_obj(nx, desc_base + (desc_start + nmaps) % desc_blocks, nx->sbraw);
	if(ret < 0)
		return ret;
	return apfs_write_obj(nx, 0, nx->sbraw);
}

int apfs_nx_commit(apfs_nx_t* nx) {
	int i, ret;

	if(!nx->writable || !nx->txn)
		return APFS_OK;

	for(i = 0; i < NX_MAX_FILE_SYSTEMS; i++) {
		if(nx->vols[i] && nx->vols[i]->dirty) {
			ret = apfs_vol_flush(nx->vols[i]);
			if(ret < 0)
				return ret;
		}
	}

	ret = apfs_omap_flush(&nx->omap);
	if(ret < 0)
		return ret;
	ret = apfs_sm_flush(nx);
	if(ret < 0)
		return ret;
	ret = write_checkpoint(nx);
	if(ret < 0)
		return ret;

	nx->xid = nx->txn;
	nx->txn = 0;
	nx->dirty = 0;
	return APFS_OK;
}

int apfs_nx_close(apfs_nx_t* nx) {
	int i, ret = APFS_OK;
	if(!nx)
		return APFS_OK;
	if(nx->writable && nx->txn)
		ret = apfs_nx_commit(nx);
	for(i = 0; i < NX_MAX_FILE_SYSTEMS; i++)
		if(nx->vols[i])
			apfs_vol_close(nx->vols[i]);
	apfs_omap_close(&nx->omap);
	apfs_sm_close(nx);
	free_eph(nx);
	free(nx->sbraw);
	free(nx);
	return ret;
}

int apfs_dev_size_blocks(apfs_nx_t* nx, uint64_t* blocks) {
	*blocks = LE64(nx->sb->nx_block_count);
	return APFS_OK;
}
