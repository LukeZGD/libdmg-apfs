/*
 * omap.c
 * apfs-tool
 *
 * Object maps: translate virtual object identifiers into physical addresses
 * for a given transaction.
 */

#include <stdlib.h>
#include <string.h>

#include "apfs/apfs.h"

int apfs_omap_open(apfs_omap_t* om, apfs_nx_t* nx, apfs_vol_t* vol, paddr_t paddr) {
	uint32_t type;
	int ret;

	memset(om, 0, sizeof(*om));
	om->nx = nx;
	om->vol = vol;
	om->paddr = paddr;
	om->raw = (uint8_t*)apfs_malloc(nx->bs);
	ret = apfs_read_obj(nx, paddr, om->raw, &type, NULL, NULL, NULL);
	if(ret < 0) {
		free(om->raw);
		om->raw = NULL;
		return ret;
	}
	if((type & OBJECT_TYPE_MASK) != OBJECT_TYPE_OMAP) {
		APFS_ERR("block 0x%llx is not an object map", (unsigned long long)paddr);
		free(om->raw);
		om->raw = NULL;
		return APFS_ECORRUPT;
	}
	apfs_bt_init(&om->tree, nx, vol, NULL, OBJ_PHYSICAL, OBJECT_TYPE_OMAP,
			LE64(APFS_OMAP_PHYS(om)->om_tree_oid), apfs_cmp_omap);
	ret = apfs_bt_load(&om->tree);
	if(ret < 0) {
		free(om->raw);
		om->raw = NULL;
		return ret;
	}
	om->loaded = 1;
	return APFS_OK;
}

int apfs_omap_create(apfs_omap_t* om, apfs_nx_t* nx, apfs_vol_t* vol, uint32_t flags) {
	omap_phys_t* p;
	int ret;

	memset(om, 0, sizeof(*om));
	om->nx = nx;
	om->vol = vol;
	ret = apfs_nx_begin(nx);
	if(ret < 0)
		return ret;
	ret = apfs_sm_alloc_block(nx, vol, &om->paddr);
	if(ret < 0)
		return ret;
	om->raw = (uint8_t*)apfs_calloc(1, nx->bs);
	p = APFS_OMAP_PHYS(om);
	p->om_o.o_oid = LE64(om->paddr);
	p->om_o.o_xid = LE64(nx->txn);
	p->om_o.o_type = LE32(OBJ_PHYSICAL | OBJECT_TYPE_OMAP);
	p->om_flags = LE32(flags);
	p->om_tree_type = LE32(OBJ_PHYSICAL | OBJECT_TYPE_BTREE);
	p->om_snapshot_tree_type = LE32(OBJ_PHYSICAL | OBJECT_TYPE_BTREE);

	apfs_bt_init(&om->tree, nx, vol, NULL, OBJ_PHYSICAL, OBJECT_TYPE_OMAP, 0, apfs_cmp_omap);
	ret = apfs_bt_create(&om->tree, BTREE_PHYSICAL, sizeof(omap_key_t), sizeof(omap_val_t));
	if(ret < 0)
		return ret;
	p->om_tree_oid = LE64(om->tree.root);
	om->dirty = 1;
	om->loaded = 1;
	return APFS_OK;
}

int apfs_omap_lookup(apfs_omap_t* om, oid_t oid, xid_t max_xid, paddr_t* paddr, xid_t* xid, uint32_t* flags) {
	uint8_t key[16];
	apfs_kv_t kv;
	int ret;

	apfs_put64(key, oid);
	apfs_put64(key + 8, max_xid ? max_xid : ~0ULL);
	ret = apfs_bt_lookup_le(&om->tree, key, sizeof(key), &kv);
	if(ret < 0)
		return ret;
	if(kv.klen != 16 || kv.vlen != 16 || apfs_get64(kv.k) != oid)
		return APFS_ENOENT;
	if(paddr)
		*paddr = apfs_get64(kv.v + 8);
	if(xid)
		*xid = apfs_get64(kv.k + 8);
	if(flags)
		*flags = apfs_get32(kv.v);
	return APFS_OK;
}

int apfs_omap_set(apfs_omap_t* om, oid_t oid, xid_t xid, uint32_t flags, paddr_t paddr) {
	uint8_t key[16], val[16];
	apfs_put64(key, oid);
	apfs_put64(key + 8, xid);
	apfs_put32(val, flags);
	apfs_put32(val + 4, om->nx->bs);
	apfs_put64(val + 8, paddr);
	om->dirty = 1;
	return apfs_bt_insert(&om->tree, key, sizeof(key), val, sizeof(val));
}

int apfs_omap_remove(apfs_omap_t* om, oid_t oid, xid_t xid) {
	uint8_t key[16];
	apfs_put64(key, oid);
	apfs_put64(key + 8, xid);
	om->dirty = 1;
	return apfs_bt_delete(&om->tree, key, sizeof(key));
}

/* Is the mapping created by this transaction still visible to a snapshot? */
static int held_by_snapshot(apfs_omap_t* om, xid_t xid) {
	omap_phys_t* p = APFS_OMAP_PHYS(om);
	return LE32(p->om_snap_count) && xid <= LE64(p->om_most_recent_snap);
}

/* A virtual object is about to be rewritten in the current transaction:
 * give it a new block and map it, releasing the old one unless a snapshot
 * still needs it. */
int apfs_omap_cow(apfs_omap_t* om, oid_t oid, xid_t old_xid, paddr_t old_paddr, paddr_t* new_paddr, uint32_t vflags) {
	apfs_nx_t* nx = om->nx;
	int ret;

	ret = apfs_sm_alloc_block(nx, om->vol, new_paddr);
	if(ret < 0)
		return ret;
	ret = apfs_omap_set(om, oid, nx->txn, vflags, *new_paddr);
	if(ret < 0)
		return ret;
	if(old_xid == nx->txn || !old_paddr)
		return APFS_OK;
	if(held_by_snapshot(om, old_xid))
		return APFS_OK;
	ret = apfs_omap_remove(om, oid, old_xid);
	if(ret < 0 && ret != APFS_ENOENT)
		return ret;
	return apfs_sm_free(nx, om->vol, old_paddr, 1);
}

/* Removes a virtual object from the current transaction */
int apfs_omap_delete_object(apfs_omap_t* om, oid_t oid, xid_t xid, paddr_t paddr) {
	apfs_nx_t* nx = om->nx;
	paddr_t old_paddr;
	xid_t old_xid;
	uint32_t old_flags;
	int ret;

	if(xid == nx->txn) {
		ret = apfs_omap_remove(om, oid, xid);
		if(ret < 0 && ret != APFS_ENOENT)
			return ret;
		ret = apfs_sm_free(nx, om->vol, paddr, 1);
		if(ret < 0)
			return ret;
		/* an older mapping kept for a snapshot must stop being visible */
		ret = apfs_omap_lookup(om, oid, nx->txn - 1, &old_paddr, &old_xid, &old_flags);
		if(ret == APFS_ENOENT)
			return APFS_OK;
		if(ret < 0)
			return ret;
		if(old_flags & OMAP_VAL_DELETED)
			return APFS_OK;
		return apfs_omap_set(om, oid, nx->txn, OMAP_VAL_DELETED, 0);
	}

	if(held_by_snapshot(om, xid))
		return apfs_omap_set(om, oid, nx->txn, OMAP_VAL_DELETED, 0);

	ret = apfs_omap_remove(om, oid, xid);
	if(ret < 0 && ret != APFS_ENOENT)
		return ret;
	return apfs_sm_free(nx, om->vol, paddr, 1);
}

/* Writes the tree and relocates the omap object if anything changed */
int apfs_omap_flush(apfs_omap_t* om) {
	apfs_nx_t* nx = om->nx;
	omap_phys_t* p = APFS_OMAP_PHYS(om);
	int ret;

	if(!om->loaded)
		return APFS_OK;
	if(om->tree.ndirty)
		om->dirty = 1;
	ret = apfs_bt_flush(&om->tree);
	if(ret < 0)
		return ret;
	if(!om->dirty && LE64(p->om_tree_oid) == om->tree.root)
		return APFS_OK;

	if(LE64(p->om_o.o_xid) != nx->txn) {
		paddr_t newp;
		ret = apfs_sm_alloc_block(nx, om->vol, &newp);
		if(ret < 0)
			return ret;
		ret = apfs_sm_free(nx, om->vol, om->paddr, 1);
		if(ret < 0)
			return ret;
		om->paddr = newp;
	}
	p->om_o.o_oid = LE64(om->paddr);
	p->om_o.o_xid = LE64(nx->txn);
	p->om_o.o_type = LE32(OBJ_PHYSICAL | OBJECT_TYPE_OMAP);
	p->om_o.o_subtype = 0;
	p->om_tree_oid = LE64(om->tree.root);
	ret = apfs_write_obj(nx, om->paddr, om->raw);
	if(ret < 0)
		return ret;
	om->dirty = 0;
	return APFS_OK;
}

int apfs_omap_list(apfs_omap_t* om, apfs_omap_rec_t** out, size_t* count) {
	apfs_omap_rec_t* list = NULL;
	size_t n = 0, cap = 0;
	apfs_btiter_t it;
	apfs_kv_t kv;
	int ret;

	ret = apfs_bt_iter_seek(&it, &om->tree, NULL, 0);
	while(ret == APFS_OK && it.valid) {
		apfs_bt_iter_get(&it, &kv);
		if(kv.klen == 16 && kv.vlen == 16) {
			if(n == cap) {
				cap = cap ? cap * 2 : 256;
				list = (apfs_omap_rec_t*)apfs_realloc(list, cap * sizeof(apfs_omap_rec_t));
			}
			list[n].oid = apfs_get64(kv.k);
			list[n].xid = apfs_get64(kv.k + 8);
			list[n].flags = apfs_get32(kv.v);
			list[n].size = apfs_get32(kv.v + 4);
			list[n].paddr = apfs_get64(kv.v + 8);
			n++;
		}
		ret = apfs_bt_iter_next(&it);
	}
	if(ret < 0) {
		free(list);
		return ret;
	}
	*out = list;
	*count = n;
	return APFS_OK;
}

void apfs_omap_close(apfs_omap_t* om) {
	if(!om->loaded)
		return;
	apfs_bt_close(&om->tree);
	free(om->raw);
	om->raw = NULL;
	om->loaded = 0;
}
