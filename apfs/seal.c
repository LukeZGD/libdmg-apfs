/*
 * seal.c
 * apfs-tool
 *
 * Sealed volumes keep their file-system tree hashed and header-less, their
 * file extents in a separate tree, and hashes of all file data. Unsealing
 * turns such a volume back into a plain, writable one.
 */

#include <stdlib.h>
#include <string.h>

#include "apfs/apfs.h"

static int read_integrity_meta(apfs_vol_t* vol, uint8_t* buf, paddr_t* paddr, xid_t* xid) {
	oid_t oid = LE64(vol->sb->apfs_integrity_meta_oid);
	uint32_t type, flags;
	int ret;

	if(!oid)
		return APFS_ENOENT;
	ret = apfs_omap_lookup(vol->fs.omap, oid, vol->fs.read_xid, paddr, xid, &flags);
	if(ret < 0)
		return ret == APFS_ENOENT ? APFS_ECORRUPT : ret;
	if(flags & OMAP_VAL_DELETED)
		return APFS_ECORRUPT;
	ret = apfs_read_obj(vol->nx, *paddr, buf, &type, NULL, NULL, NULL);
	if(ret < 0)
		return ret;
	if((type & OBJECT_TYPE_MASK) != OBJECT_TYPE_INTEGRITY_META)
		return APFS_ECORRUPT;
	return APFS_OK;
}

int apfs_vol_seal_info(apfs_vol_t* vol, uint32_t* hash_type, uint8_t* root_hash, uint32_t* hash_size, xid_t* broken_xid) {
	uint8_t* buf;
	integrity_meta_phys_t* im;
	paddr_t paddr;
	xid_t xid;
	uint32_t off, size;
	int ret;

	if(!vol->sealed)
		return APFS_ENOENT;
	buf = (uint8_t*)apfs_malloc(vol->nx->bs);
	ret = read_integrity_meta(vol, buf, &paddr, &xid);
	if(ret < 0) {
		free(buf);
		return ret;
	}
	im = (integrity_meta_phys_t*)buf;
	switch(LE32(im->im_hash_type)) {
		case APFS_HASH_SHA256: size = APFS_HASH_CCSHA256_SIZE; break;
		case APFS_HASH_SHA512_256: size = APFS_HASH_CCSHA512_256_SIZE; break;
		case APFS_HASH_SHA384: size = APFS_HASH_CCSHA384_SIZE; break;
		case APFS_HASH_SHA512: size = APFS_HASH_CCSHA512_SIZE; break;
		default: size = 0; break;
	}
	off = LE32(im->im_root_hash_offset);
	if(!size || off < sizeof(integrity_meta_phys_t) || off + size > vol->nx->bs) {
		free(buf);
		return APFS_ECORRUPT;
	}
	*hash_type = LE32(im->im_hash_type);
	*hash_size = size;
	memcpy(root_hash, buf + off, size);
	*broken_xid = (LE32(im->im_flags) & APFS_SEAL_BROKEN) ? LE64(im->im_broken_xid) : 0;
	free(buf);
	return APFS_OK;
}

int apfs_vol_unseal(apfs_vol_t* vol) {
	apfs_superblock_t* vsb = vol->sb;
	apfs_btree_t tree;
	apfs_btiter_t it;
	apfs_kv_t kv;
	uint8_t* buf;
	paddr_t paddr;
	xid_t xid;
	int ret;

	if(!vol->sealed)
		return APFS_OK;
	if(LE64(vsb->apfs_num_snapshots)) {
		APFS_ERR("the volume's snapshots must be deleted before it can be unsealed");
		return APFS_EBUSY;
	}
	ret = apfs_vol_mark_dirty(vol);
	if(ret < 0)
		return ret;

	/* the same records in a plain tree, without the data hashes */
	apfs_bt_init(&tree, vol->nx, vol, &vol->omap, OBJ_VIRTUAL, OBJECT_TYPE_FSTREE, 0, apfs_cmp_fs);
	ret = apfs_bt_create(&tree, BTREE_SEQUENTIAL_INSERT | BTREE_KV_NONALIGNED, 0, 0);
	if(ret == APFS_OK)
		ret = apfs_bt_iter_seek(&it, &vol->fs, NULL, 0);
	while(ret == APFS_OK && it.valid) {
		apfs_bt_iter_get(&it, &kv);
		if(apfs_key_type(kv.k) != APFS_TYPE_FILE_INFO)
			ret = apfs_bt_insert(&tree, kv.k, kv.klen, kv.v, kv.vlen);
		if(ret == APFS_OK)
			ret = apfs_bt_iter_next(&it);
	}

	/* file extents move back into the file-system tree */
	if(ret == APFS_OK && vol->fext.loaded)
		ret = apfs_bt_iter_seek(&it, &vol->fext, NULL, 0);
	while(ret == APFS_OK && vol->fext.loaded && it.valid) {
		uint8_t key[16], val[24];
		apfs_bt_iter_get(&it, &kv);
		if(kv.klen == 16 && kv.vlen == 16) {
			apfs_key_hdr(key, apfs_get64(kv.k), APFS_TYPE_FILE_EXTENT);
			memcpy(key + 8, kv.k + 8, 8);
			memcpy(val, kv.v, 16);
			apfs_put64(val + 16, 0);
			ret = apfs_bt_insert(&tree, key, sizeof(key), val, sizeof(val));
		}
		if(ret == APFS_OK)
			ret = apfs_bt_iter_next(&it);
	}
	if(ret < 0) {
		apfs_bt_close(&tree);
		return ret;
	}

	/* release the sealed structures */
	if(vsb->apfs_integrity_meta_oid) {
		buf = (uint8_t*)apfs_malloc(vol->nx->bs);
		ret = read_integrity_meta(vol, buf, &paddr, &xid);
		free(buf);
		if(ret == APFS_OK)
			ret = apfs_omap_delete_object(&vol->omap, LE64(vsb->apfs_integrity_meta_oid), xid, paddr);
	}
	if(ret == APFS_OK)
		ret = apfs_bt_free_all(&vol->fs);
	if(ret == APFS_OK && vol->fext.loaded)
		ret = apfs_bt_free_all(&vol->fext);
	if(ret < 0) {
		apfs_bt_close(&tree);
		return ret;
	}

	vol->fs = tree;
	vsb->apfs_root_tree_oid = LE64(tree.root);
	vsb->apfs_root_tree_type = LE32(OBJ_VIRTUAL | OBJECT_TYPE_BTREE);
	vsb->apfs_integrity_meta_oid = 0;
	vsb->apfs_fext_tree_oid = 0;
	vsb->apfs_incompatible_features = LE64(LE64(vsb->apfs_incompatible_features) & ~(uint64_t)APFS_INCOMPAT_SEALED_VOLUME);
	vol->sealed = 0;
	vol->dirty = 1;
	return APFS_OK;
}
