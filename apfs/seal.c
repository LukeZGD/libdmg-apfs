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

#define NODE_HDR_SIZE 56
#define NODE_INFO_SIZE 40

/* The .root_hash companion in an IPSW is an IM4P around 208 bytes of
 * metadata. It contains the seal for the on-disk 4 KiB catalog and seals
 * for the same records laid out as 8 KiB and 16 KiB catalogs. Those latter
 * trees are never written to disk; they let restore software use one image
 * on devices with any of the supported APFS block sizes. */

typedef struct {
	uint16_t klen;
	uint16_t vlen;
	uint8_t* kv;
} root_hash_rec_t;

typedef struct {
	uint64_t id;                  /* relative to the root, as stored in indexes */
	uint16_t level;
	root_hash_rec_t* rec;
	uint32_t nrec;
	uint32_t cap;
} root_hash_node_t;

typedef struct {
	uint32_t bs;
	uint32_t hash_size;
	btree_info_t info;
	root_hash_node_t** node;      /* node[id] */
	uint32_t count;
	uint32_t cap;
} root_hash_tree_t;

typedef struct {
	uint64_t stream;
	uint64_t ino;
} root_hash_stream_t;

static uint32_t root_hash_toc_bytes(uint32_t nrec) {
	uint32_t entries = (nrec + 7) & ~7U;
	if(!entries)
		entries = 8;
	return entries * 8;
}

static uint32_t root_hash_payload(const root_hash_node_t* n) {
	uint32_t i, total = 0;
	for(i = 0; i < n->nrec; i++)
		total += n->rec[i].klen + n->rec[i].vlen;
	return total;
}

static int root_hash_node_fits(const root_hash_tree_t* t, const root_hash_node_t* n, int root) {
	uint32_t avail = t->bs - NODE_HDR_SIZE - (root ? NODE_INFO_SIZE : 0);
	uint32_t toc = root_hash_toc_bytes(n->nrec);
	uint32_t payload = root_hash_payload(n);
	return toc <= avail && payload <= avail - toc;
}

static void root_hash_rec_set(root_hash_rec_t* r, const void* key, uint16_t klen, const void* val, uint16_t vlen) {
	r->kv = (uint8_t*)apfs_malloc((size_t)klen + vlen);
	memcpy(r->kv, key, klen);
	memcpy(r->kv + klen, val, vlen);
	r->klen = klen;
	r->vlen = vlen;
}

static void root_hash_node_reserve(root_hash_node_t* n, uint32_t count) {
	if(count <= n->cap)
		return;
	n->cap = count < 16 ? 16 : count * 2;
	n->rec = (root_hash_rec_t*)apfs_realloc(n->rec, n->cap * sizeof(*n->rec));
}

static void root_hash_node_insert(root_hash_node_t* n, uint32_t pos, const void* key, uint16_t klen,
		const void* val, uint16_t vlen) {
	root_hash_node_reserve(n, n->nrec + 1);
	memmove(&n->rec[pos + 1], &n->rec[pos], (n->nrec - pos) * sizeof(*n->rec));
	root_hash_rec_set(&n->rec[pos], key, klen, val, vlen);
	n->nrec++;
}

static root_hash_node_t* root_hash_node_new(root_hash_tree_t* t, uint16_t level) {
	root_hash_node_t* n = (root_hash_node_t*)apfs_calloc(1, sizeof(*n));
	if(t->count == t->cap) {
		t->cap = t->cap ? t->cap * 2 : 16;
		t->node = (root_hash_node_t**)apfs_realloc(t->node, t->cap * sizeof(*t->node));
	}
	n->id = t->count;
	n->level = level;
	t->node[t->count++] = n;
	return n;
}

static int root_hash_choose_split(const root_hash_tree_t* t, root_hash_node_t* n) {
	uint32_t save = n->nrec;
	int i;
	for(i = (int)save - 1; i >= 1; i--) {
		n->nrec = (uint32_t)i;
		if(root_hash_node_fits(t, n, 0)) {
			n->nrec = save;
			return i;
		}
	}
	n->nrec = save;
	return -1;
}

/* Splits a child as sequential insertion does: every left node is as full
 * as possible and the newest records remain at the right. */
static int root_hash_split(root_hash_tree_t* t, root_hash_node_t* parent, uint32_t pos, root_hash_node_t* n) {
	while(!root_hash_node_fits(t, n, 0)) {
		root_hash_node_t* right;
		uint8_t val[8 + APFS_HASH_MAX_SIZE];
		int at = root_hash_choose_split(t, n);
		uint32_t moved, i;
		if(at < 0)
			return APFS_ECORRUPT;
		right = root_hash_node_new(t, n->level);
		moved = n->nrec - (uint32_t)at;
		root_hash_node_reserve(right, moved);
		for(i = 0; i < moved; i++)
			right->rec[i] = n->rec[at + i];
		right->nrec = moved;
		n->nrec = (uint32_t)at;
		apfs_put64(val, right->id);
		memset(val + 8, 0, t->hash_size);
		root_hash_node_insert(parent, ++pos, right->rec[0].kv, right->rec[0].klen, val,
			(uint16_t)(8 + t->hash_size));
		n = right;
	}
	return APFS_OK;
}

static int root_hash_grow(root_hash_tree_t* t) {
	root_hash_node_t* root = t->node[0];
	root_hash_node_t* right;
	root_hash_node_t* left;
	uint8_t val[8 + APFS_HASH_MAX_SIZE];
	uint32_t last;

	/* Apple's sequential builder grows a full root before inserting the
	 * newest record: the new right child is allocated first, then a left
	 * child receives the old root.  The allocation order is observable in
	 * the relative child ids covered by the hash. */
	if(root->nrec < 2)
		return APFS_ECORRUPT;
	last = root->nrec - 1;
	right = root_hash_node_new(t, root->level);
	root_hash_node_reserve(right, 1);
	right->rec[0] = root->rec[last];
	right->nrec = 1;
	left = root_hash_node_new(t, root->level);
	left->rec = root->rec;
	left->nrec = last;
	left->cap = root->cap;
	root->rec = NULL;
	root->nrec = root->cap = 0;
	root->level++;
	apfs_put64(val, left->id);
	memset(val + 8, 0, t->hash_size);
	root_hash_node_insert(root, 0, left->rec[0].kv, left->rec[0].klen, val,
		(uint16_t)(8 + t->hash_size));
	apfs_put64(val, right->id);
	memset(val + 8, 0, t->hash_size);
	root_hash_node_insert(root, 1, right->rec[0].kv, right->rec[0].klen, val,
		(uint16_t)(8 + t->hash_size));
	return APFS_OK;
}

static int root_hash_insert(root_hash_tree_t* t, const void* key, uint16_t klen, const void* val, uint16_t vlen) {
	root_hash_node_t* path[APFS_BT_MAX_DEPTH];
	root_hash_node_t* n = t->node[0];
	int depth = 0, level, ret;

	while(1) {
		uint64_t child;
		if(depth >= APFS_BT_MAX_DEPTH)
			return APFS_ECORRUPT;
		path[depth++] = n;
		if(!n->level)
			break;
		if(!n->nrec || n->rec[n->nrec - 1].vlen < 8)
			return APFS_ECORRUPT;
		child = apfs_get64(n->rec[n->nrec - 1].kv + n->rec[n->nrec - 1].klen);
		if(child >= t->count)
			return APFS_ECORRUPT;
		n = t->node[child];
	}
	root_hash_node_insert(n, n->nrec, key, klen, val, vlen);
	for(level = depth - 1; level > 0; level--) {
		root_hash_node_t* parent = path[level - 1];
		if(!root_hash_node_fits(t, path[level], 0)) {
			ret = root_hash_split(t, parent, parent->nrec - 1, path[level]);
			if(ret < 0)
				return ret;
		}
	}
	while(!root_hash_node_fits(t, t->node[0], 1)) {
		ret = root_hash_grow(t);
		if(ret < 0)
			return ret;
	}
	t->info.bt_key_count++;
	if(klen > t->info.bt_longest_key)
		t->info.bt_longest_key = klen;
	if(vlen > t->info.bt_longest_val)
		t->info.bt_longest_val = vlen;
	return APFS_OK;
}

static void root_hash_tree_free(root_hash_tree_t* t) {
	uint32_t i, j;
	for(i = 0; i < t->count; i++) {
		root_hash_node_t* n = t->node[i];
		for(j = 0; j < n->nrec; j++)
			free(n->rec[j].kv);
		free(n->rec);
		free(n);
	}
	free(t->node);
	memset(t, 0, sizeof(*t));
}

/* Rounds the allocation count in an inode's dstream xfield to the target
 * block size, exactly as the sealer does for its alternate catalogs. */
static int root_hash_adjust_inode(uint8_t* val, uint16_t len, uint32_t bs) {
	uint32_t base = (uint32_t)offsetof(j_inode_val_t, xfields);
	uint16_t n, used, i;
	uint32_t off, end;
	if(len < base + sizeof(xf_blob_t))
		return APFS_OK;
	n = apfs_get16(val + base);
	used = apfs_get16(val + base + 2);
	off = base + 4 + (uint32_t)n * sizeof(x_field_t);
	end = off + used;
	if(off > len || end < off || end > len)
		return APFS_ECORRUPT;
	for(i = 0; i < n; i++) {
		uint8_t* h = val + base + 4 + (uint32_t)i * sizeof(x_field_t);
		uint16_t size = apfs_get16(h + 2);
		uint32_t padded = (size + 7U) & ~7U;
		if(off > end || padded > end - off)
			return APFS_ECORRUPT;
		if(h[0] == INO_EXT_TYPE_DSTREAM && size >= sizeof(j_dstream_t)) {
			uint64_t alloced = apfs_get64(val + off + 8);
			if(alloced > UINT64_MAX - (bs - 1))
				return APFS_ERANGE;
			apfs_put64(val + off + 8, (alloced + bs - 1) / bs * bs);
		}
		off += padded;
	}
	return APFS_OK;
}

static int root_hash_adjust_file_info(apfs_vol_t* vol, const uint8_t* key, uint16_t klen,
		uint8_t* val, uint16_t vlen, uint32_t bs, uint32_t hash_size, uint64_t ino) {
	uint64_t id, lba, bytes, off, end, padded;
	uint16_t blocks;
	uint32_t factor = bs / vol->nx->bs;
	apfs_sha256_ctx sha;
	apfs_inode_t inode;
	int have_inode = 0;
	uint8_t buf[1 << 16];
	static const uint8_t zero[4096];

	if(klen != sizeof(j_file_info_key_t) || vlen < 3 + hash_size ||
			(apfs_get64(key + 8) >> J_FILE_INFO_TYPE_SHIFT) != APFS_FILE_INFO_DATA_HASH || val[2] != hash_size)
		return APFS_ECORRUPT;
	blocks = apfs_get16(val);
	if(!blocks)
		return APFS_ECORRUPT;
	apfs_put16(val, (uint16_t)((blocks + factor - 1) / factor));
	if(blocks % factor == 0)
		return APFS_OK;

	id = apfs_key_id(key);
	lba = apfs_get64(key + 8) & J_FILE_INFO_LBA_MASK;
	if(blocks > UINT64_MAX / vol->nx->bs)
		return APFS_ERANGE;
	off = lba;
	bytes = (uint64_t)blocks * vol->nx->bs;
	if(off > UINT64_MAX - bytes || bytes > UINT64_MAX - (bs - 1))
		return APFS_ERANGE;
	end = off + bytes;
	padded = (bytes + bs - 1) / bs * bs;
	if(ino && apfs_inode_read(vol, ino, &inode) == APFS_OK)
		have_inode = 1;
	apfs_sha256_init(&sha);
	while(off < end) {
		size_t take = end - off > sizeof(buf) ? sizeof(buf) : (size_t)(end - off);
		int ret;
		memset(buf, 0, take);
		if(have_inode) {
			size_t got;
			ret = apfs_file_read(vol, &inode, off, buf, take, &got);
		} else {
			ret = apfs_dstream_read(vol, id, end, off, buf, take);
		}
		if(ret < 0)
			break;
		apfs_sha256_update(&sha, buf, take);
		off += take;
	}
	if(have_inode)
		apfs_inode_release(&inode);
	if(off < end)
		return APFS_EIO;
	bytes = padded - (uint64_t)blocks * vol->nx->bs;
	while(bytes) {
		size_t take = bytes > sizeof(zero) ? sizeof(zero) : (size_t)bytes;
		apfs_sha256_update(&sha, zero, take);
		bytes -= take;
	}
	apfs_sha256_final(&sha, val + 3);
	return APFS_OK;
}

static int root_hash_adjust_xattr(uint8_t* val, uint16_t vlen, uint32_t bs) {
	uint16_t len;
	uint64_t alloced;
	if(vlen < 4)
		return APFS_ECORRUPT;
	len = apfs_get16(val + 2);
	if(len > vlen - 4)
		return APFS_ECORRUPT;
	if(!(apfs_get16(val) & XATTR_DATA_STREAM))
		return APFS_OK;
	if(len < sizeof(j_xattr_dstream_t))
		return APFS_ECORRUPT;
	alloced = apfs_get64(val + 20);
	if(alloced > UINT64_MAX - (bs - 1))
		return APFS_ERANGE;
	apfs_put64(val + 20, (alloced + bs - 1) / bs * bs);
	return APFS_OK;
}

static void root_hash_stream_add(root_hash_stream_t** streams, size_t* count, size_t* cap,
		uint64_t stream, uint64_t ino) {
	size_t i;
	for(i = 0; i < *count; i++) {
		if((*streams)[i].stream == stream) {
			(*streams)[i].ino = ino;
			return;
		}
	}
	if(*count == *cap) {
		*cap = *cap ? *cap * 2 : 64;
		*streams = (root_hash_stream_t*)apfs_realloc(*streams, *cap * sizeof(**streams));
	}
	(*streams)[*count].stream = stream;
	(*streams)[*count].ino = ino;
	(*count)++;
}

static uint64_t root_hash_stream_owner(const root_hash_stream_t* streams, size_t count, uint64_t stream) {
	size_t i;
	for(i = 0; i < count; i++)
		if(streams[i].stream == stream)
			return streams[i].ino;
	return 0;
}

static int root_hash_collect(apfs_vol_t* vol, uint32_t bs, uint32_t hash_size, root_hash_tree_t* t) {
	apfs_btiter_t it;
	apfs_kv_t kv;
	root_hash_stream_t* streams = NULL;
	size_t nstreams = 0, stream_cap = 0;
	int ret;

	memset(t, 0, sizeof(*t));
	t->bs = bs;
	t->hash_size = hash_size;
	t->info.bt_fixed.bt_flags = vol->fs.info.bt_fixed.bt_flags;
	t->info.bt_fixed.bt_node_size = bs;
	root_hash_node_new(t, 0);

	ret = apfs_bt_iter_seek(&it, &vol->fs, NULL, 0);
	while(ret == APFS_OK && it.valid) {
		uint8_t* val;
		uint8_t type;
		apfs_bt_iter_get(&it, &kv);
		val = (uint8_t*)apfs_malloc(kv.vlen ? kv.vlen : 1);
		memcpy(val, kv.v, kv.vlen);
		type = apfs_key_type(kv.k);
		if(type == APFS_TYPE_INODE) {
			if(kv.klen >= 8 && kv.vlen >= 16)
				root_hash_stream_add(&streams, &nstreams, &stream_cap, apfs_get64(kv.v + 8), apfs_key_id(kv.k));
			ret = root_hash_adjust_inode(val, kv.vlen, bs);
		} else if(type == APFS_TYPE_XATTR && kv.klen >= 10 + sizeof(RESOURCEFORK_EA_NAME) &&
				apfs_get16(kv.k + 8) == sizeof(RESOURCEFORK_EA_NAME) &&
				!memcmp(kv.k + 10, RESOURCEFORK_EA_NAME, sizeof(RESOURCEFORK_EA_NAME)) &&
				kv.vlen >= 4 + sizeof(j_xattr_dstream_t) &&
				(apfs_get16(kv.v) & XATTR_DATA_STREAM) && apfs_get16(kv.v + 2) >= sizeof(j_xattr_dstream_t) &&
				apfs_get16(kv.v + 2) <= kv.vlen - 4) {
			apfs_inode_t inode;
			uint64_t ino = apfs_key_id(kv.k);
			ret = root_hash_adjust_xattr(val, kv.vlen, bs);
			if(apfs_inode_read(vol, ino, &inode) == APFS_OK) {
				if(inode.bsd_flags & APFS_UF_COMPRESSED)
					root_hash_stream_add(&streams, &nstreams, &stream_cap, apfs_get64(kv.v + 4), ino);
				apfs_inode_release(&inode);
			}
		} else if(type == APFS_TYPE_XATTR) {
			ret = root_hash_adjust_xattr(val, kv.vlen, bs);
		} else if(type == APFS_TYPE_FILE_INFO) {
			uint64_t stream = kv.klen >= 8 ? apfs_key_id(kv.k) : 0;
			ret = root_hash_adjust_file_info(vol, kv.k, kv.klen, val, kv.vlen, bs, hash_size,
				root_hash_stream_owner(streams, nstreams, stream));
		}
		if(ret == APFS_OK)
			ret = root_hash_insert(t, kv.k, kv.klen, val, kv.vlen);
		free(val);
		if(ret == APFS_OK)
			ret = apfs_bt_iter_next(&it);
	}
	if(ret == APFS_OK)
		t->info.bt_node_count = t->count;
	free(streams);
	return ret;
}

static int root_hash_node_digest(root_hash_tree_t* t, root_hash_node_t* n, uint8_t out[APFS_HASH_MAX_SIZE]) {
	uint8_t* raw = (uint8_t*)apfs_calloc(1, t->bs);
	uint32_t toc = root_hash_toc_bytes(n->nrec);
	uint32_t key_start = NODE_HDR_SIZE + toc;
	uint32_t val_end = t->bs - (n->id == 0 ? NODE_INFO_SIZE : 0);
	uint32_t koff = 0, voff = 0, i;
	uint16_t flags = BTNODE_HASHED | BTNODE_NOHEADER;
	int ret = APFS_OK;

	if(!n->level)
		flags |= BTNODE_LEAF;
	if(!n->id)
		flags |= BTNODE_ROOT;
	if(!root_hash_node_fits(t, n, !n->id)) {
		free(raw);
		return APFS_ECORRUPT;
	}
	apfs_put16(raw + 32, flags);
	apfs_put16(raw + 34, n->level);
	apfs_put32(raw + 36, n->nrec);
	apfs_put16(raw + 42, (uint16_t)toc);

	for(i = 0; i < n->nrec; i++) {
		root_hash_rec_t* r = &n->rec[i];
		uint8_t* val = r->kv + r->klen;
		if(n->level) {
			uint64_t child = apfs_get64(val);
			if(r->vlen != 8 + t->hash_size || child >= t->count) {
				ret = APFS_ECORRUPT;
				break;
			}
			ret = root_hash_node_digest(t, t->node[child], val + 8);
			if(ret < 0)
				break;
		}
		memcpy(raw + key_start + koff, r->kv, r->klen);
		voff += r->vlen;
		memcpy(raw + val_end - voff, val, r->vlen);
		apfs_put16(raw + NODE_HDR_SIZE + i * 8, (uint16_t)koff);
		apfs_put16(raw + NODE_HDR_SIZE + i * 8 + 2, r->klen);
		apfs_put16(raw + NODE_HDR_SIZE + i * 8 + 4, (uint16_t)voff);
		apfs_put16(raw + NODE_HDR_SIZE + i * 8 + 6, r->vlen);
		koff += r->klen;
	}
	if(ret == APFS_OK) {
		apfs_put16(raw + 44, (uint16_t)koff);
		apfs_put16(raw + 46, (uint16_t)((val_end - voff) - (key_start + koff)));
		apfs_put16(raw + 48, BTOFF_INVALID);
		apfs_put16(raw + 52, BTOFF_INVALID);
		if(!n->id) {
			uint8_t* info = raw + t->bs - NODE_INFO_SIZE;
			apfs_put32(info, t->info.bt_fixed.bt_flags);
			apfs_put32(info + 4, t->info.bt_fixed.bt_node_size);
			apfs_put32(info + 8, t->info.bt_fixed.bt_key_size);
			apfs_put32(info + 12, t->info.bt_fixed.bt_val_size);
			apfs_put32(info + 16, t->info.bt_longest_key);
			apfs_put32(info + 20, t->info.bt_longest_val);
			apfs_put64(info + 24, t->info.bt_key_count);
			apfs_put64(info + 32, t->info.bt_node_count);
		}
		apfs_sha256(raw, t->bs, out);
	}
	free(raw);
	return ret;
}

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

int apfs_vol_root_hash_metadata(apfs_vol_t* vol, uint8_t out[APFS_ROOT_HASH_METADATA_SIZE]) {
	uint8_t root[APFS_HASH_MAX_SIZE];
	root_hash_tree_t tree;
	uint32_t type, size;
	xid_t broken;
	int ret;

	ret = apfs_vol_seal_info(vol, &type, root, &size, &broken);
	if(ret < 0)
		return ret;
	if(broken)
		return APFS_ECORRUPT;
	/* Apple's root-hash companions and the file-data records needed to
	 * rebuild their alternate trees currently use SHA-256. */
	if(type != APFS_HASH_SHA256 || size != APFS_HASH_CCSHA256_SIZE)
		return APFS_EUNSUPP;
	if(vol->nx->bs != 4096 || !vol->fs.hashed || !vol->fs.noheader)
		return APFS_EUNSUPP;

	memset(out, 0, APFS_ROOT_HASH_METADATA_SIZE);
	apfs_put32(out, 2);
	apfs_put32(out + 8, type);
	apfs_put32(out + 12, size);
	memcpy(out + 16, root, size);
	ret = root_hash_collect(vol, 8192, size, &tree);
	APFS_DEBUG("root-hash 8 KiB catalog: %u nodes, level %u", tree.count, tree.count ? tree.node[0]->level : 0);
	if(ret == APFS_OK)
		ret = root_hash_node_digest(&tree, tree.node[0], out + 16 + APFS_HASH_MAX_SIZE);
	root_hash_tree_free(&tree);
	if(ret < 0)
		return ret;

	ret = root_hash_collect(vol, 16384, size, &tree);
	APFS_DEBUG("root-hash 16 KiB catalog: %u nodes, level %u", tree.count, tree.count ? tree.node[0]->level : 0);
	if(ret == APFS_OK)
		ret = root_hash_node_digest(&tree, tree.node[0], out + 16 + 2 * APFS_HASH_MAX_SIZE);
	root_hash_tree_free(&tree);
	return ret;
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
