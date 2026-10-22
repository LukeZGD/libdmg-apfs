/*
 * file.c
 * apfs-tool
 *
 * File contents and file-level operations.
 */

#include <stdlib.h>
#include <string.h>

#include "apfs/apfs.h"

static int is_compressed(const apfs_inode_t* inode) {
	return (inode->bsd_flags & APFS_UF_COMPRESSED) != 0;
}

int apfs_file_size(apfs_vol_t* vol, const apfs_inode_t* inode, uint64_t* size) {
	apfs_dstream_t ds;
	if(is_compressed(inode)) {
		if(apfs_decmpfs_size(vol, inode, size) == APFS_OK)
			return APFS_OK;
	}
	if(apfs_inode_get_dstream(inode, &ds) == APFS_OK)
		*size = ds.size;
	else
		*size = 0;
	return APFS_OK;
}

int apfs_file_read(apfs_vol_t* vol, const apfs_inode_t* inode, uint64_t off, void* buf, size_t len, size_t* got) {
	apfs_dstream_t ds;
	int ret;

	*got = 0;
	if(is_compressed(inode)) {
		ret = apfs_decmpfs_read(vol, inode, off, buf, len, got);
		if(ret != APFS_ENOENT)
			return ret;
	}
	if(apfs_inode_get_dstream(inode, &ds) < 0)
		return APFS_OK;
	if(off >= ds.size)
		return APFS_OK;
	if(len > ds.size - off)
		len = (size_t)(ds.size - off);
	ret = apfs_dstream_read(vol, inode->private_id, ds.size, off, buf, len);
	if(ret == APFS_OK)
		*got = len;
	return ret;
}

int apfs_dstream_id_ensure(apfs_vol_t* vol, uint64_t id);
int apfs_inode_drop_dstream(apfs_vol_t* vol, apfs_inode_t* inode);
int apfs_dstream_write_sparse(apfs_vol_t* vol, uint64_t id, uint64_t size, apfs_source_fn src, void* ctx,
		apfs_dstream_t* ds, uint64_t* sparse_bytes);

/* Removes transparent compression from an inode, without touching its data stream */
static int drop_compression(apfs_vol_t* vol, apfs_inode_t* inode) {
	int ret;
	if(!(inode->bsd_flags & APFS_UF_COMPRESSED))
		return APFS_OK;
	ret = apfs_xattr_remove(vol, inode->ino, DECMPFS_EA_NAME);
	if(ret < 0 && ret != APFS_ENOENT)
		return ret;
	ret = apfs_xattr_remove(vol, inode->ino, RESOURCEFORK_EA_NAME);
	if(ret < 0 && ret != APFS_ENOENT)
		return ret;
	/* the xattr removals rewrote the inode flags */
	{
		apfs_inode_t fresh;
		ret = apfs_inode_read(vol, inode->ino, &fresh);
		if(ret < 0)
			return ret;
		inode->internal_flags = fresh.internal_flags;
		apfs_inode_release(&fresh);
	}
	inode->bsd_flags &= ~(uint32_t)APFS_UF_COMPRESSED;
	inode->internal_flags &= ~(uint64_t)INODE_HAS_UNCOMPRESSED_SIZE;
	inode->uncompressed_size = 0;
	return APFS_OK;
}

static int dstream_shared(apfs_vol_t* vol, const apfs_inode_t* inode) {
	uint8_t key[8];
	apfs_kv_t kv;
	apfs_key_hdr(key, inode->private_id, APFS_TYPE_DSTREAM_ID);
	if(apfs_bt_lookup(&vol->fs, key, sizeof(key), &kv) == APFS_OK && kv.vlen >= 4)
		return apfs_get32(kv.v) > 1;
	return 0;
}

int apfs_file_write_ex(apfs_vol_t* vol, uint64_t ino, apfs_source_fn src, void* ctx, uint64_t size, int flags) {
	apfs_inode_t inode;
	apfs_dstream_t ds;
	uint64_t sparse = 0, now;
	int ret;

	ret = apfs_vol_mark_dirty(vol);
	if(ret < 0)
		return ret;
	ret = apfs_inode_read(vol, ino, &inode);
	if(ret < 0)
		return ret;
	if((inode.mode & APFS_S_IFMT) != APFS_S_IFREG) {
		apfs_inode_release(&inode);
		return (inode.mode & APFS_S_IFMT) == APFS_S_IFDIR ? APFS_EISDIR : APFS_EINVAL;
	}

	ret = drop_compression(vol, &inode);
	if(ret == APFS_OK) {
		int shared = dstream_shared(vol, &inode);
		ret = apfs_inode_drop_dstream(vol, &inode);
		if(ret == APFS_OK && shared)
			inode.private_id = apfs_vol_next_id(vol);
	}
	if(ret == APFS_OK && size > 0) {
		if(flags & APFS_WRITE_SPARSE)
			ret = apfs_dstream_write_sparse(vol, inode.private_id, size, src, ctx, &ds, &sparse);
		else
			ret = apfs_dstream_write(vol, inode.private_id, size, src, ctx, &ds);
		if(ret == APFS_OK)
			ret = apfs_dstream_id_ensure(vol, inode.private_id);
		if(ret == APFS_OK) {
			apfs_inode_set_dstream(&inode, &ds);
			if(sparse) {
				uint8_t v[8];
				apfs_put64(v, sparse);
				apfs_inode_xf_set(&inode, INO_EXT_TYPE_SPARSE_BYTES, XF_SYSTEM_FIELD | XF_CHILDREN_INHERIT, v, sizeof(v));
				inode.internal_flags |= INODE_IS_SPARSE;
			}
		}
	}
	if(ret == APFS_OK) {
		now = apfs_time_now();
		inode.mod_time = now;
		inode.change_time = now;
		inode.write_gen++;
		ret = apfs_inode_write(vol, &inode);
	}
	apfs_inode_release(&inode);
	return ret;
}

int apfs_file_write(apfs_vol_t* vol, uint64_t ino, apfs_source_fn src, void* ctx, uint64_t size) {
	return apfs_file_write_ex(vol, ino, src, ctx, size, 0);
}

/* Compression */

#include <zlib.h>
#include "lzfse.h"
#include "lzfse_internal.h"

#define CCHUNK DECMPFS_BLOCK_SIZE

/* Compresses one chunk; returns the stored length. Incompressible data is
 * stored with the algorithm's "raw" marker. */
static size_t compress_chunk(int algo, const uint8_t* src, size_t len, uint8_t* dst, size_t cap) {
	size_t n = 0;
	switch(algo) {
		case APFS_COMPRESS_ZLIB: {
			uLongf out = (uLongf)cap;
			if(compress2(dst, &out, src, (uLong)len, 9) == Z_OK)
				n = out;
			if(n == 0 || n >= len + 1) {
				dst[0] = 0xff;
				memcpy(dst + 1, src, len);
				n = len + 1;
			}
			break;
		}
		case APFS_COMPRESS_LZVN: {
			void* work = apfs_malloc(lzvn_encode_scratch_size());
			n = len >= LZVN_ENCODE_MIN_SRC_SIZE ? lzvn_encode_buffer(dst, cap, src, len, work) : 0;
			free(work);
			if(n == 0 || n >= len + 1) {
				dst[0] = 0x06;
				memcpy(dst + 1, src, len);
				n = len + 1;
			}
			break;
		}
		case APFS_COMPRESS_LZFSE: {
			void* work = apfs_malloc(lzfse_encode_scratch_size());
			n = lzfse_encode_buffer(dst, cap, src, len, work);
			free(work);
			if(n == 0 || n >= len + 1) {
				dst[0] = 0xff;
				memcpy(dst + 1, src, len);
				n = len + 1;
			}
			break;
		}
	}
	return n;
}

int apfs_file_write_compressed(apfs_vol_t* vol, uint64_t ino, const uint8_t* data, size_t size, int algo) {
	apfs_inode_t inode;
	uint32_t type_xattr, type_rsrc;
	uint8_t* hdr;
	size_t hdr_len;
	int ret;

	switch(algo) {
		case APFS_COMPRESS_ZLIB: type_xattr = DECMPFS_TYPE_ZLIB_XATTR; type_rsrc = DECMPFS_TYPE_ZLIB_RSRC; break;
		case APFS_COMPRESS_LZVN: type_xattr = DECMPFS_TYPE_LZVN_XATTR; type_rsrc = DECMPFS_TYPE_LZVN_RSRC; break;
		case APFS_COMPRESS_LZFSE: type_xattr = DECMPFS_TYPE_LZFSE_XATTR; type_rsrc = DECMPFS_TYPE_LZFSE_RSRC; break;
		default: return APFS_EINVAL;
	}

	ret = apfs_vol_mark_dirty(vol);
	if(ret < 0)
		return ret;
	ret = apfs_inode_read(vol, ino, &inode);
	if(ret < 0)
		return ret;
	if((inode.mode & APFS_S_IFMT) != APFS_S_IFREG) {
		apfs_inode_release(&inode);
		return APFS_EINVAL;
	}
	ret = drop_compression(vol, &inode);
	if(ret == APFS_OK)
		ret = apfs_inode_drop_dstream(vol, &inode);
	if(ret == APFS_OK)
		ret = apfs_inode_write(vol, &inode);
	apfs_inode_release(&inode);
	if(ret < 0)
		return ret;

	/* small files go inline into the decmpfs attribute */
	hdr = NULL;
	hdr_len = 0;
	if(size <= CCHUNK) {
		uint8_t* buf = (uint8_t*)apfs_malloc(CCHUNK + 1024);
		size_t n = size ? compress_chunk(algo, data, size, buf, CCHUNK + 1024) : 0;
		if(16 + n <= XATTR_MAX_EMBEDDED_SIZE) {
			hdr_len = 16 + n;
			hdr = (uint8_t*)apfs_malloc(hdr_len);
			apfs_put32(hdr, DECMPFS_MAGIC);
			apfs_put32(hdr + 4, type_xattr);
			apfs_put64(hdr + 8, size);
			memcpy(hdr + 16, buf, n);
		}
		free(buf);
	}

	if(!hdr) {
		size_t nchunks = (size + CCHUNK - 1) / CCHUNK, i;
		size_t cap = nchunks * (CCHUNK + 64) + 4 * (nchunks + 1) + 512;
		uint8_t* rsrc = (uint8_t*)apfs_malloc(cap);
		size_t pos;

		if(algo == APFS_COMPRESS_ZLIB) {
			/* classic resource fork: header, data (length, block table, blocks), map */
			size_t table = 0x100 + 4, data_start, data_len, map_len = 0x32;
			uint8_t* m;
			pos = table + 4 + nchunks * 8;
			for(i = 0; i < nchunks; i++) {
				size_t len = (size - i * CCHUNK) > CCHUNK ? CCHUNK : size - i * CCHUNK;
				size_t n = compress_chunk(algo, data + i * CCHUNK, len, rsrc + pos, CCHUNK + 64);
				apfs_put32(rsrc + table + 4 + i * 8, (uint32_t)(pos - table));
				apfs_put32(rsrc + table + 4 + i * 8 + 4, (uint32_t)n);
				pos += n;
			}
			apfs_put32(rsrc + table, (uint32_t)nchunks);
			data_start = 0x100;
			data_len = pos - data_start;
			memset(rsrc, 0, 0x100);
#define BE32(p, v) do { (p)[0] = (uint8_t)((v) >> 24); (p)[1] = (uint8_t)((v) >> 16); (p)[2] = (uint8_t)((v) >> 8); (p)[3] = (uint8_t)(v); } while(0)
			BE32(rsrc, (uint32_t)data_start);
			BE32(rsrc + 4, (uint32_t)(data_start + data_len));
			BE32(rsrc + 8, (uint32_t)data_len);
			BE32(rsrc + 12, (uint32_t)map_len);
			BE32(rsrc + data_start, (uint32_t)(data_len - 4));
			/* resource map: 24 reserved bytes, which must stay zero */
			m = rsrc + pos;
			memset(m, 0, map_len);
			m[24] = 0x00; m[25] = 0x1c; /* type list offset */
			m[26] = 0x00; m[27] = 0x32; /* name list offset */
			m[28] = 0x00; m[29] = 0x00; /* one type */
			memcpy(m + 30, "cmpf", 4);
			m[34] = 0x00; m[35] = 0x00; /* one resource */
			m[36] = 0x00; m[37] = 0x0a; /* reference list offset */
			m[38] = 0x00; m[39] = 0x01; /* id 1 */
			m[40] = 0xff; m[41] = 0xff; /* no name */
			pos += map_len;
#undef BE32
		} else {
			pos = 4 * (nchunks + 1);
			for(i = 0; i < nchunks; i++) {
				size_t len = (size - i * CCHUNK) > CCHUNK ? CCHUNK : size - i * CCHUNK;
				size_t n;
				apfs_put32(rsrc + i * 4, (uint32_t)pos);
				n = compress_chunk(algo, data + i * CCHUNK, len, rsrc + pos, CCHUNK + 64);
				pos += n;
			}
			apfs_put32(rsrc + nchunks * 4, (uint32_t)pos);
		}
		ret = apfs_xattr_set(vol, ino, RESOURCEFORK_EA_NAME, rsrc, pos, 0);
		free(rsrc);
		if(ret < 0)
			return ret;
		hdr_len = 16;
		hdr = (uint8_t*)apfs_malloc(hdr_len);
		apfs_put32(hdr, DECMPFS_MAGIC);
		apfs_put32(hdr + 4, type_rsrc);
		apfs_put64(hdr + 8, size);
	}

	ret = apfs_xattr_set(vol, ino, DECMPFS_EA_NAME, hdr, hdr_len, 0);
	free(hdr);
	if(ret < 0)
		return ret;

	ret = apfs_inode_read(vol, ino, &inode);
	if(ret < 0)
		return ret;
	inode.bsd_flags |= APFS_UF_COMPRESSED;
	inode.internal_flags |= INODE_HAS_UNCOMPRESSED_SIZE;
	inode.uncompressed_size = size;
	inode.mod_time = inode.change_time = apfs_time_now();
	inode.write_gen++;
	ret = apfs_inode_write(vol, &inode);
	apfs_inode_release(&inode);
	return ret;
}
