/*
 * compress.c
 * apfs-tool
 *
 * Transparent file compression (decmpfs): reading and writing files whose
 * contents live in the com.apple.decmpfs attribute or, chunked, in the
 * com.apple.ResourceFork attribute.
 */

#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "apfs/apfs.h"
#include "lzfse.h"
#include "lzfse_internal.h"
#include "lzvn_decode_base.h"

#define CHUNK DECMPFS_BLOCK_SIZE

const char* apfs_decmpfs_type_name(uint32_t type) {
	switch(type) {
		case 1: return "uncompressed (xattr)";
		case DECMPFS_TYPE_ZLIB_XATTR: return "zlib (xattr)";
		case DECMPFS_TYPE_ZLIB_RSRC: return "zlib (resource fork)";
		case DECMPFS_TYPE_DATALESS: return "dataless";
		case DECMPFS_TYPE_LZVN_XATTR: return "lzvn (xattr)";
		case DECMPFS_TYPE_LZVN_RSRC: return "lzvn (resource fork)";
		case DECMPFS_TYPE_PLAIN_XATTR: return "plain (xattr)";
		case DECMPFS_TYPE_PLAIN_RSRC: return "plain (resource fork)";
		case DECMPFS_TYPE_LZFSE_XATTR: return "lzfse (xattr)";
		case DECMPFS_TYPE_LZFSE_RSRC: return "lzfse (resource fork)";
		case DECMPFS_TYPE_LZBITMAP_XATTR: return "lzbitmap (xattr)";
		case DECMPFS_TYPE_LZBITMAP_RSRC: return "lzbitmap (resource fork)";
		default: return "unknown";
	}
}

int apfs_compress_parse(const char* name, int* algo) {
	if(!strcmp(name, "none")) *algo = APFS_COMPRESS_NONE;
	else if(!strcmp(name, "zlib")) *algo = APFS_COMPRESS_ZLIB;
	else if(!strcmp(name, "lzvn")) *algo = APFS_COMPRESS_LZVN;
	else if(!strcmp(name, "lzfse")) *algo = APFS_COMPRESS_LZFSE;
	else return APFS_EINVAL;
	return APFS_OK;
}

static size_t zlib_decode(uint8_t* dst, size_t dst_size, const uint8_t* src, size_t src_size) {
	z_stream s;
	size_t out;
	int ret;
	memset(&s, 0, sizeof(s));
	if(inflateInit(&s) != Z_OK)
		return 0;
	s.next_in = (Bytef*)src;
	s.avail_in = (uInt)src_size;
	s.next_out = dst;
	s.avail_out = (uInt)dst_size;
	ret = inflate(&s, Z_FINISH);
	out = dst_size - s.avail_out;
	inflateEnd(&s);
	if(ret != Z_STREAM_END && ret != Z_OK && ret != Z_BUF_ERROR)
		return 0;
	return out;
}

static size_t lzvn_decode_mem(uint8_t* dst, size_t dst_size, const uint8_t* src, size_t src_size) {
	lzvn_decoder_state st;
	memset(&st, 0, sizeof(st));
	st.src = src;
	st.src_end = src + src_size;
	st.dst = dst;
	st.dst_begin = dst;
	st.dst_end = dst + dst_size;
	st.dst_current = dst;
	lzvn_decode(&st);
	return (size_t)(st.dst - dst);
}

static size_t lzfse_decode_mem(uint8_t* dst, size_t dst_size, const uint8_t* src, size_t src_size) {
	void* scratch = apfs_malloc(lzfse_decode_scratch_size() + 1);
	size_t n = lzfse_decode_buffer(dst, dst_size, src, src_size, scratch);
	free(scratch);
	return n;
}

/* Decodes one block of compressed data (an xattr payload or a resource
 * fork chunk). Returns the decoded length or (size_t)-1. */
static size_t decode_block(uint32_t type, uint8_t* dst, size_t dst_size, const uint8_t* src, size_t src_size) {
	if(src_size == 0)
		return 0;
	switch(type) {
		case 1:
			if(src_size > dst_size)
				return (size_t)-1;
			memcpy(dst, src, src_size);
			return src_size;
		case DECMPFS_TYPE_ZLIB_XATTR:
		case DECMPFS_TYPE_ZLIB_RSRC:
			if((src[0] & 0x0f) == 0x0f) {
				if(src_size - 1 > dst_size)
					return (size_t)-1;
				memcpy(dst, src + 1, src_size - 1);
				return src_size - 1;
			}
			return zlib_decode(dst, dst_size, src, src_size);
		case DECMPFS_TYPE_LZVN_XATTR:
		case DECMPFS_TYPE_LZVN_RSRC:
			if(src[0] == 0x06) {
				if(src_size - 1 > dst_size)
					return (size_t)-1;
				memcpy(dst, src + 1, src_size - 1);
				return src_size - 1;
			}
			return lzvn_decode_mem(dst, dst_size, src, src_size);
		case DECMPFS_TYPE_PLAIN_XATTR:
		case DECMPFS_TYPE_PLAIN_RSRC:
			if(src_size - 1 > dst_size)
				return (size_t)-1;
			memcpy(dst, src + 1, src_size - 1);
			return src_size - 1;
		case DECMPFS_TYPE_LZFSE_XATTR:
		case DECMPFS_TYPE_LZFSE_RSRC:
			if(src[0] == 0xff) {
				if(src_size - 1 > dst_size)
					return (size_t)-1;
				memcpy(dst, src + 1, src_size - 1);
				return src_size - 1;
			}
			return lzfse_decode_mem(dst, dst_size, src, src_size);
		default:
			return (size_t)-1;
	}
}

typedef struct {
	uint32_t type;
	uint64_t size;
	uint8_t* inline_data;          /* xattr payload for xattr types */
	size_t inline_len;
	uint64_t rsrc_id;              /* resource fork data stream */
	uint64_t rsrc_size;
	uint8_t* rsrc_embedded;        /* resource fork stored inline */
} decmpfs_t;

static void decmpfs_release(decmpfs_t* d) {
	free(d->inline_data);
	free(d->rsrc_embedded);
}

static int decmpfs_open(apfs_vol_t* vol, const apfs_inode_t* inode, decmpfs_t* d) {
	uint8_t* hdr;
	size_t len;
	int ret;

	memset(d, 0, sizeof(*d));
	ret = apfs_xattr_get(vol, inode->ino, DECMPFS_EA_NAME, &hdr, &len);
	if(ret < 0)
		return ret;
	if(len < 16 || apfs_get32(hdr) != DECMPFS_MAGIC) {
		free(hdr);
		return APFS_ECORRUPT;
	}
	d->type = apfs_get32(hdr + 4);
	d->size = apfs_get64(hdr + 8);
	d->inline_len = len - 16;
	d->inline_data = (uint8_t*)apfs_malloc(d->inline_len ? d->inline_len : 1);
	memcpy(d->inline_data, hdr + 16, d->inline_len);
	free(hdr);

	switch(d->type) {
		case DECMPFS_TYPE_ZLIB_RSRC:
		case DECMPFS_TYPE_LZVN_RSRC:
		case DECMPFS_TYPE_PLAIN_RSRC:
		case DECMPFS_TYPE_LZFSE_RSRC: {
			uint16_t flags, xlen;
			uint8_t* x;
			ret = apfs_xattr_raw(vol, inode->ino, RESOURCEFORK_EA_NAME, &flags, &x, &xlen);
			if(ret < 0)
				return ret == APFS_ENOENT ? APFS_ECORRUPT : ret;
			if(flags & XATTR_DATA_STREAM) {
				if(xlen < sizeof(j_xattr_dstream_t)) {
					free(x);
					return APFS_ECORRUPT;
				}
				d->rsrc_id = apfs_get64(x);
				d->rsrc_size = apfs_get64(x + 8);
				free(x);
			} else {
				d->rsrc_embedded = x;
				d->rsrc_size = xlen;
			}
			break;
		}
		case 1:
		case DECMPFS_TYPE_ZLIB_XATTR:
		case DECMPFS_TYPE_LZVN_XATTR:
		case DECMPFS_TYPE_PLAIN_XATTR:
		case DECMPFS_TYPE_LZFSE_XATTR:
			break;
		default:
			APFS_ERR("inode %llu uses unsupported compression type %u (%s)", (unsigned long long)inode->ino, d->type,
				apfs_decmpfs_type_name(d->type));
			return APFS_EUNSUPP;
	}
	return APFS_OK;
}

static int rsrc_read(apfs_vol_t* vol, decmpfs_t* d, uint64_t off, void* buf, size_t len) {
	if(off + len > d->rsrc_size)
		return APFS_ECORRUPT;
	if(d->rsrc_embedded) {
		memcpy(buf, d->rsrc_embedded + off, len);
		return APFS_OK;
	}
	return apfs_dstream_read(vol, d->rsrc_id, d->rsrc_size, off, buf, len);
}

/* Locates the compressed bytes of chunk i in the resource fork */
static int rsrc_chunk(apfs_vol_t* vol, decmpfs_t* d, uint64_t i, uint64_t* off, uint32_t* len) {
	uint64_t nchunks = (d->size + CHUNK - 1) / CHUNK;
	uint8_t buf[8];
	int ret;

	if(i >= nchunks)
		return APFS_ERANGE;
	if(d->type == DECMPFS_TYPE_ZLIB_RSRC) {
		/* classic resource fork: 256-byte big-endian header, then a table */
		uint8_t hdr[16];
		uint32_t data_off, count;
		ret = rsrc_read(vol, d, 0, hdr, sizeof(hdr));
		if(ret < 0)
			return ret;
		data_off = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) | ((uint32_t)hdr[2] << 8) | hdr[3];
		ret = rsrc_read(vol, d, data_off + 4, buf, 4);
		if(ret < 0)
			return ret;
		count = apfs_get32(buf);
		if(i >= count)
			return APFS_ECORRUPT;
		ret = rsrc_read(vol, d, data_off + 4 + 4 + i * 8, buf, 8);
		if(ret < 0)
			return ret;
		*off = (uint64_t)data_off + 4 + apfs_get32(buf);
		*len = apfs_get32(buf + 4);
		return APFS_OK;
	} else {
		/* table of nchunks + 1 little-endian offsets */
		ret = rsrc_read(vol, d, i * 4, buf, 8);
		if(ret < 0)
			return ret;
		*off = apfs_get32(buf);
		if(apfs_get32(buf + 4) < *off)
			return APFS_ECORRUPT;
		*len = apfs_get32(buf + 4) - (uint32_t)*off;
		return APFS_OK;
	}
}

int apfs_decmpfs_size(apfs_vol_t* vol, const apfs_inode_t* inode, uint64_t* size) {
	uint8_t* hdr;
	size_t len;
	int ret = apfs_xattr_get(vol, inode->ino, DECMPFS_EA_NAME, &hdr, &len);
	if(ret < 0)
		return ret;
	if(len < 16 || apfs_get32(hdr) != DECMPFS_MAGIC) {
		free(hdr);
		return APFS_ECORRUPT;
	}
	*size = apfs_get64(hdr + 8);
	free(hdr);
	return APFS_OK;
}

int apfs_decmpfs_read(apfs_vol_t* vol, const apfs_inode_t* inode, uint64_t off, void* buf, size_t len, size_t* got) {
	decmpfs_t d;
	uint8_t* out = (uint8_t*)buf;
	size_t done = 0;
	int ret;

	*got = 0;
	ret = decmpfs_open(vol, inode, &d);
	if(ret < 0)
		return ret;
	if(off >= d.size) {
		decmpfs_release(&d);
		return APFS_OK;
	}
	if(len > d.size - off)
		len = (size_t)(d.size - off);

	if(d.rsrc_size == 0 && !d.rsrc_embedded && d.type != DECMPFS_TYPE_ZLIB_RSRC && d.type != DECMPFS_TYPE_LZVN_RSRC &&
			d.type != DECMPFS_TYPE_PLAIN_RSRC && d.type != DECMPFS_TYPE_LZFSE_RSRC) {
		/* the whole file is in the attribute */
		uint8_t* all = (uint8_t*)apfs_malloc((size_t)d.size + 1);
		size_t n = decode_block(d.type, all, (size_t)d.size, d.inline_data, d.inline_len);
		if(n != d.size) {
			APFS_ERR("cannot decompress inode %llu", (unsigned long long)inode->ino);
			free(all);
			decmpfs_release(&d);
			return APFS_ECORRUPT;
		}
		memcpy(out, all + off, len);
		free(all);
		*got = len;
		decmpfs_release(&d);
		return APFS_OK;
	}

	{
		uint8_t* chunk = (uint8_t*)apfs_malloc(CHUNK);
		uint8_t* comp = (uint8_t*)apfs_malloc(CHUNK * 2 + 64);
		while(done < len) {
			uint64_t pos = off + done;
			uint64_t ci = pos / CHUNK;
			uint64_t coff;
			uint32_t clen;
			size_t expect = (size_t)((d.size - ci * CHUNK) > CHUNK ? CHUNK : (d.size - ci * CHUNK));
			size_t n, take;

			ret = rsrc_chunk(vol, &d, ci, &coff, &clen);
			if(ret == APFS_OK && clen > CHUNK * 2 + 64)
				ret = APFS_ECORRUPT;
			if(ret == APFS_OK)
				ret = rsrc_read(vol, &d, coff, comp, clen);
			if(ret < 0)
				break;
			n = decode_block(d.type, chunk, CHUNK, comp, clen);
			if(n != expect) {
				APFS_ERR("cannot decompress chunk %llu of inode %llu", (unsigned long long)ci, (unsigned long long)inode->ino);
				ret = APFS_ECORRUPT;
				break;
			}
			take = (size_t)(n - (pos - ci * CHUNK));
			if(take > len - done)
				take = len - done;
			memcpy(out + done, chunk + (pos - ci * CHUNK), take);
			done += take;
		}
		free(chunk);
		free(comp);
	}
	decmpfs_release(&d);
	*got = done;
	return ret < 0 ? ret : APFS_OK;
}
