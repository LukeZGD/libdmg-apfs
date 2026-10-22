/*
 * trustcache.c
 * apfs-tool
 *
 * Builds trust caches from the signed code in a volume. A CDHash is the hash
 * of a code directory (the part of a code signature that lists the hashes
 * of the code pages), truncated to 20 bytes. As the kernel does, a Mach-O
 * file (each architecture of a universal one) or a dyld shared cache counts
 * with its code directory of the strongest hash type. Standalone signatures,
 * such as launchd.plist.sig, count with every code directory, as in Apple's
 * trust caches.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apfs/apfs.h"
#include "apfs/trustcache.h"
#include "apfs/image.h"
#include "apfs/platform.h"

#define MH_MAGIC 0xfeedfaceU
#define MH_MAGIC_64 0xfeedfacfU
#define FAT_MAGIC 0xcafebabeU
#define FAT_MAGIC_64 0xcafebabfU
#define LC_CODE_SIGNATURE 0x1d
#define CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0U
#define CSMAGIC_CODEDIRECTORY 0xfade0c02U
#define CSSLOT_CODEDIRECTORY 0
#define CSSLOT_ALTERNATE_CODEDIRECTORIES 0x1000
#define CSSLOT_ALTERNATE_CODEDIRECTORY_MAX 5
#define CD_MIN_SIZE 44                /* code directory fields through the hash type */
#define META_MAX (256U << 20)         /* larger load commands or signatures are damaged */

/* Code signatures and universal binary headers are big-endian */
static uint32_t be32(const uint8_t* p) {
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t be64(const uint8_t* p) {
	return ((uint64_t)be32(p) << 32) | be32(p + 4);
}

/* The kernel uses the code directory with the strongest hash */
static int hash_rank(uint8_t type) {
	switch(type) {
		case APFS_CS_SHA1: return 1;
		case APFS_CS_SHA256_TRUNCATED: return 2;
		case APFS_CS_SHA256: return 3;
		case APFS_CS_SHA384: return 4;
		default: return 0;
	}
}

static int cd_hash(const uint8_t* cd, apfs_tc_entry_t* e) {
	uint32_t len = be32(cd + 4);
	uint8_t dg[32];

	memset(e, 0, sizeof(*e));
	e->hash_type = cd[37];
	if(e->hash_type == APFS_CS_SHA1) {
		apfs_sha1_ctx c;
		apfs_sha1_init(&c);
		apfs_sha1_update(&c, cd, len);
		apfs_sha1_final(&c, dg);
	} else if(e->hash_type == APFS_CS_SHA256 || e->hash_type == APFS_CS_SHA256_TRUNCATED) {
		apfs_sha256(cd, len, dg);
	} else {
		return APFS_EUNSUPP;
	}
	memcpy(e->cdhash, dg, APFS_CDHASH_LEN);
	return APFS_OK;
}

/* The CDHashes of an embedded signature: of the strongest code directory, or of every one */
static int sig_hashes(const uint8_t* sig, size_t len, int all, apfs_tc_entry_t* out, size_t max) {
	const uint8_t* best = NULL;
	uint32_t count, i;
	size_t n = 0;
	int ret;

	if(len < 12 || be32(sig) != CSMAGIC_EMBEDDED_SIGNATURE || be32(sig + 4) < 12 || be32(sig + 4) > len)
		return APFS_ECORRUPT;
	len = be32(sig + 4);
	count = be32(sig + 8);
	if(count > (len - 12) / 8)
		return APFS_ECORRUPT;
	for(i = 0; i < count; i++) {
		uint32_t type = be32(sig + 12 + 8 * i), off = be32(sig + 16 + 8 * i);
		const uint8_t* cd = sig + off;
		if(type != CSSLOT_CODEDIRECTORY && (type < CSSLOT_ALTERNATE_CODEDIRECTORIES ||
				type >= CSSLOT_ALTERNATE_CODEDIRECTORIES + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX))
			continue;
		if(off > len || len - off < CD_MIN_SIZE || be32(cd) != CSMAGIC_CODEDIRECTORY ||
				be32(cd + 4) < CD_MIN_SIZE || be32(cd + 4) > len - off)
			return APFS_ECORRUPT;
		if(all) {
			if(n == max)
				return APFS_ECORRUPT;
			if((ret = cd_hash(cd, &out[n])) < 0)
				return ret;
			n++;
		} else if(hash_rank(cd[37]) > (best ? hash_rank(best[37]) : 0)) {
			best = cd;
		}
	}
	if(!all) {
		if(!best || !max)
			return APFS_ECORRUPT;
		if((ret = cd_hash(best, out)) < 0)
			return ret;
		n = 1;
	}
	return n ? (int)n : APFS_ECORRUPT;
}

static int read_sig(apfs_tc_read_t rd, void* ctx, uint64_t off, uint64_t len, int all, apfs_tc_entry_t* out, size_t max) {
	uint8_t* sig;
	int ret;

	if(len > META_MAX)
		return APFS_ECORRUPT;
	sig = (uint8_t*)apfs_malloc((size_t)len);
	ret = rd(ctx, off, sig, (size_t)len);
	if(ret == APFS_OK)
		ret = sig_hashes(sig, (size_t)len, all, out, max);
	free(sig);
	return ret;
}

/* One architecture of a Mach-O file, at base */
static int macho_hashes(apfs_tc_read_t rd, void* ctx, uint64_t base, uint64_t size, apfs_tc_entry_t* out, size_t max) {
	uint8_t h[28];
	uint8_t* cmds;
	uint32_t magic, ncmds, sizeofcmds, hsize, i, pos = 0, dataoff = 0, datasize = 0;
	int ret;

	if(size < sizeof(h))
		return APFS_ECORRUPT;
	if((ret = rd(ctx, base, h, sizeof(h))) < 0)
		return ret;
	magic = apfs_get32(h);
	if(magic != MH_MAGIC && magic != MH_MAGIC_64)
		return APFS_ECORRUPT;
	hsize = magic == MH_MAGIC_64 ? 32 : 28;
	ncmds = apfs_get32(h + 16);
	sizeofcmds = apfs_get32(h + 20);
	if(size < hsize || sizeofcmds > size - hsize || sizeofcmds > META_MAX)
		return APFS_ECORRUPT;
	cmds = (uint8_t*)apfs_malloc(sizeofcmds);
	ret = rd(ctx, base + hsize, cmds, sizeofcmds);
	for(i = 0; ret == APFS_OK && i < ncmds; i++) {
		uint32_t cmdsize;
		if(sizeofcmds - pos < 8 || (cmdsize = apfs_get32(cmds + pos + 4)) < 8 || cmdsize > sizeofcmds - pos) {
			ret = APFS_ECORRUPT;
			break;
		}
		if(apfs_get32(cmds + pos) == LC_CODE_SIGNATURE && cmdsize >= 16) {
			dataoff = apfs_get32(cmds + pos + 8);
			datasize = apfs_get32(cmds + pos + 12);
		}
		pos += cmdsize;
	}
	free(cmds);
	if(ret < 0)
		return ret;
	if(!datasize)
		return APFS_ENOENT;
	if(dataoff > size || datasize > size - dataoff)
		return APFS_ECORRUPT;
	return read_sig(rd, ctx, base + dataoff, datasize, 0, out, max);
}

/* Universal binaries: a fat_header and fat_arch (or fat_arch_64) records */
static int fat_hashes(apfs_tc_read_t rd, void* ctx, uint64_t size, int is64, uint32_t nfat, apfs_tc_entry_t* out, size_t max) {
	size_t esz = is64 ? 32 : 20, n = 0;
	uint8_t* archs;
	uint32_t i;
	int ret;

	/* Java class files share the magic number; their version reads as a large count */
	if(!nfat || nfat > APFS_TC_MAX_HASHES)
		return 0;
	if(8 + nfat * esz > size)
		return APFS_ECORRUPT;
	archs = (uint8_t*)apfs_malloc(nfat * esz);
	ret = rd(ctx, 8, archs, nfat * esz);
	for(i = 0; ret >= 0 && i < nfat; i++) {
		const uint8_t* a = archs + i * esz;
		uint64_t off = is64 ? be64(a + 8) : be32(a + 8);
		uint64_t len = is64 ? be64(a + 16) : be32(a + 12);
		if(off > size || len > size - off)
			ret = APFS_ECORRUPT;
		else if((ret = macho_hashes(rd, ctx, off, len, out + n, max - n)) > 0)
			n += (size_t)ret;
	}
	free(archs);
	return ret < 0 ? ret : (int)n;
}

int apfs_tc_hash_file(apfs_tc_read_t rd, void* ctx, uint64_t size, apfs_tc_entry_t* out, size_t max) {
	uint8_t h[0x38];
	uint32_t magic;
	int ret;

	/* smaller files cannot hold a signature */
	if(size < sizeof(h))
		return 0;
	if((ret = rd(ctx, 0, h, sizeof(h))) < 0)
		return ret;
	magic = apfs_get32(h);
	if(magic == MH_MAGIC || magic == MH_MAGIC_64)
		return macho_hashes(rd, ctx, 0, size, out, max);
	magic = be32(h);
	if(magic == FAT_MAGIC || magic == FAT_MAGIC_64)
		return fat_hashes(rd, ctx, size, magic == FAT_MAGIC_64, be32(h + 4), out, max);
	if(!memcmp(h, "dyld_v1", 7)) {
		/* dyld_cache_header: codeSignatureOffset and codeSignatureSize */
		uint64_t off = apfs_get64(h + 0x28), len = apfs_get64(h + 0x30);
		if(!len)
			return APFS_ENOENT;
		if(off > size || len > size - off)
			return APFS_ECORRUPT;
		return read_sig(rd, ctx, off, len, 0, out, max);
	}
	if(magic == CSMAGIC_EMBEDDED_SIGNATURE)
		return read_sig(rd, ctx, 0, size, 1, out, max);
	return 0;
}

/* Scanning volumes */

typedef struct {
	apfs_vol_t* vol;
	const apfs_inode_t* inode;
	int err;                      /* reading the file failed */
} file_ctx_t;

static int read_file(void* ctx, uint64_t off, void* buf, size_t len) {
	file_ctx_t* f = (file_ctx_t*)ctx;
	uint8_t* p = (uint8_t*)buf;
	while(len) {
		size_t got;
		int ret = apfs_file_read(f->vol, f->inode, off, p, len, &got);
		if(ret == APFS_OK && !got)
			ret = APFS_ECORRUPT;
		if(ret < 0)
			return f->err = ret;
		off += got;
		p += got;
		len -= got;
	}
	return APFS_OK;
}

static int cmp_cdhash(const void* a, const void* b) {
	return memcmp(((const apfs_tc_entry_t*)a)->cdhash, ((const apfs_tc_entry_t*)b)->cdhash, APFS_CDHASH_LEN);
}

static void tc_add(apfs_tc_t* tc, const apfs_tc_entry_t* e) {
	if(tc->base && bsearch(e, tc->entries, tc->base, sizeof(*e), cmp_cdhash))
		return;
	if(tc->count == tc->cap) {
		tc->cap = tc->cap ? tc->cap * 2 : 64;
		tc->entries = (apfs_tc_entry_t*)apfs_realloc(tc->entries, tc->cap * sizeof(*e));
	}
	tc->entries[tc->count++] = *e;
}

static int scan_file(apfs_vol_t* vol, uint64_t ino, const char* path, int named, apfs_tc_t* tc, FILE* list) {
	apfs_tc_entry_t e[APFS_TC_MAX_HASHES];
	apfs_inode_t inode;
	file_ctx_t f;
	uint64_t size;
	int ret, i, k;

	if((ret = apfs_inode_read(vol, ino, &inode)) < 0)
		return ret;
	f.vol = vol;
	f.inode = &inode;
	f.err = APFS_OK;
	apfs_file_size(vol, &inode, &size);
	ret = apfs_tc_hash_file(read_file, &f, size, e, APFS_TC_MAX_HASHES);
	apfs_inode_release(&inode);
	if(f.err) {
		APFS_ERR("cannot read %s: %s", path, apfs_strerror(f.err));
		return f.err;
	}
	if(ret < 0 || (ret == 0 && named)) {
		APFS_WARN("skipping %s: %s", path, ret == 0 ? "no code signature" : ret == APFS_ENOENT ? "not signed" :
			ret == APFS_EUNSUPP ? "unsupported code directory hash type" : "damaged code signature");
		return APFS_OK;
	}
	for(i = 0; i < ret; i++) {
		tc_add(tc, &e[i]);
		if(list) {
			for(k = 0; k < APFS_CDHASH_LEN; k++)
				fprintf(list, "%02x", e[i].cdhash[k]);
			fprintf(list, "  %s\n", path);
		}
	}
	return APFS_OK;
}

static int scan_tree(apfs_vol_t* vol, uint64_t dir, const char* path, apfs_tc_t* tc, FILE* list) {
	apfs_dirent_t* ents;
	size_t n, i;
	int ret = apfs_dir_list(vol, dir, &ents, &n);
	if(ret < 0) {
		APFS_ERR("cannot list %s: %s", path, apfs_strerror(ret));
		return ret;
	}
	for(i = 0; ret == APFS_OK && i < n; i++) {
		char* sub = plat_join(path, ents[i].name);
		uint16_t t = ents[i].flags & DREC_TYPE_MASK;
		if(t == APFS_DT_DIR)
			ret = scan_tree(vol, ents[i].ino, sub, tc, list);
		else if(t == APFS_DT_REG)
			ret = scan_file(vol, ents[i].ino, sub, 0, tc, list);
		free(sub);
	}
	apfs_dirents_free(ents, n);
	return ret;
}

int apfs_tc_scan(apfs_vol_t* vol, const char* path, apfs_tc_t* tc, FILE* list) {
	apfs_inode_t inode;
	uint64_t ino;
	int ret, is_dir;

	ret = apfs_lookup(vol, path, 1, &ino, NULL, NULL);
	if(ret == APFS_OK)
		ret = apfs_inode_read(vol, ino, &inode);
	if(ret < 0) {
		APFS_ERR("cannot access %s: %s", path, apfs_strerror(ret));
		return ret;
	}
	is_dir = (inode.mode & APFS_S_IFMT) == APFS_S_IFDIR;
	apfs_inode_release(&inode);
	return is_dir ? scan_tree(vol, ino, path, tc, list) : scan_file(vol, ino, path, 1, tc, list);
}

/* Serialized trust caches: a version, a UUID and an entry count, then the
 * entries sorted by CDHash (all little-endian) */

uint8_t* apfs_tc_build(apfs_tc_t* tc, int version, const uint8_t* uuid, size_t* len) {
	size_t esz = version == 2 ? 24 : 22, i, n = 0;
	uint8_t dg[32];
	uint8_t* buf;

	if(tc->count)
		qsort(tc->entries, tc->count, sizeof(*tc->entries), cmp_cdhash);
	for(i = 0; i < tc->count; i++)
		if(!n || cmp_cdhash(&tc->entries[i], &tc->entries[n - 1]))
			tc->entries[n++] = tc->entries[i];
	tc->count = tc->base = n;
	*len = 24 + n * esz;
	buf = (uint8_t*)apfs_calloc(1, *len);
	apfs_put32(buf, (uint32_t)version);
	apfs_put32(buf + 20, (uint32_t)n);
	for(i = 0; i < n; i++) {
		uint8_t* p = buf + 24 + i * esz;
		memcpy(p, tc->entries[i].cdhash, APFS_CDHASH_LEN);
		p[20] = tc->entries[i].hash_type;
		p[21] = tc->entries[i].flags;
		if(version == 2)
			p[22] = tc->entries[i].category;
	}
	if(uuid) {
		memcpy(buf + 4, uuid, 16);
	} else {
		apfs_sha256(buf, *len, dg);
		memcpy(buf + 4, dg, 16);
	}
	return buf;
}

int apfs_tc_parse(const uint8_t* data, size_t len, apfs_tc_t* tc, int* version, uint8_t uuid[16]) {
	uint32_t v, n, i;
	size_t esz;

	if(len < 24)
		return APFS_ECORRUPT;
	v = apfs_get32(data);
	if(v != 1 && v != 2)
		return APFS_EUNSUPP;
	esz = v == 2 ? 24 : 22;
	n = apfs_get32(data + 20);
	if(n > (len - 24) / esz)
		return APFS_ECORRUPT;
	tc->entries = (apfs_tc_entry_t*)apfs_calloc(n ? n : 1, sizeof(apfs_tc_entry_t));
	tc->count = tc->cap = tc->base = n;
	for(i = 0; i < n; i++) {
		const uint8_t* p = data + 24 + (size_t)i * esz;
		memcpy(tc->entries[i].cdhash, p, APFS_CDHASH_LEN);
		tc->entries[i].hash_type = p[20];
		tc->entries[i].flags = p[21];
		if(v == 2)
			tc->entries[i].category = p[22];
	}
	if(n)
		qsort(tc->entries, n, sizeof(*tc->entries), cmp_cdhash);
	*version = (int)v;
	if(uuid)
		memcpy(uuid, data + 4, 16);
	return APFS_OK;
}

int apfs_tc_load(const char* path, apfs_tc_t* tc, int* version) {
	uint8_t* data;
	size_t len;
	int ret = apfs_im4p_load(path, &data, &len);
	if(ret < 0)
		return ret;
	ret = apfs_tc_parse(data, len, tc, version, NULL);
	free(data);
	return ret;
}

int apfs_tc_save(apfs_tc_t* tc, int version, const char* im4p_type, const char* path) {
	size_t len;
	uint8_t* data = apfs_tc_build(tc, version, NULL, &len);
	int ret = APFS_EIO;

	if(im4p_type) {
		/* the description of IPSW trust caches */
		ret = apfs_im4p_save(im4p_type, "1", data, len, path);
	} else {
		FILE* f = fopen(path, "wb");
		if(f) {
			ret = fwrite(data, 1, len, f) == len ? APFS_OK : APFS_EIO;
			if(fclose(f) != 0)
				ret = APFS_EIO;
		}
	}
	free(data);
	return ret;
}

void apfs_tc_free(apfs_tc_t* tc) {
	free(tc->entries);
	memset(tc, 0, sizeof(*tc));
}
