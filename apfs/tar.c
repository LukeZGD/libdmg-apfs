/*
 * tar.c
 * apfs-tool
 *
 * Importing tar archives: ustar, GNU (long names, sparse files) and PAX
 * (extended and global headers, sparse files), with hard links, device
 * nodes and FIFOs. Apple metadata comes back from both places tar tools
 * keep it: PAX records (SCHILY.xattr and LIBARCHIVE.xattr extended
 * attributes, SCHILY.fflags, SCHILY.acl.ace, atime and creation times) and
 * the AppleDouble "._name" entries that macOS tar writes before a file
 * (Finder info, extended attributes, resource fork and ACL). The archive,
 * hard link targets included, is validated completely before anything is
 * written, the same two-pass approach as libdmg-hfsplus' hfs_untar_checked.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apfs/apfs.h"
#include "apfs/apfslib.h"

#define TAR_BLOCK 512
#define TAR_PATH_MAX 4096
#define PAX_MAX (16U << 20)           /* larger extended headers are refused */
#define APPLEDOUBLE_MAX (256U << 20)
#define SPARSE_MAX 1000000            /* data segments of a sparse file */

static uint16_t be16(const uint8_t* p) {
	return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t be32(const uint8_t* p) {
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void put_be32(uint8_t* p, uint32_t v) {
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

/* Extended attributes of an entry */

typedef struct {
	char* name;
	uint8_t* val;
	size_t len;
} tar_xattr_t;

typedef struct {
	tar_xattr_t* v;
	size_t n;
} tar_xattrs_t;

/* Adds an attribute, replacing one of the same name */
static void xattrs_put(tar_xattrs_t* x, const char* name, size_t nlen, const uint8_t* val, size_t len) {
	size_t i;
	for(i = 0; i < x->n; i++)
		if(!strncmp(x->v[i].name, name, nlen) && !x->v[i].name[nlen])
			break;
	if(i == x->n) {
		x->v = (tar_xattr_t*)apfs_realloc(x->v, (x->n + 1) * sizeof(tar_xattr_t));
		x->v[i].name = (char*)apfs_malloc(nlen + 1);
		memcpy(x->v[i].name, name, nlen);
		x->v[i].name[nlen] = 0;
		x->n++;
	} else {
		free(x->v[i].val);
	}
	x->v[i].val = (uint8_t*)apfs_malloc(len ? len : 1);
	if(len)
		memcpy(x->v[i].val, val, len);
	x->v[i].len = len;
}

static void xattrs_merge(tar_xattrs_t* dst, const tar_xattrs_t* src) {
	size_t i;
	for(i = 0; i < src->n; i++)
		xattrs_put(dst, src->v[i].name, strlen(src->v[i].name), src->v[i].val, src->v[i].len);
}

static void xattrs_free(tar_xattrs_t* x) {
	size_t i;
	for(i = 0; i < x->n; i++) {
		free(x->v[i].name);
		free(x->v[i].val);
	}
	free(x->v);
	x->v = NULL;
	x->n = 0;
}

/* Where the stored bytes of a sparse file go */

typedef struct {
	uint64_t* off;
	uint64_t* len;
	size_t n;
} tar_map_t;

static int map_add(tar_map_t* m, uint64_t off, uint64_t len) {
	if(m->n >= SPARSE_MAX)
		return 0;
	m->off = (uint64_t*)apfs_realloc(m->off, (m->n + 1) * sizeof(uint64_t));
	m->len = (uint64_t*)apfs_realloc(m->len, (m->n + 1) * sizeof(uint64_t));
	m->off[m->n] = off;
	m->len[m->n] = len;
	m->n++;
	return 1;
}

static void map_free(tar_map_t* m) {
	free(m->off);
	free(m->len);
	memset(m, 0, sizeof(*m));
}

/* The segments must be in order, inside the file, and add up to the stored data */
static int map_check(const tar_map_t* m, uint64_t realsize, uint64_t stored) {
	uint64_t end = 0, total = 0;
	size_t i;
	for(i = 0; i < m->n; i++) {
		if(m->off[i] < end || m->off[i] > realsize || m->len[i] > realsize - m->off[i])
			return 0;
		end = m->off[i] + m->len[i];
		total += m->len[i];
	}
	return total == stored;
}

/* ACLs. macOS keeps them in the com.apple.system.Security attribute as a
 * kauth_filesec: magic, owner and group GUIDs (unused), entry count and
 * flags, then entries of GUID, flags (kind and inheritance) and rights, all
 * big-endian. */

#define ACL_XATTR "com.apple.system.Security"
#define KAUTH_FILESEC_MAGIC 0x012cc16dU

typedef struct {
	uint8_t guid[16];
	uint32_t flags;
	uint32_t rights;
} tar_ace_t;

typedef struct {
	const char* name;
	uint32_t bit;
} tar_name_t;

static const tar_name_t ace_rights[] = {
	{ "read", 0x2 }, { "list", 0x2 }, { "write", 0x4 }, { "add_file", 0x4 }, { "execute", 0x8 },
	{ "search", 0x8 }, { "delete", 0x10 }, { "append", 0x20 }, { "add_subdirectory", 0x20 },
	{ "delete_child", 0x40 }, { "readattr", 0x80 }, { "writeattr", 0x100 }, { "readextattr", 0x200 },
	{ "writeextattr", 0x400 }, { "readsecurity", 0x800 }, { "writesecurity", 0x1000 },
	{ "chown", 0x2000 }, { "synchronize", 0x100000 }, { NULL, 0 }
}, ace_flags[] = {
	{ "allow", 1 }, { "deny", 2 }, { "inherited", 0x10 }, { "file_inherit", 0x20 },
	{ "directory_inherit", 0x40 }, { "limit_inherit", 0x80 }, { "only_inherit", 0x100 }, { NULL, 0 }
};

/* The NFSv4 letters that libarchive and star use for rights and inheritance flags */
static const char nfs4_rights[] = "rwxpdDaARWcCos";
static const uint32_t nfs4_right_bits[] = {
	0x2, 0x4, 0x8, 0x20, 0x10, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x100000
};
static const char nfs4_flags[] = "fdinI";
static const uint32_t nfs4_flag_bits[] = { 0x20, 0x40, 0x100, 0x80, 0x10 };

/* The GUID macOS gives a user or group ID that has no directory entry */
static void id_guid(uint8_t* g, int group, uint32_t id) {
	static const uint8_t user_prefix[12] = { 0xff, 0xff, 0xee, 0xee, 0xdd, 0xdd, 0xcc, 0xcc, 0xbb, 0xbb, 0xaa, 0xaa };
	static const uint8_t group_prefix[12] = { 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef };
	memcpy(g, group ? group_prefix : user_prefix, 12);
	put_be32(g + 12, id);
}

static void acl_put(tar_xattrs_t* x, const tar_ace_t* aces, size_t n) {
	size_t len = 44 + 24 * n, i;
	uint8_t* b;
	if(!n)
		return;
	b = (uint8_t*)apfs_calloc(1, len);
	put_be32(b, KAUTH_FILESEC_MAGIC);
	put_be32(b + 36, (uint32_t)n);
	for(i = 0; i < n; i++) {
		memcpy(b + 44 + 24 * i, aces[i].guid, 16);
		put_be32(b + 44 + 24 * i + 16, aces[i].flags);
		put_be32(b + 44 + 24 * i + 20, aces[i].rights);
	}
	xattrs_put(x, ACL_XATTR, strlen(ACL_XATTR), b, len);
	free(b);
}

/* Splits s at sep in place; returns the number of fields */
static size_t split(char* s, char sep, char** fields, size_t max) {
	size_t n = 0;
	while(n < max) {
		char* end = strchr(s, sep);
		fields[n++] = s;
		if(!end)
			break;
		*end = 0;
		s = end + 1;
	}
	return n;
}

static uint32_t name_bits(char* list, const tar_name_t* t, int warn, const char* what) {
	char* names[32];
	size_t n = split(list, ',', names, 32), i, k;
	uint32_t bits = 0;
	for(i = 0; i < n; i++) {
		for(k = 0; t[k].name && strcmp(t[k].name, names[i]); k++)
			;
		if(t[k].name)
			bits |= t[k].bit;
		else if(names[i][0] && warn)
			APFS_WARN("untar: unknown ACL %s %s", what, names[i]);
	}
	return bits;
}

/* acl_to_text(3), as copyfile(3) stores it in AppleDouble files: "!#acl 1",
 * then lines of "user|group:GUID:name:id:allow|deny[,flag...]:right[,right...]" */
static void acl_from_text(tar_xattrs_t* x, const uint8_t* text, size_t len, int warn) {
	char* copy = (char*)apfs_malloc(len + 1);
	char* lines[1024];
	tar_ace_t* aces;
	size_t nl, i, n = 0;

	memcpy(copy, text, len);
	copy[len] = 0;
	nl = split(copy, '\n', lines, 1024);
	if(strncmp(lines[0], "!#acl 1", 7) != 0) {
		if(warn)
			APFS_WARN("untar: unknown ACL text format");
		free(copy);
		return;
	}
	aces = (tar_ace_t*)apfs_calloc(nl, sizeof(tar_ace_t));
	for(i = 1; i < nl; i++) {
		char* f[6];
		if(!lines[i][0])
			continue;
		if(split(lines[i], ':', f, 6) != 6 || (strcmp(f[0], "user") && strcmp(f[0], "group"))) {
			if(warn)
				APFS_WARN("untar: skipping ACL entry %s", lines[i]);
			continue;
		}
		if(apfs_uuid_parse(f[1], aces[n].guid) < 0)
			id_guid(aces[n].guid, f[0][0] == 'g', (uint32_t)strtoul(f[3], NULL, 10));
		aces[n].flags = name_bits(f[4], ace_flags, warn, "flag");
		aces[n].rights = name_bits(f[5], ace_rights, warn, "right");
		n++;
	}
	acl_put(x, aces, n);
	free(aces);
	free(copy);
}

/* NFSv4 ACLs from libarchive and star: "tag:name:rights:flags:type:id"
 * entries separated by commas. The owner@, group@ and everyone@ entries
 * restate the mode, which macOS keeps apart, so they are left out. */
static void acl_from_nfs4(tar_xattrs_t* x, const uint8_t* text, size_t len, int warn) {
	char* copy = (char*)apfs_malloc(len + 1);
	char** entries;
	tar_ace_t* aces;
	size_t ne, i, n = 0;

	memcpy(copy, text, len);
	copy[len] = 0;
	entries = (char**)apfs_malloc((len / 2 + 1) * sizeof(char*));
	ne = split(copy, ',', entries, len / 2 + 1);
	aces = (tar_ace_t*)apfs_calloc(ne, sizeof(tar_ace_t));
	for(i = 0; i < ne; i++) {
		char* f[6];
		size_t nf = split(entries[i], ':', f, 6), k;
		const char* p;
		if(!entries[i][0] || f[0][strlen(f[0]) - 1] == '@')
			continue;
		if(nf != 6 || (strcmp(f[0], "user") && strcmp(f[0], "group")) ||
				(strcmp(f[4], "allow") && strcmp(f[4], "deny"))) {
			if(warn)
				APFS_WARN("untar: skipping ACL entry for %s %s", f[0], nf > 1 ? f[1] : "");
			continue;
		}
		id_guid(aces[n].guid, f[0][0] == 'g', (uint32_t)strtoul(f[5], NULL, 10));
		aces[n].flags = f[4][0] == 'a' ? 1 : 2;
		for(p = f[2]; *p; p++)
			for(k = 0; nfs4_rights[k]; k++)
				if(*p == nfs4_rights[k])
					aces[n].rights |= nfs4_right_bits[k];
		for(p = f[3]; *p; p++)
			for(k = 0; nfs4_flags[k]; k++)
				if(*p == nfs4_flags[k])
					aces[n].flags |= nfs4_flag_bits[k];
		n++;
	}
	acl_put(x, aces, n);
	free(aces);
	free(entries);
	free(copy);
}

/* AppleDouble files from copyfile(3): entry 9 holds the Finder info, then
 * the extended attributes (an "ATTR" header and 4-byte aligned records of
 * offset, length, flags and name), entry 2 the resource fork. All
 * big-endian. */

#define AD_MAGIC 0x00051607U
#define AD_VERSION 0x00020000U
#define AD_RSRC 2
#define AD_FINDERINFO 9

static int ad_attrs(const uint8_t* d, size_t len, size_t hdr, size_t end, tar_xattrs_t* x, int warn) {
	uint16_t count = be16(d + hdr + 34), i;
	size_t p = hdr + 36;
	for(i = 0; i < count; i++) {
		uint32_t off, alen;
		size_t nlen;
		const char* name;
		if(p + 11 > end)
			return 0;
		off = be32(d + p);
		alen = be32(d + p + 4);
		nlen = d[p + 10];
		name = (const char*)d + p + 11;
		if(!nlen || p + 11 + nlen > end || off > len || alen > len - off)
			return 0;
		if(!name[nlen - 1])
			nlen--;
		if(nlen == 18 && !memcmp(name, "com.apple.acl.text", 18))
			acl_from_text(x, d + off, alen, warn);
		else if(nlen)
			xattrs_put(x, name, nlen, d + off, alen);
		p += (11 + (size_t)d[p + 10] + 3) & ~(size_t)3;
	}
	return 1;
}

static int appledouble_parse(const uint8_t* d, size_t len, tar_xattrs_t* x, int warn) {
	static const uint8_t zero[32];
	uint16_t n, i;
	if(len < 26 || be32(d) != AD_MAGIC || be32(d + 4) != AD_VERSION)
		return 0;
	n = be16(d + 24);
	if(26 + 12 * (size_t)n > len)
		return 0;
	for(i = 0; i < n; i++) {
		const uint8_t* e = d + 26 + 12 * i;
		uint32_t id = be32(e), off = be32(e + 4), elen = be32(e + 8);
		if(off > len || elen > len - off)
			return 0;
		if(id == AD_RSRC && elen) {
			xattrs_put(x, RESOURCEFORK_EA_NAME, strlen(RESOURCEFORK_EA_NAME), d + off, elen);
		} else if(id == AD_FINDERINFO && elen >= 32) {
			if(memcmp(d + off, zero, 32))
				xattrs_put(x, FINDERINFO_EA_NAME, strlen(FINDERINFO_EA_NAME), d + off, 32);
			if(elen >= 34 + 36 && !memcmp(d + off + 34, "ATTR", 4) &&
					!ad_attrs(d, len, (size_t)off + 34, (size_t)off + elen, x, warn))
				return 0;
		}
	}
	return 1;
}

/* PAX extended headers */

#define HAVE_PATH 0x001
#define HAVE_LINK 0x002
#define HAVE_SIZE 0x004
#define HAVE_UID 0x008
#define HAVE_GID 0x010
#define HAVE_MTIME 0x020
#define HAVE_ATIME 0x040
#define HAVE_BTIME 0x080
#define HAVE_FLAGS 0x100
#define HAVE_MAJOR 0x200
#define HAVE_MINOR 0x400
#define HAVE_SPARSE 0x800

typedef struct {
	int have;
	char path[TAR_PATH_MAX];
	char link[TAR_PATH_MAX];
	uint64_t size;
	uint64_t uid;
	uint64_t gid;
	uint64_t mtime;
	uint64_t atime;
	uint64_t btime;
	uint32_t flags;
	uint32_t devmajor;
	uint32_t devminor;
	tar_xattrs_t x;
	/* GNU sparse files: formats 0.0 and 0.1 keep the map here, 1.0 in the data */
	int sparse_major;
	uint64_t sparse_size;
	char sparse_name[TAR_PATH_MAX];
	tar_map_t map;
	uint64_t sparse_off;          /* 0.0: an offset waiting for its length */
} tar_meta_t;

static void meta_free(tar_meta_t* m) {
	xattrs_free(&m->x);
	map_free(&m->map);
	memset(m, 0, sizeof(*m));
}

static uint64_t pax_number(const uint8_t* v, size_t len) {
	char buf[32];
	size_t n = len < sizeof(buf) - 1 ? len : sizeof(buf) - 1;
	memcpy(buf, v, n);
	buf[n] = 0;
	return strtoull(buf, NULL, 10);
}

/* Seconds with an optional fraction, as nanoseconds (times before 1970 become 0) */
static uint64_t pax_time(const uint8_t* v, size_t len) {
	uint64_t s = 0, ns = 0;
	size_t i = 0;
	int digits = 0;
	if(len && v[0] == '-')
		return 0;
	for(; i < len && v[i] >= '0' && v[i] <= '9'; i++)
		if(s < 100000000000ULL)
			s = s * 10 + (uint64_t)(v[i] - '0');
	if(i < len && v[i] == '.')
		for(i++; i < len && v[i] >= '0' && v[i] <= '9'; i++)
			if(digits < 9) {
				ns = ns * 10 + (uint64_t)(v[i] - '0');
				digits++;
			}
	for(; digits < 9; digits++)
		ns *= 10;
	return s * 1000000000ULL + ns;
}

static int b64_value(uint8_t c) {
	if(c >= 'A' && c <= 'Z')
		return c - 'A';
	if(c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if(c >= '0' && c <= '9')
		return c - '0' + 52;
	return c == '+' ? 62 : c == '/' ? 63 : -1;
}

/* Base64 with or without padding (libarchive leaves it out) */
static uint8_t* base64_decode(const uint8_t* s, size_t len, size_t* out) {
	uint8_t* d = (uint8_t*)apfs_malloc(len * 3 / 4 + 3);
	uint32_t acc = 0;
	int bits = 0;
	size_t i, n = 0;
	for(i = 0; i < len && s[i] != '='; i++) {
		int v = b64_value(s[i]);
		if(v < 0) {
			free(d);
			return NULL;
		}
		acc = (acc << 6) | (uint32_t)v;
		bits += 6;
		if(bits >= 8) {
			bits -= 8;
			d[n++] = (uint8_t)(acc >> bits);
		}
	}
	*out = n;
	return d;
}

static int hex_value(uint8_t c) {
	if(c >= '0' && c <= '9')
		return c - '0';
	if(c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if(c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* LIBARCHIVE.xattr names escape some bytes as %XX */
static size_t url_decode(char* dst, const uint8_t* s, size_t len) {
	size_t i, n = 0;
	for(i = 0; i < len; i++) {
		if(s[i] == '%' && i + 2 < len && hex_value(s[i + 1]) >= 0 && hex_value(s[i + 2]) >= 0) {
			dst[n++] = (char)(hex_value(s[i + 1]) * 16 + hex_value(s[i + 2]));
			i += 2;
		} else {
			dst[n++] = (char)s[i];
		}
	}
	return n;
}

static int pax_parse(const uint8_t* data, size_t size, tar_meta_t* m, int warn) {
	size_t pos = 0;
	while(pos < size) {
		size_t len = 0, start = pos, klen, vlen;
		const uint8_t* key;
		const uint8_t* val;
		while(pos < size && data[pos] >= '0' && data[pos] <= '9') {
			len = len * 10 + (size_t)(data[pos] - '0');
			pos++;
			if(len > size)
				return 0;
		}
		if(pos >= size || data[pos] != ' ' || len == 0 || start + len > size || data[start + len - 1] != '\n')
			return 0;
		pos++;
		key = data + pos;
		klen = 0;
		while(pos + klen < start + len && key[klen] != '=')
			klen++;
		if(pos + klen >= start + len)
			return 0;
		val = key + klen + 1;
		vlen = (start + len - 1) - (size_t)(val - data);
#define KEY(s) (klen == sizeof(s) - 1 && !memcmp(key, s, klen))
		if(KEY("path") && vlen < TAR_PATH_MAX) {
			memcpy(m->path, val, vlen);
			m->path[vlen] = 0;
			m->have |= HAVE_PATH;
		} else if(KEY("linkpath") && vlen < TAR_PATH_MAX) {
			memcpy(m->link, val, vlen);
			m->link[vlen] = 0;
			m->have |= HAVE_LINK;
		} else if(KEY("size")) {
			m->size = pax_number(val, vlen);
			m->have |= HAVE_SIZE;
		} else if(KEY("uid")) {
			m->uid = pax_number(val, vlen);
			m->have |= HAVE_UID;
		} else if(KEY("gid")) {
			m->gid = pax_number(val, vlen);
			m->have |= HAVE_GID;
		} else if(KEY("mtime")) {
			m->mtime = pax_time(val, vlen);
			m->have |= HAVE_MTIME;
		} else if(KEY("atime")) {
			m->atime = pax_time(val, vlen);
			m->have |= HAVE_ATIME;
		} else if(KEY("LIBARCHIVE.creationtime")) {
			m->btime = pax_time(val, vlen);
			m->have |= HAVE_BTIME;
		} else if(KEY("SCHILY.devmajor")) {
			m->devmajor = (uint32_t)pax_number(val, vlen);
			m->have |= HAVE_MAJOR;
		} else if(KEY("SCHILY.devminor")) {
			m->devminor = (uint32_t)pax_number(val, vlen);
			m->have |= HAVE_MINOR;
		} else if(KEY("SCHILY.fflags")) {
			/* unknown names are skipped rather than dropping all flags */
			char buf[256];
			char* names[32];
			size_t n = vlen < sizeof(buf) - 1 ? vlen : sizeof(buf) - 1, i, nn;
			memcpy(buf, val, n);
			buf[n] = 0;
			nn = split(buf, ',', names, 32);
			m->flags = 0;
			for(i = 0; i < nn; i++) {
				uint32_t set, clear;
				if(!strcmp(names[i], "archived"))
					names[i] = "arch";
				if(apfslib_parse_flags(names[i], &set, &clear) == APFS_OK)
					m->flags |= set;
				else if(names[i][0] && warn)
					APFS_WARN("untar: unknown file flag %s", names[i]);
			}
			m->have |= HAVE_FLAGS;
		} else if(klen > 13 && !memcmp(key, "SCHILY.xattr.", 13)) {
			xattrs_put(&m->x, (const char*)key + 13, klen - 13, val, vlen);
		} else if(klen > 17 && !memcmp(key, "LIBARCHIVE.xattr.", 17)) {
			char name[256];
			size_t dlen;
			uint8_t* d = base64_decode(val, vlen, &dlen);
			if(!d || klen - 17 >= sizeof(name)) {
				free(d);
				return 0;
			}
			xattrs_put(&m->x, name, url_decode(name, key + 17, klen - 17), d, dlen);
			free(d);
		} else if(KEY("SCHILY.acl.ace")) {
			acl_from_nfs4(&m->x, val, vlen, warn);
		} else if(KEY("SCHILY.acl.access") || KEY("SCHILY.acl.default")) {
			if(warn)
				APFS_WARN("untar: POSIX.1e ACLs have no APFS equivalent; skipped");
		} else if(klen > 11 && !memcmp(key, "GNU.sparse.", 11)) {
			m->have |= HAVE_SPARSE;
			if(KEY("GNU.sparse.major")) {
				m->sparse_major = (int)pax_number(val, vlen);
			} else if(KEY("GNU.sparse.name") && vlen < TAR_PATH_MAX) {
				memcpy(m->sparse_name, val, vlen);
				m->sparse_name[vlen] = 0;
			} else if(KEY("GNU.sparse.realsize") || KEY("GNU.sparse.size")) {
				m->sparse_size = pax_number(val, vlen);
			} else if(KEY("GNU.sparse.offset")) {
				m->sparse_off = pax_number(val, vlen);
			} else if(KEY("GNU.sparse.numbytes")) {
				if(!map_add(&m->map, m->sparse_off, pax_number(val, vlen)))
					return 0;
			} else if(KEY("GNU.sparse.map")) {
				/* "offset,length,offset,length..." */
				size_t i = 0, k = 0;
				uint64_t v[2];
				while(i < vlen) {
					size_t j = i;
					while(j < vlen && val[j] != ',')
						j++;
					v[k++] = pax_number(val + i, j - i);
					if(k == 2) {
						if(!map_add(&m->map, v[0], v[1]))
							return 0;
						k = 0;
					}
					i = j + 1;
				}
				if(k)
					return 0;
			}
		}
#undef KEY
		pos = start + len;
	}
	return 1;
}

/* Archive entries */

typedef struct {
	char path[TAR_PATH_MAX];
	char link[TAR_PATH_MAX];
	char type;
	uint64_t size;                /* bytes stored in the archive */
	uint64_t data_off;
	uint64_t realsize;            /* the file size, larger than size for sparse files */
	tar_map_t map;                /* where the stored bytes go in a sparse file */
	int sparse;
	uint32_t mode;
	uint32_t uid;
	uint32_t gid;
	uint64_t mtime;
	uint64_t atime;
	uint64_t btime;
	int have;                     /* HAVE_ATIME, HAVE_BTIME, HAVE_FLAGS */
	uint32_t devmajor;
	uint32_t devminor;
	uint32_t flags;
	tar_xattrs_t x;               /* extended attributes, the ACL included */
} tar_entry_t;

static void entry_free(tar_entry_t* e) {
	xattrs_free(&e->x);
	map_free(&e->map);
}

/* Takes PAX values; path, link and size only come from per-entry headers */
static void entry_apply(tar_entry_t* e, const tar_meta_t* m, int per_entry) {
	if(per_entry && (m->have & HAVE_PATH))
		strcpy(e->path, m->path);
	if(per_entry && (m->have & HAVE_LINK))
		strcpy(e->link, m->link);
	if(m->have & HAVE_UID)
		e->uid = (uint32_t)m->uid;
	if(m->have & HAVE_GID)
		e->gid = (uint32_t)m->gid;
	if(m->have & HAVE_MTIME)
		e->mtime = m->mtime;
	if(m->have & HAVE_ATIME)
		e->atime = m->atime;
	if(m->have & HAVE_BTIME)
		e->btime = m->btime;
	if(m->have & HAVE_FLAGS)
		e->flags = m->flags;
	if(m->have & HAVE_MAJOR)
		e->devmajor = m->devmajor;
	if(m->have & HAVE_MINOR)
		e->devminor = m->devminor;
	e->have |= m->have & (HAVE_ATIME | HAVE_BTIME | HAVE_FLAGS);
	xattrs_merge(&e->x, &m->x);
}

static int tar_read(AbstractFile* f, uint64_t off, void* buf, size_t len) {
	return f->seek(f, (off_t)off) == 0 && f->read(f, buf, len) == len;
}

static int tar_number(const uint8_t* field, size_t len, uint64_t* value) {
	size_t i = 0;
	*value = 0;
	if(field[0] & 0x80) {
		/* GNU base-256 */
		if(field[0] & 0x40)
			return 0;
		*value = field[0] & 0x3f;
		for(i = 1; i < len; i++) {
			if(*value > (UINT64_MAX - field[i]) / 256)
				return 0;
			*value = *value * 256 + field[i];
		}
		return 1;
	}
	while(i < len && field[i] == ' ')
		i++;
	for(; i < len && field[i] >= '0' && field[i] <= '7'; i++) {
		if(*value > (UINT64_MAX - (uint64_t)(field[i] - '0')) / 8)
			return 0;
		*value = *value * 8 + (uint64_t)(field[i] - '0');
	}
	for(; i < len; i++)
		if(field[i] != 0 && field[i] != ' ')
			return 0;
	return 1;
}

static void tar_string(char* dst, const uint8_t* field, size_t size) {
	size_t n = 0;
	while(n < size && field[n])
		n++;
	memcpy(dst, field, n);
	dst[n] = 0;
}

/* Normalizes an archive path; rejects absolute paths and traversal */
static int tar_path(char* path) {
	char* src = path;
	char* dst = path;
	while(*src == '/')
		src++;
	while(*src) {
		char* start;
		size_t len;
		while(*src == '/')
			src++;
		start = src;
		while(*src && *src != '/')
			src++;
		len = (size_t)(src - start);
		if(!len || (len == 1 && start[0] == '.'))
			continue;
		if(len > 255 || (len == 2 && start[0] == '.' && start[1] == '.'))
			return 0;
		if(dst != path)
			*dst++ = '/';
		memmove(dst, start, len);
		dst += len;
	}
	*dst = 0;
	return 1;
}

/* GNU sparse files ('S'): 4 segments in the header, 21 in each extension block after it */
static int gnu_sparse(AbstractFile* f, const uint8_t* hdr, uint64_t* off, uint64_t length, tar_entry_t* e) {
	uint8_t blk[TAR_BLOCK];
	const uint8_t* sp = hdr + 386;
	int n = 4, more = hdr[482], i;
	if(!tar_number(hdr + 483, 12, &e->realsize))
		return 0;
	for(;;) {
		for(i = 0; i < n && sp[i * 24]; i++) {
			uint64_t so, sl;
			if(!tar_number(sp + i * 24, 12, &so) || !tar_number(sp + i * 24 + 12, 12, &sl) || !map_add(&e->map, so, sl))
				return 0;
		}
		if(!more)
			return 1;
		if(*off + TAR_BLOCK > length || !tar_read(f, *off, blk, TAR_BLOCK))
			return 0;
		*off += TAR_BLOCK;
		sp = blk;
		n = 21;
		more = blk[504];
	}
}

/* GNU sparse 1.0: the map starts the data, as decimal lines padded to a block */
static int pax_sparse_map(AbstractFile* f, tar_entry_t* e) {
	uint8_t blk[TAR_BLOCK];
	uint64_t pos = 0, num = 0, count = 0, first = 0, used;
	size_t nums = 0;
	int digits = 0;
	for(;;) {
		uint8_t c;
		if(pos % TAR_BLOCK == 0 && (pos >= e->size || !tar_read(f, e->data_off + pos, blk, TAR_BLOCK)))
			return 0;
		c = blk[pos % TAR_BLOCK];
		pos++;
		if(c >= '0' && c <= '9' && digits < 20) {
			num = num * 10 + (uint64_t)(c - '0');
			digits++;
		} else if(c == '\n' && digits) {
			if(!nums)
				count = num;
			else if(nums % 2)
				first = num;
			else if(!map_add(&e->map, first, num))
				return 0;
			nums++;
			num = 0;
			digits = 0;
			if(count > SPARSE_MAX || nums == 1 + 2 * count)
				break;
		} else {
			return 0;
		}
	}
	used = (pos + TAR_BLOCK - 1) / TAR_BLOCK * TAR_BLOCK;
	if(count > SPARSE_MAX || used > e->size)
		return 0;
	e->data_off += used;
	e->size -= used;
	return 1;
}

/* Reads the file contents: the stored segments, with zeros in the holes */
typedef struct {
	AbstractFile* f;
	const tar_entry_t* e;
	uint64_t off;                 /* next stored byte */
	uint64_t pos;                 /* position in the file */
	size_t seg;
} tar_src_t;

static size_t tar_source(void* ctx, void* buf, size_t len) {
	tar_src_t* s = (tar_src_t*)ctx;
	const tar_map_t* m = &s->e->map;
	uint64_t left;
	if(s->pos >= s->e->realsize)
		return 0;
	while(s->seg < m->n && s->pos >= m->off[s->seg] + m->len[s->seg])
		s->seg++;
	if(s->seg < m->n && s->pos >= m->off[s->seg]) {
		left = m->off[s->seg] + m->len[s->seg] - s->pos;
		if(len > left)
			len = (size_t)left;
		if(!tar_read(s->f, s->off, buf, len))
			return 0;
		s->off += len;
	} else {
		left = (s->seg < m->n ? m->off[s->seg] : s->e->realsize) - s->pos;
		if(len > left)
			len = (size_t)left;
		memset(buf, 0, len);
	}
	s->pos += len;
	return len;
}

static int make_parents(apfs_vol_t* vol, const char* path, const apfslib_opts_t* o) {
	char* copy = apfs_strdup(path);
	char* p;
	int ret = APFS_OK;
	for(p = copy + 1; *p && ret == APFS_OK; p++) {
		uint64_t ino;
		if(*p != '/')
			continue;
		*p = 0;
		if(apfs_lookup(vol, copy, 0, &ino, NULL, NULL) == APFS_ENOENT)
			ret = apfslib_mkdir(vol, copy, 0, o);
		*p = '/';
	}
	free(copy);
	return ret;
}

/* Times and flags of directories, set once their contents are in place */
typedef struct {
	uint64_t ino;
	int mask;
	apfs_setattr_t a;
} tar_fixup_t;

typedef struct {
	tar_fixup_t* v;
	size_t n;
} tar_fixups_t;

static int extract_entry(apfs_vol_t* vol, AbstractFile* f, tar_entry_t* e, const char* dest, const apfslib_opts_t* o,
		tar_fixups_t* fix) {
	char full[TAR_PATH_MAX * 2];
	uint64_t parent, ino = 0;
	char* name = NULL;
	apfs_dirent_t de;
	int ret, exists;
	uint16_t type;
	apfs_setattr_t a;
	int mask, later;
	size_t i;

	if(!e->path[0])
		return APFS_OK; /* the archive root */
	snprintf(full, sizeof(full), "%s/%s", strcmp(dest, "/") == 0 ? "" : dest, e->path);
	ret = make_parents(vol, full, o);
	if(ret < 0)
		return ret;
	ret = apfs_lookup(vol, full, 0, &ino, &parent, &name);
	if(ret < 0 && ret != APFS_ENOENT)
		return ret;
	if(!name)
		return APFS_EINVAL;
	exists = ret == APFS_OK && apfs_dir_lookup(vol, parent, name, &de) == APFS_OK;

	switch(e->type) {
		case '5': type = APFS_S_IFDIR; break;
		case '2': type = APFS_S_IFLNK; break;
		case '3': type = APFS_S_IFCHR; break;
		case '4': type = APFS_S_IFBLK; break;
		case '6': type = APFS_S_IFIFO; break;
		default: type = APFS_S_IFREG; break;
	}

	if(exists) {
		int isdir = (de.flags & DREC_TYPE_MASK) == APFS_DT_DIR;
		apfs_dirent_release(&de);
		if(isdir && type == APFS_S_IFDIR && e->type != '1') {
			/* keep the directory, update its attributes below */
		} else {
			ret = isdir ? apfslib_rm(vol, full, 1, 1) : apfs_unlink(vol, parent, name);
			if(ret < 0) {
				free(name);
				return ret;
			}
			exists = 0;
		}
	}

	if(e->type == '1') {
		char target[TAR_PATH_MAX * 2];
		uint64_t tino;
		char tpath[TAR_PATH_MAX];
		strcpy(tpath, e->link);
		if(!tar_path(tpath)) {
			free(name);
			return APFS_EINVAL;
		}
		snprintf(target, sizeof(target), "%s/%s", strcmp(dest, "/") == 0 ? "" : dest, tpath);
		ret = apfs_lookup(vol, target, 0, &tino, NULL, NULL);
		if(ret == APFS_OK)
			ret = apfs_link(vol, tino, parent, name);
		free(name);
		return ret;
	}

	if(!exists) {
		apfs_create_t c;
		memset(&c, 0, sizeof(c));
		c.mode = (uint16_t)(type | (e->mode & 07777));
		c.uid = e->uid;
		c.gid = e->gid;
		c.rdev = ((e->devmajor & 0xff) << 24) | (e->devminor & 0xffffff);
		if(type == APFS_S_IFLNK)
			ret = apfs_symlink(vol, parent, name, e->link, &c, &ino);
		else
			ret = apfs_create(vol, parent, name, &c, &ino);
		if(ret < 0) {
			free(name);
			return ret;
		}
	}
	free(name);

	if(type == APFS_S_IFREG && e->realsize) {
		tar_src_t src;
		memset(&src, 0, sizeof(src));
		src.f = f;
		src.e = e;
		src.off = e->data_off;
		if(o->compress != APFS_COMPRESS_NONE && e->realsize < ((uint64_t)1 << 31)) {
			uint8_t* data = (uint8_t*)apfs_malloc((size_t)e->realsize);
			size_t got = 0, n;
			while(got < e->realsize && (n = tar_source(&src, data + got, (size_t)e->realsize - got)) > 0)
				got += n;
			ret = got == e->realsize ? apfs_file_write_compressed(vol, ino, data, got, o->compress) : APFS_EIO;
			free(data);
		} else {
			ret = apfs_file_write_ex(vol, ino, tar_source, &src, e->realsize,
				o->sparse || e->sparse ? APFS_WRITE_SPARSE : 0);
		}
		if(ret < 0)
			return ret;
	}

	for(i = 0; i < e->x.n; i++) {
		if(!strcmp(e->x.v[i].name, DECMPFS_EA_NAME) || !strcmp(e->x.v[i].name, SYMLINK_EA_NAME))
			continue;
		ret = apfs_xattr_set(vol, ino, e->x.v[i].name, e->x.v[i].val, e->x.v[i].len, 0);
		if(ret < 0)
			return ret;
	}

	/* directory times would change as entries are added to them, so they come last */
	memset(&a, 0, sizeof(a));
	mask = APFS_SETATTR_UID | APFS_SETATTR_GID;
	if(type != APFS_S_IFLNK) {
		a.mode = (uint16_t)(e->mode & 07777);
		mask |= APFS_SETATTR_MODE;
	}
	a.uid = e->uid;
	a.gid = e->gid;
	ret = apfs_setattr(vol, ino, mask, &a);
	if(ret < 0)
		return ret;
	later = APFS_SETATTR_MTIME;
	a.mtime = e->mtime;
	if(e->have & HAVE_ATIME) {
		a.atime = e->atime;
		later |= APFS_SETATTR_ATIME;
	}
	if(e->have & HAVE_BTIME) {
		a.btime = e->btime;
		later |= APFS_SETATTR_BTIME;
	} else if(e->mtime < apfs_time_now()) {
		/* as on macOS, where an earlier modification time moves the creation time back */
		a.btime = e->mtime;
		later |= APFS_SETATTR_BTIME;
	}
	if(e->have & HAVE_FLAGS) {
		a.bsd_flags = e->flags & ~(uint32_t)(APFS_UF_COMPRESSED | APFS_SF_DATALESS);
		later |= APFS_SETATTR_FLAGS;
	}
	if(type != APFS_S_IFDIR)
		return apfs_setattr(vol, ino, later, &a);
	fix->v = (tar_fixup_t*)apfs_realloc(fix->v, (fix->n + 1) * sizeof(tar_fixup_t));
	fix->v[fix->n].ino = ino;
	fix->v[fix->n].mask = later;
	fix->v[fix->n].a = a;
	fix->n++;
	return APFS_OK;
}

/* "dir/._name" carries the metadata of "dir/name" */
static int is_appledouble_of(const char* ad, const char* path) {
	const char* base = strrchr(ad, '/');
	size_t dirlen = base ? (size_t)(base - ad) + 1 : 0;
	base = base ? base + 1 : ad;
	return base[0] == '.' && base[1] == '_' && base[2] && !strncmp(ad, path, dirlen) && !strcmp(base + 2, path + dirlen);
}

static int is_appledouble_name(const char* path) {
	const char* base = strrchr(path, '/');
	base = base ? base + 1 : path;
	return base[0] == '.' && base[1] == '_' && base[2];
}

/* Paths of the entries so far, for checking hard links in the validation pass */
typedef struct {
	char* path;
	char type;
} tar_seen_ent_t;

typedef struct {
	tar_seen_ent_t* v;            /* open addressing; cap is a power of two */
	size_t n;
	size_t cap;
} tar_seen_t;

static tar_seen_ent_t* seen_slot(const tar_seen_t* s, const char* path) {
	uint64_t h = 0xcbf29ce484222325ULL; /* FNV-1a */
	const char* p;
	size_t i;
	for(p = path; *p; p++)
		h = (h ^ (uint8_t)*p) * 0x100000001b3ULL;
	for(i = (size_t)h & (s->cap - 1); s->v[i].path && strcmp(s->v[i].path, path); i = (i + 1) & (s->cap - 1))
		;
	return &s->v[i];
}

static void seen_put(tar_seen_t* s, const char* path, char type) {
	tar_seen_ent_t* e;
	size_t i;
	if(2 * (s->n + 1) > s->cap) {
		tar_seen_t g;
		g.cap = s->cap ? 2 * s->cap : 1024;
		g.n = s->n;
		g.v = (tar_seen_ent_t*)apfs_calloc(g.cap, sizeof(tar_seen_ent_t));
		for(i = 0; i < s->cap; i++)
			if(s->v[i].path)
				*seen_slot(&g, s->v[i].path) = s->v[i];
		free(s->v);
		*s = g;
	}
	e = seen_slot(s, path);
	if(!e->path) {
		e->path = apfs_strdup(path);
		s->n++;
	}
	e->type = type;
}

static void seen_free(tar_seen_t* s) {
	size_t i;
	for(i = 0; i < s->cap; i++)
		free(s->v[i].path);
	free(s->v);
}

/* Compares normalized archive paths the way the volume compares names */
static int path_equal(apfs_vol_t* vol, const char* a, const char* b) {
	for(;;) {
		size_t la = strcspn(a, "/"), lb = strcspn(b, "/");
		if(apfs_name_equal(a, la, b, lb, vol->hashed_names, vol->case_fold))
			return 0;
		if(!a[la] || !b[lb])
			return !a[la] && !b[lb];
		a += la + 1;
		b += lb + 1;
	}
}

typedef struct {
	apfs_vol_t* vol;
	AbstractFile* f;
	const char* dest;
	const apfslib_opts_t* o;
	int extract;
	tar_fixups_t fix;
	tar_seen_t seen;              /* validation: the paths so far */
} tar_ctx_t;

/* A hard link's target must be an earlier entry or already be in the volume,
 * and not a directory; extraction would stop halfway otherwise */
static int link_target_ok(tar_ctx_t* c, const tar_entry_t* e) {
	char target[TAR_PATH_MAX], full[TAR_PATH_MAX * 2];
	tar_seen_ent_t* s;
	apfs_inode_t inode;
	uint64_t ino;
	size_t i;
	char* p;
	int ok;

	strcpy(target, e->link);
	/* extraction replaces the link's own path first */
	if(!tar_path(target) || path_equal(c->vol, target, e->path))
		return 0;
	if(c->seen.cap && (s = seen_slot(&c->seen, target))->path)
		return s->type != '5';
	snprintf(full, sizeof(full), "%s/%s", strcmp(c->dest, "/") == 0 ? "" : c->dest, target);
	if(apfs_lookup(c->vol, full, 0, &ino, NULL, NULL) == APFS_OK && apfs_inode_read(c->vol, ino, &inode) == APFS_OK) {
		ok = (inode.mode & APFS_S_IFMT) != APFS_S_IFDIR;
		apfs_inode_release(&inode);
		return ok;
	}
	/* through a symbolic link from the archive: only extraction can tell */
	for(p = strchr(target, '/'); p && c->seen.cap; p = strchr(p + 1, '/')) {
		*p = 0;
		s = seen_slot(&c->seen, target);
		*p = '/';
		if(s->path && s->type == '2')
			return 1;
	}
	/* an earlier entry spelled differently */
	for(i = 0; i < c->seen.cap; i++)
		if(c->seen.v[i].path && path_equal(c->vol, c->seen.v[i].path, target))
			return c->seen.v[i].type != '5';
	return 0;
}

static int put_entry(tar_ctx_t* c, tar_entry_t* e) {
	int ret;
	if(!c->extract) {
		if(e->type == '1' && !link_target_ok(c, e)) {
			APFS_ERR("untar: cannot hard link %s to %s: not an earlier file in the archive or a file in the volume",
				e->path, e->link);
			return APFS_EINVAL;
		}
		if(e->path[0])
			seen_put(&c->seen, e->path, e->type);
		return APFS_OK;
	}
	if(!c->o->quiet)
		printf("%s: %s\n", e->type == '5' ? "folder" : "file", e->path);
	ret = extract_entry(c->vol, c->f, e, c->dest, c->o, &c->fix);
	if(ret < 0)
		APFS_ERR("untar: cannot extract %s: %s", e->path, apfs_strerror(ret));
	return ret;
}

/* An AppleDouble entry joins the entry that follows when that is its file;
 * otherwise it is an ordinary file */
static int put_appledouble(tar_ctx_t* c, tar_entry_t* ad, tar_entry_t* next) {
	tar_xattrs_t x;
	uint8_t* data;
	int ok;
	if(!next || !is_appledouble_of(ad->path, next->path) || ad->size > APPLEDOUBLE_MAX)
		return put_entry(c, ad);
	data = (uint8_t*)apfs_malloc((size_t)ad->size + 1);
	if(!tar_read(c->f, ad->data_off, data, (size_t)ad->size)) {
		free(data);
		return APFS_EIO;
	}
	memset(&x, 0, sizeof(x));
	ok = appledouble_parse(data, (size_t)ad->size, &x, c->extract);
	free(data);
	if(ok)
		xattrs_merge(&next->x, &x);
	xattrs_free(&x);
	return ok ? APFS_OK : put_entry(c, ad);
}

static int tar_pass(apfs_vol_t* vol, AbstractFile* f, const char* dest, const apfslib_opts_t* o, int extract) {
	off_t length = f->getLength(f);
	uint64_t off = 0;
	char long_name[TAR_PATH_MAX], long_link[TAR_PATH_MAX];
	int have_long_name = 0, have_long_link = 0, have_ad = 0, ret = APFS_EINVAL;
	tar_meta_t glob, pax;
	tar_entry_t e, ad;
	tar_ctx_t c;
	size_t i;

	memset(&glob, 0, sizeof(glob));
	memset(&pax, 0, sizeof(pax));
	memset(&e, 0, sizeof(e));
	memset(&ad, 0, sizeof(ad));
	memset(&c, 0, sizeof(c));
	c.vol = vol;
	c.f = f;
	c.dest = dest;
	c.o = o;
	c.extract = extract;
	if(length < 0 || (uint64_t)length % TAR_BLOCK)
		return APFS_EINVAL;

	while(off < (uint64_t)length) {
		uint8_t block[TAR_BLOCK];
		uint64_t size, mode, uid, gid, mtime, chk, padded, dmaj = 0, dmin = 0, hdr_end;
		unsigned sum = 0;
		int ssum = 0;
		char type;

		if(!tar_read(f, off, block, TAR_BLOCK)) {
			ret = APFS_EIO;
			goto out;
		}
		for(i = 0; i < TAR_BLOCK && !block[i]; i++)
			;
		if(i == TAR_BLOCK) {
			/* end of archive: everything after must be zero */
			uint64_t pos;
			if(have_long_name || have_long_link || pax.have)
				goto out;
			for(pos = off + TAR_BLOCK; pos < (uint64_t)length; pos += TAR_BLOCK) {
				int j;
				if(!tar_read(f, pos, block, TAR_BLOCK)) {
					ret = APFS_EIO;
					goto out;
				}
				for(j = 0; j < TAR_BLOCK; j++)
					if(block[j])
						goto out;
			}
			ret = have_ad ? put_appledouble(&c, &ad, NULL) : APFS_OK;
			goto out;
		}

		if(!tar_number(block + 148, 8, &chk))
			goto out;
		for(i = 0; i < TAR_BLOCK; i++) {
			uint8_t ch = (i >= 148 && i < 156) ? ' ' : block[i];
			sum += ch;
			ssum += (signed char)ch;
		}
		if(chk != sum && (ssum < 0 || chk != (uint64_t)ssum))
			goto out;
		if(!tar_number(block + 124, 12, &size) || !tar_number(block + 100, 8, &mode) ||
				!tar_number(block + 108, 8, &uid) || !tar_number(block + 116, 8, &gid) ||
				!tar_number(block + 136, 12, &mtime))
			goto out;
		tar_number(block + 329, 8, &dmaj);
		tar_number(block + 337, 8, &dmin);
		type = block[156] ? (char)block[156] : '0';
		if((pax.have & HAVE_SIZE) && type != 'x' && type != 'g' && type != 'L' && type != 'K')
			size = pax.size;

		memset(&e, 0, sizeof(e));
		hdr_end = off + TAR_BLOCK;
		if(type == 'S' && !gnu_sparse(f, block, &hdr_end, (uint64_t)length, &e))
			goto out;
		if(size > (uint64_t)length - hdr_end)
			goto out;
		padded = (size + TAR_BLOCK - 1) / TAR_BLOCK * TAR_BLOCK;

		if(type == 'L' || type == 'K') {
			char* dst = type == 'L' ? long_name : long_link;
			if(!size || size >= TAR_PATH_MAX)
				goto out;
			if(!tar_read(f, hdr_end, dst, (size_t)size)) {
				ret = APFS_EIO;
				goto out;
			}
			dst[size] = 0;
			if(type == 'L')
				have_long_name = 1;
			else
				have_long_link = 1;
			off = hdr_end + padded;
			continue;
		}
		if(type == 'x' || type == 'g') {
			uint8_t* data;
			int ok;
			if(size > PAX_MAX)
				goto out;
			data = (uint8_t*)apfs_malloc((size_t)size + 1);
			if(!tar_read(f, hdr_end, data, (size_t)size)) {
				free(data);
				ret = APFS_EIO;
				goto out;
			}
			if(type == 'x')
				meta_free(&pax);
			ok = pax_parse(data, (size_t)size, type == 'x' ? &pax : &glob, extract);
			free(data);
			if(!ok)
				goto out;
			off = hdr_end + padded;
			continue;
		}
		if(type == 'V') {
			/* a volume label */
			off = hdr_end + padded;
			continue;
		}
		if(!strchr("01234567DS", type)) {
			APFS_ERR("unsupported tar entry type '%c'", type);
			ret = APFS_EUNSUPP;
			goto out;
		}
		if(size && !strchr("071DS", type))
			goto out;

		if(have_long_name) {
			strcpy(e.path, long_name);
		} else if(!memcmp(block + 257, "ustar", 6) && block[345]) {
			/* POSIX ustar; the GNU format keeps other fields at 345 */
			char prefix[156], base[101];
			tar_string(prefix, block + 345, 155);
			tar_string(base, block, 100);
			snprintf(e.path, sizeof(e.path), "%s/%s", prefix, base);
		} else {
			tar_string(e.path, block, 100);
		}
		if(have_long_link)
			strcpy(e.link, long_link);
		else
			tar_string(e.link, block + 157, 100);
		e.type = type == '7' || type == 'S' ? '0' : type == 'D' ? '5' : type;
		e.size = size;
		e.data_off = hdr_end;
		e.mode = (uint32_t)(mode & 07777);
		e.uid = (uint32_t)uid;
		e.gid = (uint32_t)gid;
		e.mtime = mtime * 1000000000ULL;
		e.devmajor = (uint32_t)dmaj;
		e.devminor = (uint32_t)dmin;
		entry_apply(&e, &glob, 0);
		entry_apply(&e, &pax, 1);
		if(type == 'S') {
			e.sparse = 1;
		} else if(pax.have & HAVE_SPARSE) {
			if(pax.sparse_name[0])
				strcpy(e.path, pax.sparse_name);
			e.realsize = pax.sparse_size;
			e.sparse = 1;
			if(pax.sparse_major == 1) {
				if(!pax_sparse_map(f, &e))
					goto out;
			} else {
				e.map = pax.map;
				memset(&pax.map, 0, sizeof(pax.map));
			}
		}
		if(e.sparse) {
			if(e.type != '0' || !map_check(&e.map, e.realsize, e.size))
				goto out;
		} else {
			e.realsize = e.type == '0' ? size : 0;
			if(e.realsize && !map_add(&e.map, 0, size))
				goto out;
		}
		meta_free(&pax);
		have_long_name = have_long_link = 0;
		off = hdr_end + padded;

		if(!tar_path(e.path) || ((e.type == '1' || e.type == '2') && !e.link[0]))
			goto out;

		if(have_ad) {
			ret = put_appledouble(&c, &ad, &e);
			entry_free(&ad);
			have_ad = 0;
			if(ret < 0)
				goto out;
			ret = APFS_EINVAL;
		}
		if(e.type == '0' && !e.sparse && is_appledouble_name(e.path)) {
			ad = e;
			memset(&e, 0, sizeof(e));
			have_ad = 1;
			continue;
		}
		ret = put_entry(&c, &e);
		entry_free(&e);
		if(ret < 0)
			goto out;
		ret = APFS_EINVAL; /* until the end-of-archive marker */
	}
out:
	for(i = 0; ret == APFS_OK && i < c.fix.n; i++)
		ret = apfs_setattr(vol, c.fix.v[i].ino, c.fix.v[i].mask, &c.fix.v[i].a);
	free(c.fix.v);
	seen_free(&c.seen);
	entry_free(&e);
	entry_free(&ad);
	meta_free(&glob);
	meta_free(&pax);
	return ret;
}

int apfslib_untar(apfs_vol_t* vol, AbstractFile* tar, const char* dest, const apfslib_opts_t* o) {
	int ret;
	if(!tar || !tar->getLength || !tar->read || !tar->seek)
		return APFS_EINVAL;
	ret = tar_pass(vol, tar, dest, o, 0);
	if(ret < 0) {
		APFS_ERR("untar: invalid, truncated, or unsupported archive");
		return ret;
	}
	ret = tar_pass(vol, tar, dest, o, 1);
	if(ret < 0)
		APFS_ERR("untar: extraction failed");
	return ret;
}
